//! Reads done with the invoking user's credentials when this process is root
//! acting for someone else (contract: "Running as root").
//!
//! Every path the resolver reads is in the user's home or runtime directory,
//! so the user can point it anywhere with a symlink; root following it would
//! read files the user cannot. A forked child with the user's uid, gid and no
//! supplementary groups reads only what the user could read anyway, and
//! writes the bytes to a pipe.
//!
//! The child runs after `fork` in a possibly multi-threaded process, so it
//! does only async-signal-safe things: raw syscalls into buffers allocated
//! before the fork, then `_exit`. No allocation, no locks, no panics.

use std::ffi::{CStr, CString, c_int};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::keyring::{
    KEY_SPEC_USER_KEYRING, MAX_KEY_PAYLOAD, is_missing, raw_join_session_with_user, raw_read,
    raw_search,
};
use crate::sys::errno;

/// The credentials a child drops to. `None` in [`run`] means "fork but keep
/// ours", which tests use to exercise the child's own code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Creds {
    pub uid: u32,
    pub gid: u32,
}

/// Exit codes the children use.
const OK: c_int = 0;
const FAILED: c_int = 2;
const MISSING: c_int = 3;

/// A child that takes longer than this is killed: nothing it does should
/// take more than milliseconds, and the caller must never hang.
const CHILD_DEADLINE: Duration = Duration::from_secs(10);

pub(crate) enum Outcome {
    Data(Zeroizing<Vec<u8>>),
    Missing,
    Failed,
}

fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::other("path contains NUL"))
}

/// Write all of `data` to `fd`. Async-signal-safe.
fn write_all(fd: c_int, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        // SAFETY: data is a live slice; fd is the pipe's write end.
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return false;
        }
        data = &data[(n as usize).min(data.len())..];
    }
    true
}

/// Drop to `creds`: no supplementary groups, then gid, then uid. Raw
/// syscalls: they change only the calling thread, which after fork is the
/// whole process. Async-signal-safe.
fn drop_to(creds: Creds) -> bool {
    // SAFETY: setgroups with size 0 reads no memory; the set*id calls take integers.
    unsafe {
        libc::syscall(libc::SYS_setgroups, 0usize, std::ptr::null::<libc::gid_t>()) == 0
            && libc::syscall(libc::SYS_setresgid, creds.gid, creds.gid, creds.gid) == 0
            && libc::syscall(libc::SYS_setresuid, creds.uid, creds.uid, creds.uid) == 0
    }
}

/// Fork; in the child drop to `creds` and run `body(write_fd)` for its exit
/// code. In the parent collect what the child wrote (at most `max` bytes)
/// and its exit code; `Failed` covers every way the child can go wrong.
fn run(creds: Option<Creds>, max: usize, body: &mut dyn FnMut(c_int) -> c_int) -> Outcome {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds is a writable array of two ints.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Outcome::Failed;
    }
    let [read_fd, write_fd] = fds;
    // Allocated before the fork; the parent fills it.
    let mut out = Zeroizing::new(Vec::with_capacity(4096));
    // SAFETY: fork; the child below only makes async-signal-safe calls.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // SAFETY: closing our own descriptors.
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return Outcome::Failed;
    }
    if pid == 0 {
        // SAFETY: in the child: close, drop, protect, run, _exit -- all
        // async-signal-safe, none returning to the caller's stack frames.
        unsafe {
            libc::close(read_fd);
            if let Some(c) = creds
                && !drop_to(c)
            {
                libc::_exit(FAILED);
            }
            if crate::sys::protect_process().is_err() {
                libc::_exit(FAILED);
            }
            let code = body(write_fd);
            libc::_exit(code);
        }
    }
    // SAFETY: the parent's copy of the write end.
    unsafe { libc::close(write_fd) };
    let deadline = Instant::now() + CHILD_DEADLINE;
    let mut ok = true;
    let mut chunk = [0u8; 8192];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            ok = false;
            break;
        }
        let mut pfd = libc::pollfd {
            fd: read_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = c_int::try_from(left.as_millis())
            .unwrap_or(c_int::MAX)
            .max(1);
        // SAFETY: one valid pollfd.
        let r = unsafe { libc::poll(&mut pfd, 1, ms) };
        if r < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            ok = false;
            break;
        }
        if r == 0 {
            continue;
        }
        // SAFETY: chunk is writable for its length.
        let n = unsafe { libc::read(read_fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            ok = false;
            break;
        }
        if n == 0 {
            break;
        }
        let n = n as usize;
        if out.len() + n > max {
            ok = false;
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    chunk.fill(0);
    // SAFETY: closing our read end; the child, if still running, gets EPIPE.
    unsafe { libc::close(read_fd) };
    if !ok {
        // SAFETY: signalling our own child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    let mut status: c_int = 0;
    loop {
        // SAFETY: waiting for our own child.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r >= 0 || errno() != libc::EINTR {
            break;
        }
    }
    if !ok || !libc::WIFEXITED(status) {
        return Outcome::Failed;
    }
    match libc::WEXITSTATUS(status) {
        OK => Outcome::Data(out),
        MISSING => Outcome::Missing,
        _ => Outcome::Failed,
    }
}

/// The child's file read: a regular file only, non-blocking open. Async-signal-safe.
fn child_copy_file(path: &CStr, out: c_int) -> c_int {
    // SAFETY: path is NUL-terminated.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY,
        )
    };
    if fd < 0 {
        return if errno() == libc::ENOENT {
            MISSING
        } else {
            FAILED
        };
    }
    // SAFETY: zeroed stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is open; st is writable.
    if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return FAILED;
    }
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: buf is writable for its length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return FAILED;
        }
        if n == 0 {
            return OK;
        }
        if !write_all(out, &buf[..n as usize]) {
            return FAILED;
        }
    }
}

/// The file's bytes as `creds` would read them; `Ok(None)` when absent.
/// With `creds == None` this reads directly.
pub(crate) fn read_file(
    path: &Path,
    creds: Option<Creds>,
) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let Some(c) = creds else {
        return Ok(crate::fsx::read_opt(path)?.map(Zeroizing::new));
    };
    let p = cpath(path)?;
    match run(Some(c), crate::fsx::MAX_FILE, &mut |fd| {
        child_copy_file(&p, fd)
    }) {
        Outcome::Data(d) => Ok(Some(d)),
        Outcome::Missing => Ok(None),
        Outcome::Failed => Err(io::Error::other(format!(
            "cannot read {} as uid {}",
            path.display(),
            c.uid
        ))),
    }
}

/// How to test a path: `lexists` (the link itself) or `exists` (its target).
#[derive(Clone, Copy)]
pub(crate) enum Test {
    LExists,
    Exists,
}

fn child_exists(checks: &[(Test, CString)], out: c_int) -> c_int {
    for (test, path) in checks {
        // SAFETY: zeroed stat is a valid out-parameter; path is NUL-terminated.
        let found = unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            match test {
                Test::LExists => libc::lstat(path.as_ptr(), &mut st) == 0,
                Test::Exists => libc::stat(path.as_ptr(), &mut st) == 0,
            }
        };
        if !write_all(out, if found { b"1" } else { b"0" }) {
            return FAILED;
        }
    }
    OK
}

fn exists_direct(checks: &[(Test, &Path)]) -> Vec<bool> {
    checks
        .iter()
        .map(|(t, p)| match t {
            Test::LExists => crate::fsx::lexists(p),
            Test::Exists => crate::fsx::exists(p),
        })
        .collect()
}

/// Existence, tested with the invoking user's permissions: root walking a
/// path the user built would answer whether files exist behind directories
/// the user cannot enter. `Err` when the child cannot answer -- an error,
/// never "absent".
pub(crate) fn paths_exist(checks: &[(Test, &Path)], creds: Option<Creds>) -> io::Result<Vec<bool>> {
    if creds.is_none() {
        return Ok(exists_direct(checks));
    }
    paths_exist_in_child(checks, creds)
}

fn paths_exist_in_child(checks: &[(Test, &Path)], creds: Option<Creds>) -> io::Result<Vec<bool>> {
    let owned = checks
        .iter()
        .map(|(t, p)| cpath(p).map(|c| (*t, c)))
        .collect::<io::Result<Vec<_>>>()?;
    match run(creds, checks.len(), &mut |fd| child_exists(&owned, fd)) {
        Outcome::Data(d)
            if d.len() == checks.len() && d.iter().all(|b| matches!(b, b'0' | b'1')) =>
        {
            Ok(d.iter().map(|&b| b == b'1').collect())
        }
        _ => Err(io::Error::other(
            "the invoking user's existence check failed",
        )),
    }
}

fn child_read_cache(serial: Option<i32>, buf: &mut [u8], out: c_int) -> c_int {
    // A fresh session keyring with @u linked in confines the link needed for
    // possessor permission to this child.
    if raw_join_session_with_user().is_err() {
        return FAILED;
    }
    let id = match raw_search(KEY_SPEC_USER_KEYRING) {
        Ok(id) => id,
        Err(e) if is_missing(e) => match serial {
            Some(s) => s,
            None => return MISSING,
        },
        Err(_) => return FAILED,
    };
    match raw_read(id, buf) {
        Ok(n) if n <= buf.len() => {
            if write_all(out, &buf[..n]) {
                OK
            } else {
                FAILED
            }
        }
        Ok(_) => FAILED,
        Err(e) if is_missing(e) => MISSING,
        Err(_) => FAILED,
    }
}

/// The cache payload read by a child dropped to `creds` (root acting for
/// another user). `Err(())` is `cache-unreadable-as-root`.
pub(crate) fn read_cache(
    creds: Creds,
    serial: Option<i32>,
) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
    let mut buf = Zeroizing::new(vec![0u8; MAX_KEY_PAYLOAD + 1]);
    match run(Some(creds), MAX_KEY_PAYLOAD + 1, &mut |fd| {
        child_read_cache(serial, &mut buf, fd)
    }) {
        Outcome::Data(d) => Ok(Some(d)),
        Outcome::Missing => Ok(None),
        Outcome::Failed => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dangling_symlink_exists_only_as_a_link_in_parent_and_child() {
        let dir = tempfile::tempdir().expect("tempdir");
        let link = dir.path().join("dangling");
        let present = dir.path().join("present");
        let absent = dir.path().join("absent");
        std::os::unix::fs::symlink(dir.path().join("missing"), &link).expect("symlink");
        std::fs::write(&present, b"x").expect("write");
        let checks = [
            (Test::LExists, link.as_path()),
            (Test::Exists, link.as_path()),
            (Test::Exists, present.as_path()),
            (Test::LExists, absent.as_path()),
        ];
        let want = vec![true, false, true, false];
        assert_eq!(paths_exist(&checks, None).expect("direct"), want);
        // The child's own answer, forked without a credential drop.
        assert_eq!(paths_exist_in_child(&checks, None).expect("child"), want);
    }

    #[test]
    fn the_child_copies_a_file_and_reports_absence_and_refusal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("settings");
        std::fs::write(&file, b"identity_source=disk\n\x00\xff").expect("write");
        let p = cpath(&file).expect("path");
        match run(None, 1024, &mut |fd| child_copy_file(&p, fd)) {
            Outcome::Data(d) => assert_eq!(d.as_slice(), b"identity_source=disk\n\x00\xff"),
            _ => panic!("child failed"),
        }
        let gone = cpath(&dir.path().join("gone")).expect("path");
        assert!(matches!(
            run(None, 1024, &mut |fd| child_copy_file(&gone, fd)),
            Outcome::Missing
        ));
        let d = cpath(dir.path()).expect("path");
        assert!(matches!(
            run(None, 1024, &mut |fd| child_copy_file(&d, fd)),
            Outcome::Failed
        ));
        // More than the caller allows is a failure, not a truncation.
        assert!(matches!(
            run(None, 4, &mut |fd| child_copy_file(&p, fd)),
            Outcome::Failed
        ));
    }

    #[test]
    fn the_child_is_protected_from_core_dumps() {
        let probe = &mut |_fd| {
            let mut lim = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            // SAFETY: getrlimit/prctl with valid arguments.
            let core_zero =
                unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) } == 0 && lim.rlim_cur == 0;
            // SAFETY: PR_GET_DUMPABLE takes no pointers.
            let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
            if core_zero && dumpable == 0 {
                OK
            } else {
                FAILED
            }
        };
        assert!(matches!(run(None, 0, probe), Outcome::Data(_)));
    }
}
