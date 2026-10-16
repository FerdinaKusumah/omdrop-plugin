//! Thin wrappers over the libc calls the identity code needs.

use std::ffi::{CStr, CString, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

/// The message `os.strerror(errno)` gives, without Rust's " (os error N)".
pub(crate) fn strerror(errno: i32) -> String {
    let text = std::io::Error::from_raw_os_error(errno).to_string();
    match text.rfind(" (os error ") {
        Some(i) => text[..i].to_owned(),
        None => text,
    }
}

pub(crate) fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub(crate) fn euid_is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

pub(crate) fn getuid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// Keep keys out of core dumps and away from same-UID ptrace:
/// `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0`. `Err` names what failed.
///
/// Async-signal-safe (two syscalls, no allocation): the dropped child calls
/// it after `fork`.
pub(crate) fn protect_process() -> Result<(), ()> {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads the struct we pass; it outlives the call.
    let core = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
    // SAFETY: PR_SET_DUMPABLE takes integer arguments only.
    let dump = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) };
    if core == 0 && dump == 0 {
        Ok(())
    } else {
        Err(())
    }
}

/// `n` random bytes from the kernel.
pub(crate) fn random_bytes(n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        let rest = &mut buf[filled..];
        // SAFETY: the pointer and length describe `rest`, a live, writable slice.
        let got = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if got < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        filled += got as usize;
    }
    Ok(buf)
}

/// The host name, for a self-signed certificate's CN when none is given.
pub(crate) fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is writable for its full length; gethostname
    // truncates and we terminate below.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len() - 1) };
    if rc != 0 {
        return "localhost".to_owned();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len() - 1);
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// A password-database entry: home and primary group.
pub(crate) struct Passwd {
    pub gid: u32,
    pub home: PathBuf,
}

pub(crate) fn getpwuid(uid: u32) -> Option<Passwd> {
    let mut size = 4096usize;
    loop {
        let mut buf = vec![0u8; size];
        // SAFETY: zeroed passwd is a valid out-parameter (pointers null).
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call; `buf` backs the strings
        // `pwd` points into and lives until we copy them out below.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && size < 1 << 20 {
            size *= 4;
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        // SAFETY: getpwuid_r succeeded, so pw_dir is a NUL-terminated string in `buf`.
        let dir = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes().to_vec();
        return Some(Passwd {
            gid: pwd.pw_gid,
            home: PathBuf::from(OsString::from_vec(dir)),
        });
    }
}

/// `time.strftime(fmt, time.localtime(t))`.
pub(crate) fn strftime_local(fmt: &str, t: i64) -> String {
    let Ok(cfmt) = CString::new(fmt) else {
        return String::new();
    };
    let tt = t as libc::time_t;
    // SAFETY: zeroed tm is a valid out-parameter.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call.
    if unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() {
        return String::new();
    }
    let mut buf = [0u8; 256];
    // SAFETY: buf is writable for its length; cfmt is NUL-terminated; tm is initialised.
    let n = unsafe { libc::strftime(buf.as_mut_ptr().cast(), buf.len(), cfmt.as_ptr(), &tm) };
    String::from_utf8_lossy(&buf[..n.min(buf.len())]).into_owned()
}
