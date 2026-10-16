//! The run directory, held open by fd. Every file operation is relative to
//! that fd, never follows a symlink, and trusts a file only when it is a
//! regular file owned by the trusted uid and not writable by group or others.
//!
//! Why: the directory is shared with omdrop-awdl 0.9.x's omdrop-discoverable,
//! which creates it and its files with whatever umask its caller had. A
//! user-writable run directory would otherwise let that user plant a `pids`
//! line (root kills any process), or a symlink that root then appends to.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// Numbers the `.untrusted.<pid>.<n>` names entries are moved aside to.
static ASIDE: AtomicU32 = AtomicU32::new(0);
/// How deep a planted directory tree is removed; deeper parts stay, renamed
/// aside where nothing reads them.
const TREE_DEPTH: u32 = 32;

/// A trusted state file: regular, owned by `owner`, not writable by group or
/// others, and with one link (a hard link to a file elsewhere is not ours,
/// whatever fs.protected_hardlinks says).
fn ok_stat(st: &libc::stat, owner: u32) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFREG
        && st.st_uid == owner
        && st.st_mode & 0o022 == 0
        && st.st_nlink == 1
}

/// The entry names of the open directory `fd`, through /proc/self/fd (the
/// directory itself, not whatever its path now points at).
fn list(fd: i32) -> Vec<Vec<u8>> {
    std::fs::read_dir(format!("/proc/self/fd/{fd}"))
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().as_bytes().to_vec())
                .collect()
        })
        .unwrap_or_default()
}

/// Remove the directory `name` under `dirfd` and everything in it, through
/// fds only: O_NOFOLLOW|O_DIRECTORY, so a symlink inside is unlinked, never
/// followed.
fn remove_tree(dirfd: i32, name: &CStr, depth: u32) {
    if depth < TREE_DEPTH {
        // SAFETY: valid fd and NUL-terminated name; the fd is owned below.
        let raw = unsafe {
            libc::openat(
                dirfd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw >= 0 {
            // SAFETY: raw is a fresh descriptor nobody else owns.
            let sub = unsafe { OwnedFd::from_raw_fd(raw) };
            let d = sub.as_raw_fd();
            for entry in list(d) {
                let Ok(c) = CString::new(entry) else { continue };
                // SAFETY: valid fd and NUL-terminated name.
                if unsafe { libc::unlinkat(d, c.as_ptr(), 0) } != 0 {
                    remove_tree(d, &c, depth + 1);
                }
            }
        }
    }
    // SAFETY: valid fd and NUL-terminated name.
    unsafe { libc::unlinkat(dirfd, name.as_ptr(), libc::AT_REMOVEDIR) };
}

#[derive(Debug)]
pub struct RunDir {
    fd: OwnedFd,
    owner: u32,
    path: PathBuf,
    /// Remove untrusted files when they are found (only with privilege).
    fix: bool,
}

fn cstr(s: &str) -> io::Result<CString> {
    if s.is_empty() || s.contains('/') {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    CString::new(s).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn fstat(fd: i32) -> io::Result<libc::stat> {
    // SAFETY: a zeroed stat is a valid out-buffer; fstat only writes to it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a valid open descriptor owned by the caller.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

impl RunDir {
    /// Open the directory at `path`; with `create`, make it first. With
    /// `fix`, repair a group- or world-writable mode and remove untrusted
    /// files as they are found. Returns the directory and, if its mode was
    /// repaired, a line to log.
    pub fn open(
        path: &Path,
        owner: u32,
        fix: bool,
        create: bool,
    ) -> Result<(RunDir, Option<String>), String> {
        let c = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| format!("{}: bad path", path.display()))?;
        if create {
            // SAFETY: c is a valid NUL-terminated path.
            let rc = unsafe { libc::mkdir(c.as_ptr(), 0o755) };
            if rc != 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(format!("cannot create {}: {e}", path.display()));
                }
            }
        }
        // SAFETY: c is a valid path; the returned fd is owned below.
        let raw = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            let e = io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                    format!("{} is not a directory (or is a symlink)", path.display())
                }
                _ => format!("{}: {e}", path.display()),
            });
        }
        // SAFETY: raw is a fresh descriptor nobody else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let st = fstat(fd.as_raw_fd()).map_err(|e| format!("{}: {e}", path.display()))?;
        if st.st_uid != owner {
            return Err(format!(
                "{} is owned by uid {}, not {owner}",
                path.display(),
                st.st_uid
            ));
        }
        let mut note = None;
        if st.st_mode & 0o022 != 0 {
            if !fix {
                return Err(format!("{} is writable by group or others", path.display()));
            }
            // SAFETY: fd is a valid directory descriptor.
            if unsafe { libc::fchmod(fd.as_raw_fd(), 0o755) } != 0 {
                return Err(format!(
                    "{} is writable by group or others and could not be repaired",
                    path.display()
                ));
            }
            note = Some(format!(
                "run directory {} was writable by group or others (mode {:o}); reset to 755",
                path.display(),
                st.st_mode & 0o7777
            ));
        }
        let rd = RunDir {
            fd,
            owner,
            path: path.to_path_buf(),
            fix,
        };
        // Anything planted while it was writable goes: directories under
        // core's names would otherwise wedge every start (EISDIR), and a
        // hard link or a loose file under a name only tested for existence
        // would be believed.
        if let Some(n) = note.as_mut() {
            let swept = rd.sweep();
            if swept > 0 {
                n.push_str(&format!(
                    "; removed {swept} untrusted entr{}",
                    if swept == 1 { "y" } else { "ies" }
                ));
            }
        }
        Ok((rd, note))
    }

    /// Remove every entry that is not a trusted regular file. Returns how
    /// many went.
    fn sweep(&self) -> usize {
        let mut n = 0;
        for name in self.names() {
            if !self.trusted_name(&name) {
                self.remove_bytes(&name);
                n += 1;
            }
        }
        n
    }

    /// Entry names, read through the fd (/proc/self/fd/N is the open
    /// directory itself, wherever its path now points).
    fn names(&self) -> Vec<Vec<u8>> {
        list(self.fd.as_raw_fd())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn openat(&self, name: &str, flags: i32, mode: u32) -> io::Result<File> {
        let c = cstr(name)?;
        let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: the directory fd is valid and c is a NUL-terminated name.
        let raw =
            unsafe { libc::openat(self.fd.as_raw_fd(), c.as_ptr(), flags, mode as libc::c_uint) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a fresh descriptor nobody else owns.
        Ok(unsafe { File::from_raw_fd(raw) })
    }

    fn trusted(&self, f: &File) -> bool {
        fstat(f.as_raw_fd()).is_ok_and(|st| ok_stat(&st, self.owner))
    }

    /// The entry is a trusted regular file, judged without opening it.
    fn trusted_name(&self, name: &[u8]) -> bool {
        let Ok(c) = CString::new(name) else {
            return false;
        };
        // SAFETY: a zeroed stat is a valid out-buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: valid fd, NUL-terminated name, valid out-buffer.
        let rc = unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        rc == 0 && ok_stat(&st, self.owner)
    }

    /// Present and trusted: for flags whose presence is the whole content.
    pub fn has_trusted(&self, name: &str) -> bool {
        self.trusted_name(name.as_bytes())
    }

    /// A trusted state file's content, trimmed, at most `max` bytes. An
    /// untrusted one reads as absent (and is removed when we may).
    pub fn read_max(&self, name: &str, max: u64) -> Option<String> {
        let f = self.openat(name, libc::O_RDONLY | libc::O_NONBLOCK, 0);
        let f = match f {
            Ok(f) => f,
            Err(e) => {
                if e.raw_os_error() == Some(libc::ELOOP) && self.fix {
                    self.remove(name);
                }
                return None;
            }
        };
        if !self.trusted(&f) {
            if self.fix {
                self.remove(name);
            }
            return None;
        }
        let mut s = String::new();
        f.take(max).read_to_string(&mut s).ok()?;
        Some(s.trim().to_string())
    }

    pub fn read(&self, name: &str) -> Option<String> {
        self.read_max(name, 4096)
    }

    /// Replace a file atomically: the supervisor re-reads `until` every
    /// interval, and a truncate-then-write could show it an empty deadline.
    /// The rename also replaces whatever was there, symlink or not.
    pub fn write(&self, name: &str, content: &str, mode: u32) -> io::Result<()> {
        let tmp = format!(".{name}.{}.tmp", std::process::id());
        self.remove(&tmp);
        let mut f = self.openat(&tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode)?;
        // SAFETY: f is a valid descriptor; the umask may have cut the mode.
        unsafe { libc::fchmod(f.as_raw_fd(), mode as libc::mode_t) };
        let written = f.write_all(content.as_bytes());
        drop(f);
        if let Err(e) = written {
            self.remove(&tmp);
            return Err(e);
        }
        let mut renamed = self.rename(&tmp, name);
        if renamed.is_err() && self.fix {
            // A directory (or anything else rename cannot replace) in the way.
            self.remove(name);
            renamed = self.rename(&tmp, name);
        }
        if let Err(e) = renamed {
            self.remove(&tmp);
            return Err(e);
        }
        Ok(())
    }

    /// A trusted file to append to, created 0644 if absent. A symlink or an
    /// untrusted file in its place is removed and replaced.
    pub fn append(&self, name: &str) -> io::Result<File> {
        let flags = libc::O_WRONLY | libc::O_APPEND | libc::O_NONBLOCK;
        if let Ok(f) = self.openat(name, flags | libc::O_CREAT, 0o644) {
            if self.trusted(&f) {
                return Ok(f);
            }
        }
        if !self.fix {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        self.remove(name);
        let f = self.openat(name, flags | libc::O_CREAT | libc::O_EXCL, 0o644)?;
        if self.trusted(&f) {
            Ok(f)
        } else {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }

    pub fn remove(&self, name: &str) {
        if !name.is_empty() && !name.contains('/') {
            self.remove_bytes(name.as_bytes());
        }
    }

    /// Unlink an entry; a directory is renamed aside first and then removed
    /// recursively through fds, never following a link.
    fn remove_bytes(&self, name: &[u8]) {
        let Ok(c) = CString::new(name) else { return };
        let d = self.fd.as_raw_fd();
        // SAFETY: valid fd and NUL-terminated name.
        if unsafe { libc::unlinkat(d, c.as_ptr(), 0) } == 0 {
            return;
        }
        let e = io::Error::last_os_error().raw_os_error();
        if e != Some(libc::EISDIR) && e != Some(libc::EPERM) {
            return;
        }
        let aside = format!(
            ".untrusted.{}.{}",
            std::process::id(),
            ASIDE.fetch_add(1, Ordering::Relaxed)
        );
        let Ok(a) = CString::new(aside) else { return };
        // SAFETY: both names are NUL-terminated, relative to the same fd.
        if unsafe { libc::renameat(d, c.as_ptr(), d, a.as_ptr()) } == 0 {
            remove_tree(d, &a, 0);
        }
    }

    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (a, b) = (cstr(from)?, cstr(to)?);
        let d = self.fd.as_raw_fd();
        // SAFETY: both names are NUL-terminated, relative to the same valid fd.
        if unsafe { libc::renameat(d, a.as_ptr(), d, b.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Present, without following a symlink.
    pub fn exists(&self, name: &str) -> bool {
        let Ok(c) = cstr(name) else { return false };
        // SAFETY: a zeroed stat is a valid out-buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: valid fd, NUL-terminated name, valid out-buffer.
        unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            ) == 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn me() -> u32 {
        // SAFETY: geteuid cannot fail.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn a_writable_directory_is_repaired_and_a_symlink_refused() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("run");
        std::fs::create_dir(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(RunDir::open(&d, me(), false, false).is_err());
        let (_, note) = RunDir::open(&d, me(), true, true).unwrap();
        assert!(note.unwrap().contains("mode 777"));
        assert_eq!(
            std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let link = t.path().join("link");
        symlink(&d, &link).unwrap();
        assert!(
            RunDir::open(&link, me(), true, true)
                .unwrap_err()
                .contains("symlink")
        );
        assert!(
            RunDir::open(&d, me() + 1, true, true)
                .unwrap_err()
                .contains("owned by uid")
        );
        assert!(RunDir::open(&t.path().join("absent"), me(), true, false).is_err());
    }

    #[test]
    fn untrusted_files_read_as_absent_and_symlinks_are_replaced() {
        let t = tempfile::tempdir().unwrap();
        let (rd, _) = RunDir::open(t.path(), me(), true, false).unwrap();
        let p = t.path();
        std::fs::write(p.join("ok"), "1\n").unwrap();
        std::fs::set_permissions(p.join("ok"), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(rd.read("ok").as_deref(), Some("1"));
        std::fs::write(p.join("loose"), "1").unwrap();
        std::fs::set_permissions(p.join("loose"), std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(rd.read("loose"), None);
        assert!(!p.join("loose").exists());
        let outside = t.path().join("outside");
        std::fs::write(&outside, "keep").unwrap();
        symlink(&outside, p.join("log")).unwrap();
        writeln!(rd.append("log").unwrap(), "line").unwrap();
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        assert!(
            !std::fs::symlink_metadata(p.join("log"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        symlink(&outside, p.join("until")).unwrap();
        assert_eq!(rd.read("until"), None);
        rd.write("until", "5", 0o644).unwrap();
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        assert_eq!(rd.read("until").as_deref(), Some("5"));
        assert!(rd.read("../outside").is_none());
    }
}
