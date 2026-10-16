//! Small filesystem helpers: bounded reads, private writes, the flock.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// The most any identity file may hold. A cache part is at most 16 KiB; a
/// settings or window file a few lines. The limit stops a path the user
/// pointed at something endless from exhausting memory.
pub(crate) const MAX_FILE: usize = 1 << 20;

/// Open for reading without following into a FIFO or device: a regular file
/// only (through symlinks), opened non-blocking so a FIFO cannot hang us.
fn open_regular(path: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(f)
}

/// The file's bytes; `Ok(None)` when it does not exist.
pub(crate) fn read_opt(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let f = match open_regular(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    f.take(MAX_FILE as u64 + 1).read_to_end(&mut out)?;
    if out.len() > MAX_FILE {
        return Err(io::Error::other("file too large"));
    }
    Ok(Some(out))
}

/// The file's text (lossy), or `None` when it is absent or unreadable: what
/// `identity._read(path) or ''` gave for the plugin's state files.
pub(crate) fn read_text(path: &Path) -> io::Result<Option<String>> {
    Ok(read_opt(path)?.map(|b| String::from_utf8_lossy(&b).into_owned()))
}

pub(crate) fn lexists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

pub(crate) fn exists(path: &Path) -> bool {
    fs::metadata(path).is_ok()
}

pub(crate) fn make_private_dir(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Replace `path` with `data`, mode 0600, by renaming a temporary file.
pub(crate) fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        make_private_dir(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = Path::new(&tmp);
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(tmp)?;
        f.write_all(data)?;
        drop(f);
        fs::rename(tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

/// An exclusive `flock` held until drop. Per open file description, so it
/// excludes other threads of this process as well as other processes.
pub(crate) struct Flock(#[allow(dead_code)] File);

impl Flock {
    pub(crate) fn acquire(path: &Path) -> io::Result<Flock> {
        if let Some(dir) = path.parent() {
            make_private_dir(dir)?;
        }
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        loop {
            // SAFETY: flock on a descriptor we own.
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(Flock(f));
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = dir.path().join("window");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("path");
        // SAFETY: mkfifo on a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(read_opt(&fifo).is_err());
        assert!(
            read_opt(&dir.path().join("absent"))
                .expect("absent is fine")
                .is_none()
        );
    }

    #[test]
    fn private_write_replaces_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("sub/state");
        write_private(&p, b"a=1\n").expect("write");
        write_private(&p, b"a=2\n").expect("write");
        assert_eq!(fs::read(&p).expect("read"), b"a=2\n");
        assert_eq!(
            fs::metadata(&p).expect("meta").permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_dir(dir.path().join("sub")).expect("dir").count(),
            1
        );
    }
}
