//! The self-signed pair: creating it without ever replacing a file
//! (contract: "Creating the self-signed pair"), and renaming a legacy pair
//! stored under the Apple names.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::fsx::{Flock, exists, lexists, make_private_dir};
use crate::keys::{certificate_der, key_matches, openssl};

pub(crate) const CERT: &str = "certificate.self-signed.pem";
pub(crate) const KEY: &str = "key.self-signed.pem";
pub(crate) const LOCK: &str = ".identity.lock";

/// Why the pair could not be created. `Display` is the text identity.py's
/// IdentityError carried; `code` is the contract's error code.
#[derive(Debug)]
pub(crate) enum CreateError {
    HalfPair,
    /// Root never creates; or a competing creator's pair vanished meanwhile.
    Missing,
    Openssl(String),
    Link(String),
    /// Setting up (the directory, the lock, the temporary directory).
    Io(io::Error),
}

impl CreateError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            CreateError::HalfPair => "self-signed-half-pair",
            CreateError::Missing => "self-signed-missing",
            _ => "self-signed-create-failed",
        }
    }
}

impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CreateError::HalfPair => f.write_str("self-signed-half-pair"),
            CreateError::Missing => f.write_str("self-signed-missing"),
            CreateError::Openssl(e) => write!(f, "openssl could not create a certificate: {e}"),
            CreateError::Link(e) => write!(f, "could not create the self-signed pair: {e}"),
            CreateError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Both halves' presence. `lexists`: a dangling symlink counts as present,
/// so it is reported as a half pair rather than replaced.
pub(crate) fn pair_lexists(keys: &Path) -> (bool, bool) {
    (lexists(&keys.join(CERT)), lexists(&keys.join(KEY)))
}

/// `openssl -subj` treats `/` as a separator and `\` as an escape; escape
/// both so a computer name like "Brent's Mac/Air" is one CN. No shell is
/// involved.
fn subject_cn(name: &str) -> String {
    format!("/CN={}", name.replace('\\', "\\\\").replace('/', "\\/"))
}

/// What openssl said, without its key-generation progress dots.
fn openssl_errors(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    crate::contract::splitlines(&text)
        .into_iter()
        .filter(|l| !l.trim_matches(|c| matches!(c, '.' | '+' | '*')).is_empty())
        .collect::<Vec<_>>()
        .join(" / ")
}

/// Create the pair in `keys` unless it exists. `Ok(true)` when this call made
/// it, `Ok(false)` when a complete pair was already there.
pub(crate) fn create(keys: &Path, name: &str, root: bool) -> Result<bool, CreateError> {
    create_with(keys, name, root, &|src, dst| fs::hard_link(src, dst))
}

pub(crate) fn create_with(
    keys: &Path,
    name: &str,
    root: bool,
    link: &dyn Fn(&Path, &Path) -> io::Result<()>,
) -> Result<bool, CreateError> {
    if root {
        return Err(CreateError::Missing);
    }
    make_private_dir(keys).map_err(CreateError::Io)?;
    let _lock = Flock::acquire(&keys.join(LOCK)).map_err(CreateError::Io)?;
    match pair_lexists(keys) {
        (true, true) => return Ok(false),
        (false, false) => {}
        _ => return Err(CreateError::HalfPair),
    }
    let tmp = tempfile::Builder::new()
        .prefix(".self-signed.")
        .tempdir_in(keys)
        .map_err(CreateError::Io)?;
    let run = openssl(
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-x509",
            "-days",
            "365",
            "-subj",
            &subject_cn(name),
            "-keyout",
            "key.pem",
            "-out",
            "certificate.pem",
        ],
        None,
        Some(tmp.path()),
        None,
    )
    .map_err(|e| CreateError::Openssl(e.to_string()))?;
    if !run.status.success() {
        return Err(CreateError::Openssl(openssl_errors(&run.stderr)));
    }
    let (tkey, tcert) = (
        tmp.path().join("key.pem"),
        tmp.path().join("certificate.pem"),
    );
    for f in [&tkey, &tcert] {
        fs::set_permissions(f, fs::Permissions::from_mode(0o600)).map_err(CreateError::Io)?;
    }
    let mut made: Vec<(std::path::PathBuf, &Path)> = Vec::new();
    for (src, dst) in [(&tkey, keys.join(KEY)), (&tcert, keys.join(CERT))] {
        if let Err(e) = link(src, &dst) {
            // Any failure, not only a name that already exists (ENOSPC,
            // EIO...): leaving one half linked would block every later
            // attempt with self-signed-half-pair. Remove only our own inode,
            // never a competing creator's file.
            for (dst, src) in &made {
                let ours = match (fs::symlink_metadata(dst), fs::symlink_metadata(src)) {
                    (Ok(a), Ok(b)) => a.ino() == b.ino() && a.dev() == b.dev(),
                    _ => false,
                };
                if ours {
                    let _ = fs::remove_file(dst);
                }
            }
            if e.kind() != io::ErrorKind::AlreadyExists {
                let errno = e
                    .raw_os_error()
                    .map(crate::sys::strerror)
                    .unwrap_or_else(|| e.to_string());
                return Err(CreateError::Link(errno));
            }
            return match pair_lexists(keys) {
                (true, true) => Ok(false),
                (false, false) => Err(CreateError::Missing),
                _ => Err(CreateError::HalfPair),
            };
        }
        made.push((dst, src));
    }
    Ok(true)
}

/// Signed by its own key, and not chaining to Apple. `openssl`, not a name check.
fn is_self_signed(cert_pem: &[u8]) -> io::Result<bool> {
    let dir = tempfile::Builder::new().prefix("omdrop-self.").tempdir()?;
    let f = dir.path().join("cert.pem");
    fs::write(&f, cert_pem)?;
    let own = openssl(
        &[
            "verify".as_ref(),
            "-check_ss_sig".as_ref(),
            "-CAfile".as_ref(),
            f.as_os_str(),
            f.as_os_str(),
        ] as &[&std::ffi::OsStr],
        None,
        None,
        None,
    )?;
    if !own.status.success() {
        return Ok(false);
    }
    let der = certificate_der(cert_pem)
        .map(|d| d.to_vec())
        .unwrap_or_default();
    Ok(crate::apple::certificate_account(&der).is_empty())
}

/// Rename a self-signed pair stored under the Apple names, when provably
/// safe. Returns `renamed`, or the reason nothing was done.
pub(crate) fn migrate_legacy(keys: &Path) -> io::Result<&'static str> {
    let (cert, key) = (keys.join("certificate.pem"), keys.join("key.pem"));
    if !(exists(&cert) && exists(&key)) {
        return Ok("nothing-to-rename");
    }
    let _lock = Flock::acquire(&keys.join(LOCK))?;
    if exists(&keys.join("validation_record.cms")) {
        return Ok("has-record");
    }
    if exists(&keys.join(CERT)) || exists(&keys.join(KEY)) {
        return Ok("destination-exists");
    }
    let cert_pem = crate::fsx::read_opt(&cert)?.unwrap_or_default();
    let key_pem = zeroize::Zeroizing::new(crate::fsx::read_opt(&key)?.unwrap_or_default());
    if !key_matches(&cert_pem, &key_pem, None) {
        return Ok("key-mismatch");
    }
    if !is_self_signed(&cert_pem)? {
        return Ok("not-self-signed");
    }
    // link, then unlink: no moment where the pair exists under neither name,
    // and no rename can replace a file that appeared meanwhile.
    fs::hard_link(&key, keys.join(KEY))?;
    fs::hard_link(&cert, keys.join(CERT))?;
    fs::remove_file(&key)?;
    fs::remove_file(&cert)?;
    Ok("renamed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::tests::make_pair;
    use std::sync::Arc;

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .expect("dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn concurrent_creators_end_with_one_intact_pair() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let keys = Arc::new(tmp.path().join("new/keys"));
        let made: Vec<bool> = (0..4)
            .map(|_| {
                let keys = Arc::clone(&keys);
                std::thread::spawn(move || create(&keys, "Race", false).expect("create"))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .collect();
        assert_eq!(made.iter().filter(|&&m| m).count(), 1);
        let cert = fs::read(keys.join(CERT)).expect("cert");
        let key = fs::read(keys.join(KEY)).expect("key");
        assert!(key_matches(&cert, &key, None));
        assert_eq!(names(&keys), [LOCK, CERT, KEY]);
        assert_eq!(
            fs::metadata(&*keys).expect("meta").permissions().mode() & 0o777,
            0o700
        );
        for f in [CERT, KEY] {
            assert_eq!(
                fs::metadata(keys.join(f))
                    .expect("meta")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(!create(&keys, "Must not replace", false).expect("exists"));
        assert_eq!(fs::read(keys.join(CERT)).expect("cert"), cert);
    }

    #[test]
    fn half_a_pair_is_never_overwritten_and_root_never_creates() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let keys = tmp.path().join("keys");
        assert!(matches!(
            create(&keys, "X", true),
            Err(CreateError::Missing)
        ));
        assert!(!keys.exists());
        fs::create_dir_all(&keys).expect("mkdir");
        fs::write(keys.join(KEY), b"mine").expect("write");
        assert!(matches!(
            create(&keys, "X", false),
            Err(CreateError::HalfPair)
        ));
        assert_eq!(fs::read(keys.join(KEY)).expect("key"), b"mine");
        assert!(!keys.join(CERT).exists());
        // A dangling symlink is a half too, never something to replace.
        fs::remove_file(keys.join(KEY)).expect("rm");
        std::os::unix::fs::symlink(keys.join("nowhere"), keys.join(CERT)).expect("symlink");
        assert!(matches!(
            create(&keys, "X", false),
            Err(CreateError::HalfPair)
        ));
    }

    #[test]
    fn a_failed_second_link_leaves_no_half_pair_and_can_retry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let keys = tmp.path().join("keys");
        let full_disk = |src: &Path, dst: &Path| {
            if dst.ends_with(CERT) {
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
            fs::hard_link(src, dst)
        };
        let err = create_with(&keys, "X", false, &full_disk).expect_err("fails");
        assert_eq!(
            err.to_string(),
            "could not create the self-signed pair: No space left on device"
        );
        assert_eq!(err.code(), "self-signed-create-failed");
        assert_eq!(names(&keys), [LOCK]);
        assert!(create(&keys, "X", false).expect("retry"));
    }

    #[test]
    fn a_competing_pair_that_appears_mid_publication_wins() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let keys = tmp.path().join("keys");
        let theirs = make_pair(tmp.path(), "Winner", &["-newkey", "rsa:2048"]);
        let competing = |src: &Path, dst: &Path| {
            if dst.ends_with(KEY) {
                fs::write(keys.join(CERT), &theirs.0)?;
                fs::write(keys.join(KEY), &theirs.1)?;
            }
            fs::hard_link(src, dst)
        };
        assert!(!create_with(&keys, "Loser", false, &competing).expect("uses theirs"));
        assert_eq!(fs::read(keys.join(CERT)).expect("cert"), theirs.0);
        assert_eq!(fs::read(keys.join(KEY)).expect("key"), theirs.1);
    }

    #[test]
    fn a_slash_in_the_computer_name_is_part_of_the_cn() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let keys = tmp.path().join("keys");
        assert!(create(&keys, "Brent's Mac/Air\\x", false).expect("create"));
        let out = openssl(
            &[
                "x509",
                "-noout",
                "-subject",
                "-nameopt",
                "sep_multiline,utf8",
                "-in",
                CERT,
            ],
            None,
            Some(&keys),
            None,
        )
        .expect("openssl");
        // Unescaped display: the CN holds the name verbatim.
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "subject=\n    CN=Brent's Mac/Air\\x\n"
        );
    }

    #[test]
    fn progress_dots_are_not_errors() {
        assert_eq!(
            openssl_errors(b"....+++++\n*.*\nbad subject\nmore\n"),
            "bad subject / more"
        );
    }

    #[test]
    fn a_genuinely_self_signed_legacy_pair_is_renamed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let keys = tmp.path().join("keys");
        fs::create_dir_all(&keys).expect("mkdir");
        let (cert, key) = make_pair(&keys, "Legacy", &["-newkey", "rsa:2048"]);
        fs::rename(keys.join("c.pem"), keys.join("certificate.pem")).expect("mv");
        fs::rename(keys.join("k.pem"), keys.join("key.pem")).expect("mv");
        assert_eq!(migrate_legacy(&keys).expect("migrate"), "renamed");
        assert_eq!(fs::read(keys.join(CERT)).expect("cert"), cert);
        assert_eq!(fs::read(keys.join(KEY)).expect("key"), key);
        assert!(!keys.join("certificate.pem").exists());
        assert_eq!(migrate_legacy(&keys).expect("again"), "nothing-to-rename");
    }

    #[test]
    fn matching_names_without_a_self_signature_are_left_alone() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let keys = tmp.path().join("keys");
        fs::create_dir_all(&keys).expect("mkdir");
        let w = tmp.path();
        let ok = |args: &[&str]| {
            assert!(
                openssl(args, None, Some(w), None)
                    .expect("run")
                    .status
                    .success()
            )
        };
        ok(&[
            "req", "-newkey", "rsa:2048", "-nodes", "-x509", "-days", "1", "-subj", "/CN=Twin",
            "-keyout", "ca.key", "-out", "ca.pem",
        ]);
        ok(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=Twin",
            "-keyout",
            "keys/key.pem",
            "-out",
            "leaf.csr",
        ]);
        ok(&[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-out",
            "keys/certificate.pem",
        ]);
        assert_eq!(migrate_legacy(&keys).expect("migrate"), "not-self-signed");
        assert!(keys.join("certificate.pem").exists());
    }

    #[test]
    fn a_pair_with_a_record_or_an_existing_destination_is_left_alone() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let keys = tmp.path().join("keys");
        fs::create_dir_all(&keys).expect("mkdir");
        make_pair(&keys, "L", &["-newkey", "rsa:2048"]);
        fs::rename(keys.join("c.pem"), keys.join("certificate.pem")).expect("mv");
        fs::rename(keys.join("k.pem"), keys.join("key.pem")).expect("mv");
        fs::write(keys.join("validation_record.cms"), b"r").expect("write");
        assert_eq!(migrate_legacy(&keys).expect("migrate"), "has-record");
        fs::remove_file(keys.join("validation_record.cms")).expect("rm");
        fs::write(keys.join(CERT), b"keep").expect("write");
        assert_eq!(
            migrate_legacy(&keys).expect("migrate"),
            "destination-exists"
        );
        assert_eq!(fs::read(keys.join(CERT)).expect("cert"), b"keep");
    }
}
