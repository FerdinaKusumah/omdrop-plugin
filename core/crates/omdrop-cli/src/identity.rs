//! The identity commands (`identity.py`'s command line, run in a child of
//! this binary), the identity lock, and the move from ~/.opendrop to ~/.omdrop.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config::effective_name;
use crate::ctx::ctx;
use crate::proc::code_of;
use crate::util::{die, have, home, mkdir_private};

pub enum Out {
    /// `$(...)`.
    Capture,
    Inherit,
    Null,
}

pub struct IdResult {
    pub code: i32,
    pub stdout: String,
}

/// Run one identity command, as the bash ran `"$ID_PY" ARGS`: in a child
/// process, `omdrop __identity ARGS` (this same binary, through
/// /proc/self/exe), or with `OMDROP_IMPLEMENTATION=python` the plugin's identity.py. A
/// child because the identity code protects the process that holds keys --
/// no core dumps, hard limit 0, not dumpable -- and done in this process that
/// would carry over to everything `omdrop` starts afterwards, the root
/// radio helper included, whose crashes then could not be diagnosed.
pub fn id(args: &[&str], out: Out, show_stderr: bool) -> IdResult {
    let c = ctx();
    let mut cmd = match c
        .plugin_dir()
        .filter(|_| c.legacy)
        .map(|d| d.join("bin/identity.py"))
        .filter(|p| p.is_file())
    {
        Some(script) => {
            let mut cmd = Command::new("python3");
            cmd.arg(script);
            cmd
        }
        None => {
            let mut cmd = Command::new("/proc/self/exe");
            cmd.arg0("omdrop").arg(IDENTITY_SUBCOMMAND);
            cmd
        }
    };
    cmd.args(args).stderr(if show_stderr {
        Stdio::inherit()
    } else {
        Stdio::null()
    });
    let _ = io::stdout().flush();
    match out {
        Out::Capture => {
            let (code, o) = crate::proc::capture_cmd(&mut cmd);
            IdResult {
                code,
                stdout: String::from_utf8_lossy(&o).into_owned(),
            }
        }
        Out::Inherit | Out::Null => {
            if matches!(out, Out::Null) {
                cmd.stdout(Stdio::null());
            }
            let code = match cmd.status() {
                Ok(s) => code_of(s),
                Err(e) => {
                    if show_stderr {
                        errln!("omdrop: {}: {e}", cmd.get_program().to_string_lossy());
                    }
                    127
                }
            };
            IdResult {
                code,
                stdout: String::new(),
            }
        }
    }
}

/// The hidden subcommand that runs one identity command and exits with its
/// status: identity.py's command line, now inside this binary.
pub const IDENTITY_SUBCOMMAND: &str = "__identity";

pub fn cmd_identity_child(args: &[String]) -> i32 {
    let mut out = io::stdout();
    let mut err = io::stderr();
    // A panic must fail this one step, as an uncaught Python exception exited 1.
    let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        omdrop_identity::cli::run(args, &mut out, &mut err)
    }))
    .unwrap_or(1);
    let _ = io::stdout().flush();
    code
}

/// The identity lock, shared with the identity commands. `on` holds it from
/// the check that no `off` ran during a 1Password fetch until the receiver
/// and radio are up, and `off` holds it throughout, so the two can never
/// interleave. Close-on-exec, so nothing we start (a radio supervisor) can
/// inherit it and hold it for the life of the window. Dropping it unlocks.
pub struct IdentityLock(#[allow(dead_code)] File);

/// The longest anyone legitimately holds the lock: `on` while the radio comes
/// up (bounded by `RADIO_START_LIMIT`) and the receiver starts (its unit
/// waits up to 40 s for the port and awdl0's address), plus a margin.
const LOCK_WAIT: std::time::Duration =
    std::time::Duration::from_secs(crate::window::RADIO_START_LIMIT.as_secs() + 90);

pub fn identity_lock() -> IdentityLock {
    let dir = ctx().state_dir();
    if mkdir_private(&dir).is_err() {
        die(format!("omdrop could not create {}", dir.display()));
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(dir.join("identity.lock"))
        .unwrap_or_else(|_| die("omdrop could not open its identity lock"));
    // Waited for, but not forever: a holder that hung would otherwise leave
    // every later `off` hanging too, and receiving could not be turned off.
    let deadline = std::time::Instant::now() + LOCK_WAIT;
    loop {
        // SAFETY: flock on a descriptor we own.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::WouldBlock && e.kind() != io::ErrorKind::Interrupted {
            die("omdrop could not take its identity lock");
        }
        if std::time::Instant::now() >= deadline {
            die(format!(
                "Another omdrop has been starting or stopping for over {} seconds and still holds {}/identity.lock, so nothing was changed. If it is stuck, end it and try again.",
                LOCK_WAIT.as_secs(),
                dir.display()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    IdentityLock(file)
}

/// A notice from the identity step, on stderr and as a toast: falling back to
/// the self-signed identity changes who can see this computer.
pub fn identity_notice(msg: &str) {
    errln!("{msg}");
    if have("omarchy-notification-send") {
        crate::proc::run_quiet("omarchy-notification-send", &["-t", "8000", "Omdrop", msg]);
    }
}

/// `omdrop identity`: which identity this computer presents, and 1Password.
pub fn cmd_identity(args: &[String]) -> i32 {
    let sub = args.first().map(String::as_str).unwrap_or("status");
    let rest: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    match sub {
        "status" => {
            let mut a = vec!["status"];
            a.extend(rest);
            id(&a, Out::Inherit, true).code
        }
        "unlock" => id(&["unlock"], Out::Inherit, true).code,
        "lock" => {
            // Turn off first: a running receiver holds the key in its memory,
            // and revoking the cache cannot reach that copy.
            if crate::status::receiving() || ctx().window_file().exists() {
                crate::proc::with_stdout_null(|| crate::window::cmd_off(&["--force".to_string()]));
            }
            id(&["lock"], Out::Inherit, true).code
        }
        "1password" => match rest.first().copied().unwrap_or("") {
            "import" => {
                crate::driver::driver_identity_ready();
                let mut a = vec!["import"];
                a.extend(&rest[1..]);
                id(&a, Out::Inherit, true).code
            }
            "use" => {
                crate::driver::driver_identity_ready();
                let mut a = vec!["use"];
                a.extend(&rest[1..]);
                id(&a, Out::Inherit, true).code
            }
            "off" => id(&["1password-off"], Out::Inherit, true).code,
            _ => die(
                "usage: omdrop identity 1password import [--vault V] [--title T] | use ITEM [--vault V] | off",
            ),
        },
        _ => die("usage: omdrop identity [status [--json] | unlock | lock | 1password ...]"),
    }
}

/// The self-signed identity every mode falls back to, made here rather than
/// in the middle of somebody's first transfer: openssl takes a moment, and
/// the unit's start would be waiting on it while a sender is already
/// knocking. 0 created, 1 nothing to do, 2 failed (the reason on stderr).
pub fn ensure_tls() -> i32 {
    let name = effective_name();
    id(&["ensure-self-signed", "--name", &name], Out::Null, true).code
}

pub fn identity_dir() -> PathBuf {
    PathBuf::from(home()).join(".omdrop")
}

pub fn legacy_identity_dir() -> PathBuf {
    PathBuf::from(home()).join(".opendrop")
}

#[derive(Debug, PartialEq, Eq)]
pub enum Migrated {
    Copied,
    Nothing,
    Failed,
}

/// Copy an existing ~/.opendrop/keys into ~/.omdrop/keys, once. Only when
/// ~/.omdrop does not exist at all, so an identity already there is never
/// replaced, and never touching the original: opendrop itself may still be in
/// use elsewhere. The copy is assembled beside its destination and renamed
/// into place, so an interrupted copy leaves nothing that looks like an identity.
pub fn migrate_identity_in(new: &Path, old: &Path) -> Migrated {
    if new.exists() || crate::util::is_symlink(new) {
        return Migrated::Nothing;
    }
    if !old.join("keys").is_dir() {
        return Migrated::Nothing;
    }
    let Some(parent) = new.parent() else {
        return Migrated::Failed;
    };
    let prefix = format!(
        "{}.",
        new.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default()
    );
    let Ok(tmp) = make_temp_dir(parent, &prefix) else {
        return Migrated::Failed;
    };
    let ok = (|| -> io::Result<()> {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(tmp.join("keys"))?;
        copy_tree(&old.join("keys"), &tmp.join("keys"))?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(tmp.join("keys"), std::fs::Permissions::from_mode(0o700))?;
        if new.exists() || crate::util::is_symlink(new) {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        std::fs::rename(&tmp, new)
    })();
    if ok.is_ok() {
        return Migrated::Copied;
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Migrated::Failed
}

use std::os::unix::fs::DirBuilderExt;

fn make_temp_dir(parent: &Path, prefix: &str) -> io::Result<PathBuf> {
    for _ in 0..100 {
        let p = parent.join(format!("{prefix}{}", crate::util::random_suffix()));
        match std::fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::from(io::ErrorKind::AlreadyExists))
}

/// `cp -pR SRC/. DST/`: modes and times kept, links copied as links.
fn copy_tree(src: &Path, dst: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&from)?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(&from)?, &to)?;
            continue;
        }
        let times = std::fs::FileTimes::new()
            .set_accessed(meta.accessed()?)
            .set_modified(meta.modified()?);
        if ft.is_dir() {
            std::fs::DirBuilder::new().mode(0o700).create(&to)?;
            copy_tree(&from, &to)?;
            File::open(&to)?.set_times(times)?;
        } else if ft.is_file() {
            let mut input = File::open(&from)?;
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&to)?;
            io::copy(&mut input, &mut output)?;
            output.sync_all()?;
            output.set_times(times)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a file, folder or link",
            ));
        }
        std::fs::set_permissions(
            &to,
            std::fs::Permissions::from_mode(meta.permissions().mode() & 0o7777),
        )?;
    }
    Ok(())
}

pub fn migrate_identity() -> Migrated {
    migrate_identity_in(&identity_dir(), &legacy_identity_dir())
}

pub fn copied_message() -> String {
    format!(
        "Copied this computer's AirDrop identity from {}/keys to {}/keys. The original is left in place.",
        legacy_identity_dir().display(),
        identity_dir().display()
    )
}

pub fn copy_failed_message() -> String {
    format!(
        "omdrop could not copy the AirDrop identity from {}/keys to {}/keys.",
        legacy_identity_dir().display(),
        identity_dir().display()
    )
}

/// Run before anything reads the identity. Says what it did, on stderr
/// (the bash called it `>&2`), because a copied identity is something the
/// person may want to know about.
pub fn prepare_identity() -> bool {
    match migrate_identity() {
        Migrated::Copied => {
            errln!("{}", copied_message());
            true
        }
        Migrated::Failed => {
            errln!("{}", copy_failed_message());
            false
        }
        Migrated::Nothing => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn legacy(home: &Path) -> PathBuf {
        let old = home.join(".opendrop/keys");
        std::fs::create_dir_all(&old).unwrap();
        for (name, body) in [
            ("certificate.pem", "CERT"),
            ("key.pem", "KEY"),
            ("validation_record.cms", "RECORD"),
        ] {
            std::fs::write(old.join(name), body).unwrap();
            std::fs::set_permissions(old.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        old
    }

    #[test]
    fn copies_every_file_and_leaves_the_original() {
        let tmp = tempfile::tempdir().unwrap();
        let old = legacy(tmp.path());
        let new = tmp.path().join(".omdrop");
        assert_eq!(
            migrate_identity_in(&new, &tmp.path().join(".opendrop")),
            Migrated::Copied
        );
        for name in ["certificate.pem", "key.pem", "validation_record.cms"] {
            let (a, b) = (new.join("keys").join(name), old.join(name));
            assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
            assert_eq!(std::fs::metadata(&a).unwrap().mode() & 0o777, 0o600);
            assert_ne!(
                std::fs::metadata(&a).unwrap().ino(),
                std::fs::metadata(&b).unwrap().ino()
            );
        }
        assert_eq!(
            std::fs::metadata(new.join("keys")).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(std::fs::metadata(&new).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn never_replaces_an_existing_omdrop() {
        let tmp = tempfile::tempdir().unwrap();
        legacy(tmp.path());
        let new = tmp.path().join(".omdrop");
        std::fs::create_dir_all(new.join("keys")).unwrap();
        std::fs::write(new.join("keys/certificate.pem"), "MINE").unwrap();
        assert_eq!(
            migrate_identity_in(&new, &tmp.path().join(".opendrop")),
            Migrated::Nothing
        );
        assert_eq!(
            std::fs::read_to_string(new.join("keys/certificate.pem")).unwrap(),
            "MINE"
        );
        assert!(!new.join("keys/validation_record.cms").exists());
    }

    #[test]
    fn nothing_to_copy_creates_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let new = tmp.path().join(".omdrop");
        assert_eq!(
            migrate_identity_in(&new, &tmp.path().join(".opendrop")),
            Migrated::Nothing
        );
        assert!(!new.exists());
    }

    #[test]
    fn failed_copy_leaves_no_partial_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let old = legacy(tmp.path());
        std::fs::set_permissions(old.join("key.pem"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        if File::open(old.join("key.pem")).is_ok() {
            return; // running as a user who can read mode-000 files
        }
        let new = tmp.path().join(".omdrop");
        assert_eq!(
            migrate_identity_in(&new, &tmp.path().join(".opendrop")),
            Migrated::Failed
        );
        assert!(!new.exists());
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".omdrop.")
            })
            .collect();
        assert!(leftovers.is_empty());
        std::fs::set_permissions(old.join("key.pem"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert_eq!(
            migrate_identity_in(&new, &tmp.path().join(".opendrop")),
            Migrated::Copied
        );
        assert_eq!(
            std::fs::read_to_string(new.join("keys/key.pem")).unwrap(),
            "KEY"
        );
    }
}
