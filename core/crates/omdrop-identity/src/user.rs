//! Whose identity this is, and where its files are.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::IdentityError;
use crate::asuser::Creds;
use crate::sys;

/// The invoking user and every path the contract names for them.
#[derive(Clone, Debug)]
pub(crate) struct User {
    /// This process runs as root (effective UID 0).
    pub root: bool,
    pub uid: u32,
    pub gid: u32,
    /// `~/.omdrop/keys`, or `DIR/keys` for an explicit keys directory.
    pub keys: PathBuf,
    pub settings: PathBuf,
    pub state_dir: PathBuf,
    pub window: PathBuf,
    /// The lifecycle's lock (`$XDG_RUNTIME_DIR/omdrop/identity.lock`), which
    /// `omdrop` also takes; distinct from the keys directory's `.identity.lock`.
    pub lock: PathBuf,
    pub state: PathBuf,
}

/// Which user a process acts for: as root, `PKEXEC_UID`, then `SUDO_UID`,
/// else itself. A variable that is set but not a number is an error, not a
/// reason to act as root.
pub(crate) fn invoking_uid(
    root: bool,
    var: impl Fn(&str) -> Option<OsString>,
    own_uid: u32,
) -> Result<u32, IdentityError> {
    if !root {
        return Ok(own_uid);
    }
    for name in ["PKEXEC_UID", "SUDO_UID"] {
        if let Some(value) = var(name) {
            return value
                .to_str()
                .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or_else(|| IdentityError::new("invoking-user-invalid"));
        }
    }
    Ok(own_uid)
}

fn nonempty(v: Option<OsString>) -> Option<PathBuf> {
    v.filter(|s| !s.is_empty()).map(PathBuf::from)
}

impl User {
    /// Build from parts. Root uses the password database's home and
    /// `/run/user/<uid>`; a user honours `XDG_CONFIG_HOME`/`XDG_RUNTIME_DIR`.
    pub(crate) fn from_parts(
        root: bool,
        uid: u32,
        gid: u32,
        home: PathBuf,
        var: impl Fn(&str) -> Option<OsString>,
        keys_dir: Option<&Path>,
    ) -> User {
        let (config, runtime) = if root {
            (
                home.join(".config"),
                PathBuf::from(format!("/run/user/{uid}")),
            )
        } else {
            (
                nonempty(var("XDG_CONFIG_HOME")).unwrap_or_else(|| home.join(".config")),
                nonempty(var("XDG_RUNTIME_DIR"))
                    .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}"))),
            )
        };
        let base = keys_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(|| home.join(".omdrop"));
        let state_dir = runtime.join("omdrop");
        User {
            root,
            uid,
            gid,
            keys: base.join("keys"),
            settings: config.join("omdrop").join("settings"),
            window: state_dir.join("window"),
            lock: state_dir.join("identity.lock"),
            state: state_dir.join("state"),
            state_dir,
        }
    }

    /// The user this process acts for, from its credentials and environment.
    pub(crate) fn current(keys_dir: Option<&Path>) -> Result<User, IdentityError> {
        let root = sys::euid_is_root();
        let var = |k: &str| std::env::var_os(k);
        let uid = invoking_uid(root, var, sys::getuid())?;
        let pw = sys::getpwuid(uid).ok_or_else(|| IdentityError::new("invoking-user-invalid"))?;
        Ok(User::from_parts(root, uid, pw.gid, pw.home, var, keys_dir))
    }

    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.keys.join(name)
    }

    /// The credentials reads must drop to: `Some` only for root acting for
    /// another user. Root acting for itself reads directly.
    pub(crate) fn creds(&self) -> Option<Creds> {
        (self.root && self.uid != 0).then_some(Creds {
            uid: self.uid,
            gid: self.gid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let m: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), (*v).into()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn root_priority_is_pkexec_then_sudo_then_itself() {
        let all = env(&[("PKEXEC_UID", "1001"), ("SUDO_UID", "1002")]);
        assert_eq!(invoking_uid(true, &all, 0), Ok(1001));
        assert_eq!(
            invoking_uid(true, env(&[("SUDO_UID", "1002")]), 0),
            Ok(1002)
        );
        assert_eq!(invoking_uid(true, env(&[]), 0), Ok(0));
        // A user is always itself, whatever the environment says.
        assert_eq!(invoking_uid(false, &all, 1000), Ok(1000));
        for bad in ["", "abc", "-1", "99999999999"] {
            assert_eq!(
                invoking_uid(true, env(&[("PKEXEC_UID", bad)]), 0),
                Err(IdentityError::new("invoking-user-invalid")),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn root_paths_come_from_passwd_and_ignore_home_and_xdg() {
        let wrong = env(&[
            ("HOME", "/wrong"),
            ("XDG_CONFIG_HOME", "/wrong"),
            ("XDG_RUNTIME_DIR", "/wrong"),
        ]);
        let u = User::from_parts(true, 1001, 1001, "/home/user1001".into(), wrong, None);
        assert_eq!(
            u.settings,
            Path::new("/home/user1001/.config/omdrop/settings")
        );
        assert_eq!(u.window, Path::new("/run/user/1001/omdrop/window"));
        assert_eq!(u.keys, Path::new("/home/user1001/.omdrop/keys"));
        assert_eq!(
            u.creds(),
            Some(Creds {
                uid: 1001,
                gid: 1001
            })
        );
        let own = User::from_parts(true, 0, 0, "/root".into(), env(&[]), None);
        assert_eq!(own.creds(), None);
    }

    #[test]
    fn a_users_home_comes_from_passwd_not_home() {
        let u = User::from_parts(
            false,
            1001,
            1001,
            "/passwd/home".into(),
            env(&[("HOME", "/wrong")]),
            None,
        );
        assert_eq!(
            u.settings,
            Path::new("/passwd/home/.config/omdrop/settings")
        );
        assert_eq!(u.window, Path::new("/run/user/1001/omdrop/window"));
        let x = User::from_parts(
            false,
            1001,
            1001,
            "/h".into(),
            env(&[("XDG_CONFIG_HOME", "/c"), ("XDG_RUNTIME_DIR", "/r")]),
            Some(Path::new("/explicit")),
        );
        assert_eq!(x.settings, Path::new("/c/omdrop/settings"));
        assert_eq!(x.window, Path::new("/r/omdrop/window"));
        assert_eq!(x.keys, Path::new("/explicit/keys"));
        assert_eq!(x.creds(), None);
    }
}
