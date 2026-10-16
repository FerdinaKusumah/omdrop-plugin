//! The identity cache in the kernel keyring, through raw `add_key`/`keyctl`
//! syscalls (no libkeyutils).
//!
//! Staged in this process's own keyring, given its timeout and permissions
//! there, and only then linked into `@u`: a key is never visible to others
//! without a timeout.

use std::ffi::c_long;

use zeroize::{Zeroize, Zeroizing};

use crate::sys::{errno, strerror};

pub(crate) const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
pub(crate) const KEY_SPEC_SESSION_KEYRING: i32 = -3;
pub(crate) const KEY_SPEC_USER_KEYRING: i32 = -4;
/// Possessor: all; user: view.
pub(crate) const KEY_PERM: u32 = 0x3f01_0000;

const KEYCTL_JOIN_SESSION_KEYRING: c_long = 1;
const KEYCTL_REVOKE: c_long = 3;
const KEYCTL_SETPERM: c_long = 5;
const KEYCTL_LINK: c_long = 8;
const KEYCTL_UNLINK: c_long = 9;
const KEYCTL_SEARCH: c_long = 10;
const KEYCTL_READ: c_long = 11;
const KEYCTL_SET_TIMEOUT: c_long = 15;

const KEY_TYPE: &[u8] = b"user\0";
const KEY_DESC: &[u8] = b"omdrop:identity\0";
/// The kernel's limit for a `user` key's payload.
pub(crate) const MAX_KEY_PAYLOAD: usize = 32767;

/// A key that is not there, or no longer usable: absent, not an error.
pub(crate) fn is_missing(err: i32) -> bool {
    matches!(
        err,
        libc::ENOKEY | libc::EKEYEXPIRED | libc::EKEYREVOKED | libc::ENOENT
    )
}

/// A failed keyring operation; the message is what the Python printed
/// (`"<what>: <strerror>"`) and never contains key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyringError(pub String);

impl std::fmt::Display for KeyringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn fail(what: &str, err: i32) -> KeyringError {
    KeyringError(format!("{what}: {}", strerror(err)))
}

/// The identity cache's keyring. The kernel implementation is
/// [`KernelKeyring`]; tests use an in-memory fake, so no test ever writes
/// `omdrop:identity` to the real `@u`.
pub(crate) trait Keyring {
    /// The cache key's serial in `@u`, or `None`.
    fn find(&self) -> Result<Option<i32>, KeyringError>;
    /// The payload of `serial`, or of the key `find` finds when `None`.
    fn read(&self, serial: Option<i32>) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError>;
    /// Publish (contract: "Publishing"). Returns the new serial.
    fn publish(&self, payload: &[u8], timeout: i64) -> Result<i32, KeyringError>;
    /// Change the cache's timeout; revoke it when `timeout < 1`. `false` when
    /// there was no cache (or it was revoked).
    fn set_timeout(&self, timeout: i64) -> Result<bool, KeyringError>;
    /// Revoke and unlink the cache. `false` when there was none.
    fn revoke(&self) -> Result<bool, KeyringError>;
}

/// The raw operations, one syscall each; `Err` carries errno. Behind a trait
/// so the publish sequence (and its revoke-on-failure) is testable without
/// touching the real keyring.
pub(crate) trait KeyOps {
    fn search_user(&self) -> Result<i32, i32>;
    /// Fill `buf`; returns the payload's full length (may exceed `buf`).
    fn read(&self, id: i32, buf: &mut [u8]) -> Result<usize, i32>;
    fn add_to_process(&self, payload: &[u8]) -> Result<i32, i32>;
    fn set_timeout(&self, id: i32, secs: u32) -> Result<(), i32>;
    fn setperm(&self, id: i32, perm: u32) -> Result<(), i32>;
    fn link(&self, id: i32, ring: i32) -> Result<(), i32>;
    fn unlink(&self, id: i32, ring: i32) -> Result<(), i32>;
    fn revoke(&self, id: i32) -> Result<(), i32>;
}

/// `keyctl(2)`. Async-signal-safe: the dropped child uses it after fork.
pub(crate) fn keyctl(op: c_long, a2: c_long, a3: c_long, a4: c_long, a5: c_long) -> c_long {
    // SAFETY: keyctl's pointer arguments, where the operation takes any, are
    // supplied by our callers from live buffers / NUL-terminated constants.
    unsafe { libc::syscall(libc::SYS_keyctl, op, a2, a3, a4, a5) }
}

fn check(rc: c_long) -> Result<c_long, i32> {
    if rc < 0 { Err(errno()) } else { Ok(rc) }
}

/// Search `ring` for the cache key. Async-signal-safe.
pub(crate) fn raw_search(ring: i32) -> Result<i32, i32> {
    check(keyctl(
        KEYCTL_SEARCH,
        ring as c_long,
        KEY_TYPE.as_ptr() as c_long,
        KEY_DESC.as_ptr() as c_long,
        0,
    ))
    .map(|id| id as i32)
}

/// Read key `id` into `buf`; the payload's full length. Async-signal-safe.
pub(crate) fn raw_read(id: i32, buf: &mut [u8]) -> Result<usize, i32> {
    check(keyctl(
        KEYCTL_READ,
        id as c_long,
        buf.as_mut_ptr() as c_long,
        buf.len() as c_long,
        0,
    ))
    .map(|n| n as usize)
}

/// Join a new anonymous session keyring and link `@u` into it, so keys found
/// through it are possessed. Async-signal-safe.
pub(crate) fn raw_join_session_with_user() -> Result<(), i32> {
    check(keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0))?;
    check(keyctl(
        KEYCTL_LINK,
        KEY_SPEC_USER_KEYRING as c_long,
        KEY_SPEC_SESSION_KEYRING as c_long,
        0,
        0,
    ))?;
    Ok(())
}

pub(crate) struct Syscalls;

impl KeyOps for Syscalls {
    fn search_user(&self) -> Result<i32, i32> {
        raw_search(KEY_SPEC_USER_KEYRING)
    }
    fn read(&self, id: i32, buf: &mut [u8]) -> Result<usize, i32> {
        raw_read(id, buf)
    }
    fn add_to_process(&self, payload: &[u8]) -> Result<i32, i32> {
        // SAFETY: type and description are NUL-terminated constants; the
        // payload pointer and length describe a live slice.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                KEY_TYPE.as_ptr(),
                KEY_DESC.as_ptr(),
                payload.as_ptr(),
                payload.len(),
                KEY_SPEC_PROCESS_KEYRING as c_long,
            )
        };
        check(rc).map(|id| id as i32)
    }
    fn set_timeout(&self, id: i32, secs: u32) -> Result<(), i32> {
        check(keyctl(
            KEYCTL_SET_TIMEOUT,
            id as c_long,
            secs as c_long,
            0,
            0,
        ))
        .map(drop)
    }
    fn setperm(&self, id: i32, perm: u32) -> Result<(), i32> {
        check(keyctl(KEYCTL_SETPERM, id as c_long, perm as c_long, 0, 0)).map(drop)
    }
    fn link(&self, id: i32, ring: i32) -> Result<(), i32> {
        check(keyctl(KEYCTL_LINK, id as c_long, ring as c_long, 0, 0)).map(drop)
    }
    fn unlink(&self, id: i32, ring: i32) -> Result<(), i32> {
        check(keyctl(KEYCTL_UNLINK, id as c_long, ring as c_long, 0, 0)).map(drop)
    }
    fn revoke(&self, id: i32) -> Result<(), i32> {
        check(keyctl(KEYCTL_REVOKE, id as c_long, 0, 0, 0)).map(drop)
    }
}

/// The calling process's user keyring.
pub(crate) struct KernelKeyring<O: KeyOps = Syscalls> {
    pub ops: O,
}

impl KernelKeyring {
    pub(crate) fn new() -> Self {
        KernelKeyring { ops: Syscalls }
    }
}

fn clamp_secs(timeout: i64) -> u32 {
    u32::try_from(timeout.max(0)).unwrap_or(u32::MAX)
}

impl<O: KeyOps> Keyring for KernelKeyring<O> {
    fn find(&self) -> Result<Option<i32>, KeyringError> {
        match self.ops.search_user() {
            Ok(id) => Ok(Some(id)),
            Err(e) if is_missing(e) => Ok(None),
            Err(e) => Err(fail("searching for the identity cache", e)),
        }
    }

    fn read(&self, serial: Option<i32>) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError> {
        let id = match serial {
            Some(id) => id,
            None => match self.find()? {
                Some(id) => id,
                None => return Ok(None),
            },
        };
        // The bug class plugin tests/test_keyring.py pins: a key this session
        // can see but not read must come back as an error, never as a length
        // taken from an error return.
        let mut buf = Zeroizing::new(vec![0u8; MAX_KEY_PAYLOAD + 1]);
        loop {
            match self.ops.read(id, &mut buf) {
                Ok(n) if n <= buf.len() => {
                    buf.truncate(n);
                    return Ok(Some(buf));
                }
                // Grew between calls (another publish): size up and retry,
                // within a sane bound.
                Ok(n) if n <= 1 << 20 => {
                    buf.zeroize();
                    buf.resize(n, 0);
                }
                Ok(_) => {
                    return Err(KeyringError(
                        "reading the identity cache: payload too large".into(),
                    ));
                }
                Err(e) if is_missing(e) => return Ok(None),
                Err(e) => return Err(fail("reading the identity cache", e)),
            }
        }
    }

    fn publish(&self, payload: &[u8], timeout: i64) -> Result<i32, KeyringError> {
        if timeout < 1 {
            return Err(KeyringError(
                "refusing to publish a cache that has already expired".into(),
            ));
        }
        let old = self.find().ok().flatten();
        let id = self
            .ops
            .add_to_process(payload)
            .map_err(|e| fail("adding the identity cache", e))?;
        let staged = (|| {
            self.ops
                .set_timeout(id, clamp_secs(timeout))
                .map_err(|e| fail("setting the cache timeout", e))?;
            self.ops
                .setperm(id, KEY_PERM)
                .map_err(|e| fail("setting the cache permissions", e))?;
            self.ops
                .link(id, KEY_SPEC_USER_KEYRING)
                .map_err(|e| fail("linking the identity cache", e))
        })();
        if let Err(e) = staged {
            let _ = self.ops.revoke(id);
            return Err(e);
        }
        let _ = self.ops.unlink(id, KEY_SPEC_PROCESS_KEYRING);
        if let Some(old) = old
            && old != id
        {
            let _ = self.ops.revoke(old);
        }
        Ok(id)
    }

    fn set_timeout(&self, timeout: i64) -> Result<bool, KeyringError> {
        let Some(id) = self.find()? else {
            return Ok(false);
        };
        if timeout < 1 {
            self.revoke()?;
            return Ok(false);
        }
        self.ops
            .set_timeout(id, clamp_secs(timeout))
            .map_err(|e| fail("setting the cache timeout", e))?;
        Ok(true)
    }

    fn revoke(&self) -> Result<bool, KeyringError> {
        let Some(id) = self.find()? else {
            return Ok(false);
        };
        let _ = self.ops.revoke(id);
        let _ = self.ops.unlink(id, KEY_SPEC_USER_KEYRING);
        Ok(true)
    }
}

/// An in-memory keyring for tests: one key, a timeout, revoke.
#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    pub(crate) struct State {
        pub payload: Option<Vec<u8>>,
        pub timeout: Option<i64>,
        pub published: u32,
        pub fail_revoke: bool,
    }

    #[derive(Clone, Default)]
    pub(crate) struct FakeKeyring(pub Rc<RefCell<State>>);

    impl Keyring for FakeKeyring {
        fn find(&self) -> Result<Option<i32>, KeyringError> {
            Ok(self.0.borrow().payload.as_ref().map(|_| 1))
        }
        fn read(&self, _serial: Option<i32>) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError> {
            Ok(self.0.borrow().payload.clone().map(Zeroizing::new))
        }
        fn publish(&self, payload: &[u8], timeout: i64) -> Result<i32, KeyringError> {
            if timeout < 1 {
                return Err(KeyringError(
                    "refusing to publish a cache that has already expired".into(),
                ));
            }
            let mut s = self.0.borrow_mut();
            s.payload = Some(payload.to_vec());
            s.timeout = Some(timeout);
            s.published += 1;
            Ok(1)
        }
        fn set_timeout(&self, timeout: i64) -> Result<bool, KeyringError> {
            if self.0.borrow().payload.is_none() {
                return Ok(false);
            }
            if timeout < 1 {
                self.revoke()?;
                return Ok(false);
            }
            self.0.borrow_mut().timeout = Some(timeout);
            Ok(true)
        }
        fn revoke(&self) -> Result<bool, KeyringError> {
            let mut s = self.0.borrow_mut();
            if s.fail_revoke {
                return Err(KeyringError("revoking: Permission denied".into()));
            }
            s.timeout = None;
            Ok(s.payload.take().is_some())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records each raw call; fails the one named in `fail_at`.
    #[derive(Default)]
    struct Recorder {
        calls: RefCell<Vec<String>>,
        fail_at: Option<&'static str>,
        existing: Option<i32>,
    }

    impl Recorder {
        fn step(&self, name: &'static str, call: String) -> Result<(), i32> {
            self.calls.borrow_mut().push(call);
            if self.fail_at == Some(name) {
                Err(libc::EDQUOT)
            } else {
                Ok(())
            }
        }
    }

    impl KeyOps for Recorder {
        fn search_user(&self) -> Result<i32, i32> {
            self.calls.borrow_mut().push("search".into());
            self.existing.ok_or(libc::ENOKEY)
        }
        fn read(&self, _id: i32, _buf: &mut [u8]) -> Result<usize, i32> {
            Err(libc::EACCES)
        }
        fn add_to_process(&self, _payload: &[u8]) -> Result<i32, i32> {
            self.step("add", "add @p".into()).map(|_| 7)
        }
        fn set_timeout(&self, id: i32, secs: u32) -> Result<(), i32> {
            self.step("timeout", format!("timeout {id} {secs}"))
        }
        fn setperm(&self, id: i32, perm: u32) -> Result<(), i32> {
            self.step("perm", format!("perm {id} {perm:#x}"))
        }
        fn link(&self, id: i32, ring: i32) -> Result<(), i32> {
            self.step("link", format!("link {id} {ring}"))
        }
        fn unlink(&self, id: i32, ring: i32) -> Result<(), i32> {
            self.step("unlink", format!("unlink {id} {ring}"))
        }
        fn revoke(&self, id: i32) -> Result<(), i32> {
            self.step("revoke", format!("revoke {id}"))
        }
    }

    #[test]
    fn publish_stages_in_the_process_keyring_then_links_into_user() {
        let k = KernelKeyring {
            ops: Recorder {
                existing: Some(3),
                ..Default::default()
            },
        };
        assert_eq!(k.publish(b"payload", 3600), Ok(7));
        assert_eq!(
            *k.ops.calls.borrow(),
            [
                "search",
                "add @p",
                "timeout 7 3600",
                "perm 7 0x3f010000",
                "link 7 -4",
                "unlink 7 -2",
                "revoke 3"
            ]
        );
    }

    #[test]
    fn a_failed_publish_step_revokes_the_staged_key() {
        for (step, message) in [
            ("timeout", "setting the cache timeout"),
            ("perm", "setting the cache permissions"),
            ("link", "linking the identity cache"),
        ] {
            let k = KernelKeyring {
                ops: Recorder {
                    fail_at: Some(step),
                    ..Default::default()
                },
            };
            let err = k.publish(b"payload", 60).expect_err("fails");
            assert_eq!(err.0, format!("{message}: Disk quota exceeded"));
            assert_eq!(
                k.ops.calls.borrow().last().map(String::as_str),
                Some("revoke 7")
            );
            assert!(!k.ops.calls.borrow().iter().any(|c| c.starts_with("unlink")));
        }
        let k = KernelKeyring {
            ops: Recorder {
                fail_at: Some("add"),
                ..Default::default()
            },
        };
        assert_eq!(
            k.publish(b"p", 60).expect_err("fails").0,
            "adding the identity cache: Disk quota exceeded"
        );
    }

    #[test]
    fn an_expired_cache_is_never_published() {
        let k = KernelKeyring {
            ops: Recorder::default(),
        };
        assert!(k.publish(b"p", 0).is_err());
        assert!(k.ops.calls.borrow().is_empty());
    }

    #[test]
    fn an_unreadable_key_is_an_error_not_a_length() {
        let k = KernelKeyring {
            ops: Recorder::default(),
        };
        assert_eq!(
            k.read(Some(5)).expect_err("EACCES").0,
            "reading the identity cache: Permission denied"
        );
    }

    /// plugin tests/test_keyring.py against the real kernel: serial 1 is never
    /// a key this user can read. Reads only; nothing is published.
    #[test]
    fn reading_an_unreadable_real_key_does_not_crash() {
        match KernelKeyring::new().read(Some(1)) {
            Ok(None) | Err(_) => {}
            Ok(Some(_)) => panic!("serial 1 read as a payload"),
        }
    }

    fn user_ns() -> String {
        std::fs::read_link("/proc/self/ns/user")
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    const NS_VAR: &str = "OMDROP_KEYRING_TEST_PARENT_NS";

    /// The real publish sequence against the kernel, in a private user
    /// namespace, whose `@u` is a fresh keyring: the real one is never
    /// touched. Re-runs this test binary under `unshare --map-current-user`
    /// to execute [`publish_in_this_namespace`].
    #[test]
    fn the_real_publish_sequence_in_a_private_user_namespace() {
        let exe = std::env::current_exe().expect("test binary");
        let run = std::process::Command::new("unshare")
            .arg("--map-current-user")
            .arg(exe)
            .args([
                "--exact",
                "keyring::tests::publish_in_this_namespace",
                "--ignored",
                "--nocapture",
            ])
            .env(NS_VAR, user_ns())
            .output();
        let Ok(out) = run else {
            eprintln!("skipped: unshare(1) is not available");
            return;
        };
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && text.contains("unshare failed") {
            eprintln!("skipped: user namespaces are not available: {text}");
            return;
        }
        assert!(out.status.success(), "{text}");
        assert!(text.contains("1 passed"), "{text}");
    }

    #[test]
    #[ignore = "run only by the_real_publish_sequence_in_a_private_user_namespace"]
    fn publish_in_this_namespace() {
        // Never publish unless this process is provably in a namespace of
        // its own, where @u is not the user's real keyring.
        let parent = std::env::var(NS_VAR).expect("started by the namespace test");
        assert!(
            !parent.is_empty() && parent != user_ns(),
            "not in a private user namespace"
        );
        // A login session's keyring links @u, which is what makes the key
        // possessed (readable) after it leaves @p.
        raw_join_session_with_user().expect("session keyring");
        let k = KernelKeyring::new();
        assert_eq!(k.find(), Ok(None));
        let first = k.publish(b"first payload", 600).expect("publish");
        assert_eq!(k.find(), Ok(Some(first)));
        assert_eq!(
            k.read(None).expect("read").as_deref().map(Vec::as_slice),
            Some(&b"first payload"[..])
        );
        let keys = std::fs::read_to_string("/proc/keys").expect("/proc/keys");
        let line = keys
            .lines()
            .find(|l| l.starts_with(&format!("{first:08x} ")))
            .expect("listed");
        let fields: Vec<&str> = line.split_whitespace().collect();
        // serial flags usage timeout perm uid gid type description
        assert!(fields[3].ends_with('m'), "{line}");
        assert_eq!(fields[4], "3f010000", "{line}");
        // A second publish replaces the first, which is revoked.
        let second = k.publish(b"second", 600).expect("publish");
        assert_ne!(first, second);
        assert_eq!(k.find(), Ok(Some(second)));
        // The replaced key is gone: revoked, and no longer possessed.
        assert!(matches!(k.read(Some(first)), Ok(None) | Err(_)));
        assert_eq!(k.set_timeout(30), Ok(true));
        assert_eq!(k.set_timeout(0), Ok(false));
        assert_eq!(k.find(), Ok(None));
        assert_eq!(k.revoke(), Ok(false));
    }
}
