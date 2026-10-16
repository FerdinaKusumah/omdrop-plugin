//! `resolve`: read the real state, select, and return the bytes to present.
//!
//! One resolver for every program. It unifies the plugin's `identity.resolve`
//! and the driver's `awdl_identity.resolve_identity`; where they differed,
//! the stricter behaviour won (see the crate's report): an unreadable
//! settings file or cache is an error with its own code, never "absent".

use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::asuser::{self, Test};
use crate::contract::{
    CacheState, DiskState, PairState, Window, WindowState, mode, parse_payload, parse_settings,
    parse_window, select,
};
use crate::keyring::{KernelKeyring, Keyring, KeyringError};
use crate::keys::key_matches;
use crate::selfsigned;
use crate::user::User;
use crate::{Identity, IdentityError, ResolveOptions, Source};

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn fail(code: &str) -> IdentityError {
    IdentityError::new(code)
}

/// Where the cache payload comes from. The kernel in production; a fake in tests.
pub(crate) trait CacheSource {
    fn read(
        &self,
        user: &User,
        serial: Option<i32>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError>;
}

/// Search `@u`; when that finds nothing, read by the window's `cache_serial`.
///
/// A sandboxed service -- the receiver, with `ProtectHome=` and friends --
/// runs in its own user namespace, where `@u` names a different, empty user
/// keyring, but the key itself is still readable by serial.
pub(crate) fn keyring_read(
    keyring: &dyn Keyring,
    serial: Option<i32>,
) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError> {
    let data = keyring.read(None)?;
    match (data, serial) {
        (None, Some(s)) => keyring.read(Some(s)),
        (data, _) => Ok(data),
    }
}

struct KernelCache;

impl CacheSource for KernelCache {
    fn read(
        &self,
        user: &User,
        serial: Option<i32>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        match user.creds() {
            // Root acting for another user: the key's permissions (possessor
            // all, user view) give root nothing, so the read happens in a
            // child dropped to that user's uid and gid.
            Some(c) => asuser::read_cache(c, serial).map_err(|()| fail("cache-unreadable-as-root")),
            None => keyring_read(&KernelKeyring::new(), serial).map_err(|_| {
                fail(if user.root {
                    "cache-unreadable-as-root"
                } else {
                    "cache-unreadable"
                })
            }),
        }
    }
}

pub(crate) struct Ctx<'a> {
    pub user: &'a User,
    pub cache: &'a dyn CacheSource,
    pub now: i64,
    pub create: bool,
    pub name: Option<&'a str>,
}

pub(crate) fn resolve(opts: &ResolveOptions) -> Result<Identity, IdentityError> {
    let user = User::current(opts.keys_dir.as_deref())?;
    resolve_with(&Ctx {
        user: &user,
        cache: &KernelCache,
        now: now(),
        create: opts.create,
        name: opts.computer_name.as_deref(),
    })
}

fn utf8(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes).ok()
}

pub(crate) fn resolve_with(ctx: &Ctx<'_>) -> Result<Identity, IdentityError> {
    let user = ctx.user;
    let creds = user.creds();
    let settings = match asuser::read_file(&user.settings, creds) {
        Ok(None) => Default::default(),
        Ok(Some(b)) => parse_settings(utf8(&b).ok_or_else(|| fail("settings-unreadable"))?),
        Err(_) => return Err(fail("settings-unreadable")),
    };
    let mut serial = None;
    let window = match asuser::read_file(&user.window, creds) {
        Ok(None) => WindowState::Absent,
        Ok(Some(b)) => match utf8(&b) {
            Some(text) => {
                serial = parse_settings(text)
                    .get("cache_serial")
                    .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|s| s.parse::<i32>().ok());
                parse_window(text).map_or(WindowState::Unparseable, WindowState::Parsed)
            }
            None => WindowState::Unparseable,
        },
        Err(_) => WindowState::Unparseable,
    };
    if window == WindowState::Unparseable {
        return Err(fail("window-unparseable"));
    }

    // The window's expiry is checked before any cache I/O.
    let mut cache = CacheState::Absent;
    let mut payload = None;
    if let WindowState::Parsed(Window::OnePassword { hard_expiry, .. }) = &window {
        if *hard_expiry <= ctx.now {
            return Err(fail("window-expired"));
        }
        // Core dumps off before any cached secret enters this process.
        crate::sys::protect_process().map_err(|()| fail("cache-protection-unavailable"))?;
        if let Some(raw) = ctx.cache.read(user, serial)? {
            match parse_payload(&raw) {
                Some(p) => {
                    cache = CacheState::Parsed {
                        fetch_id: p.fetch_id.clone(),
                        hard_expiry: p.hard_expiry,
                    };
                    payload = Some(p);
                }
                None => cache = CacheState::Malformed,
            }
        }
    }

    let k = &user.keys;
    let (cert_path, key_path, record_path) = (
        k.join("certificate.pem"),
        k.join("key.pem"),
        k.join("validation_record.cms"),
    );
    let (self_cert, self_key) = (k.join(selfsigned::CERT), k.join(selfsigned::KEY));
    let have = asuser::paths_exist(
        &[
            (Test::LExists, &cert_path),
            (Test::LExists, &key_path),
            (Test::Exists, &record_path),
            (Test::LExists, &self_cert),
            (Test::LExists, &self_key),
        ],
        creds,
    )
    .map_err(|_| fail("invoking-user-invalid"))?;
    let [
        have_cert,
        have_key,
        have_record,
        have_self_cert,
        have_self_key,
    ] = have[..]
    else {
        return Err(fail("invoking-user-invalid"));
    };
    let mut disk = DiskState {
        certificate: have_cert,
        key: have_key,
        matches: false,
        record: have_record,
    };
    // The disk files are read only when selection can use them: an
    // unrelated, unreadable legacy key must not stop a self-signed or cached
    // identity. An unreadable file counts as present but not matching.
    let mut disk_pem = None;
    if mode(&settings, &window) == "disk" && disk.certificate && disk.key {
        let c = asuser::read_file(&cert_path, creds).ok().flatten();
        let key = asuser::read_file(&key_path, creds).ok().flatten();
        if let (Some(c), Some(key)) = (c, key) {
            disk.matches = key_matches(&c, &key, creds);
            disk_pem = Some((c, key));
        }
    }
    let pair = PairState {
        certificate: have_self_cert,
        key: have_self_key,
    };
    let choice = select(
        &settings,
        &window,
        &cache,
        disk,
        pair,
        user.root || !ctx.create,
        ctx.now,
    )
    .map_err(fail)?;
    let warnings = choice.warnings.iter().map(|w| (*w).to_owned()).collect();

    match choice.identity {
        Source::Cache => {
            let p = payload.ok_or_else(|| fail("cache-missing"))?;
            Ok(Identity {
                source: Source::Cache,
                certificate_pem: p.certificate,
                key_pem: p.key,
                record: Some(p.record),
                warnings,
            })
        }
        Source::Disk => {
            let (c, key) = disk_pem.ok_or_else(|| fail("disk-missing"))?;
            let record = if choice.record {
                match asuser::read_file(&record_path, creds) {
                    Ok(Some(r)) => Some(r.to_vec()),
                    _ => return Err(fail("disk-record-unreadable")),
                }
            } else {
                None
            };
            Ok(Identity {
                source: Source::Disk,
                certificate_pem: c.to_vec(),
                key_pem: key,
                record,
                warnings,
            })
        }
        Source::SelfSigned => {
            if choice.create {
                let host;
                let name = match ctx.name {
                    Some(n) => n,
                    None => {
                        host = crate::sys::hostname();
                        &host
                    }
                };
                selfsigned::create(k, name, user.root).map_err(|e| fail(e.code()))?;
            }
            let read = |p| match asuser::read_file(p, creds) {
                Ok(Some(b)) => Ok(b),
                _ => Err(fail("self-signed-unreadable")),
            };
            let c = read(&self_cert)?;
            let key = read(&self_key)?;
            Ok(Identity {
                source: Source::SelfSigned,
                certificate_pem: c.to_vec(),
                key_pem: key,
                record: None,
                warnings,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::fake::FakeKeyring;
    use crate::keys::tests::make_pair;
    use std::cell::RefCell;
    use std::fs;
    use std::path::{Path, PathBuf};

    struct Fixture {
        _tmp: tempfile::TempDir,
        home: PathBuf,
        config: PathBuf,
        runtime: PathBuf,
        keys: PathBuf,
        cert: Vec<u8>,
        key: Vec<u8>,
        other_key: Vec<u8>,
    }

    type Canned = Option<Result<Option<Vec<u8>>, &'static str>>;
    /// Returns a canned cache read, or panics when the test says the cache
    /// must not be read.
    struct Cache(RefCell<Canned>);

    impl CacheSource for Cache {
        fn read(
            &self,
            _u: &User,
            _s: Option<i32>,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
            match self.0.borrow().clone() {
                None => panic!("the cache must not be read"),
                Some(Ok(d)) => Ok(d.map(Zeroizing::new)),
                Some(Err(code)) => Err(IdentityError::new(code)),
            }
        }
    }

    fn no_cache() -> Cache {
        Cache(RefCell::new(None))
    }

    fn cache(r: Result<Option<Vec<u8>>, &'static str>) -> Cache {
        Cache(RefCell::new(Some(r)))
    }

    fn payload(fetch_id: &str, record: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "OMDROP-IDENTITY 1\n{{\"certificate\":11,\"key\":3,\"record\":{},\"fetched_at\":100,\"period_ends\":200,\"hard_expiry\":300,\"fetch_id\":\"{fetch_id}\"}}\n",
            record.len()
        )
        .into_bytes();
        out.extend_from_slice(b"certificatekey");
        out.extend_from_slice(record);
        out
    }

    impl Fixture {
        fn new() -> Fixture {
            let tmp = tempfile::tempdir().expect("tempdir");
            let home = tmp.path().to_path_buf();
            let work = home.join("work");
            fs::create_dir_all(&work).expect("mkdir");
            let (cert, key) = make_pair(&work, "Synthetic identity", &["-newkey", "rsa:2048"]);
            let (_, other_key) =
                make_pair(&work, "Other synthetic identity", &["-newkey", "rsa:2048"]);
            let f = Fixture {
                keys: home.join(".omdrop/keys"),
                config: home.join("config"),
                runtime: home.join("runtime"),
                home,
                _tmp: tmp,
                cert,
                key,
                other_key,
            };
            for d in [&f.keys, &f.config.join("omdrop"), &f.runtime.join("omdrop")] {
                fs::create_dir_all(d).expect("mkdir");
            }
            f
        }

        fn user_with(&self, root: bool, keys_dir: Option<&Path>) -> User {
            let (config, runtime) = (self.config.clone(), self.runtime.clone());
            let mut u = User::from_parts(
                false,
                1000,
                1000,
                self.home.clone(),
                move |k| match k {
                    "XDG_CONFIG_HOME" => Some(config.clone().into()),
                    "XDG_RUNTIME_DIR" => Some(runtime.clone().into()),
                    _ => None,
                },
                keys_dir,
            );
            // Simulated root acting for itself (uid 0 reads directly): the
            // reads that would run as the user run here as this test's own
            // uid, which is what they would get.
            u.root = root;
            u.uid = if root { 0 } else { crate::sys::getuid() };
            u
        }

        fn resolve(
            &self,
            cache: &dyn CacheSource,
            create: bool,
            keys_dir: Option<&Path>,
        ) -> Result<Identity, IdentityError> {
            self.resolve_as(false, cache, create, keys_dir)
        }

        fn resolve_as(
            &self,
            root: bool,
            cache: &dyn CacheSource,
            create: bool,
            keys_dir: Option<&Path>,
        ) -> Result<Identity, IdentityError> {
            let user = self.user_with(root, keys_dir);
            resolve_with(&Ctx {
                user: &user,
                cache,
                now: 150,
                create,
                name: Some("Synthetic fallback"),
            })
        }

        fn write_pair(&self, suffix: &str, key: Option<&[u8]>) {
            fs::write(
                self.keys.join(format!("certificate{suffix}.pem")),
                &self.cert,
            )
            .expect("write");
            fs::write(
                self.keys.join(format!("key{suffix}.pem")),
                key.unwrap_or(&self.key),
            )
            .expect("write");
        }

        fn settings(&self, source: &str) {
            fs::write(
                self.config.join("omdrop/settings"),
                format!("identity_source={source}\n"),
            )
            .expect("write");
        }

        fn window(&self, text: &str) {
            fs::write(self.runtime.join("omdrop/window"), text).expect("write");
        }

        fn window_1password(&self, expiry: i64) {
            self.window(&format!(
                "source=1password\nfetch_id={}\nhard_expiry={expiry}\n",
                "a".repeat(32)
            ));
        }

        fn names(&self) -> Vec<String> {
            let mut v: Vec<String> = fs::read_dir(&self.keys)
                .expect("dir")
                .map(|e| e.expect("e").file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        }
    }

    fn code(r: Result<Identity, IdentityError>) -> String {
        r.expect_err("an error").code
    }

    #[test]
    fn matching_disk_uses_only_its_own_record() {
        let f = Fixture::new();
        f.write_pair("", None);
        f.write_pair(".self-signed", None);
        fs::write(
            f.keys.join("validation_record.cms"),
            b"synthetic disk record",
        )
        .expect("write");
        let id = f.resolve(&no_cache(), true, None).expect("resolves");
        assert_eq!(id.source, Source::Disk);
        assert_eq!(id.record.as_deref(), Some(&b"synthetic disk record"[..]));
        assert_eq!(id.certificate_pem, f.cert);
        assert_eq!(id.key_pem.as_slice(), f.key.as_slice());
    }

    #[test]
    fn standalone_1password_ignores_cache_and_disk_record() {
        let f = Fixture::new();
        f.settings("1password");
        f.write_pair("", None);
        f.write_pair(".self-signed", None);
        fs::write(f.keys.join("validation_record.cms"), b"disk record").expect("write");
        let id = f.resolve(&no_cache(), true, None).expect("resolves");
        assert_eq!((id.source, id.record), (Source::SelfSigned, None));
    }

    #[test]
    fn a_window_pins_the_cache_and_ignores_changed_settings() {
        let f = Fixture::new();
        f.settings("disk");
        f.write_pair("", None);
        f.window_1password(300);
        let id = f
            .resolve(
                &cache(Ok(Some(payload(&"a".repeat(32), b"window record")))),
                true,
                None,
            )
            .expect("resolves");
        assert_eq!(id.source, Source::Cache);
        assert_eq!(id.record.as_deref(), Some(&b"window record"[..]));
        assert_eq!(id.certificate_pem, b"certificate");
        assert_eq!(id.key_pem.as_slice(), b"key");
    }

    #[test]
    fn cache_window_failures_never_fall_back_to_disk() {
        let f = Fixture::new();
        f.write_pair("", None);
        f.write_pair(".self-signed", None);
        f.window_1password(300);
        for (frame, want) in [
            (None, "cache-missing"),
            (Some(b"bad".to_vec()), "cache-malformed"),
            (Some(payload(&"b".repeat(32), b"r")), "cache-mismatch"),
        ] {
            assert_eq!(code(f.resolve(&cache(Ok(frame)), true, None)), want);
        }
        assert_eq!(
            code(f.resolve(&cache(Err("cache-unreadable-as-root")), true, None)),
            "cache-unreadable-as-root"
        );
        assert_eq!(
            code(f.resolve(&cache(Err("cache-unreadable")), true, None)),
            "cache-unreadable"
        );
    }

    #[test]
    fn an_expired_or_unparseable_window_precedes_cache_io() {
        let f = Fixture::new();
        f.window_1password(150);
        assert_eq!(code(f.resolve(&no_cache(), true, None)), "window-expired");
        f.window("source=other\n");
        assert_eq!(
            code(f.resolve(&no_cache(), true, None)),
            "window-unparseable"
        );
        fs::write(f.runtime.join("omdrop/window"), b"source=disk\n\xff").expect("write");
        assert_eq!(
            code(f.resolve(&no_cache(), true, None)),
            "window-unparseable"
        );
    }

    #[test]
    fn an_explicit_keys_directory_replaces_only_the_material() {
        let f = Fixture::new();
        f.settings("disk");
        let explicit = f.home.join("explicit");
        fs::create_dir_all(explicit.join("keys")).expect("mkdir");
        fs::write(explicit.join("keys/certificate.pem"), &f.cert).expect("write");
        fs::write(explicit.join("keys/key.pem"), &f.key).expect("write");
        assert_eq!(
            f.resolve(&no_cache(), true, Some(&explicit))
                .expect("disk")
                .source,
            Source::Disk
        );
        f.window("source=self-signed\n");
        assert_eq!(
            code(f.resolve(&no_cache(), false, Some(&explicit))),
            "self-signed-missing"
        );
        assert!(!explicit.join("keys/key.self-signed.pem").exists());
    }

    #[test]
    fn a_disk_mismatch_falls_back_without_touching_apple_files() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        f.write_pair("", Some(&f.other_key));
        fs::write(
            f.keys.join("validation_record.cms"),
            b"preserve this record",
        )
        .expect("write");
        let before: Vec<(String, Vec<u8>)> = f
            .names()
            .into_iter()
            .map(|n| (n.clone(), fs::read(f.keys.join(&n)).expect("read")))
            .collect();
        let id = f.resolve(&no_cache(), true, None).expect("falls back");
        assert_eq!(
            (id.source, id.record.as_deref()),
            (Source::SelfSigned, None)
        );
        assert_eq!(id.warnings, ["disk-mismatch"]);
        assert!(key_matches(&id.certificate_pem, &id.key_pem, None));
        for (name, data) in before {
            assert_eq!(fs::read(f.keys.join(&name)).expect("read"), data, "{name}");
        }
        for name in [selfsigned::CERT, selfsigned::KEY] {
            let mode = fs::metadata(f.keys.join(name))
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        f.window("source=disk\n");
        assert_eq!(code(f.resolve(&no_cache(), true, None)), "disk-mismatch");
    }

    #[test]
    fn an_incomplete_disk_identity_is_preserved_and_a_pinned_one_errors() {
        let f = Fixture::new();
        fs::write(f.keys.join("certificate.pem"), &f.cert).expect("write");
        f.write_pair(".self-signed", None);
        let id = f.resolve(&no_cache(), true, None).expect("self-signed");
        assert_eq!(
            (id.source, id.warnings.as_slice()),
            (Source::SelfSigned, &["disk-incomplete".to_owned()][..])
        );
        assert_eq!(
            fs::read(f.keys.join("certificate.pem")).expect("cert"),
            f.cert
        );
        assert!(!f.keys.join("key.pem").exists());
        f.window("source=disk\n");
        assert_eq!(code(f.resolve(&no_cache(), true, None)), "disk-missing");
    }

    #[test]
    fn a_half_pair_and_read_only_resolution_do_not_create() {
        let f = Fixture::new();
        f.settings("self-signed");
        assert_eq!(
            code(f.resolve(&no_cache(), false, None)),
            "self-signed-missing"
        );
        assert!(f.names().is_empty());
        fs::write(f.keys.join(selfsigned::KEY), &f.key).expect("write");
        assert_eq!(
            code(f.resolve(&no_cache(), true, None)),
            "self-signed-half-pair"
        );
        assert_eq!(fs::read(f.keys.join(selfsigned::KEY)).expect("key"), f.key);
        assert!(!f.keys.join(selfsigned::CERT).exists());
    }

    #[test]
    fn root_never_creates_even_when_asked() {
        let f = Fixture::new();
        assert_eq!(
            code(f.resolve_as(true, &no_cache(), true, None)),
            "self-signed-missing"
        );
        assert!(f.names().is_empty());
    }

    #[test]
    fn a_missing_pair_is_created_with_the_given_name() {
        let f = Fixture::new();
        let id = f.resolve(&no_cache(), true, None).expect("created");
        assert_eq!(id.source, Source::SelfSigned);
        assert_eq!(
            f.names(),
            [".identity.lock", selfsigned::CERT, selfsigned::KEY]
        );
        assert_eq!(
            id.certificate_pem,
            fs::read(f.keys.join(selfsigned::CERT)).expect("cert")
        );
    }

    #[test]
    fn an_unreadable_legacy_key_does_not_stop_the_self_signed_identity() {
        use std::os::unix::fs::PermissionsExt;
        if crate::sys::euid_is_root() {
            return; // root reads a mode-0 file
        }
        let f = Fixture::new();
        f.settings("self-signed");
        f.write_pair(".self-signed", None);
        fs::write(f.keys.join("key.pem"), b"legacy").expect("write");
        fs::set_permissions(f.keys.join("key.pem"), fs::Permissions::from_mode(0o000))
            .expect("chmod");
        assert_eq!(
            f.resolve(&no_cache(), true, None)
                .expect("self-signed")
                .source,
            Source::SelfSigned
        );
        // In disk mode the unreadable key counts as present but not matching.
        f.settings("disk");
        fs::write(f.keys.join("certificate.pem"), &f.cert).expect("write");
        let id = f.resolve(&no_cache(), true, None).expect("falls back");
        assert_eq!(id.warnings, ["disk-mismatch"]);
    }

    #[test]
    fn an_unknown_mode_warns_and_an_unreadable_settings_file_is_an_error() {
        let f = Fixture::new();
        f.settings("keychain");
        f.write_pair(".self-signed", None);
        assert_eq!(
            f.resolve(&no_cache(), true, None).expect("ok").warnings,
            ["unknown-mode"]
        );
        fs::write(f.config.join("omdrop/settings"), b"identity_source=\xff\n").expect("write");
        assert_eq!(
            code(f.resolve(&no_cache(), true, None)),
            "settings-unreadable"
        );
    }

    #[test]
    fn a_sandboxed_reader_falls_back_to_the_windows_serial() {
        // The fake's search finds nothing (its own @u is empty), but the key
        // is readable by serial, as in a hardened systemd service.
        struct ByType(FakeKeyring);
        impl Keyring for ByType {
            fn find(&self) -> Result<Option<i32>, KeyringError> {
                Ok(None)
            }
            fn read(
                &self,
                serial: Option<i32>,
            ) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError> {
                match serial {
                    Some(42) => self.0.read(None),
                    _ => Ok(None),
                }
            }
            fn publish(&self, p: &[u8], t: i64) -> Result<i32, KeyringError> {
                self.0.publish(p, t)
            }
            fn set_timeout(&self, t: i64) -> Result<bool, KeyringError> {
                self.0.set_timeout(t)
            }
            fn revoke(&self) -> Result<bool, KeyringError> {
                self.0.revoke()
            }
        }
        let k = ByType(FakeKeyring::default());
        k.publish(b"frame", 60).expect("publish to fake");
        assert_eq!(keyring_read(&k, None).expect("ok"), None);
        assert_eq!(
            keyring_read(&k, Some(42))
                .expect("ok")
                .as_deref()
                .map(Vec::as_slice),
            Some(&b"frame"[..])
        );

        struct Sandboxed(ByType);
        impl CacheSource for Sandboxed {
            fn read(
                &self,
                _u: &User,
                s: Option<i32>,
            ) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
                keyring_read(&self.0, s).map_err(|_| IdentityError::new("cache-unreadable"))
            }
        }
        let f = Fixture::new();
        let fake = FakeKeyring::default();
        fake.publish(&payload(&"a".repeat(32), b"rec"), 60)
            .expect("publish to fake");
        f.window(&format!(
            "source=1password\nfetch_id={}\nhard_expiry=300\ncache_serial=42\n",
            "a".repeat(32)
        ));
        let id = f
            .resolve(&Sandboxed(ByType(fake)), true, None)
            .expect("by serial");
        assert_eq!(id.source, Source::Cache);
    }
}
