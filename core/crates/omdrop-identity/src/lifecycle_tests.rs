//! The identity lifecycle (plugin tests/test_identity_lifecycle.py): the
//! 1Password fetch, the cache, windows, import.
//!
//! Commands run in process against a temporary home, runtime and config
//! directory, a stub `op` (a shell script keeping its "items" in the
//! fixture), and an in-memory keyring, so nothing touches the real keyring,
//! 1Password, or ~/.omdrop.

use std::cell::{Cell, RefCell};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::rc::Rc;

use super::*;
use crate::contract::Window;
use crate::keyring::fake::FakeKeyring;
use crate::keys::tests::make_pair;

const STUB_OP: &str = r#"#!/bin/sh
store='@STORE@'
printf '%s\n' "$*" >> "$store/calls"
if [ -f "$store/fail" ]; then
  printf '[ERROR] 2026/09/28 10:00:00 %s\n' "$(cat "$store/fail")" >&2
  exit 1
fi
case "$1" in
read)
  for last in "$@"; do :; done
  ref=${last#op://}
  rest=${ref#*/}
  item=${rest%%/*}
  name=${rest#*/}
  cat "$store/items/$item/$name" || exit 1
  if [ -f "$store/corrupt" ] && [ "$(cat "$store/corrupt")" = "$name" ]; then printf x; fi
  ;;
item)
  case "$2" in
  create)
    mkdir -p "$store/items/item1"
    for a in "$@"; do
      case "$a" in
      *"[file]="*) cp "${a#*"[file]="}" "$store/items/item1/${a%%"[file]="*}" ;;
      esac
    done
    echo '{"id": "item1", "vault": {"id": "vault1"}}'
    ;;
  get) printf '{"id": "%s", "vault": {"id": "vault1"}}\n' "$3" ;;
  esac
  ;;
account) echo '[{"account_uuid": "acct1", "email": "x", "url": "y", "user_uuid": "u"}]' ;;
esac
"#;

struct Fixture {
    tmp: tempfile::TempDir,
    config: PathBuf,
    keys: PathBuf,
    opdir: PathBuf,
    env: Env,
    keyring: FakeKeyring,
    problem: Rc<RefCell<Option<String>>>,
    clock: Rc<Cell<Option<i64>>>,
    apple: [Vec<u8>; 3],
}

impl Fixture {
    fn new() -> Fixture {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();
        let (home, runtime, config) = (root.join("home"), root.join("run"), root.join("config"));
        for d in [&home, &runtime, &config] {
            fs::create_dir(d).expect("mkdir");
        }
        let keys = home.join(".omdrop/keys");
        fs::create_dir_all(&keys).expect("mkdir");
        let opdir = root.join("op");
        fs::create_dir_all(opdir.join("items")).expect("mkdir");
        let stub = root.join("op-stub");
        fs::write(&stub, STUB_OP.replace("@STORE@", &opdir.to_string_lossy())).expect("stub");
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).expect("chmod");
        let (rt, cf) = (runtime.clone(), config.clone());
        let user = User::from_parts(
            false,
            crate::sys::getuid(),
            0,
            home,
            move |k| match k {
                "XDG_RUNTIME_DIR" => Some(rt.clone().into()),
                "XDG_CONFIG_HOME" => Some(cf.clone().into()),
                _ => None,
            },
            None,
        );
        let keyring = FakeKeyring::default();
        let problem: Rc<RefCell<Option<String>>> = Rc::default();
        let clock: Rc<Cell<Option<i64>>> = Rc::default();
        let (p, c) = (Rc::clone(&problem), Rc::clone(&clock));
        // An "Apple" identity for the stub: a real key pair, since the checks
        // that it chains to Apple are replaced by `problem`.
        let work = root.join("apple");
        fs::create_dir(&work).expect("mkdir");
        let (cert, key) = make_pair(
            &work,
            "com.apple.idms.appleid.prd.test",
            &["-newkey", "rsa:2048"],
        );
        let env = Env {
            user,
            keyring: Box::new(keyring.clone()),
            op: Some(stub),
            check_apple: Box::new(move |_, _, _| p.borrow().clone()),
            clock: Box::new(move || c.get().unwrap_or_else(crate::resolver::now)),
            hook: None,
        };
        Fixture {
            tmp,
            config,
            keys,
            opdir,
            env,
            keyring,
            problem,
            clock,
            apple: [cert, key, b"\x30\x82record".to_vec()],
        }
    }

    fn run(&self, argv: &[&str]) -> (i32, String, String) {
        let args: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let rc = match crate::args::parse(&args) {
            Parse::Run(cmd) => run(&self.env, &cmd, &mut out, &mut err),
            other => panic!("{argv:?}: {other:?}"),
        };
        (
            rc,
            String::from_utf8(out).expect("utf8"),
            String::from_utf8(err).expect("utf8"),
        )
    }

    fn settings(&self, values: &[(&str, &str)]) {
        let text: String = values.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
        fs::create_dir_all(self.config.join("omdrop")).expect("mkdir");
        fs::write(self.config.join("omdrop/settings"), text).expect("settings");
    }

    fn read_settings(&self) -> Settings {
        parse_settings(&fs::read_to_string(self.config.join("omdrop/settings")).expect("settings"))
    }

    fn op_item(&self) {
        let item = self.opdir.join("items/item1");
        fs::create_dir_all(&item).expect("mkdir");
        for (f, data) in FILES.iter().zip(&self.apple) {
            fs::write(item.join(op_name(f)), data).expect("item file");
        }
    }

    fn op_calls(&self) -> Vec<String> {
        fs::read_to_string(self.opdir.join("calls"))
            .map(|s| s.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    fn op_fail(&self, message: Option<&str>) {
        match message {
            Some(m) => fs::write(self.opdir.join("fail"), m).expect("fail"),
            None => {
                let _ = fs::remove_file(self.opdir.join("fail"));
            }
        }
    }

    fn apple_on_disk(&self) {
        for (f, data) in FILES.iter().zip(&self.apple) {
            fs::write(self.keys.join(f), data).expect("write");
            fs::set_permissions(self.keys.join(f), fs::Permissions::from_mode(0o600))
                .expect("chmod");
        }
    }

    fn files_on_disk(&self) -> Vec<String> {
        let mut v: Vec<String> = FILES
            .iter()
            .filter(|f| self.keys.join(f).exists())
            .map(|f| f.to_string())
            .collect();
        v.sort();
        v
    }

    /// `omdrop on`'s identity steps: begin, then window with the seq it got.
    fn on(&self) -> (i32, Settings, Settings) {
        let (rc, out, err) = self.run(&["begin", "--name", "Test"]);
        assert_eq!(rc, 0, "{err}");
        let begun = parse_settings(&out);
        let seq = begun.get("seq").cloned().expect("seq");
        let (rc, out, _) = self.run(&["window", "--seq", &seq]);
        (rc, begun, parse_settings(&out))
    }

    fn off(&self) {
        self.run(&["stop-begin"]);
        self.run(&["stop-end"]);
    }

    fn window(&self) -> WindowState {
        read_window(&self.env).expect("window")
    }

    fn payload(&self) -> Option<Payload> {
        self.keyring
            .0
            .borrow()
            .payload
            .as_ref()
            .and_then(|p| parse_payload(p))
    }

    fn has_cache(&self) -> bool {
        self.keyring.0.borrow().payload.is_some()
    }

    fn timeout(&self) -> i64 {
        self.keyring.0.borrow().timeout.expect("timeout")
    }
}

fn one_password() -> Fixture {
    let f = Fixture::new();
    f.settings(&[
        ("identity_source", "1password"),
        ("identity_op_account", "acct1"),
        ("identity_op_vault", "vault1"),
        ("identity_op_item", "item1"),
    ]);
    f.op_item();
    f
}

// ------------------------------------------------------------------ 1Password windows

#[test]
fn the_first_window_fetches_and_is_bound_to_that_fetch() {
    let f = one_password();
    let (rc, begun, win) = f.on();
    assert_eq!(rc, 0);
    assert!(!begun.contains_key("notice"));
    let p = f.payload().expect("cached");
    assert_eq!(p.key.as_slice(), f.apple[1].as_slice());
    assert_eq!(p.period_ends - p.fetched_at, 12 * 3600);
    assert_eq!(p.hard_expiry - p.fetched_at, 86400);
    assert_eq!(win["source"], "1password");
    assert_eq!(
        f.window(),
        WindowState::Parsed(Window::OnePassword {
            fetch_id: p.fetch_id.clone(),
            hard_expiry: p.hard_expiry
        })
    );
    // The window records the key's serial for sandboxed readers.
    let text = fs::read_to_string(&f.env.user.window).expect("window");
    assert!(text.ends_with("cache_serial=1\n"), "{text}");
    // During the window the cache lives until the hard expiry, not the period.
    assert!(f.timeout() > 12 * 3600);
    let calls = f.op_calls();
    assert_eq!(
        calls,
        [
            "read --no-newline --account acct1 op://vault1/item1/certificate",
            "read --no-newline --account acct1 op://vault1/item1/key",
            "read --no-newline --account acct1 op://vault1/item1/validation_record",
        ]
    );
}

#[test]
fn cache_hours_bound_the_period() {
    let f = one_password();
    let mut s: Vec<(&str, &str)> = vec![
        ("identity_source", "1password"),
        ("identity_op_vault", "vault1"),
        ("identity_op_item", "item1"),
    ];
    s.push(("identity_cache_hours", "3"));
    f.settings(&s);
    f.on();
    let p = f.payload().expect("cached");
    assert_eq!(p.period_ends - p.fetched_at, 3 * 3600);
    // No account configured: none is passed.
    assert_eq!(
        f.op_calls()[0],
        "read --no-newline op://vault1/item1/certificate"
    );
}

#[test]
fn a_later_window_in_the_period_uses_the_cache_without_asking() {
    let f = one_password();
    f.on();
    f.off();
    let calls = f.op_calls().len();
    let (_, _, win) = f.on();
    assert_eq!(f.op_calls().len(), calls);
    assert_eq!(win["source"], "1password");
}

#[test]
fn off_keeps_the_cache_but_shortens_it_to_the_period() {
    let f = one_password();
    f.on();
    f.off();
    assert_eq!(f.window(), WindowState::Absent);
    let p = f.payload().expect("cached");
    assert!(f.timeout() <= p.period_ends - p.fetched_at);
}

#[test]
fn a_dismissed_prompt_falls_back_to_self_signed_and_says_why() {
    let f = one_password();
    f.op_fail(Some("authorization prompt dismissed, please try again"));
    let (rc, begun, win) = f.on();
    assert_eq!(rc, 0);
    assert_eq!(
        begun["notice"],
        "1Password prompt dismissed; using self-signed certificates. Peers must be in \"Everyone\" mode."
    );
    assert_eq!(win["source"], "self-signed");
    assert!(!f.has_cache());
}

#[test]
fn a_locked_1password_is_named_without_its_error_text() {
    let f = one_password();
    f.op_fail(Some(
        "could not read secret 'op://vault1/item1/certificate': error initializing client: connecting to desktop app: connection reset",
    ));
    let (_, begun, win) = f.on();
    assert!(begun["notice"].starts_with("1Password locked; using self-signed"));
    assert!(!begun["notice"].contains("op://"));
    assert_eq!(win["source"], "self-signed");
}

#[test]
fn without_the_cli_the_notice_says_so() {
    let mut f = one_password();
    f.env.op = None;
    let (_, begun, win) = f.on();
    assert!(begun["notice"].contains("not installed"), "{begun:?}");
    assert_eq!(win["source"], "self-signed");
    let (_, out, _) = f.run(&["status"]);
    assert!(out.contains("The 1Password CLI (op) is not installed."));
}

#[test]
fn an_identity_that_fails_its_checks_is_never_cached() {
    let f = one_password();
    *f.problem.borrow_mut() = Some("validation record has expired".into());
    let (_, begun, win) = f.on();
    assert!(begun["notice"].contains("Apple identity in 1Password is unusable"));
    assert!(!f.has_cache());
    assert_eq!(win["source"], "self-signed");
}

#[test]
fn a_partial_fetch_publishes_nothing() {
    let f = one_password();
    fs::remove_file(f.opdir.join("items/item1/validation_record")).expect("rm");
    let (_, begun, _) = f.on();
    assert!(begun.contains_key("notice"));
    assert!(!f.has_cache());
}

#[test]
fn an_oversized_identity_is_unusable_not_a_crash() {
    let f = one_password();
    fs::write(
        f.opdir.join("items/item1/validation_record"),
        vec![b'r'; 16385],
    )
    .expect("write");
    let (rc, begun, win) = f.on();
    assert_eq!(rc, 0);
    assert!(begun["notice"].starts_with("The Apple identity in 1Password is unusable;"));
    assert_eq!(win["source"], "self-signed");
}

#[test]
fn off_during_the_fetch_means_nothing_starts() {
    let f = one_password();
    let (_, out, _) = f.run(&["begin", "--name", "Test"]);
    let seq = parse_settings(&out)["seq"].clone();
    f.run(&["stop-begin"]); // `off` arrives while `on` is fetching
    let (rc, out, _) = f.run(&["window", "--seq", &seq]);
    assert_eq!((rc, out.as_str()), (3, ""));
    assert_eq!(f.window(), WindowState::Absent);
}

#[test]
fn lock_during_a_fetch_discards_its_result() {
    let f = one_password();
    let generation = {
        let _l = lock(&f.env).expect("lock");
        counter(&f.env, "gen").expect("gen")
    };
    let payload = fetch(&f.env).expect("fetch");
    f.run(&["lock"]); // identity lock while the fetch was out
    assert_eq!(
        publish_if_current(&f.env, &payload, generation).expect("publish"),
        "superseded"
    );
    assert!(!f.has_cache());
}

#[test]
fn a_live_windows_cache_is_never_replaced() {
    let f = one_password();
    f.on();
    let before = f.keyring.0.borrow().payload.clone();
    let fresh = fetch(&f.env).expect("fetch");
    let generation = counter(&f.env, "gen").expect("gen");
    assert_eq!(
        publish_if_current(&f.env, &fresh, generation).expect("publish"),
        "window-open"
    );
    assert_eq!(f.keyring.0.borrow().payload, before);
}

#[test]
fn a_self_signed_window_stays_self_signed_when_the_cache_fills() {
    let f = one_password();
    f.op_fail(Some("dismissed"));
    let (_, _, win) = f.on();
    assert_eq!(win["source"], "self-signed");
    f.op_fail(None);
    // `identity unlock` during the window fills the cache for later windows.
    fill_cache(&f.env).expect("fill");
    assert!(f.has_cache());
    assert_eq!(f.window(), WindowState::Parsed(Window::SelfSigned));
    f.off();
    let (_, _, win) = f.on();
    assert_eq!(win["source"], "1password");
}

#[test]
fn unlock_fetches_once_then_does_nothing_while_the_cache_is_filled() {
    let f = one_password();
    let (rc, _, err) = f.run(&["unlock"]);
    assert_eq!(
        (rc, err.as_str()),
        (0, "Fetched the AirDrop identity from 1Password.\n")
    );
    let calls = f.op_calls().len();
    let (rc, _, err) = f.run(&["unlock"]);
    assert_eq!(
        (rc, err.as_str()),
        (0, "The identity cache is already filled.\n")
    );
    assert_eq!(f.op_calls().len(), calls);
}

#[test]
fn unlock_reports_why_it_could_not_fetch() {
    let f = one_password();
    f.op_fail(Some("authorization prompt dismissed"));
    let (rc, _, err) = f.run(&["unlock"]);
    assert_eq!(rc, 1);
    assert_eq!(
        err,
        "Could not fetch: 1Password prompt dismissed (authorization prompt dismissed)\n"
    );
    f.settings(&[("identity_source", "disk")]);
    let (rc, _, err) = f.run(&["unlock"]);
    assert_eq!(rc, 1);
    assert_eq!(
        err,
        "Omdrop is not set to use 1Password (identity_source is not 1password).\n"
    );
}

#[test]
fn identity_commands_refuse_during_a_window() {
    let f = one_password();
    f.on();
    for argv in [
        &["lock"][..],
        &["1password-off"],
        &["use", "item1"],
        &["import"],
    ] {
        let (rc, _, err) = f.run(argv);
        assert_eq!(rc, 1, "{argv:?}");
        assert!(err.contains("Turn Omdrop off first"), "{argv:?}: {err}");
    }
}

#[test]
fn lock_clears_the_cache() {
    let f = one_password();
    f.on();
    f.off();
    let (rc, _, err) = f.run(&["lock"]);
    assert_eq!((rc, err.as_str()), (0, "Cleared the identity cache.\n"));
    assert!(!f.has_cache());
    let (rc, _, err) = f.run(&["lock"]);
    assert_eq!(
        (rc, err.as_str()),
        (0, "The identity cache was already empty.\n")
    );
}

#[test]
fn an_expired_period_is_cleared_when_the_window_closes() {
    let f = one_password();
    f.on();
    let p = f.payload().expect("cached");
    f.clock.set(Some(p.period_ends + 1));
    f.off();
    assert!(!f.has_cache());
}

#[test]
fn using_another_item_clears_the_old_items_cache() {
    let f = one_password();
    f.on();
    f.off();
    assert!(f.has_cache());
    let (rc, _, err) = f.run(&["use", "item1"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(
        err,
        "Omdrop now uses that 1Password item. The next `omdrop on` fetches it.\n"
    );
    assert!(!f.has_cache());
    let s = f.read_settings();
    assert_eq!(
        (
            s["identity_source"].as_str(),
            s["identity_op_account"].as_str(),
            s["identity_op_vault"].as_str()
        ),
        ("1password", "acct1", "vault1")
    );
}

#[test]
fn a_window_opened_while_use_is_out_prevents_its_commit() {
    let mut f = one_password();
    f.env.hook = Some(Box::new(|env: &Env, point: &str, _: &[&str]| {
        if point == "op_read_files" {
            // What `omdrop on` leaves while `use` talks to 1Password.
            write_private(&env.user.window, b"source=self-signed\n")?;
        }
        Ok(())
    }));
    let (rc, _, err) = f.run(&["use", "item1"]);
    assert_eq!(rc, 1);
    assert_eq!(err, "Turn Omdrop off first.\n");
}

#[test]
fn use_is_refused_when_the_old_cache_cannot_be_cleared() {
    let f = one_password();
    f.on();
    f.off();
    let before = fs::read_to_string(f.config.join("omdrop/settings")).expect("settings");
    let cached = f.keyring.0.borrow().payload.clone();
    f.keyring.0.borrow_mut().fail_revoke = true;
    let (rc, _, err) = f.run(&["use", "item1"]);
    assert_eq!(rc, 1);
    assert_eq!(
        err,
        "Could not clear the cached identity (revoking: Permission denied); nothing changed.\n"
    );
    assert_eq!(
        fs::read_to_string(f.config.join("omdrop/settings")).expect("settings"),
        before
    );
    assert_eq!(f.keyring.0.borrow().payload, cached);
}

#[test]
fn a_lock_while_use_is_out_prevents_its_commit() {
    let mut f = one_password();
    f.settings(&[("identity_source", "self-signed")]);
    f.env.hook = Some(Box::new(|env: &Env, point: &str, _: &[&str]| {
        if point == "op_read_files" {
            let (mut o, mut e) = (Vec::new(), Vec::new());
            run(env, &Cmd::Lock, &mut o, &mut e);
        }
        Ok(())
    }));
    let (rc, _, err) = f.run(&["use", "item1"]);
    assert_eq!(rc, 1);
    assert!(err.contains("changed meanwhile"), "{err}");
    assert_eq!(f.read_settings()["identity_source"], "self-signed");
}

#[test]
fn use_reports_an_op_failure_in_full() {
    let f = one_password();
    f.op_fail(Some("\"nope\" isn't an item"));
    let (rc, _, err) = f.run(&["use", "nope", "--vault", "V"]);
    assert_eq!(rc, 1);
    assert_eq!(
        err,
        "The 1Password item is missing or incomplete (\"nope\" isn't an item)\n"
    );
    assert_eq!(f.op_calls(), ["item get nope --vault V --format json"]);
}

#[test]
fn onepassword_off_switches_to_self_signed_and_clears_the_cache() {
    let f = one_password();
    f.on();
    f.off();
    let (rc, _, err) = f.run(&["1password-off"]);
    assert_eq!(
        (rc, err.as_str()),
        (
            0,
            "Omdrop no longer uses 1Password; the item in 1Password is kept.\n"
        )
    );
    assert!(!f.has_cache());
    let s = f.read_settings();
    assert_eq!(
        (
            s["identity_source"].as_str(),
            s["identity_op_item"].as_str()
        ),
        ("self-signed", "item1")
    );
}

// ------------------------------------------------------------------ import

fn importing() -> Fixture {
    let f = Fixture::new();
    f.apple_on_disk();
    f
}

#[test]
fn import_moves_the_identity_and_deletes_the_files_last() {
    let f = importing();
    let (rc, out, err) = f.run(&["import"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(out, "");
    assert_eq!(
        err,
        "Your Apple identity is now in 1Password, and the copies on disk were deleted. The next `omdrop on` fetches it.\n"
    );
    let s = f.read_settings();
    assert_eq!(
        (
            s["identity_source"].as_str(),
            s["identity_op_account"].as_str(),
            s["identity_op_vault"].as_str(),
            s["identity_op_item"].as_str()
        ),
        ("1password", "acct1", "vault1", "item1")
    );
    assert!(f.files_on_disk().is_empty());
    let keys = f.keys.display();
    assert_eq!(
        f.op_calls()[0],
        format!(
            "item create --category Secure Note --title Omdrop AirDrop identity certificate[file]={keys}/certificate.pem key[file]={keys}/key.pem validation_record[file]={keys}/validation_record.cms --format json"
        )
    );
}

#[test]
fn a_readback_that_differs_deletes_nothing() {
    let f = importing();
    fs::write(f.opdir.join("corrupt"), "key").expect("corrupt");
    let (rc, _, err) = f.run(&["import"]);
    assert_eq!(rc, 1);
    assert_eq!(
        err,
        "The 1Password item item1 does not match the files; nothing was deleted.\n"
    );
    assert_eq!(f.files_on_disk().len(), 3);
}

#[test]
fn an_identity_that_fails_its_checks_is_not_imported() {
    let f = importing();
    *f.problem.borrow_mut() = Some("certificate is not issued by Apple".into());
    let (rc, _, err) = f.run(&["import"]);
    assert_eq!(
        (rc, err.as_str()),
        (1, "Not importing: certificate is not issued by Apple.\n")
    );
    assert!(f.op_calls().is_empty());
}

#[test]
fn nothing_to_import_names_what_is_missing() {
    let f = Fixture::new();
    fs::write(f.keys.join("key.pem"), b"k").expect("write");
    let (rc, _, err) = f.run(&["import"]);
    assert_eq!(rc, 1);
    assert_eq!(
        err,
        format!(
            "Nothing to import: certificate.pem, validation_record.cms missing from {}\n",
            f.keys.display()
        )
    );
}

#[test]
fn a_crash_before_the_mode_is_saved_is_finished_by_a_rerun() {
    let mut f = importing();
    f.env.hook = Some(Box::new(|_: &Env, point: &str, keys: &[&str]| {
        if point == "setting_set" && keys.contains(&"identity_source") {
            return Err(io::Error::other("disk full"));
        }
        Ok(())
    }));
    let (rc, _, err) = f.run(&["import"]);
    assert_eq!(rc, 1);
    assert_eq!(
        err,
        "Could not save the settings (disk full); nothing was deleted. Run the import again to finish.\n"
    );
    // The item's IDs are already saved, so the rerun reuses it.
    let s = f.read_settings();
    assert_eq!(s.get("identity_op_item").map(String::as_str), Some("item1"));
    assert_ne!(
        s.get("identity_source").map(String::as_str),
        Some("1password")
    );
    assert!(f.keys.join("key.pem").exists());
    let creates = f
        .op_calls()
        .iter()
        .filter(|c| c.contains("item create"))
        .count();
    f.env.hook = None;
    let (rc, _, err) = f.run(&["import"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(
        f.op_calls()
            .iter()
            .filter(|c| c.contains("item create"))
            .count(),
        creates
    );
    assert!(!f.keys.join("key.pem").exists());
}

#[test]
fn a_superseded_import_does_not_record_its_item() {
    let mut f = importing();
    // Another identity command runs while import is creating its item.
    f.env.hook = Some(Box::new(|env: &Env, point: &str, _: &[&str]| {
        if point == "account_id" {
            {
                let _l = lock(env)?;
                bump(env, "gen")?;
            }
            setting_set(env, &[("identity_op_item", "chosen-elsewhere")])?;
        }
        Ok(())
    }));
    let (rc, _, err) = f.run(&["import"]);
    assert_eq!(rc, 1);
    assert_eq!(
        err,
        "Cancelled: the identity settings changed meanwhile. The new 1Password item is item1; nothing was deleted.\n"
    );
    assert_eq!(f.read_settings()["identity_op_item"], "chosen-elsewhere");
    assert!(f.keys.join("key.pem").exists());
}

#[test]
fn a_window_opened_during_import_keeps_every_file() {
    let mut f = importing();
    f.env.hook = Some(Box::new(|env: &Env, point: &str, _: &[&str]| {
        if point == "op_read_files" {
            write_private(&env.user.window, b"source=disk\n")?;
        }
        Ok(())
    }));
    let (rc, _, err) = f.run(&["import"]);
    assert_eq!(rc, 1);
    assert_eq!(err, "Turn Omdrop off first. Nothing was deleted.\n");
    assert_eq!(f.files_on_disk().len(), 3);
    assert_ne!(
        f.read_settings().get("identity_source").map(String::as_str),
        Some("1password")
    );
}

#[test]
fn leftovers_after_an_interrupted_delete_are_removed_by_a_rerun() {
    let f = importing();
    assert_eq!(f.run(&["import"]).0, 0);
    fs::write(f.keys.join("certificate.pem"), &f.apple[0]).expect("write");
    let (rc, _, err) = f.run(&["import"]);
    assert_eq!(rc, 0, "{err}");
    assert!(!f.keys.join("certificate.pem").exists());
    // A leftover that differs from the item is never deleted.
    fs::write(f.keys.join("certificate.pem"), b"different").expect("write");
    let (rc, _, err) = f.run(&["import"]);
    assert_eq!(rc, 1);
    assert_eq!(
        err,
        "certificate.pem on disk differs from the 1Password item; nothing was deleted.\n"
    );
    assert!(f.keys.join("certificate.pem").exists());
}

// ------------------------------------------------------------------ window sources

#[test]
fn disk_mode_with_an_apple_identity() {
    let f = Fixture::new();
    f.apple_on_disk();
    let (_, _, win) = f.on();
    assert_eq!(win["source"], "disk");
    assert_eq!(f.window(), WindowState::Parsed(Window::Disk));
}

#[test]
fn disk_mode_with_a_failing_apple_identity_falls_back_and_says_why() {
    let f = Fixture::new();
    f.apple_on_disk();
    *f.problem.borrow_mut() = Some("validation record has expired".into());
    let (rc, out, _) = f.run(&["begin", "--name", "Test"]);
    assert_eq!(rc, 0);
    let seq = parse_settings(&out)["seq"].clone();
    let (rc, out, err) = f.run(&["window", "--seq", &seq]);
    assert_eq!(rc, 0);
    assert_eq!(
        out,
        "notice=Apple identity unusable; using self-signed certificates. Peers must be in \"Everyone\" mode.\nsource=self-signed\n"
    );
    assert_eq!(
        err,
        "omdrop: the Apple identity on disk is unusable: validation record has expired\n"
    );
}

#[test]
fn self_signed_mode_never_uses_the_disk_identity() {
    let f = Fixture::new();
    f.apple_on_disk();
    f.settings(&[("identity_source", "self-signed")]);
    let (_, _, win) = f.on();
    assert_eq!(win["source"], "self-signed");
}

#[test]
fn a_repeated_on_keeps_the_windows_identity() {
    let f = Fixture::new();
    let (_, _, win) = f.on();
    assert_eq!(win["source"], "self-signed");
    f.apple_on_disk();
    let (_, _, again) = f.on();
    assert_eq!(again["source"], "self-signed");
}

#[test]
fn begin_and_window_print_exactly_their_key_value_lines() {
    let f = one_password();
    let (rc, out, err) = f.run(&["begin", "--name", "Test"]);
    assert_eq!((rc, out.as_str(), err.as_str()), (0, "seq=0\n", ""));
    let (rc, out, _) = f.run(&["window", "--seq", "0"]);
    let p = f.payload().expect("cached");
    let expiry = p.hard_expiry - crate::resolver::now();
    assert_eq!(rc, 0);
    // expiry_in may tick by one second between the two clocks.
    assert!(
        out == format!("source=1password\nexpiry_in={expiry}\n")
            || out == format!("source=1password\nexpiry_in={}\n", expiry + 1),
        "{out}"
    );
    // A repeated `on` keeps the window's choice and says so.
    let (rc, out, _) = f.run(&["window", "--seq", "0"]);
    assert_eq!(rc, 0);
    assert!(out.starts_with("source=1password\nexpiry_in="), "{out}");
    f.run(&["stop-begin"]);
    assert_eq!(f.run(&["window", "--seq", "0"]).0, 3);
    let (rc, out, _) = f.run(&["begin", "--name", "Test"]);
    assert_eq!((rc, out.as_str()), (0, "seq=1\n"));
}

// ------------------------------------------------------------------ status, ensure-self-signed

#[test]
fn status_json_matches_pythons_json_dumps() {
    let f = one_password();
    let (rc, out, _) = f.run(&["status", "--json"]);
    assert_eq!(rc, 0);
    assert_eq!(
        out,
        "{\"apple_files_on_disk\": [], \"cache\": null, \"cache_hours\": 12, \"mode\": \"1password\", \"onepassword_configured\": true, \"op_installed\": true, \"self_signed\": false, \"window\": null}\n"
    );
    f.on();
    let p = f.payload().expect("cached");
    let (_, out, _) = f.run(&["status", "--json"]);
    assert_eq!(
        out,
        format!(
            "{{\"apple_files_on_disk\": [], \"cache\": {{\"hard_expiry\": {}, \"period_ends\": {}}}, \"cache_hours\": 12, \"mode\": \"1password\", \"onepassword_configured\": true, \"op_installed\": true, \"self_signed\": true, \"window\": \"1password\"}}\n",
            p.hard_expiry, p.period_ends
        )
    );
    f.settings(&[("identity_source", "ünï\"c\u{1F600}")]);
    fs::write(&f.env.user.window, "garbage\n").expect("write");
    let (_, out, _) = f.run(&["status", "--json"]);
    assert!(
        out.contains("\"mode\": \"\\u00fcn\\u00ef\\\"c\\ud83d\\ude00\""),
        "{out}"
    );
    assert!(out.contains("\"window\": \"unparseable\""), "{out}");
}

#[test]
fn status_text_describes_each_mode() {
    let f = Fixture::new();
    let (rc, out, _) = f.run(&["status"]);
    assert_eq!(rc, 0);
    assert_eq!(
        out,
        "Identity source: disk\nSelf-signed identity: not yet created\n"
    );
    f.apple_on_disk();
    f.run(&["ensure-self-signed", "--name", "X"]);
    let (_, out, _) = f.run(&["status"]);
    assert_eq!(
        out,
        "Identity source: disk\nApple identity on disk.\nSelf-signed identity: present\n"
    );
    fs::remove_file(f.keys.join("validation_record.cms")).expect("rm");
    let (_, out, _) = f.run(&["status"]);
    assert_eq!(
        out,
        "Identity source: disk\nIdentity on disk.\nSelf-signed identity: present\n"
    );

    let g = one_password();
    let (_, out, _) = g.run(&["status"]);
    assert_eq!(
        out,
        "Identity source: 1password\nNothing cached; the next `omdrop on` asks 1Password.\nSelf-signed identity: not yet created\n"
    );
    g.apple_on_disk();
    g.on();
    let p = g.payload().expect("cached");
    let (_, out, _) = g.run(&["status"]);
    assert_eq!(
        out,
        format!(
            "Identity source: 1password\nThis window uses: 1password\nCached from 1Password until {}\nApple identity files are still on disk: certificate.pem, key.pem, validation_record.cms (run: omdrop identity 1password import)\nSelf-signed identity: present\n",
            crate::sys::strftime_local("%Y-%m-%d %H:%M %Z", p.period_ends)
        )
    );
}

#[test]
fn ensure_self_signed_reports_creation_and_the_rename() {
    let f = Fixture::new();
    let (rc, out, err) = f.run(&["ensure-self-signed", "--name", "Mac"]);
    assert_eq!(
        (rc, out.as_str(), err.as_str()),
        (0, "renamed=nothing-to-rename\n", "")
    );
    let (rc, out, _) = f.run(&["ensure-self-signed", "--name", "Mac"]);
    assert_eq!((rc, out.as_str()), (1, "renamed=nothing-to-rename\n"));
    // A half pair: the error alone, exit 2.
    fs::remove_file(f.keys.join(selfsigned::CERT)).expect("rm");
    let (rc, out, err) = f.run(&["ensure-self-signed", "--name", "Mac"]);
    assert_eq!(
        (rc, out.as_str(), err.as_str()),
        (2, "", "self-signed-half-pair\n")
    );
    let (rc, out, err) = f.run(&["begin", "--name", "Mac"]);
    assert_eq!(
        (rc, out.as_str(), err.as_str()),
        (
            1,
            "",
            "omdrop: the self-signed identity is unusable: self-signed-half-pair\n"
        )
    );
}

#[test]
fn a_legacy_self_signed_pair_is_renamed_by_ensure_self_signed() {
    let f = Fixture::new();
    let (cert, key) = make_pair(&f.keys, "Legacy", &["-newkey", "rsa:2048"]);
    fs::rename(f.keys.join("c.pem"), f.keys.join("certificate.pem")).expect("mv");
    fs::rename(f.keys.join("k.pem"), f.keys.join("key.pem")).expect("mv");
    // ensure-self-signed creates a fresh pair first, so the legacy one finds
    // its destination taken: never replaced.
    let (rc, out, _) = f.run(&["ensure-self-signed", "--name", "Mac"]);
    assert_eq!((rc, out.as_str()), (0, "renamed=destination-exists\n"));
    assert_eq!(
        fs::read(f.keys.join("certificate.pem")).expect("cert"),
        cert
    );
    assert_eq!(fs::read(f.keys.join("key.pem")).expect("key"), key);
}

#[test]
fn the_real_apple_check_names_what_fails_first() {
    let f = Fixture::new();
    let [cert, key, record] = &f.apple;
    assert_eq!(check_apple(b"", key, record).as_deref(), Some("incomplete"));
    let dir = f.tmp.path().join("other");
    fs::create_dir(&dir).expect("mkdir");
    let (_, other_key) = make_pair(&dir, "x", &["-newkey", "rsa:2048"]);
    assert_eq!(
        check_apple(cert, &other_key, record).as_deref(),
        Some("key does not match certificate")
    );
    // Apple's name in a self-signed certificate is not Apple.
    assert_eq!(
        check_apple(cert, key, record).as_deref(),
        Some("certificate is not issued by Apple")
    );
}

#[test]
fn usage_errors_and_help_never_reach_the_users_files() {
    // cli::run would act on the real user for a valid command; these exit in
    // argument parsing, before any state is read.
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(crate::cli::run(&["bogus".into()], &mut out, &mut err), 2);
    assert!(out.is_empty());
    assert!(String::from_utf8_lossy(&err).contains("invalid choice: 'bogus'"));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(
        crate::cli::run(&["status".into(), "-h".into()], &mut out, &mut err),
        0
    );
    assert_eq!(
        String::from_utf8_lossy(&out),
        "usage: identity.py status [-h] [--json]\n\noptions:\n  -h, --help  show this help message and exit\n  --json\n"
    );
}
