//! The plugin tests that sliced functions out of the bash and ran them in a
//! harness (test_window_arming, test_start_cleanup, test_off_during_send,
//! test_once_shutdown) cannot run against a binary. These are the same
//! checks against `omdrop` itself, with systemd, pkexec, the radio helper
//! and the identity commands stubbed on PATH. Nothing here touches the real
//! session: HOME, XDG_* and the runtime directory are temporary, and every
//! program that could reach the desktop is a stub that only logs.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    capture: PathBuf,
    helper: PathBuf,
    omdrop: PathBuf,
}

const TEMPLATE: &str = "[Service]\nWorkingDirectory=@PLUGIN_DIR@\nExecStart=/usr/bin/python3 @PLUGIN_DIR@/bin/airdrop-serve.py --iface awdl0 --port 8771\n";

/// Stands in for identity.py under OMDROP_IMPLEMENTATION=python, as the bash harness's
/// `id_py` did: `window` answers with $IDENTITY.
const FAKE_IDENTITY: &str = r#"import os, sys
cmd = sys.argv[1]
if cmd == "begin":
    print("seq=0")
elif cmd == "window":
    print(os.environ.get("IDENTITY", "source=self-signed"))
elif cmd.startswith("stop-"):
    with open(os.environ["CAPTURE"], "a") as f:
        f.write(f"identity {cmd}\n")
elif cmd == "ensure-self-signed":
    sys.exit(1)
"#;

fn write_exec(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let bin = root.join("bin");
        let plugin = root.join("plugins/netmojo.omdrop");
        for d in [
            bin.clone(),
            plugin.join("bin"),
            plugin.join("share"),
            plugin.join("skills/omdrop"),
            root.join("home"),
            root.join("run"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(plugin.join("manifest.json"), r#"{"version": "9.9.9"}"#).unwrap();
        std::fs::write(plugin.join("share/airdrop-receiver.service"), TEMPLATE).unwrap();
        std::fs::write(plugin.join("bin/airdrop-serve.py"), "").unwrap();
        std::fs::write(plugin.join("bin/identity.py"), FAKE_IDENTITY).unwrap();
        std::fs::write(plugin.join("skills/omdrop/SKILL.md"), "skill\n").unwrap();
        let omdrop = plugin.join("bin/omdrop");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_omdrop"), &omdrop).unwrap();

        let log = r#"printf '%s\n' "$(basename "$0") $*" >> "$CAPTURE""#;
        write_exec(
            &bin.join("systemctl"),
            &format!(
                "#!/bin/sh\n{log}\ncase \"$*\" in\n  *\" is-active \"*) echo \"${{ACTIVE:-inactive}}\"; [ \"$ACTIVE\" = active ] ;;\n  *\" start \"*) exit \"${{START_RC:-0}}\" ;;\n  *) exit 0 ;;\nesac\n"
            ),
        );
        write_exec(
            &bin.join("systemd-run"),
            &format!(
                "#!/bin/sh\n{log}\ncase \"$*\" in *omdrop-identity-expiry*) exit \"${{ARM_RC:-0}}\" ;; esac\nexit 0\n"
            ),
        );
        write_exec(
            &bin.join("pkexec"),
            &format!(
                "#!/bin/sh\n{log}\nprintf 'pkexec-ulimit %s\\n' \"$(ulimit -Hc)\" >> \"$CAPTURE\"\n[ \"$1\" = --disable-internal-agent ] && exit 1\n[ \"$2\" = start ] || exit 0\n[ -n \"$RADIO_SLEEP\" ] && sleep \"$RADIO_SLEEP\"\n[ \"${{RADIO_RC:-0}}\" = 0 ] && exit 0\necho '12:00:08Z supervisor did not start' >&2\nexit \"$RADIO_RC\"\n"
            ),
        );
        write_exec(
            &bin.join("ip"),
            "#!/bin/sh\n[ -n \"$LINK_LOCAL\" ] && echo '    inet6 fe80::1/64 scope link'\nexit 0\n",
        );
        write_exec(
            &bin.join("journalctl"),
            "#!/bin/sh\nprintf '%s\\n' \"$JOURNAL\"\n",
        );
        for quiet in [
            "uwsm-app",
            "wl-copy",
            "omarchy-notification-send",
            "update-desktop-database",
            "update-mime-database",
            "xdg-mime",
        ] {
            write_exec(&bin.join(quiet), &format!("#!/bin/sh\n{log}\n"));
        }
        let helper = root.join("omdrop-discoverable");
        write_exec(
            &helper,
            "#!/bin/sh\nif [ -n \"$VISIBLE\" ]; then echo '{\"visible\":true}'; else echo '{\"visible\":false}'; fi\n",
        );
        // send-to-peer: its help, one peer, and a send that says it is asking.
        // HOLD_STDERR leaves a process of another session holding its stderr.
        write_exec(
            &root.join("sender"),
            "#!/bin/sh\ncase \"$1\" in\n  --help) echo '  [file ...] --url --names --stream'; exit 0 ;;\n  --list) echo 'e2:9d:03:6c:58:23   -47 dBm  [fe80::1%awdl0]:8770  Studio Mac'; exit 0 ;;\nesac\nprintf 'sender-helper %s\\n' \"$OMDROP_DISCOVERABLE\" >> \"$CAPTURE\"\necho '+0.41s FOUND x at y; asking'\n[ -n \"$HOLD_STDERR\" ] && (setsid sleep 8 >/dev/null &)\nexit 0\n",
        );
        let capture = root.join("events");
        std::fs::write(&capture, "").unwrap();
        Self {
            _tmp: tmp,
            root,
            capture,
            helper,
            omdrop,
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.omdrop);
        cmd.args(args)
            .env_clear()
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.root.join("bin").display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("home/.config"))
            .env("XDG_DATA_HOME", self.root.join("home/.local/share"))
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env("OMDROP_DISCOVERABLE", &self.helper)
            .env("OMDROP_SENDER", self.root.join("no-sender"))
            .env("OMDROP_IMPLEMENTATION", "python")
            .env("CAPTURE", &self.capture);
        cmd
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> (Output, String) {
        let mut cmd = self.command(args);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        let events = std::fs::read_to_string(&self.capture).unwrap();
        (out, events)
    }
}

fn first(events: &str, needle: &str) -> usize {
    events
        .find(needle)
        .unwrap_or_else(|| panic!("{needle:?} not in:\n{events}"))
}

fn last(events: &str, needle: &str) -> usize {
    events
        .rfind(needle)
        .unwrap_or_else(|| panic!("{needle:?} not in:\n{events}"))
}

#[test]
fn an_unknown_implementation_is_refused_before_anything_runs() {
    let f = Fixture::new();
    let (out, ev) = f.run(&["on", "10m"], &[("OMDROP_IMPLEMENTATION", "pyhton")]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "omdrop: OMDROP_IMPLEMENTATION must be python or rust, not \"pyhton\"\n"
    );
    assert!(!ev.contains("pkexec"), "{ev}");
}

#[test]
fn the_window_is_named_before_the_radio_comes_up() {
    let f = Fixture::new();
    let (out, ev) = f.run(&["on", "10m"], &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        first(&ev, "watch --window 10m") < first(&ev, "pkexec"),
        "{ev}"
    );
}

#[test]
fn the_clock_starts_only_once_receiving_works() {
    let f = Fixture::new();
    let (_, ev) = f.run(&["on", "10m"], &[]);
    let armed = first(&ev, "on-active=10m");
    assert!(armed > first(&ev, "pkexec"), "{ev}");
    assert!(
        armed > first(&ev, "--user start airdrop-receiver.service"),
        "{ev}"
    );
}

#[test]
fn the_radio_is_asked_for_the_window_again_from_that_moment() {
    let f = Fixture::new();
    let (_, ev) = f.run(&["on", "10m"], &[]);
    assert_eq!(
        ev.lines().filter(|l| l.contains("start 600")).count(),
        2,
        "{ev}"
    );
    assert!(last(&ev, "start 600") > first(&ev, "on-active=10m"), "{ev}");
}

#[test]
fn a_one_file_window_declares_itself_before_the_radio() {
    let f = Fixture::new();
    let (_, ev) = f.run(&["on", "once"], &[]);
    assert!(first(&ev, "watch --once") < first(&ev, "pkexec"), "{ev}");
    assert!(!ev.contains("on-active"), "{ev}");
}

#[test]
fn an_unbounded_window_arms_no_timer_and_names_no_span() {
    let f = Fixture::new();
    let (_, ev) = f.run(&["on", "forever"], &[]);
    assert!(!ev.contains("on-active"), "{ev}");
    assert!(ev.contains(" watch"), "{ev}");
    assert!(!ev.contains("--once") && !ev.contains("--window"), "{ev}");
}

#[test]
fn a_radio_that_will_not_start_leaves_no_window_behind() {
    let f = Fixture::new();
    let (out, ev) = f.run(&["on", "10m"], &[("RADIO_RC", "1")]);
    assert_eq!(out.status.code(), Some(1), "{ev}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "supervisor did not start"
    );
    assert_eq!(ev.matches("stop omdrop-window.timer").count(), 2, "{ev}");
    assert!(ev.contains("identity stop-end"), "{ev}");
    assert!(!ev.contains("on-active"), "{ev}");
}

#[test]
fn a_1password_window_arms_its_hard_expiry_before_anything_starts() {
    let f = Fixture::new();
    let (_, ev) = f.run(
        &["on", "10m"],
        &[("IDENTITY", "source=1password\nexpiry_in=3600")],
    );
    assert!(
        ev.contains("--on-active=3600s --unit=omdrop-identity-expiry"),
        "{ev}"
    );
    assert!(
        first(&ev, "omdrop-identity-expiry") < first(&ev, "pkexec"),
        "{ev}"
    );
}

#[test]
fn a_window_whose_hard_expiry_cannot_be_armed_never_starts() {
    let f = Fixture::new();
    let (out, ev) = f.run(
        &["on", "10m"],
        &[
            ("IDENTITY", "source=1password\nexpiry_in=3600"),
            ("ARM_RC", "1"),
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(ev.contains("identity stop-end"), "{ev}");
    assert!(!ev.contains("pkexec"), "{ev}");
    assert!(!ev.contains("--user start"), "{ev}");
}

#[test]
fn a_window_turned_off_while_starting_exits_quietly() {
    let f = Fixture::new();
    // identity.py's `window` exits 3 when an `off` ran during the fetch.
    let plugin = f.root.join("plugins/netmojo.omdrop/bin/identity.py");
    let body = FAKE_IDENTITY.replace(
        "print(os.environ.get(\"IDENTITY\", \"source=self-signed\"))",
        "sys.exit(3)",
    );
    std::fs::write(plugin, body).unwrap();
    let (out, ev) = f.run(&["on"], &[]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "Omdrop was turned off while it was starting.\n"
    );
    assert!(!ev.contains("pkexec"), "{ev}");
}

#[test]
fn receiver_first_failure_stops_a_partially_started_radio() {
    let f = Fixture::new();
    let (out, ev) = f.run(&["on", "10m"], &[("LINK_LOCAL", "1"), ("RADIO_RC", "1")]);
    assert_eq!(out.status.code(), Some(1));
    let stop = format!("pkexec {} stop", f.helper.display());
    assert!(
        first(&ev, "--user start airdrop-receiver.service") < first(&ev, &stop),
        "{ev}"
    );
    assert!(ev.contains("--user stop airdrop-receiver.service"), "{ev}");
}

#[test]
fn off_refuses_while_a_send_is_running_and_force_overrides() {
    let f = Fixture::new();
    let sends = f.root.join("run/omdrop/sends");
    std::fs::create_dir_all(&sends).unwrap();
    let mut live = Command::new("sleep").arg("30").spawn().unwrap();
    std::fs::write(sends.join(live.id().to_string()), "hume\n").unwrap();

    let (out, ev) = f.run(&["off"], &[]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0));
    assert!(
        err.contains("Still sending to hume") && err.contains("omdrop off --force"),
        "{err}"
    );
    assert!(!ev.contains(" stop "), "{ev}");

    let (out, ev) = f.run(&["off", "--force"], &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        ev.contains("systemctl --user stop airdrop-receiver.service"),
        "{ev}"
    );
    assert!(
        first(&ev, "identity stop-begin") < first(&ev, "--user stop airdrop-receiver.service"),
        "{ev}"
    );
    assert!(
        first(&ev, "--user stop airdrop-receiver.service") < first(&ev, "identity stop-end"),
        "{ev}"
    );
    live.kill().unwrap();
    live.wait().unwrap();
}

fn arrival(f: &Fixture, name: &str) -> PathBuf {
    let downloads = f.root.join("home/Downloads");
    std::fs::create_dir_all(&downloads).unwrap();
    let file = downloads.join(name);
    std::fs::write(&file, "x").unwrap();
    file
}

const TS: &str = "2026-10-10 16:14:20,098 INFO root: ";

#[test]
fn a_one_file_window_closes_in_a_unit_of_its_own() {
    let f = Fixture::new();
    arrival(&f, "arrived.jpg");
    let journal = format!("{TS}upload ABC: stored arrived.jpg");
    let (out, ev) = f.run(&["watch", "--once"], &[("JOURNAL", &journal)]);
    assert!(out.status.success());
    assert!(
        ev.lines()
            .any(|l| l.starts_with("systemd-run --user --quiet --collect ")
                && l.ends_with(" off --force")),
        "{ev}"
    );

    let f = Fixture::new();
    let file = arrival(&f, "arrived.jpg");
    let journal = format!("{TS}upload ABC: stored arrived.jpg");
    let (out, ev) = f.run(&["watch", "--window", "10m"], &[("JOURNAL", &journal)]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains(&format!("omdrop watch: announcing {}", file.display()))
    );
    assert!(!ev.lines().any(|l| l.ends_with(" off --force")), "{ev}");
}

#[test]
fn a_forged_record_naming_a_file_outside_the_download_folder_is_ignored() {
    let f = Fixture::new();
    arrival(&f, "unrelated.jpg");
    let secret = f.root.join("secret.png");
    std::fs::write(&secret, "x").unwrap();
    // Neither the receiver's own format, nor a name inside the folder: no
    // announcement, and a one-file window stays open.
    let journal = format!(
        "upload X: stored {s}\n{TS}upload X: stored {s}\n{TS}GET from Mac upload X: stored unrelated.jpg",
        s = secret.display()
    );
    let (out, ev) = f.run(&["watch", "--once"], &[("JOURNAL", &journal)]);
    assert!(out.status.success());
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("announcing"),
        "{ev}"
    );
    assert!(!ev.lines().any(|l| l.ends_with(" off --force")), "{ev}");
    assert!(!ev.contains("secret.png"), "{ev}");
}

#[test]
fn version_names_the_plugin_and_this_program() {
    let f = Fixture::new();
    let (out, _) = f.run(&["version"], &[]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("omdrop 9.9.9\nomdrop-core {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(out.stderr.is_empty());
}

fn spawn_with(f: &Fixture, args: &[&str], env: &[(&str, &str)]) -> std::process::Child {
    let mut cmd = f.command(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
}

fn signal(child: &std::process::Child, sig: i32) {
    let pid = i32::try_from(child.id()).unwrap();
    // SAFETY (test): signalling our own child.
    assert_eq!(unsafe { libc_kill(pid, sig) }, 0);
}

unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

/// Waits at most `limit` for the child; panics if it is still running.
fn finish_within(child: std::process::Child, limit: std::time::Duration) -> Output {
    let start = std::time::Instant::now();
    let mut child = child;
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > limit {
            let _ = child.kill();
            panic!("still running after {limit:?}");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn a_send_cancelled_while_its_stderr_is_held_elsewhere_still_ends() {
    let f = Fixture::new();
    let file = f.root.join("photo.jpg");
    std::fs::write(&file, "x").unwrap();
    let sender = f.root.join("sender");
    let child = spawn_with(
        &f,
        &["send", "--to", "e2:9d:03:6c:58:23", file.to_str().unwrap()],
        &[
            ("OMDROP_SENDER", sender.to_str().unwrap()),
            ("LINK_LOCAL", "1"),
            ("VISIBLE", "1"),
            ("HOLD_STDERR", "1"),
        ],
    );
    std::thread::sleep(std::time::Duration::from_millis(1500));
    signal(&child, 2);
    let out = finish_within(child, std::time::Duration::from_secs(3));
    assert_eq!(
        out.status.code(),
        Some(130),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("Cancelled."));
    // The sender was told which root helper `on` uses.
    let ev = std::fs::read_to_string(&f.capture).unwrap();
    assert!(
        ev.contains(&format!("sender-helper {}", f.helper.display())),
        "{ev}"
    );
    assert!(
        std::fs::read_dir(f.root.join("run/omdrop/sends"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn the_identity_step_leaves_the_root_helper_its_core_dumps() {
    let f = Fixture::new();
    let expected = Command::new("sh")
        .args(["-c", "ulimit -Hc"])
        .output()
        .unwrap();
    let expected = String::from_utf8_lossy(&expected.stdout).trim().to_string();
    // The real identity code, not identity.py.
    let (out, ev) = f.run(&["on", "once"], &[("OMDROP_IMPLEMENTATION", "")]);
    assert!(
        out.status.success(),
        "{}{ev}",
        String::from_utf8_lossy(&out.stderr)
    );
    let seen: Vec<&str> = ev
        .lines()
        .filter_map(|l| l.strip_prefix("pkexec-ulimit "))
        .collect();
    assert!(!seen.is_empty(), "{ev}");
    assert!(
        seen.iter().all(|s| *s == expected),
        "{seen:?} != {expected}"
    );
}

#[test]
fn a_start_cancelled_while_the_radio_comes_up_is_undone() {
    let f = Fixture::new();
    let child = spawn_with(&f, &["on", "10m"], &[("RADIO_SLEEP", "5")]);
    // Wait for the radio start to be under way.
    let start = std::time::Instant::now();
    while !std::fs::read_to_string(&f.capture)
        .unwrap()
        .contains(" start 600")
    {
        assert!(start.elapsed().as_secs() < 10, "the radio never started");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    signal(&child, 15);
    let out = finish_within(child, std::time::Duration::from_secs(5));
    let ev = std::fs::read_to_string(&f.capture).unwrap();
    assert_eq!(out.status.code(), Some(130), "{ev}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("Cancelled."));
    let stop = format!("pkexec {} stop", f.helper.display());
    assert!(first(&ev, " start 600") < first(&ev, &stop), "{ev}");
    assert!(ev.contains("identity stop-end"), "{ev}");
    assert_eq!(ev.matches("stop omdrop-window.timer").count(), 2, "{ev}");
    assert!(!ev.contains("on-active"), "{ev}");
}

#[test]
fn a_plugin_outside_the_default_directory_is_found_again_by_what_omdrop_starts() {
    // The fixture's plugin is under the test root, not ~/.config/omarchy/plugins.
    let f = Fixture::new();
    let file = f.root.join("photo.jpg");
    std::fs::write(&file, "x").unwrap();
    let sender = f.root.join("sender");
    let (out, ev) = f.run(
        &["send", "Studio Mac", file.to_str().unwrap()],
        &[("OMDROP_SENDER", sender.to_str().unwrap())],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(String::from_utf8_lossy(&out.stdout).contains("Turning it on"));
    assert!(!err.contains("cannot tell where it is installed"), "{err}");
    // The automatic `on` got as far as the receiver, and its units re-run
    // omdrop through the plugin's own command.
    assert!(ev.contains("--user start airdrop-receiver.service"), "{ev}");
    let watch = format!(
        "--unit=omdrop-watch {} watch --window 10m",
        f.omdrop.display()
    );
    assert!(ev.contains(&watch), "{ev}");
}

/// `handle` with a uwsm-app that keeps what it was given on stdin, the way
/// the real wl-copy behind it would read it.
fn handle_capturing_stdin(f: &Fixture, file: &Path, env: &[(&str, &str)]) -> (String, Vec<u8>) {
    let stdin = f.root.join("clipboard");
    write_exec(
        &f.root.join("bin/uwsm-app"),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"uwsm-app $*\" >> \"$CAPTURE\"\ncat > '{}'\n",
            stdin.display()
        ),
    );
    let (out, ev) = f.run(&["handle", file.to_str().unwrap()], env);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    (ev, std::fs::read(&stdin).unwrap_or_default())
}

fn clip_dirs_left(f: &Fixture) -> Vec<PathBuf> {
    std::fs::read_dir(f.root.join("run/omdrop"))
        .map(|d| d.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default()
}

#[test]
fn a_heic_arrival_goes_on_the_clipboard_as_a_jpeg_and_leaves_nothing_behind() {
    // #62: since the receiver asks for original-format photos, iPhone photos
    // arrive as HEIC, which few applications can paste.
    if Command::new("heif-convert")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("heif-convert is not installed; the fallback test covers this host");
        return;
    }
    let f = Fixture::new();
    let photo = f.root.join("IMG_0001.HEIC");
    std::fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gradient.heic"),
        &photo,
    )
    .unwrap();
    let original = std::fs::read(&photo).unwrap();
    let (ev, clip) = handle_capturing_stdin(&f, &photo, &[]);
    assert!(ev.contains("uwsm-app -- wl-copy --type image/jpeg"), "{ev}");
    assert_eq!(
        &clip[..2],
        &[0xff, 0xd8],
        "not a JPEG: {:?}",
        &clip[..clip.len().min(8)]
    );
    assert_eq!(
        std::fs::read(&photo).unwrap(),
        original,
        "the arrival itself changed"
    );
    assert_eq!(clip_dirs_left(&f), Vec::<PathBuf>::new());
}

#[test]
fn a_heic_that_will_not_decode_goes_on_the_clipboard_as_its_path() {
    let f = Fixture::new();
    write_exec(&f.root.join("bin/heif-convert"), "#!/bin/sh\nexit 1\n");
    let photo = f.root.join("IMG_0002.heic");
    std::fs::write(&photo, "not really a heic").unwrap();
    let (ev, clip) = handle_capturing_stdin(&f, &photo, &[]);
    assert!(ev.contains("uwsm-app -- wl-copy\n"), "{ev}");
    assert_eq!(clip, photo.as_os_str().as_encoded_bytes());
    assert_eq!(clip_dirs_left(&f), Vec::<PathBuf>::new());
}

#[test]
fn a_heic_decode_that_hangs_is_cut_off_and_the_path_is_copied() {
    let f = Fixture::new();
    write_exec(
        &f.root.join("bin/heif-convert"),
        "#!/bin/sh\nexec sleep 60\n",
    );
    let photo = f.root.join("IMG_0003.heic");
    std::fs::write(&photo, "slow").unwrap();
    let start = std::time::Instant::now();
    let (ev, clip) = handle_capturing_stdin(&f, &photo, &[]);
    let took = start.elapsed().as_secs();
    assert!((9..=20).contains(&took), "took {took} s");
    assert!(ev.contains("uwsm-app -- wl-copy\n"), "{ev}");
    assert_eq!(clip, photo.as_os_str().as_encoded_bytes());
    assert_eq!(clip_dirs_left(&f), Vec::<PathBuf>::new());
}
