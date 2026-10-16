//! Port of the airdrop-send parts of omdrop-awdl's
//! `tests/test_identity_consumers.py`: the sender presents the selected
//! certificate and the record that belongs to it, an explicit `--keys`
//! cannot override a self-signed window, and an expired window is reported
//! rather than replaced by the disk identity. Loopback TLS only.

mod common;

use std::process::Command;
use std::time::Duration;

use common::*;
use omdrop_send::airdrop_send::{parse_options, sender_from_identity};
use omdrop_send::client::Client;
use omdrop_send::http::Endpoint;
use omdrop_send::log::{Logger, Sink};

struct Fixture {
    _material: tempfile::TempDir,
    home: tempfile::TempDir,
    disk: (Vec<u8>, Vec<u8>),
    selfsigned: (Vec<u8>, Vec<u8>),
    record: Vec<u8>,
}

fn fixture() -> Fixture {
    let material = tempfile::tempdir().unwrap();
    let disk = pair(material.path(), "disk");
    let selfsigned = pair(material.path(), "self-signed");
    let record = record(material.path(), "disk");
    let home = tempfile::tempdir().unwrap();
    let keys = home.path().join(".omdrop/keys");
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::write(keys.join("certificate.pem"), &disk.0).unwrap();
    std::fs::write(keys.join("key.pem"), &disk.1).unwrap();
    std::fs::write(keys.join("certificate.self-signed.pem"), &selfsigned.0).unwrap();
    std::fs::write(keys.join("key.self-signed.pem"), &selfsigned.1).unwrap();
    std::fs::write(keys.join("validation_record.cms"), &record).unwrap();
    let settings = home.path().join(".config/omdrop");
    std::fs::create_dir_all(&settings).unwrap();
    std::fs::write(settings.join("settings"), "identity_source=disk\n").unwrap();
    let runtime = home.path().join("runtime/omdrop");
    std::fs::create_dir_all(&runtime).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        home.path().join("runtime"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    Fixture {
        _material: material,
        home,
        disk,
        selfsigned,
        record,
    }
}

/// In process: what the sender's /Discover presents with a given identity.
#[test]
fn sender_disk_record_matches_the_presented_tls_certificate() {
    let f = fixture();
    let server = identity(&f.disk.0, &f.disk.1, None);
    let (port, handle) = one_shot(&server, name_answer("Identity test peer"));
    let opts = parse_options(&[
        "--discover-only".into(),
        "--direct".into(),
        format!("127.0.0.1:{port}"),
        "--op-timeout".into(),
        "2".into(),
    ])
    .unwrap();
    let sender = sender_from_identity(
        &identity(&f.disk.0, &f.disk.1, Some(f.record.clone())),
        &opts,
        "020000000001".into(),
    )
    .unwrap();
    let log = Logger::new(Sink::Silent);
    let mut client = Client::new(
        &sender,
        Endpoint::resolve("127.0.0.1", port, "lo").unwrap(),
        &log,
    );
    assert_eq!(
        client.discover().unwrap().as_deref(),
        Some("Identity test peer")
    );
    let seen = handle.join().unwrap();
    assert_eq!(seen.path, "/Discover");
    assert_eq!(seen.client_cert_der, Some(der(&f.disk.0)));
    let body = plist::Value::from_reader(std::io::Cursor::new(&seen.body)).unwrap();
    let dict = body.as_dictionary().unwrap();
    assert_eq!(
        dict.get("SenderRecordData").and_then(|v| v.as_data()),
        Some(&f.record[..])
    );
    assert_eq!(
        dict.get("DeviceSupportFlags")
            .and_then(|v| v.as_signed_integer()),
        Some(111611)
    );
    // The request carries http.client's framing and the default headers, in order.
    let names: Vec<&str> = seen.headers.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        [
            "Host",
            "Content-Length",
            "Content-Type",
            "Connection",
            "Accept",
            "User-Agent",
            "Accept-Language",
            "Accept-Encoding"
        ]
    );
    assert_eq!(seen.headers[0].1, format!("127.0.0.1:{port}"));
}

/// The program, black box: temp HOME and XDG dirs, an explicit keys
/// directory, so the live identity is never read.
fn sender(f: &Fixture, endpoint: &str, extra: &[&str]) -> std::process::Output {
    let home = f.home.path();
    Command::new(env!("CARGO_BIN_EXE_airdrop-send"))
        .args([
            "--discover-only",
            "--iface",
            "lo",
            "--direct",
            endpoint,
            "--op-timeout",
            "2",
        ])
        .args(extra)
        .env("HOME", home.join("wrong-home"))
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_RUNTIME_DIR", home.join("runtime"))
        .env("OMDROP_DEBUG", "0")
        .env("OMDROP_DEBUG_SENSITIVE", "0")
        .env_remove("PKEXEC_UID")
        .env_remove("SUDO_UID")
        .output()
        .unwrap()
}

fn discover_black_box(f: &Fixture, extra: &[&str]) -> Observed {
    let server = identity(&f.disk.0, &f.disk.1, None);
    let (port, handle) = one_shot(&server, name_answer("Identity test peer"));
    let out = sender(f, &format!("127.0.0.1:{port}"), extra);
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "Identity test peer"
    );
    handle.join().unwrap()
}

fn keys_arg(f: &Fixture) -> String {
    f.home.path().join(".omdrop").to_string_lossy().into_owned()
}

#[test]
fn black_box_disk_identity_and_record() {
    let f = fixture();
    let seen = discover_black_box(&f, &["--keys", &keys_arg(&f)]);
    assert_eq!(seen.client_cert_der, Some(der(&f.disk.0)));
    let body = plist::Value::from_reader(std::io::Cursor::new(&seen.body)).unwrap();
    assert_eq!(
        body.as_dictionary()
            .unwrap()
            .get("SenderRecordData")
            .and_then(|v| v.as_data()),
        Some(&f.record[..])
    );
}

fn write_window(f: &Fixture, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    let w = f.home.path().join("runtime/omdrop/window");
    std::fs::write(&w, text).unwrap();
    std::fs::set_permissions(&w, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn sender_explicit_keys_cannot_override_a_self_signed_window() {
    let f = fixture();
    write_window(&f, "source=self-signed\n");
    let seen = discover_black_box(&f, &["--keys", &keys_arg(&f)]);
    assert_eq!(seen.client_cert_der, Some(der(&f.selfsigned.0)));
    let body = plist::Value::from_reader(std::io::Cursor::new(&seen.body)).unwrap();
    assert!(
        body.as_dictionary()
            .unwrap()
            .get("SenderRecordData")
            .is_none()
    );
    let keys = f.home.path().join(".omdrop/keys");
    assert_eq!(
        std::fs::read(keys.join("certificate.pem")).unwrap(),
        f.disk.0
    );
    assert_eq!(
        std::fs::read(keys.join("validation_record.cms")).unwrap(),
        f.record
    );
}

#[test]
fn sender_reports_expired_window_instead_of_using_disk() {
    let f = fixture();
    write_window(
        &f,
        &format!(
            "source=1password\nfetch_id={}\nhard_expiry=1\n",
            "a".repeat(32)
        ),
    );
    let out = sender(&f, "127.0.0.1:1", &["--keys", &keys_arg(&f)]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("identity error: window-expired"), "{err}");
    assert!(!err.contains("no answer"), "{err}");
}

#[test]
fn a_silent_peer_is_named_by_class_on_stderr() {
    let f = fixture();
    // A listener that never answers: the op timeout ends the attempt.
    let quiet = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = quiet.local_addr().unwrap().port();
    let started = std::time::Instant::now();
    let out = sender(&f, &format!("127.0.0.1:{port}"), &["--keys", &keys_arg(&f)]);
    assert!(started.elapsed() < Duration::from_secs(8));
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!("127.0.0.1:{port}: no answer (TimeoutError)\n")
    );
    assert!(out.stdout.is_empty());
    drop(quiet);
}
