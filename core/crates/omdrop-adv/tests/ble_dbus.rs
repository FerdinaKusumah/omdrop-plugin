//! The BLE advertiser against a fake BlueZ on a private `dbus-daemon
//! --session`, never the system bus, and its identity handling with injected
//! identities. Nothing reaches a radio.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use omdrop_adv::ble::{self, BleOptions, Event, Prepared, Stamper};
use omdrop_identity::{Identity, IdentityError, Source};
use zbus::blocking::Connection;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

// ---------------------------------------------------------------------------
// Harness

/// A private bus daemon, killed on drop.
struct Bus {
    child: Child,
    address: String,
}

impl Bus {
    fn start() -> Bus {
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("dbus-daemon");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let address = line.trim().to_owned();
        assert!(!address.is_empty(), "dbus-daemon printed no address");
        Bus { child, address }
    }

    fn client(&self) -> Connection {
        zbus::blocking::connection::Builder::address(self.address.as_str())
            .unwrap()
            .method_timeout(Duration::from_secs(2))
            .build()
            .unwrap()
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A test's lock: a panicking holder has already failed the test.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    fn push(&self, s: String) {
        lock(&self.0).push(s);
    }
    fn lines(&self) -> Vec<String> {
        lock(&self.0).clone()
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Accept,
    Fail,
    Hang,
}

struct Adapter {
    powered: bool,
    log: Log,
}

#[zbus::interface(name = "org.bluez.Adapter1")]
impl Adapter {
    #[zbus(property)]
    fn powered(&self) -> bool {
        self.powered
    }

    #[zbus(property)]
    fn set_powered(&mut self, on: bool) {
        self.log.push(format!("set Powered {on}"));
        self.powered = on;
    }

    #[zbus(property)]
    fn address(&self) -> String {
        "AA:BB:CC:DD:EE:FF".into()
    }

    #[zbus(property)]
    fn address_type(&self) -> String {
        "public".into()
    }
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.bluez.Error")]
enum BluezError {
    #[zbus(error)]
    ZBus(zbus::Error),
    Failed(String),
}

type Props = Arc<Mutex<Option<HashMap<String, OwnedValue>>>>;

struct Manager {
    mode: Mode,
    log: Log,
    props: Props,
}

#[zbus::interface(name = "org.bluez.LEAdvertisingManager1")]
impl Manager {
    /// Like bluetoothd: read the advertisement's properties back from the
    /// caller before answering.
    async fn register_advertisement(
        &self,
        path: OwnedObjectPath,
        _options: HashMap<String, OwnedValue>,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> Result<(), BluezError> {
        match self.mode {
            Mode::Fail => {
                return Err(BluezError::Failed(
                    "Failed to register advertisement".into(),
                ));
            }
            Mode::Hang => std::future::pending::<()>().await,
            Mode::Accept => {}
        }
        let sender = header
            .sender()
            .ok_or_else(|| BluezError::Failed("no sender".into()))?
            .to_owned();
        let reply = conn
            .call_method(
                Some(sender),
                path.as_str(),
                Some("org.freedesktop.DBus.Properties"),
                "GetAll",
                &("org.bluez.LEAdvertisement1",),
            )
            .await?;
        let all: HashMap<String, OwnedValue> = reply.body().deserialize()?;
        *lock(&self.props) = Some(all);
        self.log.push(format!("register {}", path.as_str()));
        Ok(())
    }

    fn unregister_advertisement(&self, path: OwnedObjectPath) {
        self.log.push(format!("unregister {}", path.as_str()));
    }
}

struct FakeBluez {
    _conn: Connection,
    log: Log,
    props: Props,
}

fn fake_bluez(bus: &Bus, mode: Mode, powered: bool) -> FakeBluez {
    let log = Log::default();
    let props: Props = Arc::default();
    let conn = zbus::blocking::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.bluez")
        .unwrap()
        .serve_at(
            "/org/bluez/hci0",
            Adapter {
                powered,
                log: log.clone(),
            },
        )
        .unwrap()
        .serve_at(
            "/org/bluez/hci0",
            Manager {
                mode,
                log: log.clone(),
                props: props.clone(),
            },
        )
        .unwrap()
        .build()
        .unwrap();
    FakeBluez {
        _conn: conn,
        log,
        props,
    }
}

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        lock(&self.0).extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    fn text(&self) -> String {
        String::from_utf8(lock(&self.0).clone()).unwrap()
    }
    fn wait_for(&self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let t = self.text();
            if t.contains(needle) {
                return t;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("no {needle:?} in output:\n{}", self.text());
    }
}

/// The message part of each stamped line, without `<epoch> <HH:MM:SSZ> `.
fn messages(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| {
            let mut parts = l.splitn(3, ' ');
            let epoch = parts.next().unwrap();
            let hms = parts.next().unwrap();
            assert!(
                epoch.parse::<f64>().is_ok() && epoch.split('.').nth(1).unwrap().len() == 3,
                "{l}"
            );
            assert!(hms.len() == 9 && hms.ends_with('Z'), "{l}");
            parts.next().unwrap().to_owned()
        })
        .collect()
}

fn prepared(hashes: &str) -> Prepared {
    Prepared {
        value: ble::payload(ble::Arm::A, 5, hashes, "010203").unwrap(),
        tag: "010203".into(),
    }
}

// ---------------------------------------------------------------------------
// Registration with BlueZ

#[test]
fn registers_serves_properties_and_unregisters_on_signal() {
    let bus = Bus::start();
    let fake = fake_bluez(&bus, Mode::Accept, false);
    let conn = bus.client();
    let out = Buf::default();
    let stamper = Stamper::new(Box::new(out.clone()));
    let opts = BleOptions {
        tag: Some("010203".into()),
        ..Default::default()
    };
    let prep = prepared("1111aaaa22223333");
    let (tx, rx) = mpsc::channel();
    let run = {
        let (conn, stamper, tx) = (conn.clone(), stamper.clone(), tx.clone());
        std::thread::spawn(move || ble::advertise(&conn, &opts, &prep, (tx, rx), &stamper))
    };
    out.wait_for(" START ");
    assert_eq!(
        messages(&out.text()),
        [
            "START arm=A tag=010203 type=0x05 interval_ms=100 connectable adapter_addr=AA:BB:CC:DD:EE:FF (public) \
          mfr=4c00 value=0512400102030000000003xxxxxxxxxxxxxxxx00"
        ]
    );
    assert_eq!(
        fake.log.lines(),
        ["set Powered true", "register /org/omarchy/airdrop/adv0"]
    );

    let props = lock(&fake.props).take().unwrap();
    assert_eq!(
        String::try_from(props["Type"].try_clone().unwrap()).unwrap(),
        "peripheral"
    );
    assert_eq!(u32::try_from(&props["MinInterval"]).unwrap(), 100);
    assert_eq!(u32::try_from(&props["MaxInterval"]).unwrap(), 100);
    let includes: Vec<String> = props["Includes"].try_clone().unwrap().try_into().unwrap();
    assert!(includes.is_empty());
    let mfr: HashMap<u16, OwnedValue> = props["ManufacturerData"]
        .try_clone()
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(mfr.len(), 1);
    let value: Vec<u8> = mfr[&0x004c].try_clone().unwrap().try_into().unwrap();
    assert_eq!(value, prepared("1111aaaa22223333").value);

    // bluetoothd may release the advertisement itself; that is reported.
    let me = conn.unique_name().unwrap().to_string();
    bus.client()
        .call_method(
            Some(me.as_str()),
            "/org/omarchy/airdrop/adv0",
            Some("org.bluez.LEAdvertisement1"),
            "Release",
            &(),
        )
        .unwrap();
    out.wait_for("RELEASED by bluetoothd");

    tx.send(Event::Signal).unwrap();
    assert_eq!(run.join().unwrap(), Ok(0));
    let msgs = messages(&out.text());
    assert_eq!(msgs.last().unwrap(), "STOP advertisement unregistered");
    assert_eq!(
        fake.log.lines().last().unwrap(),
        "unregister /org/omarchy/airdrop/adv0"
    );
}

#[test]
fn deadline_unregisters_a_broadcast_advert() {
    let bus = Bus::start();
    let fake = fake_bluez(&bus, Mode::Accept, true);
    let conn = bus.client();
    let out = Buf::default();
    let opts = BleOptions {
        seconds: 1,
        broadcast: true,
        interval_ms: 250,
        ..Default::default()
    };
    let started = Instant::now();
    let (tx, rx) = mpsc::channel();
    let status = ble::advertise(
        &conn,
        &opts,
        &prepared("0000000000000000"),
        (tx, rx),
        &Stamper::new(Box::new(out.clone())),
    );
    assert_eq!(status, Ok(0));
    assert!(started.elapsed() >= Duration::from_secs(1));
    let msgs = messages(&out.text());
    assert_eq!(msgs.len(), 2, "{msgs:?}");
    assert!(
        msgs[0].contains(" interval_ms=250 non-connectable "),
        "{}",
        msgs[0]
    );
    // Zero hashes are shown, not masked.
    assert!(
        msgs[0].ends_with(" value=0512400102030000000003000000000000000000"),
        "{}",
        msgs[0]
    );
    assert_eq!(msgs[1], "STOP advertisement unregistered");
    // Already powered: not touched.
    assert_eq!(
        fake.log.lines(),
        [
            "register /org/omarchy/airdrop/adv0",
            "unregister /org/omarchy/airdrop/adv0"
        ]
    );
    let props = lock(&fake.props).take().unwrap();
    assert_eq!(
        String::try_from(props["Type"].try_clone().unwrap()).unwrap(),
        "broadcast"
    );
}

#[test]
fn bluez_refusal_is_reported_as_register_failed() {
    let bus = Bus::start();
    let fake = fake_bluez(&bus, Mode::Fail, true);
    let out = Buf::default();
    let (tx, rx) = mpsc::channel();
    let status = ble::advertise(
        &bus.client(),
        &BleOptions::default(),
        &prepared("0000000000000000"),
        (tx, rx),
        &Stamper::new(Box::new(out.clone())),
    );
    assert_eq!(status, Ok(0));
    assert_eq!(
        messages(&out.text()),
        ["REGISTER FAILED org.bluez.Error.Failed: Failed to register advertisement"]
    );
    assert!(fake.log.lines().is_empty());
}

#[test]
fn missing_adapter_is_an_error_before_registration() {
    let bus = Bus::start();
    let fake = fake_bluez(&bus, Mode::Accept, true);
    let out = Buf::default();
    let opts = BleOptions {
        adapter: "hci1".into(),
        ..Default::default()
    };
    let (tx, rx) = mpsc::channel();
    let err = ble::advertise(
        &bus.client(),
        &opts,
        &prepared("0000000000000000"),
        (tx, rx),
        &Stamper::new(Box::new(out.clone())),
    )
    .unwrap_err();
    assert!(
        err.starts_with("/org/bluez/hci1 Powered: org.freedesktop.DBus.Error."),
        "{err}"
    );
    assert!(out.text().is_empty());
    assert!(fake.log.lines().is_empty());
}

#[test]
fn no_bluez_at_all_is_an_error() {
    let bus = Bus::start();
    let (tx, rx) = mpsc::channel();
    let err = ble::advertise(
        &bus.client(),
        &BleOptions::default(),
        &prepared("0000000000000000"),
        (tx, rx),
        &Stamper::new(Box::new(Buf::default())),
    )
    .unwrap_err();
    assert!(
        err.contains("org.freedesktop.DBus.Error.ServiceUnknown"),
        "{err}"
    );
}

#[test]
fn signal_while_bluez_is_deciding_stops_without_start() {
    let bus = Bus::start();
    let _fake = fake_bluez(&bus, Mode::Hang, true);
    let out = Buf::default();
    let (tx, rx) = mpsc::channel();
    let tx2 = tx.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        let _ = tx2.send(Event::Signal);
    });
    let started = Instant::now();
    let status = ble::advertise(
        &bus.client(),
        &BleOptions::default(),
        &prepared("0000000000000000"),
        (tx, rx),
        &Stamper::new(Box::new(out.clone())),
    );
    assert_eq!(status, Ok(0));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(out.text().is_empty(), "{}", out.text());
}

#[test]
fn binary_unregisters_on_sigterm() {
    let bus = Bus::start();
    let fake = fake_bluez(&bus, Mode::Accept, true);
    let mut child = Command::new(env!("CARGO_BIN_EXE_omdrop-adv"))
        // send-to-peer's argv, plus explicit hashes: no identity lookup.
        .args([
            "ble",
            "--arm",
            "A",
            "--seconds",
            "30",
            "--interval-ms",
            "100",
            "--hashes",
            "0000000000000000",
        ])
        .env("DBUS_SYSTEM_BUS_ADDRESS", &bus.address)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut lines = Vec::new();
    // send-to-peer's test: the first line containing " START ".
    loop {
        let mut line = String::new();
        assert!(
            stdout.read_line(&mut line).unwrap() > 0,
            "exited early: {lines:?}"
        );
        lines.push(line.clone());
        if line.contains(" START ") {
            break;
        }
    }
    assert!(
        lines[0].contains(" contact hashes: zeros -- a Contacts Only receiver cannot match these"),
        "{lines:?}"
    );
    // SAFETY: plain kill(2) of our own child.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    let status = child.wait().unwrap();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert_eq!(status.code(), Some(0), "stderr: {err}");
    assert!(
        rest.trim_end()
            .ends_with(" STOP advertisement unregistered"),
        "{rest}"
    );
    assert_eq!(
        fake.log.lines(),
        [
            "register /org/omarchy/airdrop/adv0",
            "unregister /org/omarchy/airdrop/adv0"
        ]
    );
}

#[test]
fn binary_reports_register_failed_for_send_to_peer() {
    let bus = Bus::start();
    let _fake = fake_bluez(&bus, Mode::Fail, true);
    let out = Command::new(env!("CARGO_BIN_EXE_omdrop-adv"))
        .args([
            "ble",
            "--seconds",
            "5",
            "--hashes",
            "0000000000000000",
            "--tag",
            "aabbcc",
        ])
        .env("DBUS_SYSTEM_BUS_ADDRESS", &bus.address)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        text.lines()
            .last()
            .unwrap()
            .contains(" REGISTER FAILED org.bluez.Error.Failed: "),
        "{text}"
    );
}

// ---------------------------------------------------------------------------
// Hash selection (ported from omdrop-awdl tests/test_identity_consumers.py)

fn golden(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name)
}

fn identity(record: Option<Vec<u8>>, warnings: &[&str]) -> Identity {
    Identity {
        source: if record.is_some() {
            Source::Disk
        } else {
            Source::SelfSigned
        },
        certificate_pem: Vec::new(),
        key_pem: zeroize::Zeroizing::new(Vec::new()),
        record,
        warnings: warnings.iter().map(|w| w.to_string()).collect(),
    }
}

fn prepare_with(
    opts: &BleOptions,
    resolve: &dyn Fn() -> Result<Identity, IdentityError>,
) -> (Result<Prepared, String>, Vec<String>, String) {
    let out = Buf::default();
    let mut warn = Vec::new();
    let r = ble::prepare(
        opts,
        resolve,
        &mut warn,
        &Stamper::new(Box::new(out.clone())),
    );
    (r, messages(&out.text()), String::from_utf8(warn).unwrap())
}

fn opts() -> BleOptions {
    BleOptions {
        tag: Some("010203".into()),
        ..Default::default()
    }
}

#[test]
fn advertiser_derives_packet_hashes_from_record_bytes() {
    let record = std::fs::read(golden("record-full.cms")).unwrap();
    let (r, msgs, warn) = prepare_with(&opts(), &|| {
        Ok(identity(Some(record.clone()), &["disk-incomplete"]))
    });
    assert_eq!(
        r.unwrap().value,
        ble::fromhex("05124001020300000000031111aaaa2222333300").unwrap()
    );
    assert_eq!(
        msgs,
        ["contact hashes: record, 7 identifiers validated, 4 slots filled"]
    );
    assert_eq!(warn, "omdrop-adv ble: RuntimeWarning: disk-incomplete\n");
}

#[test]
fn self_signed_identity_advertises_zero_hashes() {
    let (r, msgs, _) = prepare_with(&opts(), &|| Ok(identity(None, &[])));
    assert_eq!(r.unwrap().value[11..19], [0; 8]);
    assert_eq!(
        msgs,
        ["contact hashes: zeros -- a Contacts Only receiver cannot match these"]
    );
}

#[test]
fn identity_failure_never_advertises_zero_hashes() {
    for code in ["self-signed-missing", "cache-unreadable-as-root"] {
        let (r, msgs, _) = prepare_with(&opts(), &|| Err(IdentityError::new(code)));
        assert_eq!(r.unwrap_err(), format!("identity error: {code}"));
        assert!(msgs.is_empty());
    }
}

#[test]
fn explicit_research_overrides_bypass_identity_selection() {
    let never =
        || -> Result<Identity, IdentityError> { panic!("identity resolved despite an override") };
    let o = BleOptions {
        hashes: Some("123456789abcdef0".into()),
        ..opts()
    };
    let (r, msgs, _) = prepare_with(&o, &never);
    assert_eq!(
        r.unwrap().value[11..19],
        ble::fromhex("123456789abcdef0").unwrap()[..]
    );
    // As in Python: explicit hashes report as "zeros".
    assert_eq!(
        msgs,
        ["contact hashes: zeros -- a Contacts Only receiver cannot match these"]
    );

    let o = BleOptions {
        hashes_from_record: Some(Some(golden("record-full.cms"))),
        ..opts()
    };
    let (r, _, _) = prepare_with(&o, &never);
    assert_eq!(
        r.unwrap().value[11..19],
        ble::fromhex("1111aaaa22223333").unwrap()[..]
    );

    let absent = golden("absent.cms");
    let o = BleOptions {
        hashes_from_record: Some(Some(absent.clone())),
        ..opts()
    };
    let (r, msgs, _) = prepare_with(&o, &never);
    assert_eq!(r.unwrap().value[11..19], [0; 8]);
    assert_eq!(
        msgs,
        [
            format!(
                "no validation record at {}; advertising zero hashes",
                absent.display()
            ),
            "contact hashes: zeros -- a Contacts Only receiver cannot match these".into(),
        ]
    );

    let o = BleOptions {
        hashes: Some("00".repeat(8)),
        hashes_from_record: Some(None),
        ..opts()
    };
    let (r, _, _) = prepare_with(&o, &never);
    assert_eq!(
        r.unwrap_err(),
        "--hashes and --hashes-from-record are mutually exclusive"
    );
}

#[test]
fn bad_hashes_and_tags_are_refused() {
    let never = || -> Result<Identity, IdentityError> { panic!() };
    let o = BleOptions {
        hashes: Some("zz".repeat(8)),
        ..opts()
    };
    assert_eq!(
        prepare_with(&o, &never).0.unwrap_err(),
        "--hashes must be 8 bytes (four 2-byte hashes) as hex"
    );
    let o = BleOptions {
        hashes: Some("00".repeat(8)),
        tag: Some("0102".into()),
        ..opts()
    };
    assert_eq!(
        prepare_with(&o, &never).0.unwrap_err(),
        "--tag must be 3 bytes as hex"
    );
    let record = std::fs::read(golden("record-none.cms")).unwrap();
    let (r, _, _) = prepare_with(&opts(), &|| Ok(identity(Some(record.clone()), &[])));
    assert_eq!(
        r.unwrap_err(),
        "validation record validates no identifiers; nothing to advertise"
    );
}

#[test]
fn random_tag_is_three_bytes() {
    let o = BleOptions {
        tag: None,
        hashes: Some("00".repeat(8)),
        ..Default::default()
    };
    let p = prepare_with(&o, &|| panic!()).0.unwrap();
    assert_eq!(p.tag.len(), 6);
    assert_eq!(p.value[3..6], ble::fromhex(&p.tag).unwrap()[..]);
}
