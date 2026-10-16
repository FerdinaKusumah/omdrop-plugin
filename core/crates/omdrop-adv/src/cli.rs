//! The three subcommands, each taking exactly its Python predecessor's argv
//! and printing the same lines.
//!
//! - `omdrop-adv ble`      = `ble-airdrop-adv.py`
//! - `omdrop-adv mdns`     = `awdl-mdns-respond.py`
//! - `omdrop-adv announce` = `awdl-airdrop-adv.py`
//!
//! These run as root under the supervisor, so every argument is range-checked
//! here, before it reaches a frame, a path or a socket.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};
use std::time::{Duration, Instant};

use crate::args::{Exit, Kind, Opt, Parsed, Parser, py_float, py_int, py_int_auto};
use crate::ble::{self, Arm, BleOptions, Event, Stamper};
use crate::frames::{self, BuildError, MDNS_GROUP, SERVICE};
use crate::rawsock::{ETH_P_ALL, PacketSocket, os_error_text};
use crate::{clock, host, mdns};

/// D-Bus calls BlueZ does not answer fail after this (libdbus's default).
const DBUS_TIMEOUT: Duration = Duration::from_secs(25);
/// Bounds on sleeps given on the command line, in seconds.
const MAX_SLEEP: f64 = 3600.0;

fn int_arg(
    p: &Parsed,
    parser: &Parser,
    name: &str,
    default: i128,
    min: i128,
    max: i128,
) -> Result<i128, Exit> {
    let Some(text) = p.value(name) else {
        return Ok(default);
    };
    let v = py_int(text)
        .ok_or_else(|| parser.error(&format!("argument --{name}: invalid int value: '{text}'")))?;
    if !(min..=max).contains(&v) {
        return Err(parser.error(&format!("argument --{name}: {v} is outside {min}..{max}")));
    }
    Ok(v)
}

fn float_arg(p: &Parsed, parser: &Parser, name: &str, default: f64) -> Result<f64, Exit> {
    let Some(text) = p.value(name) else {
        return Ok(default);
    };
    let v = py_float(text).ok_or_else(|| {
        parser.error(&format!("argument --{name}: invalid float value: '{text}'"))
    })?;
    if !v.is_finite() || !(0.0..=MAX_SLEEP).contains(&v) {
        return Err(parser.error(&format!(
            "argument --{name}: {text} is outside 0..{MAX_SLEEP}"
        )));
    }
    Ok(v)
}

fn name_arg(
    p: &Parsed,
    parser: &Parser,
    name: &str,
    wire: impl Fn(&str) -> String,
) -> Result<Option<String>, Exit> {
    match p.value(name) {
        Some(v) => {
            frames::check_name(&wire(v))
                .map_err(|e| parser.error(&format!("argument --{name}: {e}")))?;
            Ok(Some(v.to_owned()))
        }
        None => Ok(None),
    }
}

fn iface_arg(p: &Parsed, parser: &Parser) -> Result<String, Exit> {
    let iface = p.value("iface").unwrap_or("awdl0");
    if !host::valid_iface(iface) {
        return Err(parser.error(&format!(
            "argument --iface: invalid interface name '{iface}'"
        )));
    }
    Ok(iface.to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Python's `repr` of a printable-ASCII string.
fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn mac_or_exit(cmd: &str, iface: &str) -> Result<[u8; 6], i32> {
    host::mac_of(iface).map_err(|e| {
        eprintln!(
            "omdrop-adv {cmd}: cannot read the MAC of {iface}: {}",
            os_error_text(&e)
        );
        1
    })
}

/// Host given, or the machine's AWDL host name with `.local`.
fn host_or_default(given: Option<String>) -> String {
    given.unwrap_or_else(|| format!("{}.local", host::awdl_host()))
}

fn service_id(given: Option<String>, mac: [u8; 6]) -> String {
    given.filter(|s| !s.is_empty()).unwrap_or_else(|| hex(&mac))
}

// ----------------------------------------------------------------------------
// announce

const ANNOUNCE: Parser = Parser {
    prog: "omdrop-adv announce",
    description: "Advertise _airdrop._tcp.local out awdl0 in Apple's AWDL SNAP encapsulation.",
    opts: &[
        Opt {
            name: "iface",
            kind: Kind::Value,
            metavar: "IFACE",
            help: "default awdl0",
        },
        Opt {
            name: "count",
            kind: Kind::Value,
            metavar: "COUNT",
            help: "frames to send (default 20)",
        },
        Opt {
            name: "interval",
            kind: Kind::Value,
            metavar: "INTERVAL",
            help: "seconds between frames (default 2.0)",
        },
        Opt {
            name: "seq",
            kind: Kind::Value,
            metavar: "SEQ",
            help: "first AWDL sequence number (default 0)",
        },
        Opt {
            name: "port",
            kind: Kind::Value,
            metavar: "PORT",
            help: "SRV port (default 8771)",
        },
        Opt {
            name: "flags",
            kind: Kind::Value,
            metavar: "FLAGS",
            help: "TXT flags (default 0x3fb)",
        },
        Opt {
            name: "host",
            kind: Kind::Value,
            metavar: "HOST",
            help: "SRV target and AAAA name (default the AWDL host .local)",
        },
        Opt {
            name: "service-id",
            kind: Kind::Value,
            metavar: "SERVICE_ID",
            help: "12 hex chars; defaults to the awdl0 MAC",
        },
        Opt {
            name: "plain",
            kind: Kind::Flag,
            metavar: "",
            help: "Ethernet II instead of SNAP -- the negative control",
        },
        Opt {
            name: "dump",
            kind: Kind::Flag,
            metavar: "",
            help: "print the frame instead of sending it",
        },
    ],
};

struct AnnounceOptions {
    iface: String,
    count: u32,
    interval: f64,
    seq: i64,
    port: u16,
    flags: u64,
    host: Option<String>,
    service_id: Option<String>,
    plain: bool,
    dump: bool,
}

fn parse_announce(args: &[String]) -> Result<AnnounceOptions, Exit> {
    let p = ANNOUNCE.parse(args)?;
    let a = &ANNOUNCE;
    Ok(AnnounceOptions {
        iface: iface_arg(&p, a)?,
        count: int_arg(&p, a, "count", 20, 0, i128::from(u32::MAX))? as u32,
        interval: float_arg(&p, a, "interval", 2.0)?,
        seq: int_arg(&p, a, "seq", 0, i128::from(i64::MIN), i128::from(i64::MAX))? as i64,
        port: int_arg(&p, a, "port", 8771, 0, 65535)? as u16,
        flags: int_arg(&p, a, "flags", 0x3fb, 0, i128::from(u64::MAX))? as u64,
        host: name_arg(&p, a, "host", |h| h.to_owned())?,
        service_id: name_arg(&p, a, "service-id", |s| format!("{s}.{SERVICE}"))?,
        plain: p.flag("plain"),
        dump: p.flag("dump"),
    })
}

/// `omdrop-adv announce` (`awdl-airdrop-adv.py`).
pub fn announce(args: &[String]) -> i32 {
    let o = match parse_announce(args) {
        Ok(o) => o,
        Err(exit) => return exit.emit(),
    };
    let mac = match mac_or_exit("announce", &o.iface) {
        Ok(m) => m,
        Err(code) => return code,
    };
    let sid = service_id(o.service_id, mac);
    let host = host_or_default(o.host);
    let ll = frames::eui64_ll(mac);
    let built = frames::announcement(&sid, &host, o.port, o.flags, ll)
        .and_then(|msg| frames::udp6(ll, MDNS_GROUP.octets(), &msg))
        .and_then(|payload| frames::wrap(mac, &payload, 0, !o.plain).map(|_| payload));
    let payload = match built {
        Ok(p) => p,
        Err(e) => {
            eprintln!("omdrop-adv announce: {e}");
            return 1;
        }
    };
    let kind = if o.plain { "EthernetII" } else { "AppleSNAP" };
    let seq16 = |seq: i64| (seq & 0xffff) as u16;
    let mut out = io::stdout().lock();

    if o.dump {
        let Ok(f) = frames::wrap(mac, &payload, seq16(o.seq), !o.plain) else {
            return 1;
        };
        let _ = writeln!(
            out,
            "{kind} {}B  {sid}._airdrop._tcp.local -> {host}:{} flags={} (0x{:x})",
            f.len(),
            o.port,
            o.flags,
            o.flags
        );
        for (i, row) in f.chunks(16).enumerate() {
            let bytes: Vec<String> = row.iter().map(|b| format!("{b:02x}")).collect();
            let _ = writeln!(out, "  {:04x}  {}", i * 16, bytes.join(" "));
        }
        return 0;
    }

    let _ = writeln!(
        out,
        "{}: {kind}  advertising {sid}._airdrop._tcp.local -> {host}:{} flags=0x{:x} from {}",
        o.iface,
        o.port,
        o.flags,
        Ipv6Addr::from(ll)
    );
    let _ = out.flush();
    let sock = match PacketSocket::open(&o.iface, 0) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("omdrop-adv announce: {}: {}", o.iface, os_error_text(&e));
            return 1;
        }
    };
    let (mut sent, mut fail) = (0u64, 0u64);
    let mut seq = o.seq;
    let pause = Duration::from_secs_f64(o.interval);
    for i in 0..o.count {
        let result = frames::wrap(mac, &payload, seq16(seq), !o.plain)
            .map_err(|e: BuildError| io::Error::new(io::ErrorKind::InvalidData, e.0))
            .and_then(|f| sock.send(&f));
        match result {
            Ok(_) => sent += 1,
            Err(e) => {
                fail += 1;
                if fail == 1 {
                    let _ = writeln!(out, "  send error: {}", os_error_text(&e));
                }
            }
        }
        seq = seq.wrapping_add(1);
        if i + 1 < o.count {
            std::thread::sleep(pause);
        }
    }
    let _ = writeln!(out, "  sent={sent} failed={fail} next_seq={}", seq16(seq));
    0
}

// ----------------------------------------------------------------------------
// mdns

const MDNS: Parser = Parser {
    prog: "omdrop-adv mdns",
    description: "Answer mDNS queries for our AirDrop identity on awdl0.",
    opts: &[
        Opt {
            name: "iface",
            kind: Kind::Value,
            metavar: "IFACE",
            help: "default awdl0",
        },
        Opt {
            name: "port",
            kind: Kind::Value,
            metavar: "PORT",
            help: "SRV port (default 8771)",
        },
        Opt {
            name: "flags",
            kind: Kind::Value,
            metavar: "FLAGS",
            help: "TXT flags (default 0x88)",
        },
        Opt {
            name: "host",
            kind: Kind::Value,
            metavar: "HOST",
            help: "our host name (default the AWDL host .local)",
        },
        Opt {
            name: "service-id",
            kind: Kind::Value,
            metavar: "SERVICE_ID",
            help: "default the awdl0 MAC as hex",
        },
        Opt {
            name: "min-gap",
            kind: Kind::Value,
            metavar: "MIN_GAP",
            help: "seconds between replies",
        },
        Opt {
            name: "burst",
            kind: Kind::Value,
            metavar: "BURST",
            help: "frames per reply (multicast air fate is 25-50%)",
        },
    ],
};

/// Most frames one reply may send.
const MAX_BURST: i128 = 100;

struct MdnsOptions {
    iface: String,
    port: u16,
    flags: u64,
    host: Option<String>,
    service_id: Option<String>,
    min_gap: f64,
    burst: u16,
}

fn parse_mdns(args: &[String]) -> Result<MdnsOptions, Exit> {
    let p = MDNS.parse(args)?;
    let a = &MDNS;
    Ok(MdnsOptions {
        iface: iface_arg(&p, a)?,
        port: int_arg(&p, a, "port", 8771, 0, 65535)? as u16,
        flags: int_arg(&p, a, "flags", 0x88, 0, i128::from(u64::MAX))? as u64,
        host: name_arg(&p, a, "host", |h| h.to_owned())?,
        service_id: name_arg(&p, a, "service-id", |s| format!("{s}.{SERVICE}"))?,
        min_gap: float_arg(&p, a, "min-gap", 0.1)?,
        burst: int_arg(&p, a, "burst", 5, 0, MAX_BURST)? as u16,
    })
}

/// The names this responder answers for: our host, the service type and our
/// instance, lowercased.
pub fn our_names(host: &str, sid: &str) -> BTreeSet<String> {
    BTreeSet::from([
        host.to_ascii_lowercase().trim_end_matches('.').to_owned(),
        SERVICE.to_owned(),
        format!("{sid}.{SERVICE}").to_ascii_lowercase(),
    ])
}

/// The first question in a received frame that names one of ours, if the
/// frame is an mDNS query from someone else.
pub fn wanted(frame: &[u8], mac: [u8; 6], ours: &BTreeSet<String>) -> Option<([u8; 6], String)> {
    let (src, dns) = mdns::mdns_payload(frame)?;
    if src == mac {
        return None;
    }
    let hit = mdns::questions(dns)
        .into_iter()
        .find(|q| ours.contains(q))?;
    Some((src, hit))
}

/// `omdrop-adv mdns` (`awdl-mdns-respond.py`).
///
/// WHY. A peer Mac's sharingd saw our advert, created a Bonjour service and
/// sent DISCOVER seven times over thirty seconds, every attempt timing out at
/// "Bonjour service failed discovery": it could not resolve our Arpa hostname
/// to an address, and we answered none of its 28 queries. For every query
/// naming our host, the service or our instance, this sends the announcer's
/// frame (multicast: the Mac accepts the mDNS group from us; unicast needs a
/// peer entry), at most one reply per `--min-gap`.
pub fn mdns_respond(args: &[String]) -> i32 {
    let o = match parse_mdns(args) {
        Ok(o) => o,
        Err(exit) => return exit.emit(),
    };
    let mac = match mac_or_exit("mdns", &o.iface) {
        Ok(m) => m,
        Err(code) => return code,
    };
    let sid = service_id(o.service_id, mac);
    let host = host_or_default(o.host);
    let ll = frames::eui64_ll(mac);
    let built = frames::reply(&sid, &host, o.port, o.flags, ll)
        .and_then(|msg| frames::udp6(ll, MDNS_GROUP.octets(), &msg))
        .and_then(|payload| frames::wrap(mac, &payload, 0, true).map(|_| payload));
    let payload = match built {
        Ok(p) => p,
        Err(e) => {
            eprintln!("omdrop-adv mdns: {e}");
            return 1;
        }
    };
    let ours = our_names(&host, &sid);
    let sock = match PacketSocket::open(&o.iface, ETH_P_ALL) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("omdrop-adv mdns: {}: {}", o.iface, os_error_text(&e));
            return 1;
        }
    };
    let mut out = io::stdout().lock();
    let names: Vec<String> = ours.iter().map(|n| py_repr(n)).collect();
    let _ = writeln!(
        out,
        "{:.3} responding on {} for [{}] -> {}:{}",
        clock::epoch_now(),
        o.iface,
        names.join(", "),
        Ipv6Addr::from(ll),
        o.port
    );
    let _ = out.flush();

    let gap = Duration::from_secs_f64(o.min_gap);
    let mut seq: u16 = 0x4000;
    let mut last: Option<Instant> = None;
    let mut replies: u64 = 0;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "omdrop-adv mdns: receive on {}: {}",
                    o.iface,
                    os_error_text(&e)
                );
                return 1;
            }
        };
        let Some((src, hit)) = wanted(buf.get(..n).unwrap_or(&[]), mac, &ours) else {
            continue;
        };
        if last.is_some_and(|t| t.elapsed() < gap) {
            continue;
        }
        let now = clock::epoch_now();
        let started = Instant::now();
        // A burst at 20 ms, as the announcer does: our multicast reaches the
        // air 25-50% of the time (frames outside our active slots are
        // dropped), and single replies changed nothing in the peer's query
        // rate.
        let mut failed = None;
        for i in 0..o.burst {
            let sent = frames::wrap(mac, &payload, seq.wrapping_add(i), true)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.0))
                .and_then(|f| sock.send(&f));
            if let Err(e) = sent {
                failed = Some(e);
                break;
            }
            if i + 1 < o.burst {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        if let Some(e) = failed {
            let _ = writeln!(out, "{now:.3} send error: {}", os_error_text(&e));
            let _ = out.flush();
            continue;
        }
        seq = seq.wrapping_add(o.burst);
        last = Some(started);
        replies += 1;
        let src_text: Vec<String> = src.iter().map(|b| format!("{b:02x}")).collect();
        let _ = writeln!(
            out,
            "{now:.3} {} query from {} for {hit} -> answered ({replies})",
            clock::hms_utc(now),
            src_text.join(":")
        );
        let _ = out.flush();
    }
}

// ----------------------------------------------------------------------------
// ble

const BLE: Parser = Parser {
    prog: "omdrop-adv ble",
    description: "Transmit an Apple Continuity AirDrop (type 0x05) BLE advertisement.",
    opts: &[
        Opt {
            name: "arm",
            kind: Kind::Value,
            metavar: "{A,V2,B}",
            help: "advert shape (default A)",
        },
        Opt {
            name: "tag",
            kind: Kind::Value,
            metavar: "TAG",
            help: "3 bytes hex for arm A bytes 1-3; default random",
        },
        Opt {
            name: "type",
            kind: Kind::Value,
            metavar: "TYPE",
            help: "Continuity TLV type; 0x05 = AirDrop. Anything else is a plumbing test",
        },
        Opt {
            name: "hashes",
            kind: Kind::Value,
            metavar: "HASHES",
            help: "four 2-byte contact hashes, hex; overrides the selected identity",
        },
        Opt {
            name: "hashes-from-record",
            kind: Kind::Optional,
            metavar: "RECORD",
            help: "research override: derive hashes from a disk record (default ~/.omdrop/keys/validation_record.cms)",
        },
        Opt {
            name: "seconds",
            kind: Kind::Value,
            metavar: "SECONDS",
            help: "default 120",
        },
        Opt {
            name: "interval-ms",
            kind: Kind::Value,
            metavar: "INTERVAL_MS",
            help: "default 100",
        },
        Opt {
            name: "broadcast",
            kind: Kind::Flag,
            metavar: "",
            help: "non-connectable (default: connectable, like Apple)",
        },
        Opt {
            name: "adapter",
            kind: Kind::Value,
            metavar: "ADAPTER",
            help: "default hci0",
        },
    ],
};

fn parse_ble(args: &[String]) -> Result<BleOptions, Exit> {
    let p = BLE.parse(args)?;
    let b = &BLE;
    let arm_text = p.value("arm").unwrap_or("A");
    let arm = Arm::parse(arm_text).ok_or_else(|| {
        b.error(&format!(
            "argument --arm: invalid choice: '{arm_text}' (choose from 'A', 'V2', 'B')"
        ))
    })?;
    let type_text = p.value("type").unwrap_or("0x05").to_owned();
    let tlv_type = py_int_auto(&type_text)
        .and_then(|v| u8::try_from(v).ok())
        .ok_or_else(|| b.error(&format!("argument --type: not a byte: '{type_text}'")))?;
    let adapter = p.value("adapter").unwrap_or("hci0").to_owned();
    if !ble::valid_adapter(&adapter) {
        return Err(b.error(&format!(
            "argument --adapter: invalid adapter name '{adapter}'"
        )));
    }
    Ok(BleOptions {
        arm,
        tag: p.value("tag").map(str::to_owned),
        type_text,
        tlv_type,
        hashes: p.value("hashes").map(str::to_owned),
        hashes_from_record: p
            .optional("hashes-from-record")
            .map(|v| v.map(PathBuf::from)),
        seconds: int_arg(&p, b, "seconds", 120, 0, i128::from(u32::MAX))? as u32,
        interval_ms: int_arg(&p, b, "interval-ms", 100, 0, i128::from(u32::MAX))? as u32,
        broadcast: p.flag("broadcast"),
        adapter,
    })
}

/// Block SIGINT and SIGTERM in this thread (and every thread it starts from
/// now on) and deliver them as [`Event::Signal`] from a dedicated thread, so
/// a stop unregisters the advert instead of killing the process mid-air.
fn forward_stop_signals(tx: Sender<Event>) -> io::Result<()> {
    // SAFETY: sigset_t is plain old data and is initialised by sigemptyset
    // before use; every pointer passed is to a live local.
    let set = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        set
    };
    // SAFETY: `set` is initialised; a null old-set pointer is allowed.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    std::thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            loop {
                let mut sig: libc::c_int = 0;
                // SAFETY: `set` is initialised and `sig` is a valid out pointer.
                let rc = unsafe { libc::sigwait(&set, &mut sig) };
                if rc == 0 && tx.send(Event::Signal).is_err() {
                    return;
                }
            }
        })?;
    Ok(())
}

/// `omdrop-adv ble` (`ble-airdrop-adv.py`).
pub fn ble(args: &[String]) -> i32 {
    let opts = match parse_ble(args) {
        Ok(o) => o,
        Err(exit) => return exit.emit(),
    };
    let stamper = Stamper::stdout();
    let resolve = || {
        omdrop_identity::resolve(&omdrop_identity::ResolveOptions {
            create: false,
            ..Default::default()
        })
    };
    let prep = match ble::prepare(&opts, &resolve, &mut io::stderr(), &stamper) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };
    let (tx, rx) = mpsc::channel();
    if let Err(e) = forward_stop_signals(tx.clone()) {
        eprintln!("omdrop-adv ble: signals: {e}");
        return 1;
    }
    let conn = zbus::blocking::connection::Builder::system()
        .map(|b| b.method_timeout(DBUS_TIMEOUT))
        .and_then(|b| b.build());
    let conn = match conn {
        Ok(c) => c,
        Err(e) => {
            eprintln!("omdrop-adv ble: system bus: {}", ble::dbus_error_text(&e));
            return 1;
        }
    };
    match ble::advertise(&conn, &opts, &prep, (tx, rx), &stamper) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("omdrop-adv ble: {msg}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn caller_argv_parses() {
        // omdrop-discoverable and send-to-peer, verbatim.
        let o = parse_announce(&argv(&[
            "--iface",
            "awdl0",
            "--count",
            "20",
            "--interval",
            "0.02",
            "--seq",
            "9000",
        ]))
        .ok()
        .unwrap();
        assert_eq!((o.count, o.seq, o.port, o.flags), (20, 9000, 8771, 0x3fb));
        assert!((o.interval - 0.02).abs() < 1e-12);
        let o = parse_announce(&argv(&[
            "--iface",
            "awdl0",
            "--count",
            "4",
            "--interval",
            "0.02",
            "--flags",
            "136",
            "--seq",
            "1200",
        ]))
        .ok()
        .unwrap();
        assert_eq!(o.flags, 136);
        let o = parse_mdns(&argv(&[
            "--iface", "awdl0", "--port", "8771", "--flags", "136",
        ]))
        .ok()
        .unwrap();
        assert_eq!((o.port, o.flags, o.burst), (8771, 136, 5));
        assert!((o.min_gap - 0.1).abs() < 1e-12);
        let o = parse_ble(&argv(&[
            "--arm",
            "A",
            "--seconds",
            "30",
            "--interval-ms",
            "100",
        ]))
        .ok()
        .unwrap();
        assert_eq!(
            (o.arm, o.seconds, o.interval_ms, o.tlv_type),
            (Arm::A, 30, 100, 5)
        );
        assert_eq!(o.type_text, "0x05");
        let o = parse_ble(&argv(&["--hashes-from-record"])).ok().unwrap();
        assert_eq!(o.hashes_from_record, Some(None));
    }

    #[test]
    fn hostile_arguments_are_refused_with_status_2() {
        let bad_announce: &[&[&str]] = &[
            &["--iface", "../../etc"],
            &["--iface", "a/b"],
            &["--port", "65536"],
            &["--port", "-1"],
            &["--flags", "-1"],
            &["--count", "-1"],
            &["--interval", "nan"],
            &["--interval", "-0.5"],
            &["--interval", "1e300"],
            &["--host", "héllo.local"],
            &["--host", &"a".repeat(64)],
            &["--service-id", "a\nb"],
            &["--seq", "x"],
        ];
        for a in bad_announce {
            assert_eq!(
                parse_announce(&argv(a)).err().map(|e| e.code),
                Some(2),
                "{a:?}"
            );
        }
        let bad_mdns: &[&[&str]] = &[
            &["--burst", "101"],
            &["--burst", "-1"],
            &["--min-gap", "inf"],
            &["--port", "70000"],
        ];
        for a in bad_mdns {
            assert_eq!(parse_mdns(&argv(a)).err().map(|e| e.code), Some(2), "{a:?}");
        }
        let bad_ble: &[&[&str]] = &[
            &["--arm", "C"],
            &["--type", "256"],
            &["--type", "05"],
            &["--type", "-1"],
            &["--adapter", "../hci0"],
            &["--seconds", "-1"],
            &["--interval-ms", "4294967296"],
        ];
        for a in bad_ble {
            assert_eq!(parse_ble(&argv(a)).err().map(|e| e.code), Some(2), "{a:?}");
        }
    }

    #[test]
    fn responder_matches_only_queries_from_others_for_our_names() {
        let mac = [2, 0, 0, 0, 0, 1];
        let ours = our_names("Mac-AWDL.local.", "A1B2C3D4E5F6");
        assert_eq!(
            ours.iter()
                .map(|n| py_repr(n))
                .collect::<Vec<_>>()
                .join(", "),
            "'_airdrop._tcp.local', 'a1b2c3d4e5f6._airdrop._tcp.local', 'mac-awdl.local'"
        );
        let query = |names: &[&str]| {
            let mut dns = vec![0, 0, 0, 0, 0, names.len() as u8, 0, 0, 0, 0, 0, 0];
            for n in names {
                dns.extend(frames::dname(n).unwrap());
                dns.extend([0, 1, 0, 1]);
            }
            dns
        };
        let frame = |src: [u8; 6], dns: &[u8]| {
            frames::wrap(
                src,
                &frames::udp6([0; 16], MDNS_GROUP.octets(), dns).unwrap(),
                1,
                true,
            )
            .unwrap()
        };
        let peer = [2, 9, 9, 9, 9, 9];
        let hit = wanted(
            &frame(peer, &query(&["other.local", "MAC-awdl.local"])),
            mac,
            &ours,
        );
        assert_eq!(hit, Some((peer, "mac-awdl.local".to_owned())));
        assert_eq!(
            wanted(&frame(mac, &query(&["mac-awdl.local"])), mac, &ours),
            None
        );
        assert_eq!(
            wanted(&frame(peer, &query(&["other.local"])), mac, &ours),
            None
        );
    }

    #[test]
    fn repr_quotes_like_python() {
        assert_eq!(py_repr("a'b"), "\"a'b\"");
        assert_eq!(py_repr("a'b\""), "'a\\'b\"'");
        assert_eq!(py_repr("a\\b"), "'a\\\\b'");
    }
}
