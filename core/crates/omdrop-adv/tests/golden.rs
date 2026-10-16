//! Byte-for-byte parity with the Python advertisers.
//!
//! `tests/golden/python.json` and the `record-*.cms` files are produced by
//! `tests/golden/generate.py`, which imports the Python programs and calls
//! their builders on fixed inputs (it never calls their `main()` except
//! `awdl-airdrop-adv.py --dump`, which only prints).

use std::path::{Path, PathBuf};
use std::process::Command;

use omdrop_adv::ble::{self, Arm};
use omdrop_adv::{frames, mdns};
use serde_json::Value;

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn golden() -> Value {
    let text = std::fs::read_to_string(golden_dir().join("python.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn mac(v: &Value) -> [u8; 6] {
    unhex(s(v)).try_into().unwrap()
}

#[test]
fn ble_payload_and_redaction() {
    let g = golden();
    let cases = g["ble_payload"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for c in cases {
        let arm = Arm::parse(s(&c["arm"])).unwrap();
        let ty = c["type"].as_u64().unwrap() as u8;
        let value = ble::payload(arm, ty, s(&c["hashes"]), s(&c["tag"])).unwrap();
        assert_eq!(hex(&value), s(&c["value"]), "{c}");
        assert_eq!(ble::redact(&value), s(&c["redacted"]), "{c}");
    }
    for c in g["ble_payload_errors"].as_array().unwrap() {
        let err = ble::payload(Arm::A, 5, s(&c["hashes"]), s(&c["tag"])).unwrap_err();
        assert_eq!(err, s(&c["error"]));
    }
}

#[test]
fn ble_hashes_from_signed_records() {
    let g = golden();
    let cases = g["ble_records"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for c in cases {
        let record = std::fs::read(golden_dir().join(s(&c["file"]))).unwrap();
        let got = ble::hashes_from_record(&record);
        match c.get("error") {
            Some(e) => assert_eq!(got.unwrap_err(), s(e), "{c}"),
            None => {
                let (hashes, n) = got.unwrap();
                assert_eq!(hashes, s(&c["hashes"]), "{c}");
                assert_eq!(n as u64, c["identifiers"].as_u64().unwrap(), "{c}");
            }
        }
    }
}

#[test]
fn small_builders() {
    let g = golden();
    for c in g["eui64"].as_array().unwrap() {
        assert_eq!(hex(&frames::eui64_ll(mac(&c["mac"]))), s(&c["ll"]));
    }
    for c in g["dname"].as_array().unwrap() {
        assert_eq!(
            hex(&frames::dname(s(&c["name"])).unwrap()),
            s(&c["wire"]),
            "{c}"
        );
    }
    for c in g["csum16"].as_array().unwrap() {
        assert_eq!(
            u64::from(frames::csum16(&unhex(s(&c["data"])))),
            c["sum"].as_u64().unwrap(),
            "{c}"
        );
    }
    for c in g["rr"].as_array().unwrap() {
        let wire = frames::rr(
            s(&c["name"]),
            c["type"].as_u64().unwrap() as u16,
            c["class"].as_u64().unwrap() as u16,
            c["ttl"].as_u64().unwrap() as u32,
            &unhex(s(&c["rdata"])),
        )
        .unwrap();
        assert_eq!(hex(&wire), s(&c["wire"]), "{c}");
    }
}

#[test]
fn announcement_frames_and_responder_reply() {
    let g = golden();
    let cases = g["announcement"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for c in cases {
        let m = mac(&c["mac"]);
        let ll = frames::eui64_ll(m);
        let (sid, host) = (s(&c["sid"]), s(&c["host"]));
        let port = c["port"].as_u64().unwrap() as u16;
        let flags = c["flags"].as_u64().unwrap();
        let msg = frames::announcement(sid, host, port, flags, ll).unwrap();
        assert_eq!(hex(&msg), s(&c["announcement"]), "{sid}");
        let payload = frames::udp6(ll, frames::MDNS_GROUP.octets(), &msg).unwrap();
        assert_eq!(hex(&payload), s(&c["udp6"]), "{sid}");
        for f in c["snap"].as_array().unwrap() {
            let seq = f["seq"].as_u64().unwrap() as u16;
            assert_eq!(
                hex(&frames::wrap(m, &payload, seq, true).unwrap()),
                s(&f["frame"]),
                "{sid} {seq}"
            );
        }
        assert_eq!(
            hex(&frames::wrap(m, &payload, 7, false).unwrap()),
            s(&c["plain"]),
            "{sid}"
        );
        let reply = frames::reply(sid, host, port, flags, ll).unwrap();
        assert_eq!(hex(&reply), s(&c["reply"]), "{sid}");
        let reply6 = frames::udp6(ll, frames::MDNS_GROUP.octets(), &reply).unwrap();
        assert_eq!(hex(&reply6), s(&c["reply_udp6"]), "{sid}");
    }
}

#[test]
fn announce_dump_text_matches_python_main() {
    if !Path::new("/sys/class/net/lo/address").exists() {
        eprintln!("skipped: no /sys/class/net/lo");
        return;
    }
    let g = golden();
    for c in g["announce_dump"].as_array().unwrap() {
        let argv: Vec<&str> = c["argv"].as_array().unwrap().iter().map(s).collect();
        let out = Command::new(env!("CARGO_BIN_EXE_omdrop-adv"))
            .arg("announce")
            .args(&argv)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{argv:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            s(&c["stdout"]),
            "{argv:?}"
        );
    }
}

#[test]
fn query_parsing_matches_python() {
    let g = golden();
    for c in g["questions"].as_array().unwrap() {
        let names: Vec<String> = c["names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| s(n).to_owned())
            .collect();
        assert_eq!(mdns::questions(&unhex(s(&c["dns"]))), names, "{c}");
    }
    for c in g["mdns_payload"].as_array().unwrap() {
        let frame = unhex(s(&c["frame"]));
        let got = mdns::mdns_payload(&frame).map(|(src, dns)| (hex(&src), hex(dns)));
        let want = c["src"]
            .as_str()
            .map(|src| (src.to_owned(), s(&c["dns"]).to_owned()));
        assert_eq!(got, want, "{c}");
    }
}
