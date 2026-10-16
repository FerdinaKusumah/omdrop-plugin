//! AirDrop endpoints from `awdl-af-listen` output (`--af-log`), ported from
//! omdrop-awdl's `awdl-af-parse.py`.
//!
//! Input lines are `<epoch> <freq> <sa> <hexbody>`, the body starting at the
//! action frame's category byte: `7f 00 17 f2`, the AWDL fixed header, TLVs.
//! Service Response TLVs (type 2), from a Mac's MIF (2026-09-03):
//! `name_len(u16 LE, counts the type byte) | name | type(u8) | data_len(u16 LE)
//! | 2 unknown bytes | rdata`. Names end in AWDL's fixed dictionary:
//! `c0 07` = `_airdrop._tcp.local`, `c0 0a` = `_tcp.local`, `c0 0b` =
//! `_udp.local`, `c0 0c` = `local`, `c0 00` = end. The file is research
//! input, so every read is bounds-checked: a truncated frame yields what it
//! holds, never a crash.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::Path;

/// One AirDrop receiver seen in a frame.
#[derive(Clone, Debug, PartialEq)]
pub struct AfEndpoint {
    /// The service instance, a 12-hex id.
    pub id: String,
    pub port: u16,
    pub target: Option<String>,
    pub txt: Option<Vec<String>>,
    pub host: Option<String>,
    /// When the frame was heard (epoch seconds).
    pub ts: f64,
    /// The frame's source MAC.
    pub sa: String,
}

fn dict(code: u8) -> String {
    match code {
        0x00 => String::new(),
        0x07 => "_airdrop._tcp.local".into(),
        0x0a => "_tcp.local".into(),
        0x0b => "_udp.local".into(),
        0x0c => "local".into(),
        c => format!("<c0{c:02x}>"),
    }
}

/// DNS-style labels with AWDL's `c0xx` dictionary tail: (name, next offset).
fn name(b: &[u8], mut off: usize) -> (String, usize) {
    let mut labels = Vec::new();
    while let Some(&l) = b.get(off) {
        if l == 0xc0 {
            // A truncated frame ends the name where it stops.
            let tail = b.get(off + 1).map(|&c| dict(c)).unwrap_or_default();
            if !tail.is_empty() {
                labels.push(tail);
            }
            return (labels.join("."), off + 2);
        }
        if l == 0 {
            return (labels.join("."), off + 1);
        }
        let end = (off + 1 + l as usize).min(b.len());
        labels.push(String::from_utf8_lossy(b.get(off + 1..end).unwrap_or_default()).into_owned());
        off += 1 + l as usize;
    }
    (labels.join("."), off)
}

fn u16_le(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

fn u16_be(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Service {
    ptr: Option<String>,
    srv: Option<(u16, String)>,
    txt: Option<Vec<String>>,
}

#[derive(Debug, Default)]
struct Record {
    host: Option<String>,
    services: HashMap<String, Service>,
}

/// One Service Response record: its owner name and what it says. `None` for
/// a malformed record, which is skipped as Python's struct/IndexError catch
/// skipped it.
fn service_response(v: &[u8]) -> Option<(String, Service)> {
    let nlen = u16_le(v, 0)? as usize;
    let (n, _) = name(v, 2);
    let off = (2 + nlen).checked_sub(1)?;
    let rtype = *v.get(off)?;
    let dlen = u16_le(v, off + 1)? as usize;
    let start = off + 5;
    let rd = v
        .get(start..(start + dlen).min(v.len()))
        .unwrap_or_default();
    let mut val = Service::default();
    match rtype {
        12 => val.ptr = Some(name(rd, 0).0),
        33 => val.srv = Some((u16_be(rd, 4)?, name(rd, 6).0)),
        16 => {
            let mut txt = Vec::new();
            let mut j = 0;
            while let Some(&l) = rd.get(j) {
                let end = (j + 1 + l as usize).min(rd.len());
                txt.push(
                    String::from_utf8_lossy(rd.get(j + 1..end).unwrap_or_default()).into_owned(),
                );
                j += 1 + l as usize;
            }
            val.txt = Some(txt);
        }
        _ => {}
    }
    Some((n, val))
}

fn parse_body(body: &[u8]) -> Option<Record> {
    if body.get(..4)? != [0x7f, 0x00, 0x17, 0xf2] {
        return None;
    }
    // awdl_hdr_t: magic 08, version 10, subtype, reserved, phy_tx(4), target_tx(4).
    let hdr = body.get(4..16)?;
    if hdr.first() != Some(&0x08) {
        return None;
    }
    let mut rec = Record::default();
    let tlvs = body.get(16..).unwrap_or_default();
    let mut i = 0;
    while i + 3 <= tlvs.len() {
        let t = tlvs[i];
        let l = u16_le(tlvs, i + 1).unwrap_or(0) as usize;
        let v = tlvs
            .get(i + 3..(i + 3 + l).min(tlvs.len()))
            .unwrap_or_default();
        if t == 16 && v.len() > 1 {
            rec.host = Some(name(v, 1).0);
        } else if t == 2 && v.len() > 5 {
            if let Some((n, val)) = service_response(v) {
                let entry = rec.services.entry(n).or_default();
                entry.ptr = val.ptr.or(entry.ptr.take());
                entry.srv = val.srv.or(entry.srv.take());
                entry.txt = val.txt.or(entry.txt.take());
            }
        }
        i += 3 + l;
    }
    Some(rec)
}

/// The AirDrop receiver in a parsed frame: its instance id and record.
fn airdrop_endpoint(rec: &Record) -> Option<(String, Service)> {
    let ptr = rec
        .services
        .get("_airdrop._tcp.local")?
        .ptr
        .clone()
        .filter(|p| !p.is_empty())?;
    let inst = rec
        .services
        .get(&ptr)
        .or_else(|| rec.services.get(&format!("{ptr}._airdrop._tcp.local")))
        .cloned()
        .unwrap_or_default();
    Some((ptr.split('.').next().unwrap_or("").to_owned(), inst))
}

/// The newest AirDrop endpoint per source MAC, newest first. Lines that do
/// not parse are skipped.
pub fn endpoints_from_text(text: &str) -> Vec<AfEndpoint> {
    let mut eps: BTreeMap<String, AfEndpoint> = BTreeMap::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let [ts, _freq, sa, hexbody, ..] = parts.as_slice() else {
            continue;
        };
        let Some(body) = from_hex(hexbody) else {
            continue;
        };
        let Ok(ts) = ts.parse::<f64>() else { continue };
        let Some(rec) = parse_body(&body) else {
            continue;
        };
        let Some((id, inst)) = airdrop_endpoint(&rec) else {
            continue;
        };
        let Some((port, target)) = inst.srv.filter(|(port, _)| *port != 0) else {
            continue;
        };
        let host = rec.host.clone();
        eps.insert(
            (*sa).to_owned(),
            AfEndpoint {
                id,
                port,
                target: Some(target),
                txt: inst.txt,
                host,
                ts,
                sa: (*sa).to_owned(),
            },
        );
    }
    let mut out: Vec<AfEndpoint> = eps.into_values().collect();
    out.sort_by(|a, b| b.ts.total_cmp(&a.ts));
    out
}

/// [`endpoints_from_text`] of a file.
pub fn endpoints_from_af_log(path: &Path) -> std::io::Result<Vec<AfEndpoint>> {
    let bytes = std::fs::read(path)?;
    Ok(endpoints_from_text(&String::from_utf8_lossy(&bytes)))
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(t: u8, v: &[u8]) -> Vec<u8> {
        let mut out = vec![t];
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(v);
        out
    }

    fn service(name: &[u8], rtype: u8, rdata: &[u8]) -> Vec<u8> {
        let mut v = ((name.len() + 1) as u16).to_le_bytes().to_vec();
        v.extend_from_slice(name);
        v.push(rtype);
        v.extend_from_slice(&(rdata.len() as u16).to_le_bytes());
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(rdata);
        v
    }

    fn frame() -> Vec<u8> {
        let mut body = vec![
            0x7f, 0x00, 0x17, 0xf2, 0x08, 0x10, 0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        body.extend(tlv(16, b"\x00\x04hume\xc0\x0c"));
        // PTR _airdrop._tcp.local -> 0e9d036c5823
        body.extend(tlv(
            2,
            &service(b"\xc0\x07", 12, b"\x0c0e9d036c5823\xc0\x00"),
        ));
        // SRV 0e9d036c5823._airdrop._tcp.local -> port 8770, hume.local
        let mut srv = vec![0, 0, 0, 0, 0x22, 0x42];
        srv.extend_from_slice(b"\x04hume\xc0\x0c");
        body.extend(tlv(2, &service(b"\x0c0e9d036c5823\xc0\x07", 33, &srv)));
        body.extend(tlv(
            2,
            &service(b"\x0c0e9d036c5823\xc0\x07", 16, b"\x09flags=987"),
        ));
        body
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn newest_endpoint_per_source_wins_and_sorts_first() {
        let f = hex(&frame());
        let text = format!(
            "100.0 5745 aa:aa:aa:aa:aa:aa {f}\n\
             garbage line\n\
             101.0 5745 bb:bb:bb:bb:bb:bb {f}\n\
             102.0 5745 aa:aa:aa:aa:aa:aa {f}\n\
             103.0 5745 cc:cc:cc:cc:cc:cc zz\n"
        );
        let eps = endpoints_from_text(&text);
        assert_eq!(eps.len(), 2);
        assert_eq!(eps[0].sa, "aa:aa:aa:aa:aa:aa");
        assert_eq!(eps[0].ts, 102.0);
        assert_eq!(eps[0].id, "0e9d036c5823");
        assert_eq!(eps[0].port, 8770);
        assert_eq!(eps[0].target.as_deref(), Some("hume.local"));
        assert_eq!(eps[0].host.as_deref(), Some("hume.local"));
        assert_eq!(eps[0].txt.as_deref(), Some(&["flags=987".to_owned()][..]));
    }

    #[test]
    fn truncated_frames_never_panic() {
        let full = frame();
        for cut in 0..full.len() {
            let _ = endpoints_from_text(&format!("1 2 aa:aa:aa:aa:aa:aa {}\n", hex(&full[..cut])));
        }
    }
}
