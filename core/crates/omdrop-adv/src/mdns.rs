//! Parsing of received mDNS queries on awdl0 (`awdl-mdns-respond.py`).
//!
//! Everything here reads frames from the air in a root process, so every
//! access is bounds-checked and a malformed frame is simply not a query.

use crate::frames::{APPLE_OUI, AWDL_PROTO, ETH_P_IPV6, MDNS_PORT};

/// Compression pointers followed before a name is declared a loop.
const MAX_HOPS: u32 = 16;

fn be16(buf: &[u8], at: usize) -> Option<u16> {
    let b = buf.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

/// Read a possibly compressed DNS name at `off`: the lowercased name, labels
/// joined with `.` (non-ASCII bytes become U+FFFD), and the offset after it.
pub fn dns_name(pkt: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut next = None;
    let mut hops = 0;
    loop {
        let n = *pkt.get(off)?;
        if n == 0 {
            off += 1;
            break;
        }
        if n & 0xc0 == 0xc0 {
            // The Python original indexed the second pointer byte unchecked,
            // so a frame ending in 0xc0 killed the responder.
            let low = *pkt.get(off + 1)?;
            next.get_or_insert(off + 2);
            off = (usize::from(n & 0x3f) << 8) | usize::from(low);
            hops += 1;
            if hops > MAX_HOPS {
                return None;
            }
            continue;
        }
        let start = off + 1;
        let label = pkt.get(start..start + usize::from(n))?;
        labels.push(
            label
                .iter()
                .map(|&b| {
                    if b.is_ascii() {
                        char::from(b.to_ascii_lowercase())
                    } else {
                        '\u{fffd}'
                    }
                })
                .collect(),
        );
        off = start + usize::from(n);
    }
    Some((labels.join("."), next.unwrap_or(off)))
}

/// The question names of an mDNS query, or nothing if `dns` is not a query or
/// any question is malformed. A missing type/class after the last name is
/// tolerated, as it was.
pub fn questions(dns: &[u8]) -> Vec<String> {
    let (Some(flags), Some(qd)) = (be16(dns, 2), be16(dns, 4)) else {
        return Vec::new();
    };
    if dns.len() < 12 || flags & 0x8000 != 0 || qd == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut off = 12;
    for _ in 0..qd {
        let Some((name, after)) = dns_name(dns, off) else {
            return Vec::new();
        };
        off = after + 4; // qtype, qclass
        out.push(name);
    }
    out
}

/// `(source MAC, DNS bytes)` for an IPv6/UDP frame to port 5353, plain or
/// Apple-SNAP wrapped; `None` for anything else.
///
/// Frames normally arrive decapsulated (eth:ipv6:udp) thanks to the driver's
/// `brcmf_rx_eth_type_trans`; SNAP-wrapped ones are handled too.
pub fn mdns_payload(frame: &[u8]) -> Option<([u8; 6], &[u8])> {
    let src: [u8; 6] = frame.get(6..12)?.try_into().ok()?;
    let etype = be16(frame, 12)?;
    let off = if etype == ETH_P_IPV6 {
        14
    } else if etype <= 1500 && frame.get(14..17) == Some(&[0xaa, 0xaa, 0x03][..]) {
        // 802.2 SNAP: aa aa 03 | 00 17 f2 | 08 00 | 03 04 | seq(2) | 00 00 | 86 dd
        let oui_pid = frame.get(17..22)?;
        if oui_pid.get(..3)? != APPLE_OUI || oui_pid.get(3..)? != AWDL_PROTO {
            return None;
        }
        if be16(frame, 28)? != ETH_P_IPV6 {
            return None;
        }
        30
    } else {
        return None;
    };
    let ip6 = frame.get(off..off + 40)?;
    if ip6.get(6) != Some(&17) {
        return None;
    }
    let udp = frame.get(off + 40..off + 48)?;
    if be16(udp, 2)? != MDNS_PORT {
        return None;
    }
    Some((src, frame.get(off + 48..)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(qd: u16) -> Vec<u8> {
        let mut h = vec![0, 0, 0, 0];
        h.extend_from_slice(&qd.to_be_bytes());
        h.extend_from_slice(&[0; 6]);
        h
    }

    #[test]
    fn dangling_pointer_byte_is_malformed_not_a_crash() {
        let mut pkt = header(1);
        pkt.push(0xc0);
        assert!(questions(&pkt).is_empty());
        assert!(dns_name(&pkt, 12).is_none());
    }

    #[test]
    fn pointer_loops_and_long_chains_stop() {
        // Two pointers at each other.
        let mut pkt = header(1);
        pkt.extend_from_slice(&[0xc0, 14, 0xc0, 12]);
        assert!(questions(&pkt).is_empty());
        // Sixteen hops are allowed, seventeen are not.
        for (hops, ok) in [(16, true), (17, false)] {
            let mut pkt = header(1);
            let base = pkt.len();
            for i in 0..hops {
                let target = base + 2 * (i + 1);
                pkt.extend_from_slice(&[0xc0 | (target >> 8) as u8, target as u8]);
            }
            pkt.push(0);
            assert_eq!(dns_name(&pkt, base).is_some(), ok, "{hops} hops");
        }
    }

    #[test]
    fn pointer_beyond_packet_is_malformed() {
        let mut pkt = header(1);
        pkt.extend_from_slice(&[0xff, 0xff]);
        assert!(questions(&pkt).is_empty());
    }

    #[test]
    fn deterministic_garbage_never_panics() {
        // A small xorshift: reproducible, no dependency, and it reaches labels,
        // pointers and truncation at every offset.
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..20_000 {
            let len = (next() % 160) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if round % 2 == 0 && buf.len() > 14 {
                // Bias half the inputs into the parsers' deeper branches.
                buf[2] &= 0x7f;
                buf[12] = if round % 4 == 0 { 0x86 } else { 0x00 };
                buf[13] = if round % 4 == 0 { 0xdd } else { 0x40 };
            }
            let _ = questions(&buf);
            let _ = mdns_payload(&buf);
            for off in 0..buf.len() + 2 {
                let _ = dns_name(&buf, off);
            }
            for cut in 0..buf.len() {
                let _ = questions(&buf[..cut]);
                let _ = mdns_payload(&buf[..cut]);
            }
        }
    }

    #[test]
    fn many_questions_are_bounded_by_the_packet() {
        let mut pkt = header(u16::MAX);
        pkt.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        assert!(questions(&pkt).is_empty());
    }
}
