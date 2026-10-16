//! `_airdrop._tcp.local` announcements in Apple's AWDL SNAP encapsulation
//! (`awdl-airdrop-adv.py`), shared by `announce` and the `mdns` responder.
//!
//! Record shape, from opendrop's `server.py:_init_service` and
//! `config.py:AirDropReceiverFlags`:
//!
//! ```text
//! PTR   _airdrop._tcp.local        -> <service_id>._airdrop._tcp.local
//! SRV   <service_id>._airdrop...   -> 0 0 <port> <host>.local
//! TXT   <service_id>._airdrop...   -> flags=<n>
//! AAAA  <host>.local               -> our IPv6 link-local
//! ```
//!
//! Sent as unsolicited authoritative responses, which is what an mDNS
//! announcement is. Names are uncompressed: Apple's parser handles that, and
//! compression would buy nothing but bugs.

use std::fmt;
use std::net::Ipv6Addr;

pub const APPLE_OUI: [u8; 3] = [0x00, 0x17, 0xf2];
pub const AWDL_PROTO: [u8; 2] = [0x08, 0x00];
pub const AWDL_MAGIC: [u8; 2] = [0x03, 0x04];
/// Class IN with the cache-flush bit.
pub const CACHE_FLUSH: u16 = 0x8001;
pub const ETH_P_IPV6: u16 = 0x86dd;
pub const MDNS_PORT: u16 = 5353;
/// `ff02::fb`, the mDNS group.
pub const MDNS_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
/// `33:33:00:00:00:fb`, the Ethernet multicast address of `ff02::fb`.
pub const MDNS_MAC: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb];
/// The AirDrop service type.
pub const SERVICE: &str = "_airdrop._tcp.local";

/// A frame that cannot be encoded: a bad name or a field out of range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildError(pub String);

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BuildError {}

/// The EUI-64 link-local address of `mac` (`fe80::` + U/L-flipped MAC with
/// `ff:fe` in the middle).
pub fn eui64_ll(mac: [u8; 6]) -> [u8; 16] {
    let [a, b, c, d, e, f] = mac;
    [
        0xfe,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0,
        a ^ 0x02,
        b,
        c,
        0xff,
        0xfe,
        d,
        e,
        f,
    ]
}

/// Check that `name` encodes as an uncompressed DNS name: printable ASCII,
/// labels of at most 63 bytes, at most 255 bytes on the wire. Empty labels
/// (leading, trailing or doubled dots) are skipped, as the encoder does.
pub fn check_name(name: &str) -> Result<(), BuildError> {
    if let Some(bad) = name.chars().find(|c| !(' '..='~').contains(c)) {
        return Err(BuildError(format!(
            "name {name:?}: character {bad:?} is not printable ASCII"
        )));
    }
    let mut wire = 1;
    for label in name.split('.').filter(|l| !l.is_empty()) {
        if label.len() > 63 {
            return Err(BuildError(format!(
                "name {name:?}: label longer than 63 bytes"
            )));
        }
        wire += 1 + label.len();
    }
    if wire > 255 {
        return Err(BuildError(format!(
            "name {name:?}: longer than 255 bytes encoded"
        )));
    }
    Ok(())
}

/// `name` as an uncompressed DNS name.
pub fn dname(name: &str) -> Result<Vec<u8>, BuildError> {
    check_name(name)?;
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        // check_name bounds every label to 63 bytes.
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(out)
}

/// One resource record.
pub fn rr(
    name: &str,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdata: &[u8],
) -> Result<Vec<u8>, BuildError> {
    let rdlen = u16::try_from(rdata.len())
        .map_err(|_| BuildError("record data longer than 65535 bytes".into()))?;
    let mut out = dname(name)?;
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&rclass.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&rdlen.to_be_bytes());
    out.extend_from_slice(rdata);
    Ok(out)
}

/// The Internet checksum (RFC 1071) of `data`, odd length padded with zero.
pub fn csum16(data: &[u8]) -> u16 {
    let (pairs, rest) = data.as_chunks::<2>();
    let mut sum: u64 = pairs
        .iter()
        .map(|&w| u64::from(u16::from_be_bytes(w)))
        .sum();
    if let [last] = rest {
        sum += u64::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // The fold leaves sum <= 0xffff.
    !(sum as u16)
}

/// The announcement: PTR + SRV + TXT + AAAA, QR=1 AA=1, no questions.
///
/// `flags` defaults to 0x3fb (1019) in the announcer, macOS's own default per
/// `sharingd [SDRapportBrowser defaultSFNodeFlags]`; `removeInvalidNodes:`
/// drops a node with neither SUPPORTS_PIPELINING (0x04) nor
/// SUPPORTS_MIXED_TYPES (0x08).
pub fn announcement(
    sid: &str,
    host: &str,
    port: u16,
    flags: u64,
    ll: [u8; 16],
) -> Result<Vec<u8>, BuildError> {
    let inst = format!("{sid}.{SERVICE}");
    let txt = format!("flags={flags}");
    let mut srv = Vec::with_capacity(6 + host.len() + 2);
    srv.extend_from_slice(&[0, 0, 0, 0]);
    srv.extend_from_slice(&port.to_be_bytes());
    srv.extend_from_slice(&dname(host)?);
    let mut txt_rdata = Vec::with_capacity(txt.len() + 1);
    // A u64 in decimal is at most 20 digits, so this fits in one byte.
    txt_rdata.push(txt.len() as u8);
    txt_rdata.extend_from_slice(txt.as_bytes());

    let mut out = Vec::with_capacity(256);
    // QR=1, AA=1. qdcount 0, ancount 4.
    for word in [0u16, 0x8400, 0, 4, 0, 0] {
        out.extend_from_slice(&word.to_be_bytes());
    }
    out.extend(rr(SERVICE, 12, 0x0001, 4500, &dname(&inst)?)?);
    out.extend(rr(&inst, 33, CACHE_FLUSH, 120, &srv)?);
    out.extend(rr(&inst, 16, CACHE_FLUSH, 4500, &txt_rdata)?);
    out.extend(rr(host, 28, CACHE_FLUSH, 120, &ll)?);
    Ok(out)
}

/// The responder's reply: the announcement plus an NSEC for `host`.
///
/// The queries observed were type 1 (A). We have no A record; RFC 6762 6.1
/// says to answer a query for a name we own but a type we lack with an NSEC
/// naming the types we do have (AAAA=28, NSEC=47), so the querier stops
/// waiting for an A.
pub fn reply(
    sid: &str,
    host: &str,
    port: u16,
    flags: u64,
    ll: [u8; 16],
) -> Result<Vec<u8>, BuildError> {
    let mut msg = announcement(sid, host, port, flags, ll)?;
    let mut rdata = dname(host)?;
    rdata.extend_from_slice(&[0x00, 0x06, 0, 0, 0, 0x08, 0, 0x01]);
    let nsec = rr(host, 47, CACHE_FLUSH, 120, &rdata)?;
    let ancount = msg
        .get(6..8)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .unwrap_or(0)
        .wrapping_add(1);
    if let Some(field) = msg.get_mut(6..8) {
        field.copy_from_slice(&ancount.to_be_bytes());
    }
    msg.extend(nsec);
    Ok(msg)
}

/// IPv6 + UDP 5353 -> 5353 around `payload`, hop limit 255, with checksum.
pub fn udp6(src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Result<Vec<u8>, BuildError> {
    let udp_len = u16::try_from(8 + payload.len())
        .map_err(|_| BuildError("UDP payload longer than 65527 bytes".into()))?;
    let mut sum = Vec::with_capacity(48 + payload.len());
    sum.extend_from_slice(&src);
    sum.extend_from_slice(&dst);
    sum.extend_from_slice(&u32::from(udp_len).to_be_bytes());
    sum.extend_from_slice(&[0, 0, 0, 17]);
    sum.extend_from_slice(&MDNS_PORT.to_be_bytes());
    sum.extend_from_slice(&MDNS_PORT.to_be_bytes());
    sum.extend_from_slice(&udp_len.to_be_bytes());
    sum.extend_from_slice(&[0, 0]);
    sum.extend_from_slice(payload);
    let ck = match csum16(&sum) {
        0 => 0xffff,
        ck => ck,
    };

    let mut out = Vec::with_capacity(48 + payload.len());
    out.extend_from_slice(&0x6000_0000u32.to_be_bytes());
    out.extend_from_slice(&udp_len.to_be_bytes());
    out.extend_from_slice(&[17, 255]);
    out.extend_from_slice(&src);
    out.extend_from_slice(&dst);
    out.extend_from_slice(&MDNS_PORT.to_be_bytes());
    out.extend_from_slice(&MDNS_PORT.to_be_bytes());
    out.extend_from_slice(&udp_len.to_be_bytes());
    out.extend_from_slice(&ck.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// The Ethernet frame to the mDNS group from `mac`: Apple's AWDL SNAP
/// encapsulation (`aa aa 03 | 00 17 f2 | 08 00 | 03 04 | seq LE | 00 00 |
/// 86 dd`), or plain Ethernet II (the negative control) when `snap` is false.
pub fn wrap(mac: [u8; 6], payload: &[u8], seq: u16, snap: bool) -> Result<Vec<u8>, BuildError> {
    let mut out = Vec::with_capacity(30 + payload.len());
    out.extend_from_slice(&MDNS_MAC);
    out.extend_from_slice(&mac);
    if !snap {
        out.extend_from_slice(&ETH_P_IPV6.to_be_bytes());
        out.extend_from_slice(payload);
        return Ok(out);
    }
    let body_len = u16::try_from(16 + payload.len())
        .map_err(|_| BuildError("SNAP body longer than 65535 bytes".into()))?;
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(&[0xaa, 0xaa, 0x03]);
    out.extend_from_slice(&APPLE_OUI);
    out.extend_from_slice(&AWDL_PROTO);
    out.extend_from_slice(&AWDL_MAGIC);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&ETH_P_IPV6.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_that_would_corrupt_the_frame_are_refused() {
        assert!(dname(&"a".repeat(63)).is_ok());
        assert!(dname(&"a".repeat(64)).is_err());
        let name =
            |last: usize| format!("{}.{}", vec!["a".repeat(63); 3].join("."), "a".repeat(last));
        assert!(dname(&name(61)).is_ok());
        assert_eq!(dname(&name(61)).unwrap().len(), 255);
        assert!(dname(&name(62)).is_err());
        assert!(dname("héllo.local").is_err());
        assert!(dname("a\nb.local").is_err());
        assert!(rr("x", 1, 1, 1, &vec![0; 65536]).is_err());
        assert!(udp6([0; 16], [0; 16], &vec![0; 65528]).is_err());
        assert!(wrap([0; 6], &vec![0; 65520], 0, true).is_err());
        assert!(wrap([0; 6], &vec![0; 65520], 0, false).is_ok());
    }

    #[test]
    fn checksum_verifies_to_zero() {
        let frame = udp6(
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8],
            MDNS_GROUP.octets(),
            b"abc",
        )
        .unwrap();
        let mut pseudo = frame[8..40].to_vec();
        pseudo.extend_from_slice(&11u32.to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        pseudo.extend_from_slice(&frame[40..]);
        assert_eq!(csum16(&pseudo), 0);
    }
}
