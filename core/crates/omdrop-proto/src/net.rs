//! Addresses on the AWDL interface.
//!
//! A link-local address is ambiguous without a zone, so every socket that
//! reaches a peer carries the interface's scope id: `fe80::1%awdl0`.

use std::ffi::CString;
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6};

/// The interface AirDrop traffic uses.
pub const AWDL_IFACE: &str = "awdl0";

/// The first IPv6 address the kernel lists on `iface`, from
/// `/proc/net/if_inet6`, or `None`.
pub fn interface_ipv6(iface: &str) -> Option<Ipv6Addr> {
    let text = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    parse_if_inet6(&text, iface)
}

fn parse_if_inet6(text: &str, iface: &str) -> Option<Ipv6Addr> {
    text.lines().find_map(|line| {
        let row: Vec<&str> = line.split_whitespace().collect();
        if row.len() != 6 || row[5] != iface || row[0].len() != 32 {
            return None;
        }
        let mut octets = [0u8; 16];
        for (i, octet) in octets.iter_mut().enumerate() {
            *octet = u8::from_str_radix(row[0].get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        Some(Ipv6Addr::from(octets))
    })
}

/// The interface index of `iface`, as a socket scope id.
pub fn scope_id(iface: &str) -> io::Result<u32> {
    let name = CString::new(iface).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `name` is a valid NUL-terminated string for the call's duration.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}

/// Parse a MAC address, `aa:bb:cc:dd:ee:ff` (case-insensitive).
pub fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = mac.split(':');
    for byte in &mut out {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 2 {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// MAC -> EUI-64 link-local, the address an Apple peer answers on: `fe80::`
/// plus the MAC with its universal/local bit flipped and `ff:fe` in the
/// middle. `e2:9d:03:6c:58:23` -> `fe80::e09d:3ff:fe6c:5823`.
pub fn eui64_link_local(mac: [u8; 6]) -> Ipv6Addr {
    let [a, b, c, d, e, f] = mac;
    Ipv6Addr::from([
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
    ])
}

/// `addr` on `port`, scoped to `iface` when it is link-local. Other addresses
/// (`::1` in tests) carry no scope.
pub fn scoped(addr: Ipv6Addr, port: u16, iface: &str) -> io::Result<SocketAddrV6> {
    let scope = if addr.is_unicast_link_local() {
        scope_id(iface)?
    } else {
        0
    };
    Ok(SocketAddrV6::new(addr, port, 0, scope))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_matches_what_a_mac_reports_for_itself() {
        let mac = parse_mac("e2:9d:03:6c:58:23").unwrap();
        assert_eq!(
            eui64_link_local(mac).to_string(),
            "fe80::e09d:3ff:fe6c:5823"
        );
    }

    #[test]
    fn mac_parsing_rejects_malformed_input() {
        for bad in [
            "",
            "e2:9d:03:6c:58",
            "e2:9d:03:6c:58:23:00",
            "e2:9d:03:6c:58:2g",
            "e2::03:6c:58:23",
            "e2:9d:03:6c:58:123",
        ] {
            assert_eq!(parse_mac(bad), None, "{bad}");
        }
        assert_eq!(
            parse_mac("E2:9D:3:6C:58:23"),
            Some([0xe2, 0x9d, 0x03, 0x6c, 0x58, 0x23])
        );
    }

    #[test]
    fn if_inet6_picks_the_named_interface() {
        let text = "00000000000000000000000000000001 01 80 10 80       lo\n\
                    fe80000000000000e09d03fffe6c5823 05 40 20 80    awdl0\n";
        assert_eq!(
            parse_if_inet6(text, "awdl0"),
            Some("fe80::e09d:3ff:fe6c:5823".parse().unwrap())
        );
        assert_eq!(parse_if_inet6(text, "wlan0"), None);
    }
}
