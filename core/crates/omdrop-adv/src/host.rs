//! Machine identity and tunables shared by the AWDL helpers (`awdl_identity.py`).
//!
//! Nothing here is baked in. The AWDL address, the infrastructure address and
//! the advertised hostname belong to the machine this runs on, and the channel
//! knobs to the room it is in: a helper that hardcodes any of them ships one
//! laptop's configuration to everybody. They are read from the running system
//! and overridden per machine from `$OMDROP_CONF` (default `/etc/omdrop`).

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// The configuration directory: `$OMDROP_CONF`, or `/etc/omdrop`.
pub fn conf_dir() -> PathBuf {
    std::env::var_os("OMDROP_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/omdrop"))
}

/// The AWDL interface: `$OMDROP_AWDL_IFACE`, or `awdl0`.
pub fn awdl_iface() -> String {
    std::env::var("OMDROP_AWDL_IFACE").unwrap_or_else(|_| "awdl0".to_owned())
}

/// Knob files are one line; anything past this is not a knob.
const KNOB_MAX: u64 = 64 * 1024;

/// One line of configuration from `$OMDROP_CONF/<name>`, or `default` when the
/// file is missing, unreadable, not UTF-8 or blank.
pub fn knob(name: &str, default: &str) -> String {
    knob_in(&conf_dir(), name, default)
}

fn knob_in(dir: &Path, name: &str, default: &str) -> String {
    let mut text = String::new();
    let read =
        fs::File::open(dir.join(name)).and_then(|f| f.take(KNOB_MAX).read_to_string(&mut text));
    match read {
        Ok(_) if !text.trim().is_empty() => text.trim().to_owned(),
        _ => default.to_owned(),
    }
}

/// True when `$OMDROP_CONF/<name>` exists: the diagnostic on/off files.
pub fn switch(name: &str) -> bool {
    conf_dir().join(name).exists()
}

/// Whether `name` is a name the kernel accepts for a network interface
/// (`dev_valid_name`). Interface names reach `/sys/class/net/<name>/...` paths
/// in programs that run as root, so nothing else gets that far.
pub fn valid_iface(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name != "."
        && name != ".."
        && !name
            .bytes()
            .any(|b| b == b'/' || b == b':' || b.is_ascii_whitespace() || b == 0)
}

/// Parse `aa:bb:cc:dd:ee:ff` (colons optional, surrounding whitespace ignored).
pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let hex: Vec<u8> = text.trim().bytes().filter(|&b| b != b':').collect();
    if hex.len() != 12 {
        return None;
    }
    let mut mac = [0u8; 6];
    let (pairs, _) = hex.as_chunks::<2>();
    for (slot, &[h, l]) in mac.iter_mut().zip(pairs) {
        let hi = char::from(h).to_digit(16)?;
        let lo = char::from(l).to_digit(16)?;
        *slot = (hi * 16 + lo) as u8;
    }
    Some(mac)
}

/// The MAC of `iface`, from `/sys/class/net/<iface>/address`.
pub fn mac_of(iface: &str) -> io::Result<[u8; 6]> {
    mac_in(Path::new("/sys/class/net"), iface)
}

fn mac_in(root: &Path, iface: &str) -> io::Result<[u8; 6]> {
    if !valid_iface(iface) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid interface name {iface:?}"),
        ));
    }
    let path = root.join(iface).join("address");
    let mut text = String::new();
    fs::File::open(&path)?.take(256).read_to_string(&mut text)?;
    parse_mac(&text).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: not a MAC address", path.display()),
        )
    })
}

/// The Wi-Fi interface AWDL shares the radio with.
///
/// Found rather than assumed: it is `wlan0` on a stock Arch install and `wld0`
/// on machines carrying a naming rule. Picks the first Broadcom FullMAC
/// wireless netdev; `$OMDROP_INFRA_IFACE` or `$OMDROP_CONF/infra-iface`
/// override it on a machine with two. Empty when there is none.
pub fn infra_iface() -> String {
    let forced = std::env::var("OMDROP_INFRA_IFACE").unwrap_or_default();
    let forced = if forced.is_empty() {
        knob("infra-iface", "")
    } else {
        forced
    };
    if !forced.is_empty() {
        return forced;
    }
    infra_in(Path::new("/sys/class/net"), &awdl_iface())
}

fn infra_in(root: &Path, awdl: &str) -> String {
    let Ok(entries) = fs::read_dir(root) else {
        return String::new();
    };
    let mut names: Vec<OsString> = entries
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();
    names.sort();
    for name in names {
        let Some(name) = name.to_str() else { continue };
        if name == awdl {
            continue;
        }
        let base = root.join(name);
        if !base.join("phy80211").is_dir() {
            continue;
        }
        let Ok(driver) = fs::read_link(base.join("device/driver")) else {
            continue;
        };
        let is_brcm = driver
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("brcmfmac"));
        if is_brcm {
            return name.to_owned();
        }
    }
    String::new()
}

/// The infrastructure MAC a PSF advertises, or six zero bytes.
///
/// Zeros rather than an error: the field is one TLV of a frame still worth
/// sending, and refusing to build it because the STA interface went away
/// mid-window is a worse failure than advertising an unset address.
pub fn infra_mac() -> [u8; 6] {
    let iface = infra_iface();
    if iface.is_empty() {
        return [0; 6];
    }
    mac_of(&iface).unwrap_or([0; 6])
}

/// The hostname this machine publishes over AWDL, without `.local`.
///
/// A Mac resolves the Arpa name out of our PSF and then queries mDNS for it,
/// so the announcer, the responder and the PSF template must agree; they agree
/// by all calling this. Distinct from the system hostname because the name
/// only ever resolves to an awdl0 link-local address.
pub fn awdl_host() -> String {
    let forced = std::env::var("OMDROP_AWDL_HOST").unwrap_or_default();
    let forced = if forced.is_empty() {
        knob("awdl-host", "")
    } else {
        forced
    };
    host_from(&forced, &system_hostname())
}

/// `awdl_host` without the environment: `forced` wins, else a label derived
/// from the system hostname.
///
/// DNS labels are letters, digits and hyphen. The hostname is user-supplied
/// text that goes on air inside an Arpa TLV, so anything else is dropped rather
/// than encoded: a label the peer cannot parse loses the whole service record.
pub fn host_from(forced: &str, hostname: &str) -> String {
    if !forced.is_empty() {
        let trimmed = forced.trim_end_matches('.');
        return trimmed.strip_suffix(".local").unwrap_or(trimmed).to_owned();
    }
    let short = hostname.split('.').next().unwrap_or("").to_lowercase();
    let label: String = short
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
        .collect();
    let label = label.trim_matches('-');
    if label.is_empty() {
        "omdrop-awdl".to_owned()
    } else {
        format!("{label}-awdl")
    }
}

fn system_hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is a valid writable buffer of the length passed; the
    // kernel writes at most that many bytes.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return String::new();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(buf.get(..end).unwrap_or(&[])).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knob_reads_one_trimmed_line_or_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("set"), "  6 \n").unwrap();
        fs::write(dir.path().join("blank"), " \n").unwrap();
        fs::write(dir.path().join("binary"), [0xff, 0xfe]).unwrap();
        assert_eq!(knob_in(dir.path(), "set", "x"), "6");
        assert_eq!(knob_in(dir.path(), "blank", "x"), "x");
        assert_eq!(knob_in(dir.path(), "binary", "x"), "x");
        assert_eq!(knob_in(dir.path(), "absent", "x"), "x");
    }

    #[test]
    fn interface_names_cannot_escape_sysfs() {
        for bad in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            "a:b",
            "a b",
            "0123456789abcdef",
        ] {
            assert!(!valid_iface(bad), "{bad:?}");
        }
        for good in ["awdl0", "wlan0", "wld0", "0123456789abcde"] {
            assert!(valid_iface(good), "{good:?}");
        }
        let dir = tempfile::tempdir().unwrap();
        let err = mac_in(dir.path(), "../etc").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn mac_reads_sysfs_format_and_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        for (iface, text) in [
            ("ok", "a1:b2:c3:d4:e5:f6\n"),
            ("short", "a1:b2\n"),
            ("junk", "zz:zz:zz:zz:zz:zz\n"),
        ] {
            fs::create_dir(dir.path().join(iface)).unwrap();
            fs::write(dir.path().join(iface).join("address"), text).unwrap();
        }
        assert_eq!(
            mac_in(dir.path(), "ok").unwrap(),
            [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]
        );
        assert!(mac_in(dir.path(), "short").is_err());
        assert!(mac_in(dir.path(), "junk").is_err());
        assert!(mac_in(dir.path(), "absent").is_err());
        assert_eq!(parse_mac("+1:b2:c3:d4:e5:f6"), None);
    }

    #[test]
    fn infra_picks_first_broadcom_wireless_netdev_other_than_awdl() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("net");
        let mk = |name: &str, wireless: bool, driver: Option<&str>| {
            let base = root.join(name);
            fs::create_dir_all(base.join("device")).unwrap();
            if wireless {
                fs::create_dir(base.join("phy80211")).unwrap();
            }
            if let Some(d) = driver {
                std::os::unix::fs::symlink(
                    format!("../../bus/drivers/{d}"),
                    base.join("device/driver"),
                )
                .unwrap();
            }
        };
        mk("awdl0", true, Some("brcmfmac"));
        mk("eth0", false, Some("brcmfmac"));
        mk("wlan0", true, Some("iwlwifi"));
        mk("wlp1", true, None);
        mk("wld0", true, Some("brcmfmac_wcc"));
        assert_eq!(infra_in(&root, "awdl0"), "wld0");
        assert_eq!(infra_in(&root.join("absent"), "awdl0"), "");
    }

    #[test]
    fn host_label_is_sanitised_and_forced_names_lose_local() {
        assert_eq!(host_from("", "Brent's MacBook.lan"), "brentsmacbook-awdl");
        assert_eq!(host_from("", "-x-.example"), "x-awdl");
        assert_eq!(host_from("", "ÉÉ"), "omdrop-awdl");
        assert_eq!(host_from("", ""), "omdrop-awdl");
        assert_eq!(host_from("my-awdl.local.", "ignored"), "my-awdl");
        assert_eq!(host_from("other", "ignored"), "other");
    }
}
