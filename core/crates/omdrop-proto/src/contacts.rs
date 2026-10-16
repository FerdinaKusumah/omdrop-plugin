//! Contacts Only: is an AirDrop sender someone this machine knows?
//!
//! Apple's "Contacts Only" is not a name check. Every sender that proposes a
//! transfer presents two things (measured from real transfers, 2026-09-18):
//!
//! - an Apple-issued client certificate, on `/Ask` and `/Upload` but never on
//!   `/Discover`, subject `CN=com.apple.idms.appleid.prd.<altDsID>`, issued by
//!   Apple Application Integration Certification Authority;
//! - an Apple ID validation record: CMS signed by Apple, carrying the SHA-256
//!   of every phone number and email address verified for that Apple ID, and
//!   the same altDsID.
//!
//! Three checks, and all three matter: the record's signature verifies to
//! Apple's root (otherwise anyone can assert any identifiers); the certificate
//! chains to Apple AND names the record's account (otherwise a record
//! harvested off the air by a passive prober can be replayed by someone without
//! the matching key; records are handed to any prober that asks); and a hashed
//! identifier in the record is in our known-senders list. `SenderComputerName`
//! is never trusted: anybody can call their laptop anything.
//!
//! The cryptography is `omdrop_identity::apple`; this module is the policy.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use omdrop_identity::apple::Record;
use sha2::{Digest, Sha256};

/// A policy outcome. The receiver turns it into an HTTP answer and a log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Accept,
    NoRecord,
    BadRecord,
    NoCertificate,
    Unbound,
    Unknown,
}

impl Outcome {
    /// `contacts.py`'s outcome constants.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Accept => "accept",
            Outcome::NoRecord => "no-record",
            Outcome::BadRecord => "bad-record",
            Outcome::NoCertificate => "no-certificate",
            Outcome::Unbound => "record-not-bound-to-certificate",
            Outcome::Unknown => "not-a-known-sender",
        }
    }

    /// `contacts.WHY`: the reason the receiver logs.
    pub fn why(self) -> &'static str {
        match self {
            Outcome::Accept => "sender is a known contact",
            Outcome::NoRecord => "sender sent no Apple ID validation record",
            Outcome::BadRecord => "the validation record is not signed by Apple, or has expired",
            Outcome::NoCertificate => "sender presented no client certificate",
            Outcome::Unbound => {
                "the validation record does not belong to the presented certificate"
            }
            Outcome::Unknown => "sender is not in the known-senders list",
        }
    }
}

/// What a decision rests on, without any identifier: the record's hashes are
/// reversible to a phone number by brute force and must never reach a log.
/// Displays as the Python receiver logged its detail dict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detail {
    None,
    Expired(bool),
    AppleIssuedCertificate(bool),
    KnownSenders(usize),
    Identified(bool),
}

impl Detail {
    pub fn is_none(self) -> bool {
        self == Detail::None
    }
}

impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let py = |b: bool| if b { "True" } else { "False" };
        match self {
            Detail::None => f.write_str("{}"),
            Detail::Expired(b) => write!(f, "{{'expired': {}}}", py(*b)),
            Detail::AppleIssuedCertificate(b) => {
                write!(f, "{{'apple_issued_certificate': {}}}", py(*b))
            }
            Detail::KnownSenders(n) => write!(f, "{{'known_senders': {n}}}"),
            Detail::Identified(b) => write!(f, "{{'identified': {}}}", py(*b)),
        }
    }
}

/// The Apple checks the policy needs. [`Apple`] is the real one; tests
/// substitute a fake CA.
pub trait AppleChecks {
    /// The record's contents if Apple's signature over it verifies.
    fn verify_record(&self, record: &[u8]) -> Option<Record>;
    /// The account a certificate chaining to Apple names, or `""`.
    fn certificate_account(&self, der: &[u8]) -> String;
}

/// `omdrop_identity::apple`.
pub struct Apple;

impl AppleChecks for Apple {
    fn verify_record(&self, record: &[u8]) -> Option<Record> {
        omdrop_identity::apple::verify_record(record)
    }

    fn certificate_account(&self, der: &[u8]) -> String {
        omdrop_identity::apple::certificate_account(der)
    }
}

/// Normalize an address-book entry the way AirDrop does before hashing: email
/// lowercased, phone digits only (`+1 (234) 567-8901` → `12345678901`). Getting
/// this wrong is a silent non-match, which looks exactly like "not a contact".
/// `None` for blanks and `#` comments.
pub fn normalize(entry: &str) -> Option<String> {
    let entry = entry.trim();
    if entry.is_empty() || entry.starts_with('#') {
        return None;
    }
    if entry.contains('@') {
        return Some(entry.to_lowercase());
    }
    let digits: String = entry.chars().filter(char::is_ascii_digit).collect();
    (!digits.is_empty()).then_some(digits)
}

/// Lowercase hex SHA-256 of a normalized identifier.
pub fn hash_identifier(entry: &str) -> String {
    hex::encode(Sha256::digest(entry.as_bytes()))
}

/// `$XDG_CONFIG_HOME/omdrop`, else `$HOME/.config/omdrop`.
pub fn config_dir() -> PathBuf {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => home_dir().join(".config"),
    };
    base.join("omdrop")
}

/// `$HOME`, else the passwd entry's home, else `/`.
pub fn home_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(home);
    }
    passwd_home().unwrap_or_else(|| PathBuf::from("/"))
}

/// This user's home directory from the passwd database.
pub fn passwd_home() -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call; `buf` outlives the use of
    // the strings getpwuid_r points into it.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            pwd.as_mut_ptr(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded and `result` points at `pwd`, whose
    // pw_dir is a NUL-terminated string inside `buf`.
    let dir = unsafe { CStr::from_ptr((*result).pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

/// `config_dir()/known-senders`: identifiers in the clear, one per line, so a
/// user can read and edit it; hashing happens at comparison time.
pub fn known_senders_path() -> PathBuf {
    config_dir().join("known-senders")
}

/// Hashed identifiers of everyone we accept from. A missing or unreadable
/// file is an empty list.
pub fn known_hashes(path: &Path) -> BTreeSet<String> {
    let Ok(bytes) = std::fs::read(path) else {
        return BTreeSet::new();
    };
    String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(normalize)
        .map(|e| hash_identifier(&e))
        .collect()
}

/// Who may see this machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    Everyone,
    Contacts,
}

impl Visibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Visibility::Everyone => "everyone",
            Visibility::Contacts => "contacts",
        }
    }
}

/// `config_dir()/visibility`.
pub fn visibility_path() -> PathBuf {
    config_dir().join("visibility")
}

/// `contacts` only when the file says so; absent, unreadable or anything else
/// is Everyone, because a machine that silently refuses everybody is worse
/// than one that asks.
pub fn visibility(path: &Path) -> Visibility {
    match std::fs::read_to_string(path) {
        Ok(text) if text.trim().to_lowercase() == "contacts" => Visibility::Contacts,
        _ => Visibility::Everyone,
    }
}

/// Should we accept a transfer from this sender?
pub fn decide(
    record: Option<&[u8]>,
    peer_cert: Option<&[u8]>,
    known: &BTreeSet<String>,
    apple: &(impl AppleChecks + ?Sized),
) -> (Outcome, Detail) {
    let Some(record) = record.filter(|r| !r.is_empty()) else {
        return (Outcome::NoRecord, Detail::None);
    };
    let info = match apple.verify_record(record) {
        Some(info) if !info.expired => info,
        other => {
            return (
                Outcome::BadRecord,
                Detail::Expired(other.is_some_and(|i| i.expired)),
            );
        }
    };
    let Some(peer_cert) = peer_cert.filter(|c| !c.is_empty()) else {
        return (Outcome::NoCertificate, Detail::None);
    };
    let account = apple.certificate_account(peer_cert);
    if account.is_empty() || account != info.account {
        return (
            Outcome::Unbound,
            Detail::AppleIssuedCertificate(!account.is_empty()),
        );
    }
    if known.is_empty() {
        return (Outcome::Unknown, Detail::KnownSenders(0));
    }
    if info.hashes.iter().any(|h| known.contains(h)) {
        (Outcome::Accept, Detail::KnownSenders(known.len()))
    } else {
        (Outcome::Unknown, Detail::KnownSenders(known.len()))
    }
}

/// May this sender even see us? DELIBERATELY WEAKER THAN [`decide`], and
/// usable only for discovery.
///
/// A sender presents its certificate on `/Ask` and never on `/Discover`, so
/// here nothing binds the record to the connection: a replay of a contact's
/// record is answered. That must never gate a transfer; it only keeps this
/// machine out of an honest stranger's share sheet, as Apple's mode does.
///
/// FAILS OPEN: a missing, malformed or expired record is accepted, because
/// "we could not tell who this is" must not become "hide from a device we
/// have never measured" (an iPhone that omits the record would stop seeing
/// us). The `/Ask` gate refuses the transfer either way.
pub fn decide_discovery(
    record: Option<&[u8]>,
    known: &BTreeSet<String>,
    apple: &(impl AppleChecks + ?Sized),
) -> (Outcome, Detail) {
    let Some(record) = record.filter(|r| !r.is_empty()) else {
        return (Outcome::Accept, Detail::Identified(false));
    };
    match apple.verify_record(record) {
        Some(info) if !info.expired => {
            if !known.is_empty() && info.hashes.iter().any(|h| known.contains(h)) {
                (Outcome::Accept, Detail::Identified(true))
            } else {
                (Outcome::Unknown, Detail::KnownSenders(known.len()))
            }
        }
        _ => (Outcome::Accept, Detail::Identified(false)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "001288-10-AAAA-BBBB-CCCC-DDDD";
    const OTHER: &str = "001288-10-FFFF-9999-8888-7777";

    /// A stand-in for Apple: a "record" is `account|expired|hash,hash` signed
    /// by a `SIGNED:` prefix, and a certificate is `APPLE:<account>` when it
    /// chains to the fake root. The real CMS and chain checks are
    /// omdrop-identity's and are tested there.
    struct FakeApple;

    impl AppleChecks for FakeApple {
        fn verify_record(&self, record: &[u8]) -> Option<Record> {
            let text = std::str::from_utf8(record).ok()?.strip_prefix("SIGNED:")?;
            let mut parts = text.split('|');
            let account = parts.next()?.to_string();
            let expired = parts.next()? == "expired";
            let hashes = parts
                .next()?
                .split(',')
                .filter(|h| !h.is_empty())
                .map(str::to_string)
                .collect();
            Some(Record {
                account,
                hashes,
                expires: None,
                expired,
            })
        }

        fn certificate_account(&self, der: &[u8]) -> String {
            std::str::from_utf8(der)
                .ok()
                .and_then(|s| s.strip_prefix("APPLE:"))
                .unwrap_or("")
                .to_string()
        }
    }

    fn record(identifiers: &[&str], account: &str, expired: bool) -> Vec<u8> {
        let hashes: Vec<String> = identifiers
            .iter()
            .map(|i| hash_identifier(&normalize(i).unwrap()))
            .collect();
        format!(
            "SIGNED:{account}|{}|{}",
            if expired { "expired" } else { "valid" },
            hashes.join(",")
        )
        .into_bytes()
    }

    fn cert(account: &str) -> Vec<u8> {
        format!("APPLE:{account}").into_bytes()
    }

    fn known(entries: &[&str]) -> BTreeSet<String> {
        entries
            .iter()
            .map(|e| hash_identifier(&normalize(e).unwrap()))
            .collect()
    }

    fn decide_(record: Option<&[u8]>, cert: Option<&[u8]>, known: &BTreeSet<String>) -> Outcome {
        decide(record, cert, known, &FakeApple).0
    }

    #[test]
    fn phone_matches_however_the_user_typed_it() {
        let r = record(&["+1 (555) 010-9999"], ACCOUNT, false);
        for written in ["+1 555 010 9999", "15550109999", "+1-555-010-9999"] {
            assert_eq!(
                decide_(Some(&r), Some(&cert(ACCOUNT)), &known(&[written])),
                Outcome::Accept,
                "{written}"
            );
        }
    }

    #[test]
    fn email_matches_regardless_of_case_and_one_match_is_enough() {
        let r = record(
            &["a@example.com", "Someone@Example.com", "5550001111"],
            ACCOUNT,
            false,
        );
        assert_eq!(
            decide_(
                Some(&r),
                Some(&cert(ACCOUNT)),
                &known(&["someone@example.com"])
            ),
            Outcome::Accept
        );
    }

    #[test]
    fn a_stranger_and_an_empty_list_are_refused() {
        let r = record(&["stranger@example.com"], ACCOUNT, false);
        assert_eq!(
            decide(
                Some(&r),
                Some(&cert(ACCOUNT)),
                &known(&["friend@example.com"]),
                &FakeApple
            ),
            (Outcome::Unknown, Detail::KnownSenders(1))
        );
        let r = record(&["friend@example.com"], ACCOUNT, false);
        assert_eq!(
            decide(Some(&r), Some(&cert(ACCOUNT)), &BTreeSet::new(), &FakeApple),
            (Outcome::Unknown, Detail::KnownSenders(0))
        );
    }

    #[test]
    fn a_replayed_record_and_a_self_signed_certificate_are_unbound() {
        let r = record(&["friend@example.com"], ACCOUNT, false);
        let k = known(&["friend@example.com"]);
        assert_eq!(
            decide(Some(&r), Some(&cert(OTHER)), &k, &FakeApple),
            (Outcome::Unbound, Detail::AppleIssuedCertificate(true))
        );
        assert_eq!(
            decide(Some(&r), Some(b"self-signed CN=airdrop"), &k, &FakeApple),
            (Outcome::Unbound, Detail::AppleIssuedCertificate(false))
        );
    }

    #[test]
    fn unsigned_expired_missing_record_or_certificate_are_refused() {
        let k = known(&["friend@example.com"]);
        let c = cert(ACCOUNT);
        let forged = String::from_utf8(record(&["friend@example.com"], ACCOUNT, false))
            .unwrap()
            .replace("SIGNED:", "");
        assert_eq!(
            decide(Some(forged.as_bytes()), Some(&c), &k, &FakeApple),
            (Outcome::BadRecord, Detail::Expired(false))
        );
        let expired = record(&["friend@example.com"], ACCOUNT, true);
        assert_eq!(
            decide(Some(&expired), Some(&c), &k, &FakeApple),
            (Outcome::BadRecord, Detail::Expired(true))
        );
        let r = record(&["friend@example.com"], ACCOUNT, false);
        assert_eq!(decide_(Some(&r), None, &k), Outcome::NoCertificate);
        assert_eq!(decide_(Some(&r), Some(b""), &k), Outcome::NoCertificate);
        assert_eq!(decide_(None, Some(&c), &k), Outcome::NoRecord);
        assert_eq!(decide_(Some(b""), Some(&c), &k), Outcome::NoRecord);
    }

    #[test]
    fn discovery_fails_open_and_hides_only_from_identified_strangers() {
        let k = known(&["friend@example.com"]);
        assert_eq!(
            decide_discovery(None, &k, &FakeApple),
            (Outcome::Accept, Detail::Identified(false))
        );
        assert_eq!(
            decide_discovery(Some(b"x"), &k, &FakeApple),
            (Outcome::Accept, Detail::Identified(false))
        );
        let expired = record(&["stranger@example.com"], ACCOUNT, true);
        assert_eq!(
            decide_discovery(Some(&expired), &k, &FakeApple).0,
            Outcome::Accept
        );
        let friend = record(&["friend@example.com"], ACCOUNT, false);
        assert_eq!(
            decide_discovery(Some(&friend), &k, &FakeApple),
            (Outcome::Accept, Detail::Identified(true))
        );
        let stranger = record(&["stranger@example.com"], ACCOUNT, false);
        assert_eq!(
            decide_discovery(Some(&stranger), &k, &FakeApple),
            (Outcome::Unknown, Detail::KnownSenders(1))
        );
        assert_eq!(
            decide_discovery(Some(&friend), &BTreeSet::new(), &FakeApple),
            (Outcome::Unknown, Detail::KnownSenders(0))
        );
    }

    #[test]
    fn visibility_defaults_to_everyone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("visibility");
        assert_eq!(visibility(&path), Visibility::Everyone);
        std::fs::write(&path, " Contacts\n").unwrap();
        assert_eq!(visibility(&path), Visibility::Contacts);
        std::fs::write(&path, "garbage\n").unwrap();
        assert_eq!(visibility(&path), Visibility::Everyone);
    }

    #[test]
    fn known_senders_file_ignores_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known-senders");
        std::fs::write(
            &path,
            "# my people\n\nFriend@Example.com\n+1 (555) 010-9999\n  # indented comment\n",
        )
        .unwrap();
        let hashes = known_hashes(&path);
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&hash_identifier("friend@example.com")));
        assert!(hashes.contains(&hash_identifier("15550109999")));
        assert!(known_hashes(&dir.path().join("absent")).is_empty());
    }

    #[test]
    fn hashes_match_python() {
        // hashlib.sha256(b"someone@example.com").hexdigest()
        assert_eq!(
            hash_identifier("someone@example.com"),
            "72497f475e4f76d0b28f57c73a084ece576d170874eba3ee2609d9afe4b71aab"
        );
        assert_eq!(
            hash_identifier("15550109999"),
            "91a02cd9e0fdea8309e2361e0c1d2eb133b283c1cc08d5562185d25a613783af"
        );
        assert_eq!(normalize("  # x"), None);
        assert_eq!(normalize("no digits"), None);
        assert_eq!(
            normalize("ÉMILE@Example.com").as_deref(),
            Some("émile@example.com")
        );
    }

    #[test]
    fn details_print_as_python_dicts() {
        assert_eq!(Detail::Expired(false).to_string(), "{'expired': False}");
        assert_eq!(
            Detail::AppleIssuedCertificate(true).to_string(),
            "{'apple_issued_certificate': True}"
        );
        assert_eq!(Detail::KnownSenders(3).to_string(), "{'known_senders': 3}");
    }
}
