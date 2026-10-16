//! The pure half of the identity contract: the parsers and `select`.
//!
//! They take state already read and return a decision, so the shared vectors
//! (`tests/identity-vectors.json`) can drive them without a keyring, a window
//! or a filesystem. Everything that reads the real state lives elsewhere.

use std::collections::HashMap;

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use zeroize::Zeroizing;

use crate::Source;

pub(crate) const MAGIC: &[u8] = b"OMDROP-IDENTITY 1";
pub(crate) const MAX_LIFETIME: i64 = 86400;
const MAX_PART: i64 = 16384;
const MAX_PAYLOAD: usize = 32767;
const HEADER_KEYS: [&str; 7] = [
    "certificate",
    "fetch_id",
    "fetched_at",
    "hard_expiry",
    "key",
    "period_ends",
    "record",
];

pub(crate) type Settings = HashMap<String, String>;

/// Python's `str.splitlines()`: the plugin parsed settings, windows and its
/// state file with it, so `\r\n` line ends (and the other Unicode line
/// boundaries) end a line rather than becoming part of a value.
pub(crate) fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let boundary = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !boundary {
            continue;
        }
        lines.push(&text[start..i]);
        let mut end = i + c.len_utf8();
        if c == '\r'
            && let Some(&(j, '\n')) = chars.peek()
        {
            chars.next();
            end = j + 1;
        }
        start = end;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// `key=value` lines; the last occurrence of a key wins; lines without `=`
/// are ignored.
pub(crate) fn parse_settings(text: &str) -> Settings {
    let mut out = Settings::new();
    for line in splitlines(text) {
        if let Some((k, v)) = line.split_once('=') {
            out.insert(k.to_owned(), v.to_owned());
        }
    }
    out
}

pub(crate) fn is_fetch_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// What a parsed window file says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Window {
    OnePassword { fetch_id: String, hard_expiry: i64 },
    Disk,
    SelfSigned,
}

impl Window {
    pub(crate) fn source(&self) -> &'static str {
        match self {
            Window::OnePassword { .. } => "1password",
            Window::Disk => "disk",
            Window::SelfSigned => "self-signed",
        }
    }
}

/// The window file's contents, or `None` when it is unparseable.
pub(crate) fn parse_window(text: &str) -> Option<Window> {
    let fields = parse_settings(text);
    match fields.get("source").map(String::as_str) {
        Some("disk") => Some(Window::Disk),
        Some("self-signed") => Some(Window::SelfSigned),
        Some("1password") => {
            let fetch_id = fields.get("fetch_id").map(String::as_str).unwrap_or("");
            let expiry = fields.get("hard_expiry").map(String::as_str).unwrap_or("");
            if !is_fetch_id(fetch_id)
                || expiry.is_empty()
                || !expiry.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            // Python's int is unbounded; an expiry past i64 is "never" either way.
            let hard_expiry = expiry.parse::<i64>().unwrap_or(i64::MAX);
            Some(Window::OnePassword {
                fetch_id: fetch_id.to_owned(),
                hard_expiry,
            })
        }
        _ => None,
    }
}

/// A parsed cache payload.
pub(crate) struct Payload {
    pub fetch_id: String,
    /// Read only by the vectors; part of the payload all the same.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fetched_at: i64,
    pub period_ends: i64,
    pub hard_expiry: i64,
    pub certificate: Vec<u8>,
    pub key: Zeroizing<Vec<u8>>,
    pub record: Vec<u8>,
}

/// The header's members in order, duplicates kept so they can be refused:
/// a duplicate key is malformed, not last-wins.
struct Members(Vec<(String, serde_json::Value)>);

impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Members;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Members, A::Error> {
                let mut out = Vec::new();
                while let Some((k, v)) = map.next_entry::<String, serde_json::Value>()? {
                    out.push((k, v));
                }
                Ok(Members(out))
            }
        }
        d.deserialize_map(V)
    }
}

/// A JSON integer (never a boolean or a float) that is at least zero.
fn nonneg_int(v: &serde_json::Value) -> Option<i64> {
    match v {
        serde_json::Value::Number(n) if !n.is_f64() => n.as_i64().filter(|&x| x >= 0),
        _ => None,
    }
}

/// The cache payload, or `None` when it is malformed.
pub(crate) fn parse_payload(data: &[u8]) -> Option<Payload> {
    if data.len() > MAX_PAYLOAD {
        return None;
    }
    let first = data.iter().position(|&b| b == b'\n')?;
    if data.get(..first)? != MAGIC {
        return None;
    }
    let rest = data.get(first + 1..)?;
    let second = rest.iter().position(|&b| b == b'\n')?;
    let header = serde_json::from_slice::<Members>(rest.get(..second)?).ok()?;
    let mut fields: HashMap<&str, &serde_json::Value> = HashMap::new();
    for (k, v) in &header.0 {
        if fields.insert(k.as_str(), v).is_some() {
            return None;
        }
    }
    if fields.len() != HEADER_KEYS.len() || !HEADER_KEYS.iter().all(|k| fields.contains_key(k)) {
        return None;
    }
    let field = |k: &str| fields.get(k).copied();
    let fetch_id = field("fetch_id")?.as_str()?;
    if !is_fetch_id(fetch_id) {
        return None;
    }
    let t0 = nonneg_int(field("fetched_at")?)?;
    let t1 = nonneg_int(field("period_ends")?)?;
    let t2 = nonneg_int(field("hard_expiry")?)?;
    if !(t0 <= t1 && t1 <= t2) || t2 - t0 > MAX_LIFETIME {
        return None;
    }
    let mut lengths = [0usize; 3];
    for (slot, k) in lengths.iter_mut().zip(["certificate", "key", "record"]) {
        let n = nonneg_int(field(k)?)?;
        if !(1..=MAX_PART).contains(&n) {
            return None;
        }
        *slot = usize::try_from(n).ok()?;
    }
    let body = rest.get(second + 1..)?;
    let [c, k, r] = lengths;
    if body.len() != c + k + r {
        return None;
    }
    Some(Payload {
        fetch_id: fetch_id.to_owned(),
        fetched_at: t0,
        period_ends: t1,
        hard_expiry: t2,
        certificate: body.get(..c)?.to_vec(),
        key: Zeroizing::new(body.get(c..c + k)?.to_vec()),
        record: body.get(c + k..)?.to_vec(),
    })
}

/// Frame a payload; `None` when the result would not parse (an empty or
/// oversized part, a bad time order).
pub(crate) fn encode_payload(
    fetch_id: &str,
    fetched_at: i64,
    period_ends: i64,
    hard_expiry: i64,
    certificate: &[u8],
    key: &[u8],
    record: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    // Compact, keys sorted: what Python's json.dumps(separators=(',', ':'),
    // sort_keys=True) wrote.
    let header = format!(
        "{{\"certificate\":{},\"fetch_id\":{},\"fetched_at\":{},\"hard_expiry\":{},\"key\":{},\"period_ends\":{},\"record\":{}}}",
        certificate.len(),
        serde_json::to_string(fetch_id).ok()?,
        fetched_at,
        hard_expiry,
        key.len(),
        period_ends,
        record.len()
    );
    let mut data = Zeroizing::new(Vec::with_capacity(
        MAGIC.len() + header.len() + 2 + certificate.len() + key.len() + record.len(),
    ));
    data.extend_from_slice(MAGIC);
    data.push(b'\n');
    data.extend_from_slice(header.as_bytes());
    data.push(b'\n');
    data.extend_from_slice(certificate);
    data.extend_from_slice(key);
    data.extend_from_slice(record);
    parse_payload(&data)?;
    Some(data)
}

// ------------------------------------------------------------------ selection

/// The window file as selection sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WindowState {
    Absent,
    Unparseable,
    Parsed(Window),
}

/// The cache as selection sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CacheState {
    Absent,
    Malformed,
    Parsed { fetch_id: String, hard_expiry: i64 },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DiskState {
    pub certificate: bool,
    pub key: bool,
    /// Meaningful only when both `certificate` and `key` are true.
    pub matches: bool,
    pub record: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PairState {
    pub certificate: bool,
    pub key: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Choice {
    pub identity: Source,
    pub record: bool,
    pub create: bool,
    /// Sorted.
    pub warnings: Vec<&'static str>,
}

fn self_signed(
    pair: PairState,
    root: bool,
    mut warnings: Vec<&'static str>,
) -> Result<Choice, &'static str> {
    warnings.sort_unstable();
    if pair.certificate && pair.key {
        return Ok(Choice {
            identity: Source::SelfSigned,
            record: false,
            create: false,
            warnings,
        });
    }
    if pair.certificate || pair.key {
        return Err("self-signed-half-pair");
    }
    if root {
        return Err("self-signed-missing");
    }
    Ok(Choice {
        identity: Source::SelfSigned,
        record: false,
        create: true,
        warnings,
    })
}

fn disk_choice(disk: DiskState) -> Choice {
    Choice {
        identity: Source::Disk,
        record: disk.record,
        create: false,
        warnings: Vec::new(),
    }
}

/// The mode selection uses: the window's source when a parsed window exists,
/// else `identity_source` (absent means `disk`).
pub(crate) fn mode<'a>(settings: &'a Settings, window: &WindowState) -> &'a str {
    match window {
        WindowState::Parsed(w) => w.source(),
        _ => settings
            .get("identity_source")
            .map(String::as_str)
            .unwrap_or("disk"),
    }
}

/// The identity to present (contract: "Selection"). Rows are checked in
/// order; the first match wins. `root` also stands for "may not create".
pub(crate) fn select(
    settings: &Settings,
    window: &WindowState,
    cache: &CacheState,
    disk: DiskState,
    pair: PairState,
    root: bool,
    now: i64,
) -> Result<Choice, &'static str> {
    match window {
        WindowState::Unparseable => Err("window-unparseable"),
        WindowState::Parsed(Window::OnePassword {
            fetch_id,
            hard_expiry,
        }) => {
            if *hard_expiry <= now {
                return Err("window-expired");
            }
            match cache {
                CacheState::Absent => Err("cache-missing"),
                CacheState::Malformed => Err("cache-malformed"),
                CacheState::Parsed { fetch_id: f, .. } if f != fetch_id => Err("cache-mismatch"),
                CacheState::Parsed { hard_expiry: e, .. } if *e <= now => Err("cache-expired"),
                CacheState::Parsed { .. } => Ok(Choice {
                    identity: Source::Cache,
                    record: true,
                    create: false,
                    warnings: Vec::new(),
                }),
            }
        }
        WindowState::Parsed(Window::Disk) => {
            if !(disk.certificate && disk.key) {
                return Err("disk-missing");
            }
            if !disk.matches {
                return Err("disk-mismatch");
            }
            Ok(disk_choice(disk))
        }
        WindowState::Parsed(Window::SelfSigned) => self_signed(pair, root, Vec::new()),
        WindowState::Absent => {
            let m = mode(settings, window);
            if m == "1password" || m == "self-signed" {
                return self_signed(pair, root, Vec::new());
            }
            if m != "disk" {
                return self_signed(pair, root, vec!["unknown-mode"]);
            }
            if disk.certificate && disk.key {
                if disk.matches {
                    return Ok(disk_choice(disk));
                }
                return self_signed(pair, root, vec!["disk-mismatch"]);
            }
            if disk.certificate || disk.key {
                return self_signed(pair, root, vec!["disk-incomplete"]);
            }
            self_signed(pair, root, Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    const VECTORS: &str = include_str!("../tests/identity-vectors.json");
    /// The frozen file's hash, as both repositories pin it.
    const VECTOR_SHA256: &str = "7c4df91563d32240ad1dc17c18415cde012b373b9a4afc23f0387f384daed1b9";

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("vectors are JSON")
    }

    fn b(v: &Value, k: &str) -> bool {
        v[k].as_bool().expect("boolean")
    }

    fn window_json(w: &Option<Window>) -> Value {
        match w {
            None => json!("unparseable"),
            Some(Window::OnePassword {
                fetch_id,
                hard_expiry,
            }) => {
                json!({"source": "1password", "fetch_id": fetch_id, "hard_expiry": hard_expiry})
            }
            Some(other) => json!({"source": other.source()}),
        }
    }

    #[test]
    fn vectors_file_is_the_frozen_one() {
        assert_eq!(
            hex::encode(Sha256::digest(VECTORS.as_bytes())),
            VECTOR_SHA256
        );
    }

    #[test]
    fn selection_vectors() {
        let v = vectors();
        let group = v["selection"].as_array().expect("selection");
        assert_eq!(group.len(), 37);
        for vector in group {
            let name = vector["name"].as_str().expect("name");
            let input = &vector["input"];
            let settings: Settings = input["settings"]
                .as_object()
                .expect("settings")
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().expect("string").to_owned()))
                .collect();
            let window = match &input["window"] {
                Value::Null => WindowState::Absent,
                Value::String(s) if s == "unparseable" => WindowState::Unparseable,
                w => WindowState::Parsed(match w["source"].as_str().expect("source") {
                    "1password" => Window::OnePassword {
                        fetch_id: w["fetch_id"].as_str().expect("fetch_id").to_owned(),
                        hard_expiry: w["hard_expiry"].as_i64().expect("hard_expiry"),
                    },
                    "disk" => Window::Disk,
                    "self-signed" => Window::SelfSigned,
                    other => panic!("{name}: source {other}"),
                }),
            };
            let cache = match &input["cache"] {
                Value::Null => CacheState::Absent,
                Value::String(s) if s == "malformed" => CacheState::Malformed,
                c => CacheState::Parsed {
                    fetch_id: c["fetch_id"].as_str().expect("fetch_id").to_owned(),
                    hard_expiry: c["hard_expiry"].as_i64().expect("hard_expiry"),
                },
            };
            let d = &input["disk"];
            let disk = DiskState {
                certificate: b(d, "certificate"),
                key: b(d, "key"),
                matches: b(d, "match"),
                record: b(d, "record"),
            };
            let p = &input["self_signed"];
            let pair = PairState {
                certificate: b(p, "certificate"),
                key: b(p, "key"),
            };
            let got = match select(
                &settings,
                &window,
                &cache,
                disk,
                pair,
                b(input, "root"),
                input["now"].as_i64().expect("now"),
            ) {
                Ok(c) => json!({"identity": c.identity.as_str(), "record": c.record,
                                "create": c.create, "warnings": c.warnings}),
                Err(e) => json!({"error": e}),
            };
            assert_eq!(got, vector["expect"], "selection: {name}");
        }
    }

    #[test]
    fn payload_vectors() {
        let v = vectors();
        let group = v["payloads"].as_array().expect("payloads");
        assert_eq!(group.len(), 21);
        for vector in group {
            let name = vector["name"].as_str().expect("name");
            let raw = B64
                .decode(vector["payload_b64"].as_str().expect("b64"))
                .expect("base64");
            let got = match parse_payload(&raw) {
                None => json!("malformed"),
                Some(p) => json!({
                    "fetch_id": p.fetch_id, "fetched_at": p.fetched_at,
                    "period_ends": p.period_ends, "hard_expiry": p.hard_expiry,
                    "certificate_b64": B64.encode(&p.certificate),
                    "key_b64": B64.encode(p.key.as_slice()),
                    "record_b64": B64.encode(&p.record),
                }),
            };
            assert_eq!(got, vector["expect"], "payloads: {name}");
        }
    }

    #[test]
    fn window_file_vectors() {
        let v = vectors();
        for vector in v["window_files"].as_array().expect("window_files") {
            let name = vector["name"].as_str().expect("name");
            let got = window_json(&parse_window(vector["text"].as_str().expect("text")));
            assert_eq!(got, vector["expect"], "window_files: {name}");
        }
    }

    #[test]
    fn settings_file_vectors() {
        let v = vectors();
        for vector in v["settings_files"].as_array().expect("settings_files") {
            let name = vector["name"].as_str().expect("name");
            let got = parse_settings(vector["text"].as_str().expect("text"));
            let got: serde_json::Map<String, Value> = got
                .into_iter()
                .map(|(k, v)| (k, Value::String(v)))
                .collect();
            assert_eq!(
                Value::Object(got),
                vector["expect"],
                "settings_files: {name}"
            );
        }
    }

    // Boundaries from the driver's PayloadBoundaryTests.

    fn header() -> serde_json::Map<String, Value> {
        json!({"certificate": 1, "key": 1, "record": 1, "fetch_id": "a".repeat(32),
               "fetched_at": 0, "period_ends": 0, "hard_expiry": 86400})
        .as_object()
        .cloned()
        .expect("object")
    }

    fn frame(header: &serde_json::Map<String, Value>, body: &[u8]) -> Vec<u8> {
        let mut out = b"OMDROP-IDENTITY 1\n".to_vec();
        out.extend_from_slice(serde_json::to_string(header).expect("json").as_bytes());
        out.push(b'\n');
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn duplicate_header_keys_are_malformed_not_last_wins() {
        let f = frame(&header(), b"CKR");
        let text = String::from_utf8(f)
            .expect("utf8")
            .replacen('{', "{\"key\":1,", 1);
        assert!(parse_payload(text.as_bytes()).is_none());
    }

    #[test]
    fn integer_fields_reject_booleans_floats_strings_and_null() {
        for field in [
            "certificate",
            "key",
            "record",
            "fetched_at",
            "period_ends",
            "hard_expiry",
        ] {
            for value in [
                json!(true),
                json!(false),
                json!(1.0),
                json!("1"),
                Value::Null,
            ] {
                let mut h = header();
                h.insert(field.to_owned(), value.clone());
                assert!(
                    parse_payload(&frame(&h, b"CKR")).is_none(),
                    "{field}={value}"
                );
            }
        }
    }

    #[test]
    fn binary_sections_are_not_searched_for_newlines() {
        let mut h = header();
        h.insert("certificate".into(), json!(3));
        h.insert("key".into(), json!(2));
        h.insert("record".into(), json!(4));
        let p = parse_payload(&frame(&h, b"\xff\nC\x00K\x00\n\xffR")).expect("parses");
        assert_eq!(p.certificate, b"\xff\nC");
        assert_eq!(p.key.as_slice(), b"\x00K");
        assert_eq!(p.record, b"\x00\n\xffR");
    }

    #[test]
    fn exact_kernel_limit_and_the_next_byte() {
        let mut h = header();
        h.insert("certificate".into(), json!(16000));
        h.insert("key".into(), json!(16000));
        for _ in 0..3 {
            let overhead = frame(&h, b"").len();
            h.insert("record".into(), json!(32767 - overhead - 32000));
        }
        let r = usize::try_from(h["record"].as_u64().expect("record")).expect("fits");
        let mut body = vec![b'C'; 16000];
        body.extend(vec![b'K'; 16000]);
        body.extend(vec![b'R'; r]);
        let f = frame(&h, &body);
        assert_eq!(f.len(), 32767);
        assert!(parse_payload(&f).is_some());
        h.insert("record".into(), json!(r + 1));
        body.push(b'R');
        assert!(parse_payload(&frame(&h, &body)).is_none());
    }

    #[test]
    fn invalid_json_and_non_object_headers() {
        for header in [&b"\xff"[..], b"null", b"[]", b"1", b"\"text\"", b"{"] {
            let mut f = b"OMDROP-IDENTITY 1\n".to_vec();
            f.extend_from_slice(header);
            f.extend_from_slice(b"\nCKR");
            assert!(parse_payload(&f).is_none());
        }
    }

    #[test]
    fn time_order_and_inclusive_lifetime_boundary() {
        assert!(parse_payload(&frame(&header(), b"CKR")).is_some());
        for (k, v) in [
            ("hard_expiry", 86401),
            ("period_ends", -1),
            ("period_ends", 86401),
        ] {
            let mut h = header();
            h.insert(k.into(), json!(v));
            assert!(parse_payload(&frame(&h, b"CKR")).is_none(), "{k}={v}");
        }
    }

    #[test]
    fn encode_round_trips_and_refuses_what_would_not_parse() {
        let id = "0123456789abcdef0123456789abcdef";
        let data = encode_payload(id, 10, 20, 30, b"cert", b"key", b"rec").expect("encodes");
        let p = parse_payload(&data).expect("parses");
        assert_eq!(
            (
                p.fetch_id.as_str(),
                p.fetched_at,
                p.period_ends,
                p.hard_expiry
            ),
            (id, 10, 20, 30)
        );
        assert!(data.starts_with(
            b"OMDROP-IDENTITY 1\n{\"certificate\":4,\"fetch_id\":\"0123456789abcdef0123456789abcdef\",\"fetched_at\":10,\"hard_expiry\":30,\"key\":3,\"period_ends\":20,\"record\":3}\n"
        ));
        assert!(encode_payload(id, 10, 20, 30, b"", b"key", b"rec").is_none());
        assert!(encode_payload(id, 0, 1, 86401, b"c", b"k", b"r").is_none());
        assert!(encode_payload(id, 0, 1, 2, &vec![0; 16385], b"k", b"r").is_none());
    }

    #[test]
    fn settings_lines_end_where_python_splitlines_ends_them() {
        let s = parse_settings("a=1\r\nb=2\rc=3\x0bd=4\u{2028}e=5");
        for (k, v) in [("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5")] {
            assert_eq!(s.get(k).map(String::as_str), Some(v));
        }
        assert_eq!(parse_window("source=disk\r\n"), Some(Window::Disk));
        assert_eq!(splitlines("a\n\nb\n"), vec!["a", "", "b"]);
    }
}
