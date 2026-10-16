//! Property lists from untrusted peers, parsed under limits.
//!
//! `plist::Value::from_reader` is not safe on a peer's bytes. A binary plist
//! may reference one object many times, and the `plist` crate expands every
//! reference into a fresh copy (Python's plistlib shares the object instead):
//! a few hundred bytes of `[A, A]`, `[[A, A], [A, A]]`, ... decode to billions
//! of values, and a 1 MiB body of one 850 KB data object referenced 199 000
//! times decodes to 169 GB. And a deeply nested array is dropped recursively,
//! so 100 000 levels overflow the stack and abort the process. This builds the
//! value from the event stream itself, refusing more than [`MAX_EVENTS`]
//! events, collections deeper than [`MAX_DEPTH`], or more decoded bytes than
//! [`byte_budget`] allows.

use std::fmt;
use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use plist::stream::{Event, Reader};
use plist::{Dictionary, Value};

/// Values (and collection ends) one plist may hold. A real Ask with 512 files
/// is well under 10 000.
pub const MAX_EVENTS: usize = 200_000;
/// Collections inside collections. AirDrop plists are three deep.
pub const MAX_DEPTH: usize = 32;
/// What a value other than data or a string counts against the byte budget.
const VALUE_OVERHEAD: usize = 16;
/// The byte budget never goes below this.
const MIN_BYTE_BUDGET: usize = 4 << 20;

/// Decoded bytes a plist of `input_len` bytes may produce: data and string
/// lengths, plus [`VALUE_OVERHEAD`] per other value, at most four times the
/// input or 4 MiB, whichever is more. An honest plist decodes to about its
/// own size.
pub fn byte_budget(input_len: usize) -> usize {
    input_len.saturating_mul(4).max(MIN_BYTE_BUDGET)
}

#[derive(Debug, PartialEq, Eq)]
pub enum PlistError {
    /// Not a property list.
    Invalid(String),
    /// Over [`MAX_EVENTS`], [`MAX_DEPTH`] or [`byte_budget`].
    TooComplex,
}

impl fmt::Display for PlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlistError::Invalid(m) => f.write_str(m),
            PlistError::TooComplex => write!(
                f,
                "property list deeper than {MAX_DEPTH}, larger than {MAX_EVENTS} values, \
                 or larger than four times its own size decoded"
            ),
        }
    }
}

impl std::error::Error for PlistError {}

enum Frame {
    Array(Vec<Value>),
    Dict(Dictionary, Option<String>),
}

/// Parse an XML or binary property list.
pub fn parse(data: &[u8]) -> Result<Value, PlistError> {
    let mut stack: Vec<Frame> = Vec::new();
    let mut root: Option<Value> = None;
    let budget = byte_budget(data.len());
    let mut decoded = 0usize;
    for (count, event) in Reader::new(Cursor::new(data)).enumerate() {
        if count >= MAX_EVENTS {
            return Err(PlistError::TooComplex);
        }
        let event = event.map_err(|e| PlistError::Invalid(e.to_string()))?;
        decoded = decoded.saturating_add(match &event {
            Event::Data(d) => d.len(),
            Event::String(s) => s.len(),
            _ => VALUE_OVERHEAD,
        });
        if decoded > budget {
            return Err(PlistError::TooComplex);
        }
        let value = match event {
            Event::StartArray(_) | Event::StartDictionary(_) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(PlistError::TooComplex);
                }
                stack.push(match event {
                    Event::StartArray(_) => Frame::Array(Vec::new()),
                    _ => Frame::Dict(Dictionary::new(), None),
                });
                continue;
            }
            Event::EndCollection => match stack.pop() {
                Some(Frame::Array(items)) => Value::Array(items),
                Some(Frame::Dict(dict, None)) => Value::Dictionary(dict),
                _ => return Err(PlistError::Invalid("unbalanced collection".into())),
            },
            Event::Boolean(b) => Value::Boolean(b),
            Event::Data(d) => Value::Data(d.into_owned()),
            Event::Date(d) => Value::Date(in_range(d)?),
            Event::Integer(i) => Value::Integer(i),
            Event::Real(r) => Value::Real(r),
            Event::String(s) => Value::String(s.into_owned()),
            Event::Uid(u) => Value::Uid(u),
            _ => return Err(PlistError::Invalid("unknown plist event".into())),
        };
        match stack.last_mut() {
            None if root.is_none() => root = Some(value),
            None => return Err(PlistError::Invalid("more than one root value".into())),
            Some(Frame::Array(items)) => items.push(value),
            Some(Frame::Dict(_, key @ None)) => match value {
                Value::String(k) => *key = Some(k),
                _ => return Err(PlistError::Invalid("dictionary key is not a string".into())),
            },
            Some(Frame::Dict(dict, key @ Some(_))) => {
                if let Some(k) = key.take() {
                    dict.insert(k, value);
                }
            }
        }
    }
    match (root, stack.is_empty()) {
        (Some(value), true) => Ok(value),
        _ => Err(PlistError::Invalid("truncated property list".into())),
    }
}

/// 0001-01-01T00:00:00Z and the second after 9999-12-31T23:59:59Z, from the
/// Unix epoch: Python's `datetime` range, so plistlib refuses the same dates.
const DATE_MIN_BEFORE_EPOCH: Duration = Duration::from_secs(62_135_596_800);
const DATE_END_AFTER_EPOCH: Duration = Duration::from_secs(253_402_300_800);

/// A date the `plist` crate can format. It accepts any finite binary date and
/// any RFC 3339 XML date, but its `Debug`, XML and serde output panic outside
/// years 0001-9999 (cargo-fuzz, `safeplist` target), and the receiver formats
/// an Ask's odd values with `Debug`.
fn in_range(d: plist::Date) -> Result<plist::Date, PlistError> {
    let ok = match SystemTime::from(d).duration_since(UNIX_EPOCH) {
        Ok(after) => after < DATE_END_AFTER_EPOCH,
        Err(before) => before.duration() <= DATE_MIN_BEFORE_EPOCH,
    };
    if ok {
        Ok(d)
    } else {
        Err(PlistError::Invalid("date outside years 0001-9999".into()))
    }
}

/// [`parse`], then the root dictionary; `None` for anything else.
pub fn parse_dict(data: &[u8]) -> Option<Dictionary> {
    parse(data).ok().and_then(Value::into_dictionary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binary(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        value.to_writer_binary(&mut out).unwrap();
        out
    }

    #[test]
    fn ordinary_plists_parse() {
        let mut d = Dictionary::new();
        d.insert(
            "Files".into(),
            Value::Array(vec![
                Value::Dictionary(Dictionary::new()),
                Value::Integer(3.into()),
            ]),
        );
        d.insert("SenderRecordData".into(), Value::Data(vec![1, 2, 3]));
        let v = Value::Dictionary(d);
        assert_eq!(parse(&binary(&v)).unwrap(), v);
        let mut xml = Vec::new();
        v.to_writer_xml(&mut xml).unwrap();
        assert_eq!(parse(&xml).unwrap(), v);
        assert!(parse(b"not a plist").is_err());
        assert!(parse(b"").is_err());
        assert_eq!(parse_dict(&binary(&Value::Array(vec![]))), None);
    }

    fn xml_date(date: &str) -> Vec<u8> {
        format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><date>{date}</date></plist>")
            .into_bytes()
    }

    #[test]
    fn dates_outside_years_0001_to_9999_are_refused_not_a_panic() {
        // Found by cargo-fuzz: the plist crate formats these with a panic,
        // and the receiver formats an Ask's odd values with Debug.
        let far = UNIX_EPOCH + DATE_END_AFTER_EPOCH;
        let refused = [
            binary(&Value::Date(far.into())),
            binary(&Value::Date((far + Duration::from_secs(1 << 40)).into())),
            xml_date("0000-12-31T23:59:59Z"),
            xml_date("0000-01-01T00:00:00+01:00"),
        ];
        for data in refused {
            assert!(
                matches!(parse(&data), Err(PlistError::Invalid(_))),
                "{data:?}"
            );
        }
        // The range's ends still parse, and format.
        let first = UNIX_EPOCH - DATE_MIN_BEFORE_EPOCH;
        let last = UNIX_EPOCH + DATE_END_AFTER_EPOCH - Duration::from_secs(1);
        for data in [
            binary(&Value::Date(first.into())),
            binary(&Value::Date(last.into())),
            xml_date("0001-01-01T00:00:00Z"),
            xml_date("9999-12-31T23:59:59Z"),
        ] {
            let value = parse(&data).unwrap();
            assert!(format!("{value:?}").contains("Date"));
        }
    }

    #[test]
    fn deep_nesting_is_refused_not_a_stack_overflow() {
        let depth = 200_000;
        let xml = format!(
            "<?xml version=\"1.0\"?><plist version=\"1.0\">{}{}</plist>",
            "<array>".repeat(depth),
            "</array>".repeat(depth)
        );
        assert_eq!(parse(xml.as_bytes()), Err(PlistError::TooComplex));
    }

    #[test]
    fn shared_references_cannot_expand_exponentially() {
        // A hand-built binary plist, five levels deep: object 0 is an empty
        // array, object k an array of 200 references to object k-1. About
        // 1 KB describes 200^4 = 1.6 billion values.
        let n = 5u8;
        let mut body = b"bplist00".to_vec();
        let mut offsets: Vec<u16> = vec![body.len() as u16];
        body.push(0xa0);
        for k in 1..n {
            offsets.push(body.len() as u16);
            body.extend([0xaf, 0x10, 200]);
            body.extend(std::iter::repeat_n(k - 1, 200));
        }
        let table = body.len();
        body.extend(offsets.iter().flat_map(|o| o.to_be_bytes()));
        body.extend([0u8; 6]);
        body.extend([2u8, 1]);
        body.extend(u64::from(n).to_be_bytes());
        body.extend(u64::from(n - 1).to_be_bytes());
        body.extend((table as u64).to_be_bytes());
        assert!(body.len() < 1024);
        assert_eq!(parse(&body), Err(PlistError::TooComplex));
        // The same shape, small enough, decodes: the bytes are a valid plist.
        let mut small = body.clone();
        let top = small.len() - 16;
        small[top..top + 8].copy_from_slice(&1u64.to_be_bytes());
        assert!(matches!(parse(&small), Ok(Value::Array(a)) if a.len() == 200));
    }

    /// A binary plist: object 0 is `size` bytes of data, object 1 (the root)
    /// an array of `refs` references to it.
    fn shared_data(size: u32, refs: u32) -> Vec<u8> {
        let mut body = b"bplist00".to_vec();
        let mut offsets: Vec<u32> = vec![body.len() as u32];
        body.extend([0x4f, 0x12]);
        body.extend(size.to_be_bytes());
        body.extend(std::iter::repeat_n(0x41, size as usize));
        offsets.push(body.len() as u32);
        body.extend([0xaf, 0x12]);
        body.extend(refs.to_be_bytes());
        body.extend(std::iter::repeat_n(0u8, refs as usize));
        let table = body.len();
        body.extend(offsets.iter().flat_map(|o| o.to_be_bytes()));
        body.extend([0u8; 6]);
        body.extend([4u8, 1]);
        body.extend(2u64.to_be_bytes());
        body.extend(1u64.to_be_bytes());
        body.extend((table as u64).to_be_bytes());
        body
    }

    #[test]
    fn shared_data_cannot_expand_past_the_byte_budget() {
        // Under 1 MiB on the wire, 167 GB decoded.
        let bomb = shared_data(840_000, 199_000);
        assert!(bomb.len() < 1 << 20);
        let started = std::time::Instant::now();
        assert_eq!(parse(&bomb), Err(PlistError::TooComplex));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // Three references to the same object are within budget: the shape
        // itself is valid.
        let fine = parse(&shared_data(840_000, 3)).unwrap();
        assert!(matches!(fine, Value::Array(a) if a.len() == 3));
    }
}
