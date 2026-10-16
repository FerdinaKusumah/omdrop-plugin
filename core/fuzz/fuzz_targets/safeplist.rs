//! The bounded plist parse used on peer bodies (`/Discover`, `/Ask` and the
//! sender's view of the answers): `safeplist::parse`, `parse_dict`, and what
//! the receiver does with a parsed value: `Debug` text in its log lines
//! (`py_value_repr`) and the redacted XML debug dump. An accepted value must
//! respect the limits the parse promises.

#![no_main]

use libfuzzer_sys::fuzz_target;
use omdrop_proto::debugdump::redacted;
use omdrop_proto::safeplist::{MAX_DEPTH, MAX_EVENTS, byte_budget, parse, parse_dict};
use plist::Value;

/// Collection depth and value count, without recursion.
fn shape(value: &Value) -> (usize, usize) {
    let mut stack = vec![(value, 0usize)];
    let (mut depth, mut count) = (0, 0);
    while let Some((v, d)) = stack.pop() {
        count += 1;
        match v {
            Value::Array(items) => {
                depth = depth.max(d + 1);
                stack.extend(items.iter().map(|i| (i, d + 1)));
            }
            Value::Dictionary(dict) => {
                depth = depth.max(d + 1);
                stack.extend(dict.values().map(|i| (i, d + 1)));
            }
            _ => {}
        }
    }
    (depth, count)
}

fn decoded_bytes(value: &Value) -> usize {
    match value {
        Value::Data(d) => d.len(),
        Value::String(s) => s.len(),
        Value::Array(items) => items.iter().map(decoded_bytes).sum(),
        Value::Dictionary(dict) => dict.iter().map(|(k, v)| k.len() + decoded_bytes(v)).sum(),
        _ => 0,
    }
}

fuzz_target!(|data: &[u8]| {
    let parsed = parse(data);
    if let Ok(value) = &parsed {
        let (depth, count) = shape(value);
        assert!(depth <= MAX_DEPTH, "depth {depth}");
        assert!(count <= MAX_EVENTS, "{count} values");
        let bytes = decoded_bytes(value);
        assert!(bytes <= byte_budget(data.len()), "{bytes} decoded bytes");
        assert!(!format!("{value:?}").is_empty());
    }
    let dict = parse_dict(data);
    assert_eq!(
        dict.is_some(),
        matches!(parsed, Ok(Value::Dictionary(_))),
        "parse_dict disagrees with parse"
    );
    let dump = redacted(data);
    assert!(!dump.is_empty());
});
