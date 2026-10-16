//! A connection's bytes through the receiver's HTTP/1.1 path: `read_request`
//! for the head and, when it parses, `body_plan` and `BodyReader` for the
//! body under a small limit, then the next request on the same connection.
//!
//! Input: a byte choosing the read buffer's capacity (1 to 256 bytes, so
//! lines and chunks cross buffer boundaries), then the connection's bytes.

#![no_main]

use std::io::{BufReader, Read};

use libfuzzer_sys::fuzz_target;
use omdrop_proto::http::{BodyError, BodyPlan, BodyReader, ReadDeadline, body_plan, read_request};

/// The body limit: small, so chunk sizes and Content-Length reach it.
const LIMIT: u64 = 4096;
/// Requests read from one connection.
const MAX_REQUESTS: usize = 8;

fuzz_target!(|data: &[u8]| {
    let Some((&capacity, rest)) = data.split_first() else {
        return;
    };
    let mut conn = BufReader::with_capacity(usize::from(capacity) + 1, rest);
    for _ in 0..MAX_REQUESTS {
        let Ok(req) = read_request(&mut conn) else {
            return;
        };
        let _ = req.keep_alive();
        let planned = body_plan(&req.headers, LIMIT);
        if req.method != "POST" {
            continue;
        }
        let Ok(plan) = planned else { return };
        if let BodyPlan::Length(n) = plan {
            assert!(n <= LIMIT, "planned {n} bytes over the {LIMIT}-byte limit");
        }
        let mut deadline = ReadDeadline::new();
        let mut reader = BodyReader::new(&mut conn, plan, LIMIT, &mut deadline);
        let mut body = Vec::new();
        let read = reader.read_to_end(&mut body);
        let total = reader.total();
        assert_eq!(
            total,
            body.len() as u64,
            "total() disagrees with the bytes read"
        );
        assert!(
            total <= LIMIT,
            "{total} body bytes over the {LIMIT}-byte limit"
        );
        match read {
            Ok(_) => {
                if let BodyPlan::Length(n) = plan {
                    assert_eq!(n, total, "a Content-Length body of the wrong size");
                }
            }
            Err(e) => {
                assert!(
                    BodyError::classify(e).is_ok(),
                    "a body error that is not a BodyError"
                );
                return;
            }
        }
    }
});
