//! `DvzipDecoder` on an arbitrary `/Upload` body (DVZip blocks or gzip),
//! read to its end under a ceiling, with read sizes that vary so short reads
//! cross block and buffer boundaries. A body that decodes must survive a
//! `DvzipEncoder` round trip unchanged.

#![no_main]

use std::io::{Read, Write};

use libfuzzer_sys::fuzz_target;
use omdrop_proto::archive::{DvzipDecoder, DvzipEncoder};

/// Decoded bytes read before giving up: a zlib block expands about 1000:1.
const MAX_DECODED: usize = 8 << 20;
const READ_SIZES: [usize; 5] = [1, 7, 512, 4096, 65536];

fn decode(body: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = DvzipDecoder::new(body).ok()?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    for size in READ_SIZES.iter().cycle() {
        match decoder.read(&mut buf[..*size]) {
            Ok(0) => return Some(out),
            Ok(n) => {
                assert!(n <= *size, "read returned {n} for a {size}-byte buffer");
                out.extend_from_slice(&buf[..n]);
                if out.len() > MAX_DECODED {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
    None
}

fuzz_target!(|data: &[u8]| {
    let Some(decoded) = decode(data) else { return };
    let mut encoder = DvzipEncoder::new(Vec::new());
    encoder.write_all(&decoded).expect("encoding into memory");
    let body = encoder.finish().expect("encoding into memory");
    assert_eq!(decode(&body).as_deref(), Some(&decoded[..]), "round trip");
});
