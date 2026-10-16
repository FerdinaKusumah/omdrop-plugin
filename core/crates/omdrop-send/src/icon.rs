//! The Ask's `FileIcon`: a JPEG thumbnail of the first file, at most 240x240,
//! quality 80, as airdrop-send.py made it with PIL. A Mac's own Ask carries a
//! ~25 KB icon (captured 2026-09-07); the receiver shows it in its prompt.
//!
//! The icon is decoration and must never cost the transfer. Anything that is
//! not a decodable image within the limits below simply goes without one,
//! and so does a decoder that panics on a malformed file: the decode runs
//! under `catch_unwind` (this relies on the default `panic = "unwind"`).

use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::panic::{self, AssertUnwindSafe};

use image::codecs::jpeg::JpegEncoder;
use image::{ImageReader, Limits};

const EDGE: u32 = 240;
const QUALITY: u8 = 80;
/// Files larger than this are not decoded for an icon.
pub const MAX_ICON_SOURCE_BYTES: u64 = 64 << 20;
/// 64 megapixels at 4 bytes per pixel.
const MAX_ALLOC: u64 = 256 << 20;
const MAX_EDGE: u32 = 16384;
const MAX_PIXELS: u64 = 64_000_000;

/// The thumbnail's JPEG bytes, or `None` when `file` is not an image this
/// build decodes (JPEG, PNG, GIF, WebP, BMP) within the limits. Reads from
/// the start of `file` and leaves its position at the start again, so the
/// same open file can then be uploaded.
pub fn file_icon(mut file: &File) -> Option<Vec<u8>> {
    if file.metadata().ok()?.len() > MAX_ICON_SOURCE_BYTES {
        return None;
    }
    let data = read_if_image(file);
    // Rewound either way: the upload streams from this same open file.
    let rewound = file.seek(SeekFrom::Start(0)).is_ok();
    icon_from_bytes(&data?).filter(|_| rewound)
}

/// The whole file, if its first bytes are an image format's magic (so a
/// large video is never read just to learn it is not a picture).
fn read_if_image(mut file: &File) -> Option<Vec<u8>> {
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut head = Vec::new();
    file.take(64).read_to_end(&mut head).ok()?;
    image::guess_format(&head).ok()?;
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut data = Vec::new();
    file.take(MAX_ICON_SOURCE_BYTES + 1)
        .read_to_end(&mut data)
        .ok()?;
    (data.len() as u64 <= MAX_ICON_SOURCE_BYTES).then_some(data)
}

/// [`file_icon`] of bytes already in memory.
pub fn icon_from_bytes(data: &[u8]) -> Option<Vec<u8>> {
    // A panicking decoder must not print a backtrace into the send's stderr,
    // which `omdrop` shows to the person sending. The program is
    // single-threaded while it builds the Ask, so swapping the hook is safe.
    let previous = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(AssertUnwindSafe(|| thumbnail(data)));
    panic::set_hook(previous);
    result.ok().flatten()
}

fn thumbnail(data: &[u8]) -> Option<Vec<u8>> {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_EDGE);
    limits.max_image_height = Some(MAX_EDGE);
    limits.max_alloc = Some(MAX_ALLOC);
    let probe = ImageReader::new(BufReader::new(Cursor::new(data)))
        .with_guessed_format()
        .ok()?;
    let (w, h) = probe.into_dimensions().ok()?;
    if u64::from(w) * u64::from(h) > MAX_PIXELS {
        return None;
    }
    let mut reader = ImageReader::new(BufReader::new(Cursor::new(data)))
        .with_guessed_format()
        .ok()?;
    reader.limits(limits);
    let img = reader.decode().ok()?;
    // PIL's thumbnail(): shrink to fit, keep the aspect ratio, never enlarge.
    let img = if img.width() > EDGE || img.height() > EDGE {
        img.thumbnail(EDGE, EDGE)
    } else {
        img
    };
    let rgb = img.to_rgb8();
    let mut out = Cursor::new(Vec::new());
    JpegEncoder::new_with_quality(&mut out, QUALITY)
        .encode_image(&rgb)
        .ok()?;
    Some(out.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let mut out = Vec::new();
        image::RgbImage::from_pixel(w, h, image::Rgb([200, 10, 10]))
            .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    }

    fn jpeg(w: u32, h: u32) -> Vec<u8> {
        let mut out = Vec::new();
        image::RgbImage::from_pixel(w, h, image::Rgb([10, 200, 10]))
            .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Jpeg)
            .unwrap();
        out
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn images_get_a_bounded_jpeg_and_the_file_is_rewound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wide.png");
        std::fs::write(&path, png(600, 300)).unwrap();
        let mut f = File::open(&path).unwrap();
        let icon = file_icon(&f).unwrap();
        assert_eq!(&icon[..3], b"\xff\xd8\xff");
        let decoded = image::load_from_memory(&icon).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (240, 120));
        assert_eq!(f.stream_position().unwrap(), 0);
        let text = dir.path().join("notes.txt");
        std::fs::write(&text, b"not an image").unwrap();
        assert_eq!(file_icon(&File::open(&text).unwrap()), None);
    }

    #[test]
    fn truncated_and_corrupt_images_give_no_icon() {
        for good in [png(64, 48), jpeg(64, 48)] {
            assert!(icon_from_bytes(&good).is_some());
            for cut in [1, 8, 16, 33, good.len() / 2, good.len() - 1] {
                let _ = icon_from_bytes(&good[..cut]);
            }
            let mut corrupt = good.clone();
            for (i, b) in corrupt.iter_mut().enumerate().skip(20) {
                *b ^= (i * 31) as u8;
            }
            assert_eq!(icon_from_bytes(&corrupt), None);
        }
    }

    #[test]
    fn a_declared_giant_is_refused_before_decoding() {
        // A valid 1x1 PNG whose header claims 16000 x 16000 (256 MP).
        let mut data = png(1, 1);
        data[16..20].copy_from_slice(&16000u32.to_be_bytes());
        data[20..24].copy_from_slice(&16000u32.to_be_bytes());
        let crc = crc32(&data[12..29]);
        data[29..33].copy_from_slice(&crc.to_be_bytes());
        let started = std::time::Instant::now();
        assert_eq!(icon_from_bytes(&data), None);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
}
