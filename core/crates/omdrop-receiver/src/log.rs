//! The Python receiver's log format, line for line:
//! `%(asctime)s %(levelname)s %(name)s: %(message)s` on stdout, flushed per
//! record. Under systemd it goes to the journal, where `omdrop watch` follows
//! `upload ...: stored ...` and `link stored as ... -> ...`.

use std::fmt;
use std::io::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Debug,
    Info,
    Warning,
    Error,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warning => "WARNING",
            Level::Error => "ERROR",
        }
    }
}

/// Local time as Python logging's `asctime`: `2026-10-10 21:40:00,123`.
fn asctime() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as libc::time_t;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::zeroed();
    // SAFETY: both pointers are valid for the call; localtime_r is the
    // thread-safe variant and fills `tm`.
    let ok = !unsafe { libc::localtime_r(&secs, tm.as_mut_ptr()) }.is_null();
    // SAFETY: zero-initialised, and filled by localtime_r when it succeeded.
    let tm = unsafe { tm.assume_init() };
    if !ok {
        return format!("{secs},{:03}", now.subsec_millis());
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02},{:03}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        now.subsec_millis()
    )
}

/// Longest message written, in bytes. journald splits a stdout line longer
/// than its `LineMax` (48 KiB by default) into several entries, and with
/// `-o cat` a fragment would read as a line of its own, starting with
/// whatever text a peer placed at the cut.
pub const MAX_MESSAGE_BYTES: usize = 32 * 1024;

/// The message with every character that could end or disguise a log line
/// escaped: C0/C1 controls (newlines included) as `\xNN`, and line/paragraph
/// separators, bidi controls, zero-width characters and the BOM as `\uNNNN`.
/// Peers write into this log (names, file names, request lines), and
/// `omdrop watch` acts on what it reads here, so no peer text may ever start
/// a line of its own.
pub fn escape(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    for c in message.chars() {
        if c.is_control() {
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else if matches!(c,
            '\u{2028}' | '\u{2029}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}' | '\u{feff}')
        {
            out.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            out.push(c);
        }
    }
    if out.len() > MAX_MESSAGE_BYTES {
        let mut cut = MAX_MESSAGE_BYTES;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        let dropped = out.len() - cut;
        out.truncate(cut);
        out.push_str(&format!(" [... {dropped} more bytes]"));
    }
    out
}

pub fn log(level: Level, message: fmt::Arguments<'_>) {
    let message = escape(&message.to_string());
    let line = format!("{} {} root: {message}\n", asctime(), level.as_str());
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
}

macro_rules! debug {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Level::Debug, format_args!($($arg)*)) };
}
macro_rules! info {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Level::Info, format_args!($($arg)*)) };
}
macro_rules! warning {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Level::Warning, format_args!($($arg)*)) };
}
macro_rules! error {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Level::Error, format_args!($($arg)*)) };
}

pub(crate) use {debug, error, info, warning};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_text_cannot_start_a_line_or_hide_itself() {
        let forged = "Mac\n2026-10-10 16:14:20,098 INFO root: upload X: stored /home/u/secret.png\r\u{85}\u{2028}\u{202e}";
        let out = escape(forged);
        assert!(!out.chars().any(|c| c.is_control()), "{out}");
        assert_eq!(
            out,
            "Mac\\x0a2026-10-10 16:14:20,098 INFO root: upload X: stored /home/u/secret.png\\x0d\\x85\\u2028\\u202e"
        );
        assert_eq!(escape("café, ok"), "café, ok");
    }

    #[test]
    fn messages_stay_under_journald_line_max() {
        let out = escape(&"é".repeat(40_000));
        assert!(out.len() < MAX_MESSAGE_BYTES + 40);
        assert!(
            out.ends_with(" [... 47232 more bytes]"),
            "{}",
            &out[out.len() - 40..]
        );
    }
}
