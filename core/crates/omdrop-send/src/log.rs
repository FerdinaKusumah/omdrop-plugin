//! airdrop-send.py's logging, line for line.
//!
//! A transfer logs every step to stdout as
//! `2026-09-18 12:00:02,000 INFO send: +  2.10s ASK -> accepted (1.69s)`;
//! `omdrop`'s narrate_send turns the `send` lines into sentences, so their text
//! is a contract. Protocol detail goes to the `airdrop` logger at DEBUG.
//! `--discover-only` keeps stdout for the name: WARNING and above only, to
//! stderr, in Python's bare `LEVEL:logger:message` form.

use std::io::Write;
use std::time::Instant;

/// Where log records go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sink {
    /// Everything from DEBUG, to stdout, timestamped (a transfer).
    Transfer,
    /// WARNING and above, to stderr (`--discover-only`).
    Warnings,
    /// Nothing (a name lookup inside send-to-peer, whose subprocess output
    /// the Python version captured and dropped).
    Silent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Debug,
    Info,
    Warning,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warning => "WARNING",
        }
    }
}

/// The program's logger. `t()` is the `+  0.41s` elapsed-time stamp every
/// `send` line starts with.
#[derive(Debug)]
pub struct Logger {
    sink: Sink,
    t0: Instant,
}

impl Logger {
    pub fn new(sink: Sink) -> Logger {
        Logger {
            sink,
            t0: Instant::now(),
        }
    }

    /// Seconds since start, as `+{:6.2f}s`.
    pub fn t(&self) -> String {
        format!("+{:6.2}s", self.t0.elapsed().as_secs_f64())
    }

    pub fn debug(&self, logger: &str, msg: &str) {
        self.emit(Level::Debug, logger, msg);
    }

    pub fn info(&self, logger: &str, msg: &str) {
        self.emit(Level::Info, logger, msg);
    }

    pub fn warning(&self, logger: &str, msg: &str) {
        self.emit(Level::Warning, logger, msg);
    }

    /// `send` at INFO: the lines callers parse.
    pub fn send(&self, msg: &str) {
        self.info("send", msg);
    }

    /// `airdrop` at DEBUG: protocol detail.
    pub fn wire(&self, msg: &str) {
        self.debug("airdrop", msg);
    }

    fn emit(&self, level: Level, logger: &str, msg: &str) {
        // Python's StreamHandler flushes every record, so a pipe reader sees
        // each line as it happens; write and flush one line at a time.
        match self.sink {
            Sink::Silent => {}
            Sink::Transfer => {
                let line = format!("{} {} {logger}: {msg}\n", timestamp(), level.name());
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(line.as_bytes());
                let _ = out.flush();
            }
            Sink::Warnings if level >= Level::Warning => {
                let line = format!("{}:{logger}:{msg}\n", level.name());
                let _ = std::io::stderr().lock().write_all(line.as_bytes());
            }
            Sink::Warnings => {}
        }
    }
}

/// Local time as Python's logging `asctime`: `2026-09-18 12:00:00,000`.
fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = libc::time_t::try_from(now.as_secs()).unwrap_or(0);
    let millis = now.subsec_millis();
    // SAFETY: `tm` is plain old data; localtime_r writes into it and reads
    // only `secs`, both valid for the call's duration.
    let tm = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&secs, &mut tm).is_null() {
            return format!("{secs},{millis:03}");
        }
        tm
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02},{millis:03}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_have_python_shapes() {
        let log = Logger::new(Sink::Silent);
        let t = log.t();
        assert!(t.starts_with("+  0.0") && t.ends_with('s'), "{t}");
        let ts = timestamp();
        assert_eq!(ts.len(), "2026-09-18 12:00:00,000".len(), "{ts}");
        assert_eq!(&ts[19..20], ",");
    }
}
