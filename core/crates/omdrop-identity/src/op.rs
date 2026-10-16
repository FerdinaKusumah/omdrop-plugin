//! The 1Password CLI (`op`), with a deadline and a pid file so `off` and
//! `identity lock` can kill a running request.

use std::ffi::OsString;
use std::fmt;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub(crate) const FETCH_SECONDS: u64 = 60;

/// Why 1Password gave nothing. `Display` is short enough for a notification;
/// `detail` keeps what 1Password itself said, for the command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FetchFailed {
    pub message: String,
    pub detail: String,
}

impl FetchFailed {
    pub(crate) fn new(message: impl Into<String>, detail: impl Into<String>) -> Self {
        FetchFailed {
            message: message.into(),
            detail: detail.into(),
        }
    }

    /// `describe(e)`: the message, and the detail in parentheses if any.
    pub(crate) fn describe(&self) -> String {
        if self.detail.is_empty() {
            self.message.clone()
        } else {
            format!("{} ({})", self.message, self.detail)
        }
    }
}

impl fmt::Display for FetchFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// op's own errors name an op:// path and a client library; what the person
/// can act on is which of these happened.
pub(crate) fn plain_op_error(message: &str) -> &'static str {
    let m = message.to_lowercase();
    if m.contains("prompt dismissed") {
        return "1Password prompt dismissed";
    }
    if [
        "locked",
        "initializing client",
        "desktop app",
        "signed in",
        "sign in",
        "session expired",
    ]
    .iter()
    .any(|s| m.contains(s))
    {
        return "1Password locked";
    }
    if [
        "isn't an item",
        "isn't a field",
        "could not find",
        "no item",
    ]
    .iter()
    .any(|s| m.contains(s))
    {
        return "The 1Password item is missing or incomplete";
    }
    "1Password could not provide the identity"
}

/// `shutil.which(name)`: the first executable regular file on `PATH`.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file() && is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: access on a NUL-terminated path.
    unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
}

/// `OMDROP_OP`, else `op` on `PATH`.
pub(crate) fn op_binary() -> Option<PathBuf> {
    std::env::var_os("OMDROP_OP")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| which("op"))
}

/// Drop op's `[ERROR] 2026/09/28 23:06:41 ` prefix; keep the message.
fn strip_log_prefix(line: &str) -> &str {
    let b = line.as_bytes();
    let mut i = 0;
    if b.first() != Some(&b'[') {
        return line;
    }
    i += 1;
    let word = b[i..]
        .iter()
        .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
        .count();
    if word == 0 || b.get(i + word) != Some(&b']') {
        return line;
    }
    i += word + 1;
    let ws = |from: usize| {
        b[from..]
            .iter()
            .take_while(|c| c.is_ascii_whitespace())
            .count()
    };
    let w = ws(i);
    if w == 0 {
        return line;
    }
    i += w;
    // \d{4}/\d\d/\d\d \d\d:\d\d:\d\d
    let shape = b"dddd/dd/dd dd:dd:dd";
    if b.len() < i + shape.len() {
        return line;
    }
    for (k, s) in shape.iter().enumerate() {
        let c = b[i + k];
        let ok = if *s == b'd' {
            c.is_ascii_digit()
        } else {
            c == *s
        };
        if !ok {
            return line;
        }
    }
    i += shape.len();
    let w = ws(i);
    if w == 0 {
        return line;
    }
    &line[i + w..]
}

/// The reason a failed `op` gives: the last line of its stderr, without the
/// log prefix, at most 300 characters.
fn failure_reason(stderr: &[u8], code: i32) -> String {
    let text = String::from_utf8_lossy(stderr);
    let lines = crate::contract::splitlines(text.trim());
    let reason = match lines.last() {
        Some(l) if !text.trim().is_empty() => strip_log_prefix(l).to_owned(),
        _ => format!("exit {code}"),
    };
    reason.chars().take(300).collect()
}

fn did_not_answer() -> FetchFailed {
    FetchFailed::new(
        "1Password did not answer",
        format!("no answer within {FETCH_SECONDS} s"),
    )
}

/// Read a pipe to its end on a thread; the result arrives on the channel.
fn reader(mut pipe: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = pipe.read_to_end(&mut out);
        let _ = tx.send(out);
    });
    rx
}

/// What a reader collected, waiting no later than `until` (and at least a
/// moment, for a pipe that closes as its writer exits). `None` if a
/// descendant still holds the pipe open: never wait on it forever.
fn collect(rx: &mpsc::Receiver<Vec<u8>>, until: Instant) -> Option<Vec<u8>> {
    let wait = until
        .saturating_duration_since(Instant::now())
        .max(Duration::from_secs(1));
    rx.recv_timeout(wait).ok()
}

/// Run `op ARGS`, recorded in `pid_file` so `off` or `identity lock` can kill it.
///
/// In this process's own session, deliberately: 1Password's app integration
/// grants an approval per session, so a new session for each call made every
/// call prompt again. `op` is a single binary with no children, so killing
/// its pid is enough.
pub(crate) fn op_run(
    op: Option<&Path>,
    pid_file: &Path,
    args: &[OsString],
    deadline: Instant,
) -> Result<Vec<u8>, FetchFailed> {
    let Some(op) = op else {
        return Err(FetchFailed::new("1Password CLI (op) not installed", ""));
    };
    if Instant::now() >= deadline {
        return Err(did_not_answer());
    }
    let mut child = match Command::new(op)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FetchFailed::new("1Password CLI (op) not installed", ""));
        }
        Err(e) => {
            return Err(FetchFailed::new(
                "1Password could not provide the identity",
                e.to_string(),
            ));
        }
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(FetchFailed::new(
            "1Password could not provide the identity",
            "no pipes",
        ));
    };
    let out = reader(stdout);
    let err = reader(stderr);
    let recorded = crate::fsx::write_private(pid_file, format!("{}\n", child.id()).as_bytes());
    let status = if let Err(e) = recorded {
        // Without the pid file, `off` could not cancel this request.
        let _ = child.kill();
        let _ = child.wait();
        Err(FetchFailed::new(
            "1Password could not provide the identity",
            e.to_string(),
        ))
    } else {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(did_not_answer());
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(FetchFailed::new(
                        "1Password could not provide the identity",
                        e.to_string(),
                    ));
                }
            }
        }
    };
    let _ = std::fs::remove_file(pid_file);
    let stdout = collect(&out, deadline);
    let stderr = collect(&err, deadline);
    let status = status?;
    let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
        return Err(did_not_answer());
    };
    match status.code() {
        None => Err(FetchFailed::new("1Password request cancelled", "")),
        Some(0) => Ok(stdout),
        Some(code) => {
            let reason = failure_reason(&stderr, code);
            Err(FetchFailed::new(plain_op_error(&reason), reason))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_errors_are_named_without_their_text() {
        assert_eq!(
            plain_op_error("authorization prompt dismissed, please try again"),
            "1Password prompt dismissed"
        );
        assert_eq!(
            plain_op_error(
                "error initializing client: connecting to desktop app: connection reset"
            ),
            "1Password locked"
        );
        assert_eq!(
            plain_op_error("\"x\" isn't an item in the \"y\" vault"),
            "The 1Password item is missing or incomplete"
        );
        assert_eq!(
            plain_op_error("boom"),
            "1Password could not provide the identity"
        );
    }

    #[test]
    fn the_log_prefix_is_dropped_and_the_reason_bounded() {
        assert_eq!(
            strip_log_prefix("[ERROR] 2026/09/28 23:06:41 message here"),
            "message here"
        );
        assert_eq!(
            strip_log_prefix("[ERROR] soon message"),
            "[ERROR] soon message"
        );
        assert_eq!(
            failure_reason(b"first\n[ERROR] 2026/09/28 10:00:00 last\n", 1),
            "last"
        );
        assert_eq!(failure_reason(b"  \n", 7), "exit 7");
        assert_eq!(
            failure_reason("é".repeat(400).as_bytes(), 1)
                .chars()
                .count(),
            300
        );
    }

    #[test]
    fn a_hung_op_is_killed_at_the_deadline_and_its_pid_file_removed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid = dir.path().join("fetch.pid");
        let started = Instant::now();
        let r = op_run(
            Some(Path::new("/bin/sleep")),
            &pid,
            &["30".into()],
            Instant::now() + Duration::from_millis(300),
        );
        assert_eq!(r, Err(did_not_answer()));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!pid.exists());
        assert_eq!(
            op_run(None, &pid, &[], Instant::now() + Duration::from_secs(1)),
            Err(FetchFailed::new("1Password CLI (op) not installed", ""))
        );
        assert_eq!(
            op_run(
                Some(&dir.path().join("no-such-op")),
                &pid,
                &[],
                Instant::now() + Duration::from_secs(1)
            ),
            Err(FetchFailed::new("1Password CLI (op) not installed", ""))
        );
    }
}
