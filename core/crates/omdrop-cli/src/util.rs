//! Small helpers the bash got from the shell itself: output that never
//! panics, `die`, exit-time cleanup, `${VAR:-default}`, `command -v`, POSIX
//! `dirname`/`basename`, `[[ == *glob* ]]`, `printf %q`, and Python's
//! `json.dumps` byte format, which the panel has always been handed.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// `printf` to stdout. A closed stdout (the panel went away) is not a reason
/// to panic halfway through turning the radio off.
#[macro_export]
macro_rules! outln {
    () => {{ let _ = ::std::io::Write::write_all(&mut ::std::io::stdout(), b"\n"); }};
    ($($arg:tt)*) => {{
        let _ = ::std::io::Write::write_fmt(&mut ::std::io::stdout(), format_args!("{}\n", format_args!($($arg)*)));
    }};
}

/// `printf ... >&2`.
#[macro_export]
macro_rules! errln {
    ($($arg:tt)*) => {{
        let _ = ::std::io::Write::write_fmt(&mut ::std::io::stderr(), format_args!("{}\n", format_args!($($arg)*)));
    }};
}

/// Files removed however the process ends (the bash's EXIT traps).
static CLEANUP: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

pub fn remove_at_exit(path: PathBuf) {
    if let Ok(mut list) = CLEANUP.lock() {
        list.push(path);
    }
}

pub fn run_cleanup() {
    crate::proc::spinner_restore_tty();
    if let Ok(mut list) = CLEANUP.lock() {
        for path in list.drain(..) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Every exit goes through here, so the EXIT-trap work always runs.
pub fn exit(code: i32) -> ! {
    let _ = io::stdout().flush();
    run_cleanup();
    std::process::exit(code)
}

/// `die`: the sentence on stderr, exit 1.
pub fn die(msg: impl AsRef<str>) -> ! {
    let _ = io::stdout().flush();
    errln!("{}", msg.as_ref());
    exit(1)
}

/// `${NAME:-}`: unset and empty are the same thing to the bash.
pub fn env_nonempty(name: &str) -> Option<String> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string_lossy().into_owned())
}

pub fn home() -> String {
    std::env::var("HOME").unwrap_or_default()
}

/// `[[ -x PATH ]]`.
pub fn is_executable(path: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated string for the duration of the call.
    unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
}

/// `[[ -r PATH ]]`.
pub fn is_readable(path: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: as above.
    unsafe { libc::access(c.as_ptr(), libc::R_OK) == 0 }
}

/// `[[ -w PATH ]]`.
pub fn is_writable(path: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: as above.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

/// `[[ -L PATH ]]`.
pub fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// `[[ -e PATH || -L PATH ]]`.
pub fn lexists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// `command -v NAME` for a program: the first executable regular file on
/// PATH, so the test suites' stubs win exactly as they did for bash.
pub fn which(name: &str) -> Option<PathBuf> {
    if name.is_empty() {
        return None;
    }
    if name.contains('/') {
        let p = PathBuf::from(name);
        return (p.is_file() && is_executable(&p)).then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let dir = if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
        };
        let candidate = dir.join(name);
        if candidate.is_file() && is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

pub fn have(name: &str) -> bool {
    which(name).is_some()
}

/// POSIX `dirname`.
pub fn dirname(s: &OsStr) -> OsString {
    let b = s.as_bytes();
    let mut end = b.len();
    while end > 1 && b[end - 1] == b'/' {
        end -= 1;
    }
    let trimmed = &b[..end];
    match trimmed.iter().rposition(|&c| c == b'/') {
        None => OsString::from("."),
        Some(pos) => {
            let mut stop = pos;
            while stop > 0 && trimmed[stop - 1] == b'/' {
                stop -= 1;
            }
            if stop == 0 {
                OsString::from("/")
            } else {
                OsString::from_vec(trimmed[..stop].to_vec())
            }
        }
    }
}

/// POSIX `basename` (and `${f##*/}` for paths without a trailing slash).
pub fn basename(s: &OsStr) -> OsString {
    let b = s.as_bytes();
    if b.is_empty() {
        return OsString::new();
    }
    let mut end = b.len();
    while end > 1 && b[end - 1] == b'/' {
        end -= 1;
    }
    let trimmed = &b[..end];
    if trimmed == b"/" {
        return OsString::from("/");
    }
    let start = trimmed
        .iter()
        .rposition(|&c| c == b'/')
        .map_or(0, |p| p + 1);
    OsString::from_vec(trimmed[start..].to_vec())
}

/// `${f##*/}`: everything after the last slash, even when that is nothing.
pub fn after_last_slash(s: &OsStr) -> OsString {
    let b = s.as_bytes();
    let start = b.iter().rposition(|&c| c == b'/').map_or(0, |p| p + 1);
    OsString::from_vec(b[start..].to_vec())
}

/// What `$(...)` does to a command's output.
pub fn strip_trailing_newlines(s: &str) -> &str {
    s.trim_end_matches('\n')
}

pub fn strip_trailing_newlines_bytes(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && b[end - 1] == b'\n' {
        end -= 1;
    }
    &b[..end]
}

/// `[[ "$s" == PATTERN ]]` for patterns whose only metacharacter is `*`,
/// which matches anything, slashes included.
pub fn glob_match(pattern: &str, s: &str) -> bool {
    let p = pattern.as_bytes();
    let t = s.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            mark = ti;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// `case "$line" in *"A"*"B"*)`: the pieces occur in this order.
pub fn contains_in_order(line: &str, pieces: &[&str]) -> bool {
    let mut rest = line;
    for piece in pieces {
        match rest.find(piece) {
            Some(i) => rest = &rest[i + piece.len()..],
            None => return false,
        }
    }
    true
}

/// `${line#*PAT}`: after the first occurrence, or the whole line.
pub fn after_first<'a>(line: &'a str, pat: &str) -> &'a str {
    line.find(pat).map_or(line, |i| &line[i + pat.len()..])
}

/// `printf %q` as bash 5.3 writes it, for commands shown to a person.
pub fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let is_control = |c: char| c.is_control();
    if s.chars().any(is_control) {
        let mut out = String::new();
        let mut run = String::new();
        let mut ctl = String::new();
        let flush_run = |run: &mut String, out: &mut String| {
            if !run.is_empty() {
                out.push('\'');
                out.push_str(&run.replace('\'', "'\\''"));
                out.push('\'');
                run.clear();
            }
        };
        let flush_ctl = |ctl: &mut String, out: &mut String| {
            if !ctl.is_empty() {
                out.push_str("$'");
                out.push_str(ctl);
                out.push('\'');
                ctl.clear();
            }
        };
        if s.starts_with(is_control) {
            out.push_str("''");
        }
        for c in s.chars() {
            if is_control(c) {
                flush_run(&mut run, &mut out);
                match c {
                    '\n' => ctl.push_str("\\n"),
                    '\t' => ctl.push_str("\\t"),
                    '\r' => ctl.push_str("\\r"),
                    '\x07' => ctl.push_str("\\a"),
                    '\x08' => ctl.push_str("\\b"),
                    '\x0b' => ctl.push_str("\\v"),
                    '\x0c' => ctl.push_str("\\f"),
                    '\x1b' => ctl.push_str("\\E"),
                    _ => {
                        let mut buf = [0u8; 4];
                        for b in c.encode_utf8(&mut buf).bytes() {
                            ctl.push_str(&format!("\\{b:03o}"));
                        }
                    }
                }
            } else {
                flush_ctl(&mut ctl, &mut out);
                run.push(c);
            }
        }
        flush_run(&mut run, &mut out);
        flush_ctl(&mut ctl, &mut out);
        return out;
    }
    const SPECIAL: &[char] = &[
        ' ', '!', '"', '$', '&', '\'', '(', ')', '*', ';', '<', '=', '>', '?', '[', '\\', '^', '`',
        '|',
    ];
    let needs = s.contains(SPECIAL) || s.starts_with(['#', '~']);
    if !needs {
        return s.to_string();
    }
    if s.contains('\'') && !s.contains(['$', '`', '\\', '"', '!']) {
        return format!("\"{s}\"");
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// `json.dumps` with Python's defaults: `", "` and `": "` separators and
/// every non-ASCII character escaped. The panel was written against that.
struct PyFormatter;

impl serde_json::ser::Formatter for PyFormatter {
    fn begin_array_value<W: ?Sized + Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
    fn begin_object_key<W: ?Sized + Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
    fn begin_object_value<W: ?Sized + Write>(&mut self, w: &mut W) -> io::Result<()> {
        w.write_all(b": ")
    }
    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        w: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        for c in fragment.chars() {
            if c.is_ascii() && c != '\x7f' {
                w.write_all(&[c as u8])?;
            } else {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    write!(w, "\\u{u:04x}")?;
                }
            }
        }
        Ok(())
    }
}

pub fn py_json<T: serde::Serialize + ?Sized>(value: &T) -> String {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, PyFormatter);
    if value.serialize(&mut ser).is_err() {
        return "null".to_string();
    }
    String::from_utf8(buf).unwrap_or_else(|_| "null".to_string())
}

/// Write a file through a temporary beside it and a rename, so a reader
/// never sees half of it. `prefix` names the temporary. A symlinked file
/// (dotfiles kept in stow or chezmoi) is written at its target, so the link
/// survives, and an existing file keeps its mode; `mode` is for a new one.
pub fn atomic_write(path: &Path, prefix: &str, content: &[u8], mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let target = if is_symlink(path) {
        std::fs::canonicalize(path)?
    } else {
        path.to_path_buf()
    };
    let mode = std::fs::metadata(&target).map_or(mode, |m| m.permissions().mode() & 0o7777);
    let dir = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let (tmp, mut file) = create_unique(dir, prefix, mode)?;
    let result = file.write_all(content).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) =
        result.and_then(|()| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)))
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, &target).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// `mktemp DIR/PREFIXXXXXXX`: a new file nobody else can have opened.
pub fn create_unique(dir: &Path, prefix: &str, mode: u32) -> io::Result<(PathBuf, std::fs::File)> {
    for _ in 0..100 {
        let name = format!("{prefix}{}", random_suffix());
        let path = dir.join(name);
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
        {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no unique temporary name",
    ))
}

/// Six characters, as mktemp's XXXXXX.
pub fn random_suffix() -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut n = random_u64();
    (0..6)
        .map(|_| {
            let c = CHARS[(n % CHARS.len() as u64) as usize] as char;
            n /= CHARS.len() as u64;
            c
        })
        .collect()
}

/// Not for secrets: temporary names and the spinner's first verb.
pub fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.write_u32(std::process::id());
    h.finish()
}

/// `${p/#$HOME/\~}`.
pub fn tildify(p: &str) -> String {
    let home = home();
    if !home.is_empty() {
        if let Some(rest) = p.strip_prefix(&home) {
            return format!("~{rest}");
        }
    }
    p.to_string()
}

/// `mkdir -p` under `umask 077`.
pub fn mkdir_private(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

/// Read a file as bash's `$(cat FILE)` would: missing or unreadable is "".
pub fn read_trimmed(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(String::from_utf8_lossy(strip_trailing_newlines_bytes(&bytes)).into_owned())
}

/// POSIX `[[:space:]]` for the bytes and characters config files hold.
pub fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r') || (!c.is_ascii() && c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirname_and_basename_follow_posix() {
        for (input, dir, base) in [
            ("/a/b/c", "/a/b", "c"),
            ("/a/b/", "/a", "b"),
            ("c", ".", "c"),
            ("/", "/", "/"),
            ("//x", "/", "x"),
            ("a/b", "a", "b"),
        ] {
            assert_eq!(dirname(OsStr::new(input)), OsStr::new(dir), "{input}");
            assert_eq!(basename(OsStr::new(input)), OsStr::new(base), "{input}");
        }
    }

    #[test]
    fn glob_stars_cross_slashes() {
        assert!(glob_match(
            "*/plugins/*/bin/omdrop",
            "/h/.config/omarchy/plugins/x/bin/omdrop"
        ));
        assert!(glob_match(
            "*/plugins/*/skills/omdrop",
            "/a/plugins/b/c/skills/omdrop"
        ));
        assert!(!glob_match("*/plugins/*/bin/omdrop", "/h/bin/omdrop"));
        assert!(!glob_match(
            "*/plugins/*/bin/omdrop",
            "/a/plugins/b/bin/omdrop2"
        ));
    }

    #[test]
    fn printf_q_matches_bash() {
        // Captured from bash 5.3.20 `printf '%q'`.
        for (input, quoted) in [
            ("a,b", "a,b"),
            ("x=y", "'x=y'"),
            ("~x", "'~x'"),
            ("a~", "a~"),
            ("#a", "'#a'"),
            ("a#b", "a#b"),
            ("https://e.com/a?q=1&b=2#s", "'https://e.com/a?q=1&b=2#s'"),
            ("é", "é"),
            ("a b", "'a b'"),
            ("it's", "\"it's\""),
            ("it's $x", "'it'\\''s $x'"),
            ("a'b\"c", "'a'\\''b\"c'"),
            ("a:b", "a:b"),
            ("%^+@", "'%^+@'"),
            ("a\nb", "'a'$'\\n''b'"),
            ("a\tb", "'a'$'\\t''b'"),
            ("\x7f", "''$'\\177'"),
            ("", "''"),
            ("fe:63:e6:68:9f:12", "fe:63:e6:68:9f:12"),
        ] {
            assert_eq!(shell_quote(input), quoted, "{input:?}");
        }
    }

    #[test]
    fn json_is_byte_compatible_with_python() {
        let v = serde_json::json!({"a": [1, null, "é\u{7f}\u{1F600}\n"], "b": true});
        assert_eq!(
            py_json(&v),
            r#"{"a": [1, null, "\u00e9\u007f\ud83d\ude00\n"], "b": true}"#
        );
        assert_eq!(py_json(&Vec::<String>::new()), "[]");
    }
}
