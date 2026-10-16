//! config.toml (the receiver's), and omdrop's own `settings` file.
//!
//! The receiver validates config.toml and refuses to start on a bad value;
//! the checks here are a courtesy so a typo fails with a readable message,
//! and a set the receiver rejects is rolled back by the caller.

use std::path::Path;

use toml_edit::{DocumentMut, Item, Value};

use crate::ctx::ctx;
use crate::util::{atomic_write, home};

/// The value as Python's `print(tomllib.load(f).get(key, ''))` showed it.
/// A missing file is empty; a file that does not parse says so on stderr
/// and reads as empty, as the bash's failed `$(cfg_get ...)` did.
pub fn cfg_get(key: &str) -> String {
    let path = &ctx().config;
    let text = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    let doc = match parse(path, &text) {
        Ok(d) => d,
        Err(msg) => {
            errln!("{msg}");
            return String::new();
        }
    };
    match doc.get(key) {
        Some(Item::Value(v)) => python_str(v),
        Some(Item::Table(t)) => t.to_string(),
        Some(Item::ArrayOfTables(a)) => a.to_string(),
        _ => String::new(),
    }
}

fn parse(path: &Path, text: &[u8]) -> Result<DocumentMut, String> {
    let s = std::str::from_utf8(text).map_err(|e| format!("{}: {e}", path.display()))?;
    s.parse::<DocumentMut>()
        .map_err(|e| format!("{}: {}", path.display(), e.to_string().trim_end()))
}

fn python_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.value().clone(),
        Value::Integer(i) => i.value().to_string(),
        Value::Boolean(b) => if *b.value() { "True" } else { "False" }.to_string(),
        Value::Float(f) => f.value().to_string(),
        other => other.to_string().trim().to_string(),
    }
}

/// Rewrite one key, keeping every other key and the file's comments and
/// layout. Atomic, so a receiver starting mid-write never reads half a file.
/// `max_receive_percent` is an integer, everything else a string.
pub fn cfg_set(key: &str, val: &str) -> bool {
    match try_cfg_set(&ctx().config, key, val) {
        Ok(()) => true,
        Err(msg) => {
            errln!("{msg}");
            false
        }
    }
}

pub fn try_cfg_set(path: &Path, key: &str, val: &str) -> Result<(), String> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut doc = match std::fs::read(path) {
        Ok(text) => parse(path, &text)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DocumentMut::new(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut new: Value = if key == "max_receive_percent" {
        let n: i64 = val
            .trim()
            .parse()
            .map_err(|_| format!("{}: {val} is not an integer", path.display()))?;
        n.into()
    } else {
        val.into()
    };
    // Keep what surrounds the old value: its spacing and a trailing comment.
    if let Some(Item::Value(old)) = doc.get(key) {
        *new.decor_mut() = old.decor().clone();
    }
    doc[key] = Item::Value(new);
    atomic_write(path, ".config.toml.", doc.to_string().as_bytes(), 0o644)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The last `KEY=` line of the settings file.
pub fn setting_get(key: &str) -> String {
    let Ok(text) = std::fs::read(&ctx().settings) else {
        return String::new();
    };
    let prefix = format!("{key}=");
    String::from_utf8_lossy(&text)
        .lines()
        .filter_map(|l| l.strip_prefix(&prefix))
        .next_back()
        .unwrap_or_default()
        .to_string()
}

pub fn setting_set(key: &str, val: &str) {
    let path = &ctx().settings;
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let prefix = format!("{key}=");
    let mut out = String::new();
    if let Ok(text) = std::fs::read(path) {
        for line in String::from_utf8_lossy(&text).lines() {
            if !line.starts_with(&prefix) {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out.push_str(&format!("{key}={val}\n"));
    let prefix = format!(
        "{}.",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default()
    );
    if let Err(e) = atomic_write(path, &prefix, out.as_bytes(), 0o600) {
        errln!("omdrop: could not write {}: {e}", path.display());
    }
}

/// This computer's short host name, as `hostname -s` printed it.
pub fn default_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is writable for its whole length.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let name = String::from_utf8_lossy(&buf[..end]);
        let short = name.split('.').next().unwrap_or("");
        if !short.is_empty() {
            return short.to_string();
        }
    }
    "omdrop".to_string()
}

pub fn effective_name() -> String {
    let n = cfg_get("name");
    if n.is_empty() { default_name() } else { n }
}

pub fn effective_dir() -> String {
    let d = cfg_get("download_dir");
    if d.is_empty() {
        format!("{}/Downloads", home())
    } else {
        d
    }
}

pub fn effective_limit() -> String {
    let n = cfg_get("max_receive_percent");
    if n.is_empty() { "30".to_string() } else { n }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setting_a_key_keeps_comments_and_other_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("airdrop/config.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "# mine\nname = \"Old\"  # the name\nmodel = \"MacBookPro18,3\"\n",
        )
        .unwrap();
        try_cfg_set(&path, "name", "Brent's \"Mac\"").unwrap();
        try_cfg_set(&path, "max_receive_percent", "45").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# mine\nname = "), "{text}");
        assert!(text.contains("# the name"), "{text}");
        assert!(text.contains("model = \"MacBookPro18,3\""), "{text}");
        assert!(text.contains("max_receive_percent = 45\n"), "{text}");
        let doc: DocumentMut = text.parse().unwrap();
        assert_eq!(doc["name"].as_str(), Some("Brent's \"Mac\""));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn a_file_that_does_not_parse_is_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        std::fs::write(&path, "name = \n").unwrap();
        assert!(try_cfg_set(&path, "name", "x").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "name = \n");
    }

    #[test]
    fn a_missing_file_is_created() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("new/config.toml");
        try_cfg_set(&path, "download_dir", "/x").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "download_dir = \"/x\"\n"
        );
    }
}
