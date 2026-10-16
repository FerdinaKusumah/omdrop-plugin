//! Opt-in dumps of AirDrop requests and answers (identity contract, "Debug
//! dumps").
//!
//! Off unless `OMDROP_DEBUG=1` (redacted) or `OMDROP_DEBUG_SENSITIVE=1`
//! (verbatim). Dumps land in `$XDG_RUNTIME_DIR/omdrop/debug/<name>`, mode
//! 0600 in a private 0700 directory, never in the home directory: a request
//! carries validation records, ours and the peer's.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use plist::Value;

/// Whether dumps are on, and whether they are verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Off,
    Redacted,
    Sensitive,
}

/// The mode the environment asks for. `verbose` (a `--verbose` flag) turns
/// redacted dumps on.
pub fn mode(verbose: bool) -> Mode {
    let set = |name| std::env::var_os(name).is_some_and(|v| v == "1");
    if set("OMDROP_DEBUG_SENSITIVE") {
        Mode::Sensitive
    } else if verbose || set("OMDROP_DEBUG") {
        Mode::Redacted
    } else {
        Mode::Off
    }
}

/// Write one exchange's body as `name` if dumps are on. Returns the path
/// written, `None` when dumps are off. Callers log an error and carry on: a
/// diagnostic must never break a transfer.
pub fn dump(name: &str, data: &[u8], verbose: bool) -> io::Result<Option<PathBuf>> {
    let mode = mode(verbose);
    if mode == Mode::Off {
        return Ok(None);
    }
    let root = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("protocol dumps require XDG_RUNTIME_DIR"))?;
    dump_into(&root, name, data, mode).map(Some)
}

/// [`dump`] with an explicit runtime directory and mode.
pub fn dump_into(root: &Path, name: &str, data: &[u8], mode: Mode) -> io::Result<PathBuf> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid protocol dump name",
        ));
    }
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let private = |path: &Path| -> io::Result<()> {
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "protocol dump directory is not private and user-owned",
            ));
        }
        Ok(())
    };
    if !root.is_absolute() {
        return Err(io::Error::other(
            "protocol dumps require an absolute runtime directory",
        ));
    }
    private(root)?;
    let directory = root.join("omdrop").join("debug");
    for path in [root.join("omdrop"), directory.clone()] {
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        private(&path)?;
    }
    let body = match mode {
        Mode::Sensitive => data.to_vec(),
        _ => redacted(data),
    };
    let mut tmp = tempfile::Builder::new()
        .prefix(".dump-")
        .permissions(fs::Permissions::from_mode(0o600))
        .tempfile_in(&directory)?;
    tmp.write_all(&body)?;
    let path = directory.join(name);
    tmp.persist(&path).map_err(|e| e.error)?;
    Ok(path)
}

/// A plist body with secrets replaced, as XML; anything else as its size.
pub fn redacted(data: &[u8]) -> Vec<u8> {
    let Ok(value) = crate::safeplist::parse(data) else {
        return format!("<opaque {} bytes>", data.len()).into_bytes();
    };
    let mut out = Vec::new();
    match redact(value).to_writer_xml(&mut out) {
        Ok(()) => out,
        Err(_) => format!("<opaque {} bytes>", data.len()).into_bytes(),
    }
}

/// In every dictionary, at any depth, a value whose key ends in `RecordData`
/// or `Certificate` becomes `<redacted N bytes>`: N is the byte length of data
/// or UTF-8 text, and the element count of an array or dictionary.
fn redact(value: Value) -> Value {
    match value {
        Value::Dictionary(dict) => Value::Dictionary(
            dict.into_iter()
                .map(|(key, item)| {
                    let secret = key.ends_with("RecordData") || key.ends_with("Certificate");
                    let size = match &item {
                        Value::Data(d) => Some(d.len()),
                        Value::String(s) => Some(s.len()),
                        Value::Array(a) => Some(a.len()),
                        Value::Dictionary(d) => Some(d.len()),
                        _ => None,
                    };
                    match (secret, size) {
                        (true, Some(n)) => (key, Value::String(format!("<redacted {n} bytes>"))),
                        _ => (key, redact(item)),
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(redact).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::Dictionary;

    fn plist_bytes(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        value.to_writer_binary(&mut out).unwrap();
        out
    }

    #[test]
    fn secrets_are_replaced_at_any_depth() {
        let mut inner = Dictionary::new();
        inner.insert("SenderRecordData".into(), Value::Data(vec![7; 40]));
        inner.insert("SenderComputerName".into(), Value::String("hume".into()));
        let mut outer = Dictionary::new();
        outer.insert("Items".into(), Value::Array(vec![Value::Dictionary(inner)]));
        outer.insert("ReceiverCertificate".into(), Value::String("héllo".into()));
        let out = String::from_utf8(redacted(&plist_bytes(&Value::Dictionary(outer)))).unwrap();
        assert!(out.contains("&lt;redacted 40 bytes&gt;"), "{out}");
        assert!(out.contains("&lt;redacted 6 bytes&gt;"), "{out}");
        assert!(out.contains("hume"));
    }

    #[test]
    fn non_plist_bodies_are_sized_not_kept() {
        assert_eq!(redacted(b"\x1f\x8b not a plist"), b"<opaque 14 bytes>");
    }

    #[test]
    fn dumps_are_private_and_refuse_path_names() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dump_into(root.path(), "ask.plist", b"x", Mode::Sensitive).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"x");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        assert!(dump_into(root.path(), "../x", b"x", Mode::Sensitive).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(dump_into(root.path(), "ask.plist", b"x", Mode::Sensitive).is_err());
    }
}
