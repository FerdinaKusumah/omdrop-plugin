//! Does a key belong to a certificate, and running `openssl`.

use std::ffi::OsStr;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use rustls::crypto::ring::sign::any_supported_type;
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::asuser::Creds;

/// Run `openssl ARGS` (an argv vector, never a shell) with `stdin` (or
/// `/dev/null`), optionally in `cwd` and with dropped credentials.
pub(crate) fn openssl<S: AsRef<OsStr>>(
    args: &[S],
    stdin: Option<&[u8]>,
    cwd: Option<&Path>,
    creds: Option<Creds>,
) -> io::Result<Output> {
    let mut cmd = Command::new("openssl");
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    if let Some(c) = creds {
        // std clears supplementary groups when root sets a uid.
        cmd.uid(c.uid).gid(c.gid);
    }
    let mut child = cmd.spawn()?;
    let input = child.stdin.take();
    std::thread::scope(|s| {
        if let (Some(mut pipe), Some(data)) = (input, stdin) {
            // A child that exits without reading its input is not an error
            // here; its exit status says what happened.
            s.spawn(move || {
                let _ = pipe.write_all(data);
            });
        }
        child.wait_with_output()
    })
}

/// The first certificate in a PEM text, as DER.
pub(crate) fn certificate_der(pem: &[u8]) -> Option<CertificateDer<'static>> {
    CertificateDer::from_pem_slice(pem).ok()
}

/// In process: the key's public half against the certificate's
/// SubjectPublicKeyInfo, byte for byte, as rustls checks a `CertifiedKey`.
/// `Some(true)` only on a positive match.
fn matches_in_process(cert_pem: &[u8], key_pem: &[u8]) -> Option<bool> {
    let cert = certificate_der(cert_pem)?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).ok()?;
    let signer = any_supported_type(&key).ok()?;
    Some(CertifiedKey::new(vec![cert], signer).keys_match().is_ok())
}

/// `openssl x509 -pubkey` against `openssl pkey -pubout`, as both Python
/// implementations did.
fn matches_by_openssl(cert_pem: &[u8], key_pem: &[u8], creds: Option<Creds>) -> bool {
    let a = openssl(&["x509", "-noout", "-pubkey"], Some(cert_pem), None, creds);
    let b = openssl(
        &["pkey", "-passin", "pass:", "-pubout"],
        Some(key_pem),
        None,
        creds,
    );
    match (a, b) {
        (Ok(a), Ok(b)) => a.status.success() && b.status.success() && a.stdout == b.stdout,
        _ => false,
    }
}

/// Does this private key belong to this certificate?
///
/// Checked in process for every key type rustls loads (RSA >= 2048 bits,
/// ECDSA P-256/P-384, Ed25519). Anything else -- and any in-process "no",
/// in case the certificate encodes the same key differently -- is decided
/// by `openssl`, run with `creds` when root acts for another user, since
/// the bytes came from that user's files.
pub(crate) fn key_matches(cert_pem: &[u8], key_pem: &[u8], creds: Option<Creds>) -> bool {
    if cert_pem.is_empty() || key_pem.is_empty() {
        return false;
    }
    if matches_in_process(cert_pem, key_pem) == Some(true) {
        return true;
    }
    matches_by_openssl(cert_pem, key_pem, creds)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fresh self-signed pair from `openssl req`, as (certificate, key) PEM.
    pub(crate) fn make_pair(dir: &Path, cn: &str, newkey: &[&str]) -> (Vec<u8>, Vec<u8>) {
        let mut args: Vec<String> = vec![
            "req".into(),
            "-nodes".into(),
            "-x509".into(),
            "-days".into(),
            "1".into(),
        ];
        args.extend(newkey.iter().map(|s| s.to_string()));
        args.extend(
            [
                "-subj",
                &format!("/CN={cn}"),
                "-keyout",
                "k.pem",
                "-out",
                "c.pem",
            ]
            .iter()
            .map(|s| s.to_string()),
        );
        let out = openssl(&args, None, Some(dir), None).expect("openssl runs");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        (
            std::fs::read(dir.join("c.pem")).expect("cert"),
            std::fs::read(dir.join("k.pem")).expect("key"),
        )
    }

    #[test]
    fn rsa_and_ec_keys_match_their_certificates_in_process() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rsa = make_pair(dir.path(), "a", &["-newkey", "rsa:2048"]);
        let rsa2 = make_pair(dir.path(), "b", &["-newkey", "rsa:2048"]);
        let ec = make_pair(
            dir.path(),
            "c",
            &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
        );
        assert_eq!(matches_in_process(&rsa.0, &rsa.1), Some(true));
        assert_eq!(matches_in_process(&ec.0, &ec.1), Some(true));
        assert_eq!(matches_in_process(&rsa.0, &rsa2.1), Some(false));
        assert!(key_matches(&rsa.0, &rsa.1, None));
        assert!(key_matches(&ec.0, &ec.1, None));
        assert!(!key_matches(&rsa.0, &rsa2.1, None));
        assert!(!key_matches(&rsa.0, &ec.1, None));
        assert!(!key_matches(b"", &rsa.1, None));
        assert!(!key_matches(b"not pem", b"not pem", None));
    }

    #[test]
    fn keys_rustls_cannot_load_fall_back_to_openssl() {
        let dir = tempfile::tempdir().expect("tempdir");
        // P-521 is not a rustls/ring signing key; openssl still decides.
        let p521 = make_pair(
            dir.path(),
            "d",
            &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-521"],
        );
        assert_eq!(matches_in_process(&p521.0, &p521.1), None);
        assert!(key_matches(&p521.0, &p521.1, None));
    }
}
