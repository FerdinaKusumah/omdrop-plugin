//! Loopback fixtures: certificate material from openssl, and a one-shot TLS
//! receiver that records what the sender presented.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::thread::JoinHandle;

use omdrop_identity::{Identity, Source};
use omdrop_proto::tls::{ClientAuth, server_config};
use rustls::{ServerConnection, StreamOwned};
use zeroize::Zeroizing;

/// A self-signed RSA pair `(cert_pem, key_pem)` with CN `name`.
pub fn pair(dir: &Path, name: &str) -> (Vec<u8>, Vec<u8>) {
    let cert = dir.join(format!("{name}.pem"));
    let key = dir.join(format!("{name}.key"));
    let ok = Command::new("openssl")
        .args([
            "req", "-newkey", "rsa:2048", "-nodes", "-x509", "-days", "1", "-subj",
        ])
        .arg(format!("/CN={name}"))
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .expect("openssl")
        .status
        .success();
    assert!(ok, "openssl req failed");
    (std::fs::read(cert).unwrap(), std::fs::read(key).unwrap())
}

/// A CMS-signed identifiers plist, as in test_identity_consumers.py.
pub fn record(dir: &Path, signer: &str) -> Vec<u8> {
    let mut identifiers = plist::Dictionary::new();
    identifiers.insert(
        "ValidatedEmailHashes".into(),
        plist::Value::Array(vec![
            format!("1111{}", "a".repeat(60)).into(),
            format!("2222{}", "b".repeat(60)).into(),
        ]),
    );
    identifiers.insert(
        "ValidatedPhoneHashes".into(),
        plist::Value::Array(vec![format!("AAAA{}", "d".repeat(60)).into()]),
    );
    let mut xml = Vec::new();
    plist::Value::Dictionary(identifiers)
        .to_writer_xml(&mut xml)
        .unwrap();
    let mut child = Command::new("openssl")
        .args([
            "cms",
            "-sign",
            "-binary",
            "-nodetach",
            "-outform",
            "DER",
            "-signer",
        ])
        .arg(dir.join(format!("{signer}.pem")))
        .arg("-inkey")
        .arg(dir.join(format!("{signer}.key")))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&xml).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    out.stdout
}

pub fn identity(cert: &[u8], key: &[u8], record: Option<Vec<u8>>) -> Identity {
    Identity {
        source: Source::Disk,
        certificate_pem: cert.to_vec(),
        key_pem: Zeroizing::new(key.to_vec()),
        record,
        warnings: Vec::new(),
    }
}

/// What the one-shot receiver saw.
#[derive(Debug)]
pub struct Observed {
    pub client_cert_der: Option<Vec<u8>>,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Serve one POST on 127.0.0.1 over TLS, asking for a client certificate,
/// and answer `answer` (a plist). Returns the port and the observation.
pub fn one_shot(server: &Identity, answer: Vec<u8>) -> (u16, JoinHandle<Observed>) {
    let config: Arc<rustls::ServerConfig> = server_config(
        server,
        ClientAuth::Request {
            hint_subjects: Vec::new(),
        },
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let conn = ServerConnection::new(config).unwrap();
        let mut tls = StreamOwned::new(conn, sock);
        let mut reader = BufReader::new(&mut tls);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
        let mut headers = Vec::new();
        let mut length = 0usize;
        loop {
            let mut h = String::new();
            reader.read_line(&mut h).unwrap();
            let h = h.trim_end().to_owned();
            if h.is_empty() {
                break;
            }
            let (k, v) = h.split_once(": ").unwrap();
            if k.eq_ignore_ascii_case("content-length") {
                length = v.parse().unwrap();
            }
            headers.push((k.to_owned(), v.to_owned()));
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).unwrap();
        drop(reader);
        let client_cert_der = tls
            .conn
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.as_ref().to_vec());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            answer.len()
        );
        tls.write_all(resp.as_bytes()).unwrap();
        tls.write_all(&answer).unwrap();
        tls.flush().unwrap();
        Observed {
            client_cert_der,
            path,
            headers,
            body,
        }
    });
    (port, handle)
}

pub fn name_answer(name: &str) -> Vec<u8> {
    let mut d = plist::Dictionary::new();
    d.insert(
        "ReceiverComputerName".into(),
        plist::Value::String(name.into()),
    );
    let mut out = Vec::new();
    plist::Value::Dictionary(d)
        .to_writer_binary(&mut out)
        .unwrap();
    out
}

/// PEM -> DER of the first certificate.
pub fn der(pem: &[u8]) -> Vec<u8> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem)
        .next()
        .unwrap()
        .unwrap()
        .as_ref()
        .to_vec()
}
