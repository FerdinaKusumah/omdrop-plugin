//! A peer that drops the first connection right after reading the /Discover
//! request, as an Apple peer does while it restarts its AirDrop server for a
//! "legacy" sender (R7d, 2026-10-14), gets one more /Discover on a send; a
//! name lookup and other failures do not. Loopback only.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use common::*;
use omdrop_proto::tls::{ClientAuth, server_config};
use omdrop_send::airdrop_send::{parse_options, run, sender_from_identity};
use omdrop_send::log::{Logger, Sink};
use rustls::{ServerConnection, StreamOwned};

/// What the fake peer does with each connection, in order. Past the end of
/// the list, connections are read and dropped.
#[derive(Clone)]
enum Step {
    /// Complete TLS, read the request head, close without answering.
    DropAfterRequest,
    /// Answer with this status and plist body.
    Answer(u16, Vec<u8>),
}

/// Serve `steps` on 127.0.0.1; every request's path is sent down the channel.
fn fake(m: &(Vec<u8>, Vec<u8>), steps: Vec<Step>) -> (u16, Receiver<String>) {
    let config: Arc<rustls::ServerConfig> =
        server_config(&identity(&m.0, &m.1, None), ClientAuth::None).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let mut steps = steps.into_iter();
        for sock in listener.incoming() {
            let Ok(sock) = sock else { return };
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut tls = StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), sock);
            let mut reader = BufReader::new(&mut tls);
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
            let mut length = 0usize;
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).is_err() {
                    break;
                }
                let h = h.trim_end();
                if h.is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(": ")
                    && k.eq_ignore_ascii_case("content-length")
                {
                    length = v.parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; length];
            let _ = reader.read_exact(&mut body);
            drop(reader);
            let _ = tx.send(path);
            match steps.next() {
                Some(Step::Answer(status, answer)) => {
                    let head = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        answer.len()
                    );
                    let _ = tls.write_all(head.as_bytes());
                    let _ = tls.write_all(&answer);
                    let _ = tls.flush();
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                }
                Some(Step::DropAfterRequest) | None => {}
            }
        }
    });
    (port, rx)
}

fn paths(rx: &Receiver<String>) -> Vec<String> {
    std::thread::sleep(Duration::from_millis(300));
    rx.try_iter().collect()
}

fn send(port: u16, extra: &[&str]) -> i32 {
    let dir = tempfile::tempdir().unwrap();
    let me = pair(dir.path(), "sender");
    let file = dir.path().join("x.txt");
    std::fs::write(&file, b"hello").unwrap();
    let mut args: Vec<String> = vec![
        "--direct".into(),
        format!("127.0.0.1:{port}"),
        "--iface".into(),
        "lo".into(),
        "--op-timeout".into(),
        "3".into(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    if !extra.contains(&"--discover-only") {
        args.push("--".into());
        args.push(file.to_string_lossy().into_owned());
    }
    let opts = parse_options(&args).unwrap();
    let sender =
        sender_from_identity(&identity(&me.0, &me.1, None), &opts, "020000000001".into()).unwrap();
    run(&opts, &sender, &Logger::new(Sink::Silent))
}

#[test]
fn a_send_retries_a_discover_the_peer_dropped_once() {
    let dir = tempfile::tempdir().unwrap();
    let peer = pair(dir.path(), "peer");
    let (port, rx) = fake(
        &peer,
        vec![
            Step::DropAfterRequest,
            Step::Answer(200, name_answer("Phone")),
        ],
    );
    // The third connection, the Ask, is dropped too: the send gets past
    // /Discover, and the Ask is not retried.
    assert_ne!(send(port, &[]), 0);
    assert_eq!(paths(&rx), ["/Discover", "/Discover", "/Ask"]);
}

#[test]
fn an_ask_the_peer_drops_is_not_retried_and_nothing_is_uploaded() {
    let dir = tempfile::tempdir().unwrap();
    let peer = pair(dir.path(), "peer");
    let (port, rx) = fake(
        &peer,
        vec![
            Step::Answer(200, name_answer("Phone")),
            Step::DropAfterRequest,
        ],
    );
    assert_ne!(send(port, &[]), 0);
    assert_eq!(paths(&rx), ["/Discover", "/Ask"]);
}

#[test]
fn a_tls_failure_at_discover_is_not_retried() {
    // A peer that answers the ClientHello with plaintext: an SSLError, not a
    // dropped connection.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for sock in listener.incoming() {
            let Ok(mut sock) = sock else { return };
            let _ = tx.send(String::from("connection"));
            let mut buf = [0u8; 512];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        }
    });
    assert_eq!(send(port, &[]), 2);
    assert_eq!(paths(&rx), ["connection"]);
}

#[test]
fn a_discover_dropped_twice_fails_after_one_retry() {
    let dir = tempfile::tempdir().unwrap();
    let peer = pair(dir.path(), "peer");
    let (port, rx) = fake(&peer, vec![]);
    assert_eq!(send(port, &[]), 2);
    assert_eq!(paths(&rx), ["/Discover", "/Discover"]);
}

#[test]
fn a_name_lookup_does_not_retry_on_its_own() {
    // send-to-peer's lookup already makes two attempts of its own.
    let dir = tempfile::tempdir().unwrap();
    let peer = pair(dir.path(), "peer");
    let (port, rx) = fake(&peer, vec![]);
    assert_eq!(send(port, &["--discover-only"]), 2);
    assert_eq!(paths(&rx), ["/Discover"]);
}

#[test]
fn a_discover_the_peer_answers_with_an_error_is_not_retried() {
    let dir = tempfile::tempdir().unwrap();
    let peer = pair(dir.path(), "peer");
    let (port, rx) = fake(&peer, vec![Step::Answer(500, Vec::new())]);
    assert_eq!(send(port, &[]), 2);
    assert_eq!(paths(&rx), ["/Discover"]);
}
