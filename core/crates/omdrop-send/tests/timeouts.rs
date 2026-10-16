//! The TLS handshake and every response read are bounded by the
//! per-operation timeout and by the overall deadline, against peers that
//! stall: one that accepts TCP and never speaks TLS, one that answers half a
//! response and stops, and one that trickles a byte at a time. Loopback only.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use omdrop_proto::tls::{ClientAuth, client_config, server_config};
use omdrop_send::error::PyErr;
use omdrop_send::http::{Body, Conn, Endpoint};
use rustls::{ServerConnection, StreamOwned};

struct Material {
    _dir: tempfile::TempDir,
    cert: Vec<u8>,
    key: Vec<u8>,
}

fn material() -> Material {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = pair(dir.path(), "peer");
    Material {
        _dir: dir,
        cert,
        key,
    }
}

/// How the fake peer misbehaves.
#[derive(Clone, Copy)]
enum Peer {
    /// Accepts TCP, never answers the Client Hello.
    SilentHandshake,
    /// Completes TLS, reads the request, sends half a response, stalls.
    HalfResponse,
    /// Completes TLS, then sends the response one byte every 300 ms.
    Trickle,
}

fn serve(m: &Material, how: Peer) -> u16 {
    let config: Arc<rustls::ServerConfig> =
        server_config(&identity(&m.cert, &m.key, None), ClientAuth::None).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let Ok((sock, _)) = listener.accept() else {
            return;
        };
        if let Peer::SilentHandshake = how {
            std::thread::sleep(Duration::from_secs(30));
            drop(sock);
            return;
        }
        let mut tls = StreamOwned::new(ServerConnection::new(config).unwrap(), sock);
        let mut buf = [0u8; 4096];
        let _ = tls.read(&mut buf);
        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc";
        match how {
            Peer::HalfResponse => {
                let _ = tls.write_all(answer);
                let _ = tls.flush();
                std::thread::sleep(Duration::from_secs(30));
            }
            Peer::Trickle => {
                for b in answer.iter().chain(std::iter::repeat(&b'x')).take(400) {
                    if tls.write_all(&[*b]).and_then(|()| tls.flush()).is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(300));
                }
            }
            Peer::SilentHandshake => {}
        }
    });
    port
}

fn attempt(m: &Material, how: Peer, op: Duration, deadline: Option<Duration>) -> (Duration, PyErr) {
    let port = serve(m, how);
    let tls = client_config(&identity(&m.cert, &m.key, None)).unwrap();
    let ep = Endpoint::resolve("127.0.0.1", port, "lo").unwrap();
    let started = Instant::now();
    let deadline = deadline.map(|d| started + d);
    let result = Conn::open(&ep, &tls, Some(op), deadline)
        .and_then(|mut c| c.post("/Discover", &ep.host_header(), &[], Body::Bytes(b"x")));
    let elapsed = started.elapsed();
    let err = result.expect_err("a stalled peer must fail");
    (elapsed, PyErr::from_io(&err))
}

fn assert_bounded(name: &str, elapsed: Duration, bound: Duration) {
    eprintln!(
        "{name}: failed after {:.3} s (bound {:.3} s)",
        elapsed.as_secs_f64(),
        bound.as_secs_f64()
    );
    assert!(
        elapsed >= bound.mul_f64(0.9),
        "{name}: gave up early at {elapsed:?}"
    );
    assert!(
        elapsed <= bound + Duration::from_millis(500),
        "{name}: took {elapsed:?}, bound {bound:?}"
    );
}

#[test]
fn a_silent_handshake_is_bounded_by_the_op_timeout() {
    let m = material();
    let (elapsed, err) = attempt(&m, Peer::SilentHandshake, Duration::from_secs(1), None);
    assert_eq!(err.repr, "TimeoutError('timed out')");
    assert_bounded("silent handshake, op 1 s", elapsed, Duration::from_secs(1));
}

#[test]
fn a_silent_handshake_is_bounded_by_the_deadline() {
    let m = material();
    let (elapsed, err) = attempt(
        &m,
        Peer::SilentHandshake,
        Duration::from_secs(10),
        Some(Duration::from_millis(700)),
    );
    assert_eq!(err.class, "TimeoutError");
    assert_bounded(
        "silent handshake, op 10 s, deadline 0.7 s",
        elapsed,
        Duration::from_millis(700),
    );
}

#[test]
fn a_half_response_is_bounded_by_the_op_timeout() {
    let m = material();
    let (elapsed, err) = attempt(&m, Peer::HalfResponse, Duration::from_secs(1), None);
    assert_eq!(err.class, "TimeoutError");
    // Handshake and request are instant on loopback; the stalled body read
    // is the one that times out.
    assert_bounded("half response, op 1 s", elapsed, Duration::from_secs(1));
}

#[test]
fn a_trickling_peer_is_bounded_by_the_deadline() {
    let m = material();
    // Each byte arrives inside the 1 s op timeout, so only the deadline
    // can end this exchange.
    let (elapsed, err) = attempt(
        &m,
        Peer::Trickle,
        Duration::from_secs(1),
        Some(Duration::from_secs(2)),
    );
    assert_eq!(err.class, "TimeoutError");
    assert_bounded(
        "trickle, op 1 s, deadline 2 s",
        elapsed,
        Duration::from_secs(2),
    );
}
