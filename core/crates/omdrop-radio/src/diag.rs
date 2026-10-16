//! Commands that validate their arguments and hand the work to a hook:
//! `probe`, `peers`, `diag`, `read`, `trace`.

use std::io::Write;
use std::time::Duration;

use crate::ctx::{Ctx, Res, exit, is_uint};
use crate::proc::{self, Opts, Outcome};
use crate::window::need_root;

const RELAY_MAX: usize = 1 << 20;

pub struct Probe {
    pub backend: String,
    pub hooks: Option<u64>,
    pub hardware: Option<bool>,
    pub first_missing: Option<String>,
}

/// The probe's answer, if it is one: a JSON object with a non-empty
/// `backend` string. `missing[0].say` is reduced to printable text, since it
/// becomes the last line a person reads.
pub fn parse_probe(out: &[u8]) -> Option<Probe> {
    let v: serde_json::Value = serde_json::from_slice(out).ok()?;
    let o = v.as_object()?;
    let backend = o.get("backend")?.as_str()?.trim();
    if backend.is_empty() {
        return None;
    }
    let first_missing = o
        .get("missing")
        .and_then(|m| m.as_array())
        .and_then(|m| m.first())
        .and_then(|m| m.get("say"))
        .and_then(|s| s.as_str())
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .map(|s| {
            s.chars()
                .filter(|c| !c.is_control())
                .take(400)
                .collect::<String>()
        })
        .filter(|s| !s.is_empty());
    Some(Probe {
        backend: backend
            .chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect(),
        hooks: o.get("hooks").and_then(|h| h.as_u64()),
        hardware: o.get("hardware").and_then(|h| h.as_bool()),
        first_missing,
    })
}

fn relay(out: &[u8]) {
    let mut so = std::io::stdout().lock();
    let _ = so.write_all(out);
    let _ = so.flush();
}

fn unsupported(what: &str) -> Res {
    Err(exit(
        4,
        format!("{what}: not supported by this radio backend"),
    ))
}

/// Unprivileged: what the plugin's doctor asks (omdrop-plugin PR #25).
pub fn probe(ctx: &mut Ctx, args: &[String]) -> Res {
    if !matches!(args, [a] if a == "--json") {
        return Err(crate::usage(ctx));
    }
    let opts = Opts {
        timeout: Duration::from_secs(5),
        stdout: Some(64 << 10),
        log_stderr: true,
        cancellable: true,
        record: false,
    };
    let r = proc::hook(ctx, "probe", &["--json"], opts);
    match r.outcome {
        Outcome::Exited(0) => {}
        Outcome::Missing => {
            return Err(exit(
                4,
                format!(
                    "no radio backend is installed ({})",
                    ctx.paths.hooks.display()
                ),
            ));
        }
        o => {
            return Err(exit(
                4,
                format!("the radio backend's probe failed: {}", o.describe()),
            ));
        }
    }
    if parse_probe(&r.stdout).is_none() {
        return Err(exit(
            4,
            "the radio backend's probe did not answer with a probe",
        ));
    }
    let text = String::from_utf8_lossy(&r.stdout);
    println!("{}", text.trim());
    Ok(0)
}

/// The radio's own view of who is on air. Read-only.
pub fn peers(ctx: &mut Ctx, args: &[String]) -> Res {
    if !args.is_empty() {
        return Err(crate::usage(ctx));
    }
    need_root(ctx, &["peers"])?;
    ctx.mkdir_run()?;
    let opts = Opts {
        timeout: Duration::from_secs(20),
        stdout: Some(RELAY_MAX),
        log_stderr: true,
        cancellable: true,
        record: false,
    };
    let r = proc::hook(ctx, "peers", &[], opts);
    relay(&r.stdout);
    match r.outcome {
        Outcome::Exited(0) => Ok(0),
        Outcome::Missing => unsupported("peers"),
        Outcome::Exited(2) => Ok(2),
        Outcome::Exited(_) => Ok(4),
        o => Err(exit(4, format!("peers: {}", o.describe()))),
    }
}

/// Why is the receive side dead? Read-only GETs, safe inside a live window.
pub fn diag(ctx: &mut Ctx, args: &[String]) -> Res {
    let usage = || {
        exit(
            2,
            format!("usage: {} diag [seconds, at most 600]", ctx.self_str()),
        )
    };
    let secs = match args {
        [] => "15",
        [s] => s.as_str(),
        _ => return Err(usage()),
    };
    let n: u64 = if is_uint(secs) {
        secs.parse().map_err(|_| usage())?
    } else {
        return Err(usage());
    };
    if n > 600 {
        return Err(usage());
    }
    need_root(ctx, &["diag"])?;
    ctx.mkdir_run()?;
    let opts = Opts {
        timeout: Duration::from_secs(n + 60),
        stdout: Some(RELAY_MAX),
        log_stderr: true,
        cancellable: true,
        record: false,
    };
    let r = proc::hook(ctx, "diag", &[secs], opts);
    relay(&r.stdout);
    match r.outcome {
        Outcome::Exited(0) => Ok(0),
        Outcome::Missing => unsupported("diag"),
        Outcome::Exited(2) => Ok(2),
        Outcome::Exited(_) => Ok(4),
        o => Err(exit(4, format!("diag: {}", o.describe()))),
    }
}

/// One GET, printed. Only AWDL state and the firmware's version and
/// capability strings: any active user reaches this as root without a prompt,
/// and other iovars carry the Wi-Fi network's credentials (wsec_key, pmk,
/// sae_password).
pub fn allowed_read(name: &str) -> bool {
    name == "ver"
        || name == "cap"
        || name.len() <= 64
            && name.strip_prefix("awdl_").is_some_and(|r| {
                !r.is_empty()
                    && r.bytes()
                        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
            })
}

pub fn read(ctx: &mut Ctx, args: &[String]) -> Res {
    let (name, len) = match args {
        [n] => (n.as_str(), "512"),
        [n, l] => (n.as_str(), l.as_str()),
        _ => {
            return Err(exit(
                2,
                format!("usage: {} read <iovar> [len]", ctx.self_str()),
            ));
        }
    };
    if name.is_empty() {
        return Err(exit(
            2,
            format!("usage: {} read <iovar> [len]", ctx.self_str()),
        ));
    }
    if !allowed_read(name) {
        return Err(exit(2, "read is limited to awdl_* iovars, ver and cap"));
    }
    let ok_len = is_uint(len) && len.parse::<u64>().is_ok_and(|l| (1..=8192).contains(&l));
    if !ok_len {
        return Err(exit(2, "len must be a number up to 8192"));
    }
    need_root(ctx, &["read", name])?;
    ctx.mkdir_run()?;
    let opts = Opts {
        timeout: Duration::from_secs(20),
        stdout: Some(RELAY_MAX),
        log_stderr: true,
        cancellable: true,
        record: false,
    };
    let r = proc::hook(ctx, "read", &[name, len], opts);
    relay(&r.stdout);
    match r.outcome {
        Outcome::Exited(0) => Ok(0),
        Outcome::Missing => unsupported("read"),
        Outcome::Exited(2) => Ok(2),
        Outcome::Exited(_) => Ok(4),
        o => Err(exit(4, format!("read: {}", o.describe()))),
    }
}

/// The per-frame transmit log, for a human diagnosing a send.
pub fn trace(ctx: &mut Ctx, args: &[String]) -> Res {
    let want = match args {
        [] => "status",
        [a] if matches!(a.as_str(), "on" | "off" | "status") => a.as_str(),
        _ => return Err(exit(2, format!("usage: {} trace [on|off]", ctx.self_str()))),
    };
    need_root(ctx, &["trace", want])?;
    ctx.mkdir_run()?;
    let opts = Opts {
        timeout: Duration::from_secs(10),
        stdout: Some(RELAY_MAX),
        log_stderr: true,
        cancellable: true,
        record: false,
    };
    let r = proc::hook(ctx, "trace", &[want], opts);
    relay(&r.stdout);
    match r.outcome {
        Outcome::Exited(0) => Ok(0),
        Outcome::Missing => unsupported("trace"),
        Outcome::Exited(2) => Ok(2),
        Outcome::Exited(_) => Ok(4),
        o => Err(exit(4, format!("trace: {}", o.describe()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_allowlist() {
        for ok in ["awdl_peer_table", "awdl_stats", "ver", "cap", "awdl_a1_"] {
            assert!(allowed_read(ok), "{ok}");
        }
        for bad in [
            "wsec_key",
            "pmk",
            "sae_password",
            "awdl",
            "awdl_",
            "AWDL_X",
            "awdl_x y",
            "awdl_x;id",
            "ver2",
        ] {
            assert!(!allowed_read(bad), "{bad}");
        }
        assert!(!allowed_read(&format!("awdl_{}", "a".repeat(60))));
    }

    #[test]
    fn probe_needs_a_backend_name() {
        assert!(parse_probe(b"{}").is_none());
        assert!(parse_probe(b"{\"backend\":\"  \"}").is_none());
        assert!(parse_probe(b"[1]").is_none());
        assert!(parse_probe(b"not json").is_none());
        let p = parse_probe(br#"{"backend":"awdl","hooks":1,"hardware":false,"missing":[{"id":"hardware","say":"No\n Broadcom\u001b[31m Wi-Fi."}]}"#)
            .unwrap();
        assert_eq!(p.backend, "awdl");
        assert_eq!(p.hooks, Some(1));
        assert_eq!(p.hardware, Some(false));
        assert_eq!(p.first_missing.as_deref(), Some("No Broadcom[31m Wi-Fi."));
    }
}
