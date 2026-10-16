//! What core reads about `awdl0` itself, and the avahi host-name repair.

use std::fs;
use std::time::Duration;

use crate::ctx::{Ctx, IFACE, read_state};
use crate::proc::{self, Opts, Outcome};

pub fn iface_exists(ctx: &Ctx) -> bool {
    ctx.paths.sys_net.join(IFACE).exists()
}

/// An IPv6 link-local address on awdl0, tentative or not (as `ip -6 addr show
/// dev awdl0 scope link` lists it). The interface can exist, and the firmware
/// can be transmitting, while the netdev is down with no address: then nothing
/// can bind to :8771 and no transfer can land, so a window without one is not
/// a window (08:26:12Z).
pub fn has_link_local(ctx: &Ctx) -> bool {
    let Ok(table) = fs::read_to_string(&ctx.paths.if_inet6) else {
        return false;
    };
    table.lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.len() >= 6 && f[5] == IFACE && f[3] == "20"
    })
}

/// Data frames delivered on awdl0. Action frames (PSFs, MIFs: what discovery
/// runs on) never increment it, so silence is weak evidence.
pub fn rx_packets(ctx: &Ctx) -> u64 {
    read_state(&ctx.paths.sys_net.join(IFACE).join("statistics/rx_packets"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

// Infrastructure reassociations make avahi re-announce on every interface,
// awdl0 included, where the announcement comes back off the AWDL link; avahi
// reads the echo as another host holding the name and renames itself, host ->
// host-2 (130913T180746). The rename outlives the window, and every other
// machine resolving <host>.local then gets nothing. Put a drifted name back
// wherever we touch the radio.

fn mdns_current(ctx: &mut Ctx) -> Option<String> {
    let busctl = ctx.paths.busctl.clone();
    if !busctl.exists() {
        return None;
    }
    let args = [
        "--no-pager",
        "call",
        "org.freedesktop.Avahi",
        "/",
        "org.freedesktop.Avahi.Server",
        "GetHostName",
    ];
    let opts = Opts {
        timeout: Duration::from_secs(5),
        stdout: Some(4096),
        log_stderr: false,
        cancellable: true,
        record: false,
    };
    let run = proc::run(ctx, &busctl, &args, opts);
    if run.outcome != Outcome::Exited(0) {
        return None;
    }
    let out = String::from_utf8_lossy(&run.stdout);
    out.lines().find_map(|l| {
        l.strip_prefix("s \"")?
            .strip_suffix('"')
            .map(str::to_string)
    })
}

fn plain_label(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Only ever undoes avahi's own conflict rename: exactly our name plus
/// avahi's numeric suffix. A deliberately different mDNS name is left alone.
pub fn mdns_reclaim(ctx: &mut Ctx) {
    let Some(want) = read_state(&ctx.paths.hostname) else {
        return;
    };
    if !plain_label(&want) {
        return;
    }
    let Some(cur) = mdns_current(ctx) else { return };
    if cur.is_empty() || cur == want {
        return;
    }
    let renamed = cur
        .strip_prefix(&want)
        .and_then(|r| r.strip_prefix('-'))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    if !renamed {
        return;
    }
    let tool = ctx.paths.avahi_set_host_name.clone();
    if !tool.exists() {
        return;
    }
    let opts = Opts {
        timeout: Duration::from_secs(10),
        stdout: None,
        log_stderr: false,
        cancellable: true,
        record: false,
    };
    if proc::run(ctx, &tool, &[want.as_str()], opts).outcome == Outcome::Exited(0) {
        ctx.log(&format!(
            "reclaimed the mDNS name {want}.local (avahi had renamed it {cur}.local)"
        ));
    }
}
