//! omdrop-radio: make this machine discoverable to AirDrop "Everyone" for a
//! bounded window. The radio-independent core of omdrop-awdl's
//! `omdrop-discoverable`, with the same argv, exit codes, run directory and
//! status JSON; the radio work is done by backend hooks
//! (docs/backend-contract.md).
//!
//!   omdrop-radio start <seconds>     become discoverable for N seconds (0: until stopped)
//!   omdrop-radio stop                stop advertising, tear down
//!   omdrop-radio status [--json]     {"visible":bool,"remaining":int|null,"reason":str,...}
//!   omdrop-radio peers | diag [s] | read <iovar> [len] | trace [on|off] | probe --json
//!
//! ROOT: runs as root for any active user through polkit, with any argv they
//! choose, so every argument is validated here before any work, and nothing
//! reaches a shell. `status` and `probe` run unprivileged.
//!
//! Exit codes (the contract the omdrop CLI and the panel call against):
//!   0  visible (start), stopped (stop), always (status)
//!   2  usage error, or not root
//!   3  data path parked, or the window could not be opened; retryable
//!   4  awdl0 absent or down; no radio backend
//!   5  already discoverable; the window was extended instead of stacking

mod ctx;
mod diag;
mod net;
mod proc;
mod rundir;
mod window;

use std::path::PathBuf;

use ctx::{Ctx, Exit, exit};
/// The bare usage line on stderr, as omdrop-discoverable printed it (no
/// timestamp, not logged), and exit 2.
pub fn usage(ctx: &Ctx) -> Exit {
    eprintln!(
        "usage: {} start <seconds> | stop | status [--json] | peers | diag [seconds] | read <iovar> [len] | trace [on|off] | probe --json",
        ctx.self_str()
    );
    exit(2, "")
}

fn main() {
    // Argv as bytes: a non-UTF-8 argument is simply not one we accept.
    let raw: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let args: Option<Vec<String>> = raw.into_iter().map(|a| a.into_string().ok()).collect();
    // Resolved from /proc/self/exe, never from argv[0] or the working
    // directory: pkexec runs us with the caller's cwd.
    let self_exe = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("/usr/lib/omdrop-core/omdrop-radio"));
    // SAFETY: umask only sets this process's file-creation mask.
    unsafe { libc::umask(0o022) };
    let mut ctx = Ctx::new(self_exe);
    let result = match args {
        None => Err(usage(&ctx)),
        Some(args) => {
            let rest = args.get(1..).unwrap_or(&[]);
            match args.first().map(String::as_str) {
                Some("start") => window::start(&mut ctx, rest),
                Some("stop") => window::stop(&mut ctx, rest),
                Some("status") => window::status(&mut ctx, rest),
                Some("__supervise") => window::supervise_entry(&mut ctx, rest),
                Some("peers") => diag::peers(&mut ctx, rest),
                Some("diag") => diag::diag(&mut ctx, rest),
                Some("read") => diag::read(&mut ctx, rest),
                Some("trace") => diag::trace(&mut ctx, rest),
                Some("probe") => diag::probe(&mut ctx, rest),
                _ => Err(usage(&ctx)),
            }
        }
    };
    let code = match result {
        Ok(code) => code,
        Err(Exit { code, msg }) => {
            if !msg.is_empty() {
                ctx.log(&msg);
            }
            code
        }
    };
    std::process::exit(code);
}
