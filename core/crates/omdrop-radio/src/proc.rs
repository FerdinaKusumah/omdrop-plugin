//! Processes: signals, /proc enumeration, and running hooks with a timeout.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

use crate::ctx::Ctx;

static CANCELLED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    CANCELLED.store(true, Ordering::SeqCst);
}

/// TERM and INT set a flag that every wait below polls, so a `stop` reaches a
/// running hook (and its whole process group) instead of only this process.
pub fn catch_termination() {
    for sig in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: a zeroed sigaction is a valid starting value; the handler
        // only stores to an atomic, which is async-signal-safe.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

pub fn cancelled() -> bool {
    CANCELLED.load(Ordering::SeqCst)
}

/// Sleep, waking early on cancellation. Returns false when cancelled.
pub fn sleep(d: Duration) -> bool {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if cancelled() {
            return false;
        }
        std::thread::sleep((end - Instant::now()).min(Duration::from_millis(100)));
    }
    !cancelled()
}

pub fn signal(pid: i32, sig: libc::c_int) -> bool {
    if pid == 0 || pid == -1 {
        return false;
    }
    // SAFETY: kill has no memory-safety preconditions; pid 0 and -1 (whole
    // group / everything) are refused above.
    unsafe { libc::kill(pid, sig) == 0 }
}

/// The NUL-separated argv of a process; empty when unreadable.
pub fn cmdline(pid: u32) -> Vec<Vec<u8>> {
    let mut buf = Vec::new();
    if File::open(format!("/proc/{pid}/cmdline"))
        .and_then(|f| f.take(1 << 16).read_to_end(&mut buf))
        .is_err()
    {
        return Vec::new();
    }
    buf.split(|&b| b == 0)
        .map(<[u8]>::to_vec)
        .filter(|a| !a.is_empty())
        .collect()
}

/// Fields of /proc/<pid>/stat after the command name: [state, ppid, pgrp, ...].
fn stat_fields(pid: u32) -> Option<Vec<String>> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = &s[s.rfind(')')? + 1..];
    Some(tail.split_whitespace().map(str::to_string).collect())
}

/// Alive and not a zombie.
pub fn running(pid: u32) -> bool {
    stat_fields(pid)
        .and_then(|f| f.first().cloned())
        .is_some_and(|s| s != "Z" && s != "X")
}

pub fn pgrp(pid: u32) -> Option<u32> {
    stat_fields(pid)?.get(2)?.parse().ok()
}

/// Start time in clock ticks since boot: with the pid, it names one process.
pub fn start_time(pid: u32) -> Option<u64> {
    stat_fields(pid)?.get(19)?.parse().ok()
}

/// Parent pid, from /proc/<pid>/stat.
pub fn ppid(pid: u32) -> Option<u32> {
    stat_fields(pid)?.get(1)?.parse().ok()
}

/// argv[0] is `exe` and argv[1] is `verb`, by position (a pair later in argv
/// is just arguments someone passed). As root, /proc/<pid>/exe must be `exe`
/// as well (or `exe (deleted)`: a supervisor that outlived a package upgrade).
/// Unprivileged `status` cannot read a root process's exe link, and the test
/// seam's stand-in processes are not this binary, so only root checks it.
pub fn is_invocation(pid: u32, exe: &Path, verb: &str) -> bool {
    let argv = cmdline(pid);
    let e = exe.as_os_str().as_encoded_bytes();
    if argv.first().map(Vec::as_slice) != Some(e)
        || argv.get(1).map(Vec::as_slice) != Some(verb.as_bytes())
    {
        return false;
    }
    // SAFETY: geteuid cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return true;
    }
    let Ok(link) = fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    let link = link.as_os_str().as_encoded_bytes();
    link == e || link.strip_suffix(b" (deleted)") == Some(e)
}

/// A script run by an interpreter: basename(argv[0]) is one of
/// `interpreters`, argv[1] is `script`, and, if given, argv[2] is `verb`.
/// That is how /proc shows `#!/usr/bin/env bash` scripts and Python programs.
pub fn is_script_run(pid: u32, interpreters: &[&str], script: &Path, verb: Option<&str>) -> bool {
    let argv = cmdline(pid);
    let base = argv
        .first()
        .map(|a| a.rsplit(|&b| b == b'/').next().unwrap_or(a))
        .unwrap_or_default();
    interpreters.iter().any(|i| i.as_bytes() == base)
        && argv.get(1).map(Vec::as_slice) == Some(script.as_os_str().as_encoded_bytes())
        && verb.is_none_or(|v| argv.get(2).map(Vec::as_slice) == Some(v.as_bytes()))
}

/// Every live process running as `owner` for which `pred` holds.
pub fn find(owner: u32, pred: impl Fn(u32) -> bool) -> Vec<u32> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    dir.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| pred(pid) && owned_by(pid, owner) && running(pid))
        .collect()
}

/// Real and effective uid, from /proc/<pid>/status (world-readable, so an
/// unprivileged `status` can check that a supervisor really runs as root).
pub fn uids(pid: u32) -> Option<(u32, u32)> {
    let s = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = s.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    let mut f = line.split_whitespace().map(|x| x.parse::<u32>().ok());
    Some((f.next()??, f.next()??))
}

/// Runs as `owner`, both real and effective.
pub fn owned_by(pid: u32, owner: u32) -> bool {
    uids(pid) == Some((owner, owner))
}

/// The errno pidfd_open failed with, once it has (ENOSYS before Linux 5.3,
/// EPERM under a seccomp filter); 0 while it works.
static PIDFD_ERRNO: AtomicI32 = AtomicI32::new(0);

pub fn pidfd_unavailable() -> Option<i32> {
    Some(PIDFD_ERRNO.load(Ordering::SeqCst)).filter(|e| *e != 0)
}

/// A process handle that cannot be confused with a later process reusing
/// the pid: signals go through pidfd_send_signal, and exit is polled on it.
/// Without pidfds it falls back to kill(), re-checking the start time and
/// `check` (argv, uid) immediately before every signal.
pub struct Pidfd {
    fd: Option<OwnedFd>,
    pub pid: u32,
    start: Option<u64>,
    check: Box<dyn Fn(u32) -> bool>,
}

impl Pidfd {
    /// Open the process at `pid`, then require `check` to hold for it. The
    /// check runs after the open, so it judges the process the fd names.
    pub fn open(pid: u32, check: impl Fn(u32) -> bool + 'static) -> Option<Pidfd> {
        let start = start_time(pid);
        // SAFETY: pidfd_open takes a pid and flags and returns a new fd or -1.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        let fd = if raw < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno != libc::ENOSYS && errno != libc::EPERM {
                return None;
            }
            PIDFD_ERRNO.store(errno, Ordering::SeqCst);
            start?;
            None
        } else {
            // SAFETY: raw is a fresh descriptor nobody else owns.
            Some(unsafe { OwnedFd::from_raw_fd(raw as i32) })
        };
        let p = Pidfd {
            fd,
            pid,
            start,
            check: Box::new(check),
        };
        ((p.check)(pid) && !p.exited()).then_some(p)
    }

    pub fn signal(&self, sig: libc::c_int) -> bool {
        match &self.fd {
            // SAFETY: a valid pidfd, a signal number, no siginfo, no flags.
            Some(fd) => unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    sig,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                ) == 0
            },
            None => {
                start_time(self.pid) == self.start
                    && (self.check)(self.pid)
                    && signal(self.pid as i32, sig)
            }
        }
    }

    pub fn exited(&self) -> bool {
        match &self.fd {
            Some(fd) => {
                let mut p = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one valid pollfd, zero timeout.
                unsafe { libc::poll(&mut p, 1, 0) == 1 }
            }
            None => !running(self.pid) || start_time(self.pid) != self.start,
        }
    }
}

/// Wait until every process has exited, up to `limit`.
pub fn wait_exited(procs: &[Pidfd], limit: Duration) -> bool {
    let end = Instant::now() + limit;
    loop {
        if procs.iter().all(Pidfd::exited) {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Exited(i32),
    Signaled(i32),
    TimedOut,
    Cancelled,
    /// The executable does not exist: an optional hook that is not provided.
    Missing,
    /// Present but failing the ownership check, or failing to start.
    Broken(String),
}

impl Outcome {
    pub fn describe(&self) -> String {
        match self {
            Outcome::Exited(c) => format!("rc={c}"),
            Outcome::Signaled(s) => format!("killed by signal {s}"),
            Outcome::TimedOut => "timed out".into(),
            Outcome::Cancelled => "cancelled".into(),
            Outcome::Missing => "not installed".into(),
            Outcome::Broken(e) => e.clone(),
        }
    }
}

pub struct Run {
    pub outcome: Outcome,
    pub stdout: Vec<u8>,
    /// Whether the program wrote any stderr line.
    pub said: bool,
}

#[derive(Clone, Copy)]
pub struct Opts {
    pub timeout: Duration,
    /// Capture stdout (up to this many bytes); None sends it to /dev/null.
    pub stdout: Option<usize>,
    /// Copy stderr lines to the log; false sends stderr to /dev/null.
    pub log_stderr: bool,
    /// Whether TERM/INT to this process aborts the program.
    pub cancellable: bool,
    /// Record the program's process group in `hook.pgid` while it runs, so
    /// `stop` can kill it if this process is killed first.
    pub record: bool,
}

const LINE_MAX: usize = 4096;
/// After the program exits, how long its pipes may stay open (a daemon it
/// left behind holding them) before we stop reading.
const DRAIN: Duration = Duration::from_secs(1);
/// Between TERM and KILL for a program that outlives its timeout.
const GRACE: Duration = Duration::from_secs(2);
/// After KILL, how long to wait for the exit. A process in uninterruptible
/// sleep (blocked behind a hung firmware) cannot die; we stop waiting.
const REAP: Duration = Duration::from_secs(5);

/// Run a backend hook from the hook directory, checked first.
pub fn hook(ctx: &mut Ctx, name: &str, args: &[&str], opts: Opts) -> Run {
    let path = ctx.paths.hooks.join(name);
    if !path.exists() {
        return Run {
            outcome: Outcome::Missing,
            stdout: Vec::new(),
            said: false,
        };
    }
    if let Err(e) = crate::ctx::trusted(&path, ctx.trusted_owner()) {
        ctx.log(&format!("radio hook {name} not run: {e}"));
        return Run {
            outcome: Outcome::Broken(e),
            stdout: Vec::new(),
            said: false,
        };
    }
    run(ctx, &path, args, opts)
}

/// Run a program with the fixed environment, in its own process group, and
/// wait for it within `opts.timeout`. Never through a shell.
pub fn run<S: AsRef<OsStr>>(ctx: &mut Ctx, path: &Path, args: &[S], opts: Opts) -> Run {
    let mut cmd = Command::new(path);
    cmd.args(args)
        .env_clear()
        .envs(ctx.child_env())
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(if opts.stdout.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(if opts.log_stderr {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .process_group(0);
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let e = format!("{}: {e}", path.display());
            return Run {
                outcome: Outcome::Broken(e),
                stdout: Vec::new(),
                said: false,
            };
        }
    };
    let pgid = child.id();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if opts.record {
        let start = start_time(pgid).map(|s| s.to_string()).unwrap_or_default();
        ctx.set("hook.pgid", &format!("{pgid} {start}\n"));
    }
    let run = supervise_run(ctx, child, &name, opts);
    if opts.record {
        ctx.unset("hook.pgid");
    }
    run
}

/// Read once, retrying EINTR (our TERM handler does not set SA_RESTART).
/// None means the pipe is finished.
fn read_some(p: &mut impl Read, buf: &mut [u8]) -> Option<usize> {
    loop {
        match p.read(buf) {
            Ok(0) => return None,
            Ok(k) => return Some(k),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Some(0),
            Err(_) => return None,
        }
    }
}

fn supervise_run(ctx: &mut Ctx, mut child: Child, name: &str, opts: Opts) -> Run {
    let pgid = child.id() as i32;
    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    let mut stdout = Vec::new();
    let mut line = Vec::new();
    let mut said = false;
    let start = Instant::now();
    let mut status = None;
    let mut exited_at: Option<Instant> = None;
    let mut killed: Option<(Instant, Outcome)> = None;
    let mut kill_at: Option<Instant> = None;
    let mut unkillable = false;
    let mut buf = [0u8; 8192];

    loop {
        if status.is_none() {
            if let Ok(Some(s)) = child.try_wait() {
                status = Some(s);
                exited_at = Some(Instant::now());
            }
        }
        if status.is_none() && killed.is_none() {
            let why = if opts.cancellable && cancelled() {
                Some(Outcome::Cancelled)
            } else if start.elapsed() >= opts.timeout {
                Some(Outcome::TimedOut)
            } else {
                None
            };
            if let Some(why) = why {
                signal(-pgid, libc::SIGTERM);
                killed = Some((Instant::now(), why));
            }
        }
        if let Some((at, _)) = &killed {
            if status.is_none() && kill_at.is_none() && at.elapsed() >= GRACE {
                signal(-pgid, libc::SIGKILL);
                kill_at = Some(Instant::now());
            }
        }
        if status.is_none() && kill_at.is_some_and(|t| t.elapsed() >= REAP) {
            unkillable = true;
            break;
        }
        let open = out_pipe.is_some() || err_pipe.is_some();
        if status.is_some() && (!open || exited_at.is_some_and(|t| t.elapsed() >= DRAIN)) {
            break;
        }
        if !open {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        let mut fds = Vec::with_capacity(2);
        if let Some(p) = &out_pipe {
            fds.push(libc::pollfd {
                fd: p.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if let Some(p) = &err_pipe {
            fds.push(libc::pollfd {
                fd: p.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        // SAFETY: fds is a live, correctly sized array of pollfd.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
        if n <= 0 {
            continue;
        }
        let ready = |fd: i32| {
            fds.iter().any(|p| {
                p.fd == fd && p.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
            })
        };
        if let Some(p) = out_pipe.as_mut() {
            if ready(p.as_raw_fd()) {
                match read_some(p, &mut buf) {
                    None => out_pipe = None,
                    Some(k) => {
                        let cap = opts.stdout.unwrap_or(0);
                        let room = cap.saturating_sub(stdout.len());
                        stdout.extend_from_slice(&buf[..k.min(room)]);
                    }
                }
            }
        }
        if let Some(p) = err_pipe.as_mut() {
            if ready(p.as_raw_fd()) {
                match read_some(p, &mut buf) {
                    None => err_pipe = None,
                    Some(k) => {
                        for &b in &buf[..k] {
                            if b == b'\n' {
                                said |= flush_line(ctx, &mut line);
                            } else if line.len() < LINE_MAX {
                                line.push(b);
                            }
                        }
                    }
                }
            }
        }
    }
    said |= flush_line(ctx, &mut line);
    if unkillable {
        ctx.log(&format!(
            "hook {name} unkillable (pid {pgid} survived SIGKILL for {}s); no longer waiting for it",
            REAP.as_secs()
        ));
        // Reaped whenever it does die; nothing here waits for it.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        return Run {
            // Why it was killed: a cancelled start must still read as cancelled.
            outcome: killed.map(|(_, why)| why).unwrap_or(Outcome::TimedOut),
            stdout,
            said,
        };
    }
    let leftovers = killed.is_some() && kill_at.is_none();
    let outcome = match (killed, status) {
        (Some((_, why)), _) => why,
        (None, Some(s)) => match (s.code(), s.signal()) {
            (Some(c), _) => Outcome::Exited(c),
            (None, Some(sig)) => Outcome::Signaled(sig),
            (None, None) => Outcome::Exited(255),
        },
        (None, None) => Outcome::Exited(255),
    };
    // A cancelled or timed-out program exited on TERM; what it left in its
    // group goes too.
    if leftovers {
        signal(-pgid, libc::SIGKILL);
    }
    Run {
        outcome,
        stdout,
        said,
    }
}

fn flush_line(ctx: &mut Ctx, line: &mut Vec<u8>) -> bool {
    if line.is_empty() {
        return false;
    }
    let text: String = String::from_utf8_lossy(line)
        .chars()
        .filter(|c| *c == '\t' || !c.is_control())
        .collect();
    line.clear();
    if text.trim().is_empty() {
        return false;
    }
    ctx.log_hook_line(&text);
    true
}
