//! Fixed paths, the test seam, logging, and small file helpers.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::rundir::RunDir;

/// The radio interface every backend provides (contract v1 fixes the name).
pub const IFACE: &str = "awdl0";
/// The run directory: kept from omdrop-discoverable, because `status` callers,
/// the Broadcom peer watcher (`peerop.degraded`) and people diagnosing a window
/// all know it by this name.
const RUN: &str = "/run/awdl-discoverable";
const HOOKS: &str = "/usr/lib/omdrop/radio";
const CONF: &str = "/etc/omdrop";
/// Where omdrop-awdl 0.9.x installs omdrop-discoverable and its advertisers.
const LEGACY: &str = "/usr/lib/omdrop";
/// The only variable that may relocate the paths above, and only for a process
/// that is not root at all (see `Paths::detect`).
pub const TEST_ROOT_VAR: &str = "OMDROP_RADIO_TEST_ROOT";

/// Every path the helper touches outside its own executable.
pub struct Paths {
    pub run: PathBuf,
    pub hooks: PathBuf,
    pub conf: PathBuf,
    pub sys_net: PathBuf,
    pub if_inet6: PathBuf,
    pub hostname: PathBuf,
    pub busctl: PathBuf,
    pub avahi_set_host_name: PathBuf,
    /// omdrop-awdl 0.9.x's helper directory: its supervisor shares our run
    /// directory, so a live one is a live window.
    pub legacy: PathBuf,
    /// Set only when the test seam is honoured.
    pub test_root: Option<PathBuf>,
}

impl Paths {
    /// Production paths, unless the test seam applies.
    ///
    /// The seam is honoured only when neither the real nor the effective uid
    /// is 0 and the kernel did not mark the exec secure (AT_SECURE: setuid,
    /// setgid or file capabilities). Under pkexec the helper runs as uid 0, so
    /// the variable is ignored there (and pkexec, `--user` included, has
    /// stripped it anyway). A process that honours it already has exactly its
    /// caller's privileges, so redirecting its hooks lets a user run nothing
    /// they could not have run directly.
    pub fn detect() -> Paths {
        // SAFETY: getuid/geteuid/getauxval have no preconditions and cannot fail.
        let unprivileged = unsafe {
            libc::getuid() != 0 && libc::geteuid() != 0 && libc::getauxval(libc::AT_SECURE) == 0
        };
        let root = if unprivileged {
            std::env::var_os(TEST_ROOT_VAR)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        } else {
            None
        };
        match root {
            Some(t) => Paths {
                run: t.join("run"),
                hooks: t.join("hooks"),
                conf: t.join("conf"),
                sys_net: t.join("sys/class/net"),
                if_inet6: t.join("proc/net/if_inet6"),
                hostname: t.join("proc/sys/kernel/hostname"),
                busctl: t.join("bin/busctl"),
                avahi_set_host_name: t.join("bin/avahi-set-host-name"),
                legacy: t.join("legacy"),
                test_root: Some(t),
            },
            None => Paths {
                run: PathBuf::from(RUN),
                hooks: PathBuf::from(HOOKS),
                conf: PathBuf::from(CONF),
                sys_net: PathBuf::from("/sys/class/net"),
                if_inet6: PathBuf::from("/proc/net/if_inet6"),
                hostname: PathBuf::from("/proc/sys/kernel/hostname"),
                busctl: PathBuf::from("/usr/bin/busctl"),
                avahi_set_host_name: PathBuf::from("/usr/bin/avahi-set-host-name"),
                legacy: PathBuf::from(LEGACY),
                test_root: None,
            },
        }
    }
}

pub struct Ctx {
    pub paths: Paths,
    /// Our own resolved executable: the supervisor is matched by it in
    /// /proc/<pid>/cmdline, and the advertisers live beside it.
    pub self_exe: PathBuf,
    /// The supervisor's stderr IS the log file, so it logs to the file only.
    pub log_to_stderr: bool,
    /// The last line written to stderr, so a failed start can repeat the
    /// sentence a person reads after any cleanup output.
    pub last_stderr: Option<String>,
    /// The run directory, once opened and checked (see rundir.rs). Until
    /// then nothing is read from or written to it, the log included.
    pub rd: Option<RunDir>,
}

/// An exit with a code and, unless empty, a final log line.
pub struct Exit {
    pub code: i32,
    pub msg: String,
}

pub fn exit(code: i32, msg: impl Into<String>) -> Exit {
    Exit {
        code,
        msg: msg.into(),
    }
}

pub type Res = Result<i32, Exit>;

impl Ctx {
    pub fn new(self_exe: PathBuf) -> Ctx {
        Ctx {
            paths: Paths::detect(),
            self_exe,
            log_to_stderr: true,
            last_stderr: None,
            rd: None,
        }
    }

    pub fn self_str(&self) -> String {
        self.self_exe.display().to_string()
    }

    /// A trusted state file, trimmed; None when absent, untrusted, or the run
    /// directory is not open.
    pub fn state(&self, name: &str) -> Option<String> {
        self.rd.as_ref()?.read(name)
    }

    /// Replace a state file atomically (mode 0644).
    pub fn set(&self, name: &str, content: &str) {
        if let Some(rd) = &self.rd {
            let _ = rd.write(name, content, 0o644);
        }
    }

    pub fn unset(&self, name: &str) {
        if let Some(rd) = &self.rd {
            rd.remove(name);
        }
    }

    /// A trusted flag file is present (a planted one does not count).
    pub fn has(&self, name: &str) -> bool {
        self.rd.as_ref().is_some_and(|rd| rd.has_trusted(name))
    }

    pub fn is_privileged(&self) -> bool {
        // SAFETY: geteuid has no preconditions and cannot fail.
        self.paths.test_root.is_some() || unsafe { libc::geteuid() } == 0
    }

    /// The owner a trusted hook, directory or sibling binary must have.
    pub fn trusted_owner(&self) -> u32 {
        if self.paths.test_root.is_some() {
            // SAFETY: geteuid has no preconditions and cannot fail.
            unsafe { libc::geteuid() }
        } else {
            0
        }
    }

    /// `HH:MM:SSZ message` to stderr, and to the run log once the run
    /// directory is open and checked.
    pub fn log(&mut self, msg: &str) {
        let line = format!("{} {msg}", clock(now()));
        self.emit(&line);
    }

    /// A hook's stderr line: timestamped unless it already is.
    pub fn log_hook_line(&mut self, raw: &str) {
        if has_timestamp(raw) {
            self.emit(raw);
        } else {
            self.log(raw);
        }
    }

    fn emit(&mut self, line: &str) {
        if self.log_to_stderr {
            eprintln!("{line}");
            self.last_stderr = Some(line.to_string());
        }
        if let Some(Ok(mut f)) = self.rd.as_ref().map(|rd| rd.append("log")) {
            use std::io::Write;
            let _ = writeln!(f, "{line}");
        }
    }

    /// Re-emit a sentence to stderr only, so it is the last line a caller sees.
    pub fn repeat_last(&mut self, line: &str) {
        if self.log_to_stderr && self.last_stderr.as_deref() != Some(line) {
            eprintln!("{line}");
            self.last_stderr = Some(line.to_string());
        }
    }

    /// Open the run directory with privilege: create it if missing, refuse a
    /// symlink or a directory someone else owns, and reset a group- or
    /// world-writable mode to 0755.
    pub fn mkdir_run(&mut self) -> Result<(), Exit> {
        if self.rd.is_some() {
            return Ok(());
        }
        let (rd, note) = RunDir::open(&self.paths.run, self.trusted_owner(), true, true)
            .map_err(|e| exit(3, format!("refusing the run directory: {e}")))?;
        self.rd = Some(rd);
        if let Some(note) = note {
            self.log(&note);
        }
        Ok(())
    }

    /// Open an existing run directory for `status`, which never creates it.
    /// With privilege it is repaired as for any command; without, one that
    /// fails the checks reads as no state at all.
    pub fn open_run_for_status(&mut self) {
        if self.rd.is_some() {
            return;
        }
        let fix = self.is_privileged();
        if let Ok((rd, note)) = RunDir::open(&self.paths.run, self.trusted_owner(), fix, false) {
            self.rd = Some(rd);
            if let Some(note) = note {
                self.log(&note);
            }
        }
    }

    /// The fixed environment of every hook and child (docs/backend-contract.md).
    pub fn child_env(&self) -> Vec<(OsString, OsString)> {
        let mut env: Vec<(OsString, OsString)> = vec![
            ("PATH".into(), "/usr/bin:/usr/sbin".into()),
            ("LANG".into(), "C.UTF-8".into()),
            ("OMDROP_CONF".into(), self.paths.conf.clone().into()),
            ("OMDROP_RUN_DIR".into(), self.paths.run.clone().into()),
            ("OMDROP_RADIO_HOOKS".into(), "1".into()),
        ];
        // The invoking user, whose identity the advertisers publish.
        for var in ["PKEXEC_UID", "SUDO_UID"] {
            if let Ok(v) = std::env::var(var) {
                if v.len() <= 10 && is_uint(&v) {
                    env.push((var.into(), v.into()));
                }
            }
        }
        if let Some(t) = &self.paths.test_root {
            env.push((TEST_ROOT_VAR.into(), t.clone().into()));
        }
        env
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// UTC time of day, `HH:MM:SSZ`, as `date -u +%H:%M:%SZ` prints it.
pub fn clock(epoch: u64) -> String {
    let s = epoch % 86_400;
    format!("{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

fn has_timestamp(line: &str) -> bool {
    let b = line.as_bytes();
    b.len() >= 10
        && [0, 1, 3, 4, 6, 7].iter().all(|&i| b[i].is_ascii_digit())
        && b[2] == b':'
        && b[5] == b':'
        && b[8] == b'Z'
        && b[9] == b' '
}

/// Canonical decimal, at most twelve digits: what a deadline may be. Bash read
/// a leading 0 as octal and wrapped long digit strings; nothing here does, but
/// the same inputs are refused so both helpers accept exactly the same argv.
pub fn is_uint(s: &str) -> bool {
    canonical(s, 12)
}

/// Canonical decimal, at most nine digits (about 31 years): a duration. Now
/// plus any duration stays a valid deadline until the year 33,000.
pub fn is_duration(s: &str) -> bool {
    canonical(s, 9)
}

fn canonical(s: &str, max: usize) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && b.iter().all(u8::is_ascii_digit)
        && (b[0] != b'0' || b.len() == 1)
}

/// A small kernel-provided file (sysfs, procfs), trimmed. None when absent or
/// unreadable. Run-directory state goes through `Ctx::state` instead.
pub fn read_state(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut s = String::new();
    fs::File::open(path)
        .ok()?
        .take(4096)
        .read_to_string(&mut s)
        .ok()?;
    Some(s.trim().to_string())
}

/// Owned by `owner` and not writable by group or others, for the file and
/// its directory. Symlinks are followed: a packaged hook may be a link.
pub fn trusted(path: &Path, owner: u32) -> Result<(), String> {
    let check = |p: &Path| -> Result<(), String> {
        let m = fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        if m.uid() != owner {
            return Err(format!(
                "{} is owned by uid {}, not {owner}",
                p.display(),
                m.uid()
            ));
        }
        if m.mode() & 0o022 != 0 {
            return Err(format!("{} is writable by group or others", p.display()));
        }
        Ok(())
    };
    check(path)?;
    let canon = fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(dir) = canon.parent() {
        check(dir)?;
    }
    if let Some(dir) = path.parent() {
        check(dir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_bash_would_misread_are_refused() {
        for bad in [
            "", "08", "09", "010", "-1", "+1", " 1", "1 ", "1e3", "a[$(x)]", "٣",
        ] {
            assert!(!is_uint(bad), "{bad:?}");
            assert!(!is_duration(bad), "{bad:?}");
        }
        assert!(!is_uint(&"9".repeat(13)));
        assert!(is_uint(&"9".repeat(12)));
        assert!(!is_duration("1000000000"));
        assert!(is_duration("999999999"));
        assert!(is_duration("0") && is_uint("0"));
    }

    #[test]
    fn the_longest_duration_gives_an_accepted_deadline() {
        assert!(is_uint(&(now() + 999_999_999).to_string()));
    }

    #[test]
    fn clock_is_utc_time_of_day() {
        assert_eq!(clock(0), "00:00:00Z");
        assert_eq!(clock(86_399), "23:59:59Z");
        assert_eq!(clock(1_760_131_845), "21:30:45Z");
    }

    #[test]
    fn hook_lines_keep_their_own_timestamp() {
        assert!(has_timestamp("21:30:45Z gate: probe"));
        assert!(!has_timestamp("gate: probe"));
        assert!(!has_timestamp("21:30:45Zgate"));
        assert!(!has_timestamp("2x:30:45Z x"));
    }
}
