//! The identity commands `omdrop` runs: windows, the 1Password cache, import
//! (plugin `bin/lifecycle.py`, run by `identity.py`'s `__main__`).
//!
//! `omdrop` holds the identity lock itself around `window`, `stop-begin` and
//! `stop-end`, so that the check that no `off` has happened and the start of
//! the receiver and radio are one step; every other command takes the lock
//! here. The only step that ever runs without the lock is the 1Password
//! fetch, so `off` and `identity lock` can always interrupt one.
//!
//! Machine-readable results go to stdout as `key=value` lines; anything for
//! a person goes to stderr. Nothing here prints a key, a record, an account
//! identifier or a hash.

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::args::{Cmd, Parse};
use crate::contract::{
    MAX_LIFETIME, Payload, Settings, Window, WindowState, encode_payload, parse_payload,
    parse_settings, parse_window,
};
use crate::fsx::{Flock, exists, lexists, read_opt, read_text, write_private};
use crate::keyring::{KernelKeyring, Keyring, KeyringError};
use crate::keys::{certificate_der, key_matches};
use crate::op::{FETCH_SECONDS, FetchFailed, op_binary, op_run};
use crate::selfsigned::{self, CreateError};
use crate::user::User;

const DEFAULT_HOURS: i64 = 12;
const FILES: [&str; 3] = ["certificate.pem", "key.pem", "validation_record.cms"];

/// The attachments' names in the 1Password item. Without dots: in an
/// `op item create` assignment a dot separates a section from a field, so
/// "certificate.pem[file]=" made a section "certificate" holding a file "pem".
fn op_name(file: &str) -> &'static str {
    match file {
        "certificate.pem" => "certificate",
        "key.pem" => "key",
        _ => "validation_record",
    }
}

type CheckApple = dyn Fn(&[u8], &[u8], &[u8]) -> Option<String>;
#[cfg(test)]
type Hook = dyn Fn(&Env, &str, &[&str]) -> io::Result<()>;

/// Everything a command touches beyond its arguments. Production values come
/// from the process; tests substitute a fake keyring, a stub `op`, a clock
/// and the Apple check.
pub(crate) struct Env {
    pub user: User,
    pub keyring: Box<dyn Keyring>,
    pub op: Option<PathBuf>,
    pub check_apple: Box<CheckApple>,
    pub clock: Box<dyn Fn() -> i64>,
    /// Called at named points so a test can act "meanwhile".
    #[cfg(test)]
    pub hook: Option<Box<Hook>>,
}

impl Env {
    fn production(user: User) -> Env {
        Env {
            user,
            keyring: Box::new(KernelKeyring::new()),
            op: op_binary(),
            check_apple: Box::new(check_apple),
            clock: Box::new(crate::resolver::now),
            #[cfg(test)]
            hook: None,
        }
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    fn hook(&self, point: &str, keys: &[&str]) -> io::Result<()> {
        #[cfg(test)]
        if let Some(h) = &self.hook {
            return h(self, point, keys);
        }
        let _ = (point, keys);
        Ok(())
    }
}

/// What can stop a command. `Io` and an unexpected `Keyring` are the cases
/// where `identity.py` died with a traceback (exit 1).
#[derive(Debug)]
pub(crate) enum Fail {
    Fetch(FetchFailed),
    Keyring(KeyringError),
    Superseded(String),
    Io(io::Error),
}

impl From<io::Error> for Fail {
    fn from(e: io::Error) -> Self {
        Fail::Io(e)
    }
}

impl From<FetchFailed> for Fail {
    fn from(e: FetchFailed) -> Self {
        Fail::Fetch(e)
    }
}

impl From<KeyringError> for Fail {
    fn from(e: KeyringError) -> Self {
        Fail::Keyring(e)
    }
}

/// `str(OSError)`: `[Errno 28] No space left on device`.
fn py_oserror(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => format!("[Errno {n}] {}", crate::sys::strerror(n)),
        None => e.to_string(),
    }
}

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fail::Fetch(e) => f.write_str(&e.describe()),
            Fail::Keyring(e) => f.write_str(&e.0),
            Fail::Superseded(s) => f.write_str(s),
            Fail::Io(e) => f.write_str(&py_oserror(e)),
        }
    }
}

type R<T = i32> = Result<T, Fail>;

fn say(out: &mut dyn Write, key: &str, value: impl fmt::Display) {
    let _ = writeln!(out, "{key}={value}");
}

fn warn(err: &mut dyn Write, message: impl fmt::Display) {
    let _ = writeln!(err, "{message}");
}

// ------------------------------------------------------------------ small state

fn read_kv(path: &std::path::Path) -> io::Result<Settings> {
    Ok(parse_settings(&read_text(path)?.unwrap_or_default()))
}

fn read_state(env: &Env) -> io::Result<Settings> {
    read_kv(&env.user.state)
}

pub(crate) fn counter(env: &Env, name: &str) -> io::Result<u64> {
    let value = read_state(env)?.remove(name).unwrap_or_else(|| "0".into());
    let digits = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
    Ok(if digits {
        value.parse().unwrap_or(0)
    } else {
        0
    })
}

pub(crate) fn bump(env: &Env, name: &str) -> io::Result<u64> {
    let value = counter(env, name)? + 1;
    let mut state = read_state(env)?;
    state.insert(name.to_owned(), value.to_string());
    let mut keys: Vec<_> = state.into_iter().collect();
    keys.sort();
    let text: String = keys.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
    write_private(&env.user.state, text.as_bytes())?;
    Ok(value)
}

fn settings(env: &Env) -> io::Result<Settings> {
    read_kv(&env.user.settings)
}

/// Rewrite settings the way `omdrop` does: drop the keys' lines, append one each.
pub(crate) fn setting_set(env: &Env, changes: &[(&str, &str)]) -> io::Result<()> {
    let keys: Vec<&str> = changes.iter().map(|(k, _)| *k).collect();
    env.hook("setting_set", &keys)?;
    let text = read_text(&env.user.settings)?.unwrap_or_default();
    let mut lines: Vec<String> = crate::contract::splitlines(&text)
        .into_iter()
        .filter(|l| !keys.contains(&l.split('=').next().unwrap_or("")))
        .map(str::to_owned)
        .collect();
    lines.extend(changes.iter().map(|(k, v)| format!("{k}={v}")));
    write_private(
        &env.user.settings,
        format!("{}\n", lines.join("\n")).as_bytes(),
    )
}

fn mode(env: &Env) -> io::Result<String> {
    Ok(settings(env)?
        .remove("identity_source")
        .unwrap_or_else(|| "disk".into()))
}

fn cache_hours(s: &Settings) -> i64 {
    match s.get("identity_cache_hours") {
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => match v.parse::<i64>()
        {
            Ok(n) if (1..=24).contains(&n) => n,
            _ => DEFAULT_HOURS,
        },
        _ => DEFAULT_HOURS,
    }
}

/// The pid of a running `op`, in its own file rather than in `state`: op_run
/// records it without the lock, and a read-modify-write of `state` there
/// could otherwise overwrite a concurrent bump of `seq` or `gen`.
fn fetch_pid_path(env: &Env) -> PathBuf {
    env.user.state_dir.join("fetch.pid")
}

fn kill_fetch(env: &Env) -> io::Result<()> {
    let path = fetch_pid_path(env);
    let pid = read_text(&path)?.unwrap_or_default();
    let pid = pid.trim();
    if !pid.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
        && let Ok(pid) = pid.parse::<libc::pid_t>()
        && pid > 0
    {
        // SAFETY: kill with a positive pid and a signal number. A pid that
        // no longer exists or is not ours is ignored, as in the Python.
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
    match std::fs::remove_file(&path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn lock(env: &Env) -> io::Result<Flock> {
    Flock::acquire(&env.user.lock)
}

pub(crate) fn read_window(env: &Env) -> io::Result<WindowState> {
    Ok(match read_text(&env.user.window)? {
        None => WindowState::Absent,
        Some(t) => parse_window(&t).map_or(WindowState::Unparseable, WindowState::Parsed),
    })
}

fn window_open(env: &Env) -> bool {
    exists(&env.user.window)
}

// ------------------------------------------------------------------ the cache

/// The parsed cache, or `None` when there is none worth using.
fn current_cache(env: &Env) -> Option<Payload> {
    let raw = env.keyring.read(None).ok()??;
    parse_payload(&raw).filter(|p| p.hard_expiry > env.now())
}

fn usable_for_new_window(env: &Env, p: &Option<Payload>) -> bool {
    p.as_ref().is_some_and(|p| p.period_ends > env.now())
}

fn op(env: &Env, args: Vec<OsString>, deadline: Instant) -> Result<Vec<u8>, FetchFailed> {
    op_run(env.op.as_deref(), &fetch_pid_path(env), &args, deadline)
}

fn item_ref(env: &Env) -> R<(String, String, String)> {
    let s = settings(env)?;
    let get = |k: &str| s.get(k).cloned().unwrap_or_default();
    let (account, vault, item) = (
        get("identity_op_account"),
        get("identity_op_vault"),
        get("identity_op_item"),
    );
    if vault.is_empty() || item.is_empty() {
        return Err(FetchFailed::new(
            "No 1Password item configured",
            "run: omdrop identity 1password import",
        )
        .into());
    }
    Ok((account, vault, item))
}

/// The three files of a 1Password item, in `FILES` order.
pub(crate) struct Files(pub [Zeroizing<Vec<u8>>; 3]);

impl Files {
    fn cert(&self) -> &[u8] {
        &self.0[0]
    }
    fn key(&self) -> &[u8] {
        &self.0[1]
    }
    fn record(&self) -> &[u8] {
        &self.0[2]
    }
}

pub(crate) fn op_read_files(
    env: &Env,
    account: &str,
    vault: &str,
    item: &str,
    deadline: Instant,
) -> R<Files> {
    let mut files: [Zeroizing<Vec<u8>>; 3] = Default::default();
    for (slot, name) in files.iter_mut().zip(FILES) {
        let mut args: Vec<OsString> = vec!["read".into(), "--no-newline".into()];
        if !account.is_empty() {
            args.push("--account".into());
            args.push(account.into());
        }
        args.push(format!("op://{vault}/{item}/{}", op_name(name)).into());
        *slot = Zeroizing::new(op(env, args, deadline)?);
    }
    env.hook("op_read_files", &[])?;
    Ok(Files(files))
}

/// None when the set is a usable Apple identity, else the failed check.
pub(crate) fn check_apple(cert_pem: &[u8], key_pem: &[u8], record: &[u8]) -> Option<String> {
    if cert_pem.is_empty() || key_pem.is_empty() || record.is_empty() {
        return Some("incomplete".into());
    }
    if !key_matches(cert_pem, key_pem, None) {
        return Some("key does not match certificate".into());
    }
    let der = certificate_der(cert_pem)
        .map(|d| d.to_vec())
        .unwrap_or_default();
    let account = crate::apple::certificate_account(&der);
    if account.is_empty() {
        return Some("certificate is not issued by Apple".into());
    }
    let Some(verified) = crate::apple::verify_record(record) else {
        return Some("validation record does not carry Apple's signature".into());
    };
    if verified.expired {
        return Some("validation record has expired".into());
    }
    if verified.account != account {
        return Some("certificate and validation record belong to different Apple accounts".into());
    }
    None
}

/// Fetch, check and encode the identity: the payload to publish.
pub(crate) fn fetch(env: &Env) -> R<Zeroizing<Vec<u8>>> {
    let deadline = Instant::now() + Duration::from_secs(FETCH_SECONDS);
    let (account, vault, item) = item_ref(env)?;
    let files = op_read_files(env, &account, &vault, &item, deadline)?;
    let unusable =
        |problem: String| FetchFailed::new("The Apple identity in 1Password is unusable", problem);
    if let Some(problem) = (env.check_apple)(files.cert(), files.key(), files.record()) {
        return Err(unusable(problem).into());
    }
    let t0 = env.now();
    let t2 = t0 + MAX_LIFETIME;
    let t1 = (t0 + cache_hours(&settings(env)?) * 3600).min(t2);
    let fetch_id = hex::encode(crate::sys::random_bytes(16)?);
    // identity.py raised an uncaught ValueError here (a part over 16 KiB),
    // which killed `omdrop on`; it is an unusable identity like any other.
    encode_payload(
        &fetch_id,
        t0,
        t1,
        t2,
        files.cert(),
        files.key(),
        files.record(),
    )
    .ok_or_else(|| unusable("too large for the identity cache".into()).into())
}

/// Publish under the lock, only if nothing invalidated this fetch.
pub(crate) fn publish_if_current(env: &Env, payload: &[u8], generation: u64) -> R<&'static str> {
    let _l = lock(env)?;
    if counter(env, "gen")? != generation {
        return Ok("superseded");
    }
    if let WindowState::Parsed(Window::OnePassword { .. }) = read_window(env)? {
        return Ok("window-open"); // never replace a live window's cache
    }
    let parsed = parse_payload(payload)
        .ok_or_else(|| KeyringError("identity payload would not parse".into()))?;
    env.keyring
        .publish(payload, parsed.period_ends - env.now())?;
    Ok("published")
}

/// Fetch and publish. Returns the outcome and what stopped it, if anything.
pub(crate) fn fill_cache(env: &Env) -> R<(&'static str, Option<Fail>)> {
    let generation = {
        let _l = lock(env)?;
        counter(env, "gen")?
    };
    let payload = match fetch(env) {
        Ok(p) => p,
        Err(Fail::Fetch(e)) => return Ok(("failed", Some(Fail::Fetch(e)))),
        Err(e) => return Err(e),
    };
    match publish_if_current(env, &payload, generation) {
        Ok(outcome) => Ok((outcome, None)),
        Err(Fail::Keyring(e)) => Ok(("failed", Some(Fail::Keyring(e)))),
        Err(e) => Err(e),
    }
}

// ------------------------------------------------------------------ window commands

/// Self-signed creation failures that identity.py reported as IdentityError;
/// setup failures (OSError there) end the command like a traceback did.
fn create_pair(env: &Env, name: &str) -> R<Result<bool, CreateError>> {
    match selfsigned::create(&env.user.keys, name, env.user.root) {
        Err(CreateError::Io(e)) => Err(Fail::Io(e)),
        other => Ok(other),
    }
}

/// Before a window starts: the self-signed pair, the rename, and the cache.
fn cmd_begin(env: &Env, name: &str, out: &mut dyn Write, err: &mut dyn Write) -> R {
    if let Err(e) = create_pair(env, name)? {
        warn(
            err,
            format_args!("omdrop: the self-signed identity is unusable: {e}"),
        );
        return Ok(1);
    }
    selfsigned::migrate_legacy(&env.user.keys)?;
    let seq = {
        let _l = lock(env)?;
        counter(env, "seq")?
    };
    say(out, "seq", seq);
    if mode(env)? != "1password" || usable_for_new_window(env, &current_cache(env)) {
        return Ok(0);
    }
    if let WindowState::Parsed(_) = read_window(env)? {
        return Ok(0); // a repeated `on`: the window keeps its identity
    }
    let (outcome, why) = fill_cache(env)?;
    if outcome == "failed" {
        let reason = match why {
            Some(Fail::Fetch(e)) => e.message,
            _ => "Could not cache the Apple identity".into(),
        };
        say(
            out,
            "notice",
            format_args!(
                "{reason}; using self-signed certificates. Peers must be in \"Everyone\" mode."
            ),
        );
    }
    Ok(0)
}

/// With `omdrop` holding the lock: fix this window's identity, or refuse.
fn cmd_window(env: &Env, seq: Option<i128>, out: &mut dyn Write, err: &mut dyn Write) -> R {
    if seq != Some(i128::from(counter(env, "seq")?)) {
        return Ok(3); // `off` ran meanwhile: start nothing
    }
    if let WindowState::Parsed(existing) = read_window(env)? {
        say(out, "source", existing.source()); // a repeated `on` keeps the window's choice
        if let Window::OnePassword { hard_expiry, .. } = existing {
            say(out, "expiry_in", (hard_expiry - env.now()).max(0));
        }
        return Ok(0);
    }
    let m = mode(env)?;
    let mut lines: Vec<String> = Vec::new();
    if m == "1password" {
        let payload = current_cache(env);
        if usable_for_new_window(env, &payload)
            && let Some(p) = payload
        {
            // cache_serial is for sandboxed readers such as the receiver,
            // which cannot search the user keyring (resolver::keyring_read).
            let serial = match env.keyring.find() {
                Ok(Some(s)) => s.to_string(),
                _ => "None".into(),
            };
            lines = vec![
                "source=1password".into(),
                format!("fetch_id={}", p.fetch_id),
                format!("hard_expiry={}", p.hard_expiry),
                format!("cache_serial={serial}"),
            ];
            env.keyring.set_timeout(p.hard_expiry - env.now())?;
            say(out, "source", "1password");
            say(out, "expiry_in", p.hard_expiry - env.now());
        }
    } else if m == "disk" {
        let u = &env.user;
        let (cert_p, key_p, rec_p) = (u.path(FILES[0]), u.path(FILES[1]), u.path(FILES[2]));
        // As identity.disk_state: an unreadable file counts as present but
        // not matching.
        let read = |p: &std::path::Path| match read_opt(p) {
            Ok(d) => (d, lexists(p)),
            Err(_) => (None, true),
        };
        let ((cert, have_cert), (key, have_key)) = (read(&cert_p), read(&key_p));
        let key = key.map(Zeroizing::new);
        let matches = match (&cert, &key) {
            (Some(c), Some(k)) if !c.is_empty() && !k.is_empty() => key_matches(c, k, None),
            _ => false,
        };
        if have_cert && have_key && matches {
            let mut problem = None;
            if exists(&rec_p) {
                let record = read_opt(&rec_p)?.unwrap_or_default();
                let cert = cert.unwrap_or_default();
                let key = key.unwrap_or_default();
                problem = (env.check_apple)(&cert, &key, &record);
            }
            if let Some(problem) = problem {
                say(
                    out,
                    "notice",
                    "Apple identity unusable; using self-signed certificates. Peers must be in \"Everyone\" mode.",
                );
                warn(
                    err,
                    format_args!("omdrop: the Apple identity on disk is unusable: {problem}"),
                );
            } else {
                lines = vec!["source=disk".into()];
                say(out, "source", "disk");
            }
        }
    }
    if lines.is_empty() {
        lines = vec!["source=self-signed".into()];
        say(out, "source", "self-signed");
    }
    write_private(
        &env.user.window,
        format!("{}\n", lines.join("\n")).as_bytes(),
    )?;
    Ok(0)
}

fn cmd_stop_begin(env: &Env) -> R {
    bump(env, "seq")?;
    Ok(0)
}

fn cmd_stop_end(env: &Env, err: &mut dyn Write) -> R {
    match std::fs::remove_file(&env.user.window) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    if let Some(p) = current_cache(env)
        && let Err(e) = env.keyring.set_timeout(p.period_ends - env.now())
    {
        warn(err, format_args!("omdrop: {e}"));
    }
    Ok(0)
}

// ------------------------------------------------------------------ identity commands

fn cmd_lock(env: &Env, err: &mut dyn Write) -> R {
    let revoked = {
        let _l = lock(env)?;
        if window_open(env) {
            warn(err, "Turn Omdrop off first.");
            return Ok(1);
        }
        bump(env, "gen")?;
        kill_fetch(env)?;
        match env.keyring.revoke() {
            Ok(r) => r,
            Err(e) => {
                warn(err, format_args!("omdrop: {e}"));
                return Ok(1);
            }
        }
    };
    warn(
        err,
        if revoked {
            "Cleared the identity cache."
        } else {
            "The identity cache was already empty."
        },
    );
    Ok(0)
}

fn cmd_unlock(env: &Env, err: &mut dyn Write) -> R {
    if mode(env)? != "1password" {
        warn(
            err,
            "Omdrop is not set to use 1Password (identity_source is not 1password).",
        );
        return Ok(1);
    }
    if current_cache(env).is_some() {
        warn(err, "The identity cache is already filled.");
        return Ok(0);
    }
    let (outcome, why) = fill_cache(env)?;
    match outcome {
        "published" => {
            warn(err, "Fetched the AirDrop identity from 1Password.");
            return Ok(0);
        }
        "superseded" => warn(err, "Cancelled: the identity settings changed meanwhile."),
        "window-open" => warn(err, "Turn Omdrop off first."),
        _ => warn(
            err,
            format_args!(
                "Could not fetch: {}",
                why.map(|e| e.to_string()).unwrap_or_default()
            ),
        ),
    }
    Ok(1)
}

/// `json.dumps(s)` with Python's default `ensure_ascii=True`.
fn py_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn cmd_status(env: &Env, json: bool, out: &mut dyn Write) -> R {
    let payload = current_cache(env);
    let window = match read_window(env)? {
        WindowState::Absent => None,
        WindowState::Unparseable => Some("unparseable"),
        WindowState::Parsed(w) => Some(w.source()),
    };
    let u = &env.user;
    let (disk_cert, disk_key) = (lexists(&u.path(FILES[0])), lexists(&u.path(FILES[1])));
    let disk_record = exists(&u.path(FILES[2]));
    let self_signed = exists(&u.path(selfsigned::CERT)) && exists(&u.path(selfsigned::KEY));
    let s = settings(env)?;
    let mode = s
        .get("identity_source")
        .cloned()
        .unwrap_or_else(|| "disk".into());
    let configured = s.get("identity_op_item").is_some_and(|v| !v.is_empty());
    let op_installed = env.op.is_some();
    let apple_files: Vec<&str> = FILES
        .iter()
        .copied()
        .filter(|f| exists(&u.path(f)))
        .collect();
    let hours = cache_hours(&s);
    if json {
        let bool_s = |b: bool| if b { "true" } else { "false" };
        let cache = match &payload {
            None => "null".to_owned(),
            Some(p) => format!(
                "{{\"hard_expiry\": {}, \"period_ends\": {}}}",
                p.hard_expiry, p.period_ends
            ),
        };
        let files: Vec<String> = apple_files.iter().map(|f| py_json_str(f)).collect();
        let _ = writeln!(
            out,
            "{{\"apple_files_on_disk\": [{}], \"cache\": {cache}, \"cache_hours\": {hours}, \"mode\": {}, \"onepassword_configured\": {}, \"op_installed\": {}, \"self_signed\": {}, \"window\": {}}}",
            files.join(", "),
            py_json_str(&mode),
            bool_s(configured),
            bool_s(op_installed),
            bool_s(self_signed),
            window.map_or_else(|| "null".to_owned(), py_json_str),
        );
        return Ok(0);
    }
    let mut lines = vec![format!("Identity source: {mode}")];
    if let Some(w) = window {
        lines.push(format!("This window uses: {w}"));
    }
    if mode == "1password" {
        match &payload {
            Some(p) => lines.push(format!(
                "Cached from 1Password until {}",
                crate::sys::strftime_local("%Y-%m-%d %H:%M %Z", p.period_ends)
            )),
            None => lines.push("Nothing cached; the next `omdrop on` asks 1Password.".into()),
        }
        if !op_installed {
            lines.push("The 1Password CLI (op) is not installed.".into());
        }
        if !apple_files.is_empty() {
            lines.push(format!(
                "Apple identity files are still on disk: {} (run: omdrop identity 1password import)",
                apple_files.join(", ")
            ));
        }
    } else if disk_cert && disk_key {
        lines.push(
            if disk_record {
                "Apple identity on disk."
            } else {
                "Identity on disk."
            }
            .into(),
        );
    }
    lines.push(format!(
        "Self-signed identity: {}",
        if self_signed {
            "present"
        } else {
            "not yet created"
        }
    ));
    let _ = writeln!(out, "{}", lines.join("\n"));
    Ok(0)
}

fn op_json(env: &Env, mut args: Vec<OsString>, deadline: Instant) -> R<serde_json::Value> {
    args.push("--format".into());
    args.push("json".into());
    let raw = op(env, args, deadline)?;
    let raw: &[u8] = if raw.is_empty() { b"{}" } else { &raw };
    // identity.py died on output that is not JSON; it is 1Password failing.
    serde_json::from_slice(raw).map_err(|_| {
        FetchFailed::new(
            "1Password could not provide the identity",
            "op printed something that is not JSON",
        )
        .into()
    })
}

fn json_id(v: &serde_json::Value) -> String {
    v.get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("")
        .to_owned()
}

fn json_vault_id(v: &serde_json::Value) -> String {
    v.get("vault").map(json_id).unwrap_or_default()
}

/// The 1Password account to pin, when the app has exactly one.
///
/// Not `op whoami`: with the desktop app integration it reports only an
/// existing sign-in and never asks for one, so it fails in a fresh process
/// even right after the user approved a prompt.
pub(crate) fn account_id(env: &Env, deadline: Instant) -> R<String> {
    let raw = op(
        env,
        vec![
            "account".into(),
            "list".into(),
            "--format".into(),
            "json".into(),
        ],
        deadline,
    )?;
    let raw: &[u8] = if raw.is_empty() { b"[]" } else { &raw };
    let accounts: serde_json::Value = serde_json::from_slice(raw).map_err(|_| {
        FetchFailed::new(
            "1Password could not provide the identity",
            "op printed something that is not JSON",
        )
    })?;
    let id = match accounts.as_array().map(Vec::as_slice) {
        Some([one]) => one
            .get("account_uuid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        _ => String::new(), // several accounts: op's own default decides
    };
    env.hook("account_id", &[])?;
    Ok(id)
}

/// Under the lock: refuse if a window opened or the generation moved.
fn check_current(env: &Env, generation: u64) -> R<()> {
    if window_open(env) {
        return Err(Fail::Superseded("Turn Omdrop off first.".into()));
    }
    if counter(env, "gen")? != generation {
        return Err(Fail::Superseded(
            "Cancelled: the identity settings changed meanwhile.".into(),
        ));
    }
    Ok(())
}

/// Record a newly created item's IDs, mode unchanged, under the same checks
/// as a commit: a superseded import must not overwrite a newer choice.
fn save_item_ids(env: &Env, account: &str, vault: &str, item: &str, generation: u64) -> R<()> {
    let _l = lock(env)?;
    check_current(env, generation)?;
    setting_set(
        env,
        &[
            ("identity_op_account", account),
            ("identity_op_vault", vault),
            ("identity_op_item", item),
        ],
    )?;
    Ok(())
}

/// Commit to a 1Password item, under the lock.
///
/// Refused if a window opened or another identity command ran since this one
/// began. The old cache is cleared first, and a failure to clear it refuses
/// the commit: the cache may hold a different identity, and the next window
/// would present it. Then the IDs are saved and the mode last, the mode
/// write being the commit point, and the generation moves so no fetch still
/// out can publish.
fn adopt(env: &Env, account: &str, vault: &str, item: &str, generation: u64) -> R<()> {
    let _l = lock(env)?;
    check_current(env, generation)?;
    if let Err(e) = env.keyring.revoke() {
        return Err(Fail::Superseded(format!(
            "Could not clear the cached identity ({e}); nothing changed."
        )));
    }
    setting_set(
        env,
        &[
            ("identity_op_account", account),
            ("identity_op_vault", vault),
            ("identity_op_item", item),
        ],
    )?;
    setting_set(env, &[("identity_source", "1password")])?;
    bump(env, "gen")?;
    kill_fetch(env)?;
    Ok(())
}

fn read_present(env: &Env) -> io::Result<[Option<Zeroizing<Vec<u8>>>; 3]> {
    let mut present: [Option<Zeroizing<Vec<u8>>>; 3] = Default::default();
    for (slot, f) in present.iter_mut().zip(FILES) {
        *slot = read_opt(&env.user.path(f))?.map(Zeroizing::new);
    }
    Ok(present)
}

fn cmd_import(env: &Env, vault_arg: Option<&str>, title: &str, err: &mut dyn Write) -> R {
    let generation = {
        let _l = lock(env)?;
        if window_open(env) {
            warn(err, "Turn Omdrop off first.");
            return Ok(1);
        }
        counter(env, "gen")?
    };
    let deadline = Instant::now() + Duration::from_secs(5 * FETCH_SECONDS);
    let present = read_present(env)?;
    let s = settings(env)?;
    let result: R<Option<i32>> = (|| {
        if s.get("identity_op_item").is_some_and(|v| !v.is_empty()) {
            // A rerun: an item exists. Compare what's left on disk with it.
            let (account, vault, item) = item_ref(env)?;
            let stored = op_read_files(env, &account, &vault, &item, deadline)?;
            for ((f, data), stored) in FILES.iter().zip(&present).zip(&stored.0) {
                if let Some(d) = data
                    && d.as_slice() != stored.as_slice()
                {
                    warn(
                        err,
                        format_args!(
                            "{f} on disk differs from the 1Password item; nothing was deleted."
                        ),
                    );
                    return Ok(Some(1));
                }
            }
            if s.get("identity_source").map(String::as_str) != Some("1password") {
                if let Some(problem) =
                    (env.check_apple)(stored.cert(), stored.key(), stored.record())
                {
                    warn(
                        err,
                        format_args!(
                            "The 1Password item is not usable: {problem}; nothing was deleted."
                        ),
                    );
                    return Ok(Some(1));
                }
                adopt(env, &account, &vault, &item, generation)?;
            }
            return Ok(None);
        }
        let missing: Vec<&str> = FILES
            .iter()
            .zip(&present)
            .filter(|(_, d)| d.is_none())
            .map(|(f, _)| *f)
            .collect();
        if !missing.is_empty() {
            warn(
                err,
                format_args!(
                    "Nothing to import: {} missing from {}",
                    missing.join(", "),
                    env.user.keys.display()
                ),
            );
            return Ok(Some(1));
        }
        let [Some(cert), Some(key), Some(record)] = &present else {
            return Ok(Some(1));
        };
        if let Some(problem) = (env.check_apple)(cert, key, record) {
            warn(err, format_args!("Not importing: {problem}."));
            return Ok(Some(1));
        }
        let mut create: Vec<OsString> = [
            "item",
            "create",
            "--category",
            "Secure Note",
            "--title",
            title,
        ]
        .iter()
        .map(|s| OsString::from(*s))
        .collect();
        if let Some(v) = vault_arg {
            create.push("--vault".into());
            create.push(v.into());
        }
        for f in FILES {
            let mut a = OsString::from(format!("{}[file]=", op_name(f)));
            a.push(env.user.path(f));
            create.push(a);
        }
        let made = op_json(env, create, deadline)?;
        let (item, vault) = (json_id(&made), json_vault_id(&made));
        if item.is_empty() || vault.is_empty() {
            warn(
                err,
                "1Password did not report the new item; nothing was deleted.",
            );
            return Ok(Some(1));
        }
        let account = account_id(env, deadline)?;
        // Saved straight away, with the mode unchanged: if anything below
        // fails, a rerun finds this item instead of creating another.
        match save_item_ids(env, &account, &vault, &item, generation) {
            Ok(()) => {}
            Err(Fail::Io(e)) => {
                warn(
                    err,
                    format_args!(
                        "Could not save the settings ({}). The item is {item}; run: omdrop identity 1password use {item}",
                        py_oserror(&e)
                    ),
                );
                return Ok(Some(1));
            }
            Err(Fail::Superseded(e)) => {
                warn(
                    err,
                    format_args!("{e} The new 1Password item is {item}; nothing was deleted."),
                );
                return Ok(Some(1));
            }
            Err(e) => return Err(e),
        }
        let stored = op_read_files(env, &account, &vault, &item, deadline)?;
        let same = stored
            .0
            .iter()
            .zip(&present)
            .all(|(s, p)| p.as_ref().is_some_and(|p| p.as_slice() == s.as_slice()));
        if !same {
            warn(
                err,
                format_args!(
                    "The 1Password item {item} does not match the files; nothing was deleted."
                ),
            );
            return Ok(Some(1));
        }
        match adopt(env, &account, &vault, &item, generation) {
            Ok(()) => Ok(None),
            Err(Fail::Io(e)) => {
                warn(
                    err,
                    format_args!(
                        "Could not save the settings ({}); nothing was deleted. Run the import again to finish.",
                        py_oserror(&e)
                    ),
                );
                Ok(Some(1))
            }
            Err(e) => Err(e),
        }
    })();
    match result {
        Ok(Some(rc)) => return Ok(rc),
        Ok(None) => {}
        Err(Fail::Fetch(e)) => {
            warn(err, format_args!("{}; nothing was deleted.", e.describe()));
            return Ok(1);
        }
        Err(Fail::Superseded(e)) => {
            warn(err, format_args!("{e} Nothing was deleted."));
            return Ok(1);
        }
        Err(e) => return Err(e),
    }
    // Committed. The key first: it is the one that matters most.
    for f in ["key.pem", "validation_record.cms", "certificate.pem"] {
        match std::fs::remove_file(env.user.path(f)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    warn(
        err,
        "Your Apple identity is now in 1Password, and the copies on disk were deleted. The next `omdrop on` fetches it.",
    );
    Ok(0)
}

fn cmd_use(
    env: &Env,
    item_arg: &str,
    vault_arg: Option<&str>,
    account_arg: Option<&str>,
    err: &mut dyn Write,
) -> R {
    let generation = {
        let _l = lock(env)?;
        if window_open(env) {
            warn(err, "Turn Omdrop off first.");
            return Ok(1);
        }
        let g = bump(env, "gen")?;
        kill_fetch(env)?;
        g
    };
    let deadline = Instant::now() + Duration::from_secs(FETCH_SECONDS);
    let fetched: R<(String, String, String, Files)> = (|| {
        let mut get: Vec<OsString> = vec!["item".into(), "get".into(), item_arg.into()];
        if let Some(v) = vault_arg {
            get.push("--vault".into());
            get.push(v.into());
        }
        let found = op_json(env, get, deadline)?;
        let (item, vault) = (json_id(&found), json_vault_id(&found));
        let account = match account_arg {
            Some(a) if !a.is_empty() => a.to_owned(),
            _ => account_id(env, deadline)?,
        };
        let files = op_read_files(env, &account, &vault, &item, deadline)?;
        Ok((account, vault, item, files))
    })();
    let (account, vault, item, files) = match fetched {
        Ok(f) => f,
        Err(Fail::Fetch(e)) => {
            warn(err, e.describe());
            return Ok(1);
        }
        Err(e) => return Err(e),
    };
    if let Some(problem) = (env.check_apple)(files.cert(), files.key(), files.record()) {
        warn(err, format_args!("That item is not usable: {problem}."));
        return Ok(1);
    }
    match adopt(env, &account, &vault, &item, generation) {
        Ok(()) => {}
        Err(Fail::Superseded(e)) => {
            warn(err, e);
            return Ok(1);
        }
        Err(e) => return Err(e),
    }
    warn(
        err,
        "Omdrop now uses that 1Password item. The next `omdrop on` fetches it.",
    );
    Ok(0)
}

fn cmd_onepassword_off(env: &Env, err: &mut dyn Write) -> R {
    {
        let _l = lock(env)?;
        if window_open(env) {
            warn(err, "Turn Omdrop off first.");
            return Ok(1);
        }
        bump(env, "gen")?;
        kill_fetch(env)?;
        let _ = env.keyring.revoke();
        setting_set(env, &[("identity_source", "self-signed")])?;
    }
    warn(
        err,
        "Omdrop no longer uses 1Password; the item in 1Password is kept.",
    );
    Ok(0)
}

fn cmd_ensure_self_signed(env: &Env, name: &str, out: &mut dyn Write, err: &mut dyn Write) -> R {
    let made = match create_pair(env, name)? {
        Ok(m) => m,
        Err(e) => {
            warn(err, e);
            return Ok(2);
        }
    };
    say(out, "renamed", selfsigned::migrate_legacy(&env.user.keys)?);
    Ok(if made { 0 } else { 1 })
}

pub(crate) fn run(env: &Env, cmd: &Cmd, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let result = match cmd {
        Cmd::Begin { name } => cmd_begin(env, name, out, err),
        Cmd::Window { seq } => cmd_window(env, *seq, out, err),
        Cmd::StopBegin => cmd_stop_begin(env),
        Cmd::StopEnd => cmd_stop_end(env, err),
        Cmd::Lock => cmd_lock(env, err),
        Cmd::Unlock => cmd_unlock(env, err),
        Cmd::Status { json } => cmd_status(env, *json, out),
        Cmd::Import { vault, title } => cmd_import(env, vault.as_deref(), title, err),
        Cmd::Use {
            item,
            vault,
            account,
        } => cmd_use(env, item, vault.as_deref(), account.as_deref(), err),
        Cmd::OnePasswordOff => cmd_onepassword_off(env, err),
        Cmd::EnsureSelfSigned { name } => cmd_ensure_self_signed(env, name, out, err),
    };
    match result {
        Ok(rc) => rc,
        Err(e) => {
            // Where identity.py died with a traceback: say what failed, exit 1.
            warn(err, format_args!("omdrop: {e}"));
            1
        }
    }
}

/// `python3 identity.py ARGS`, in process.
pub(crate) fn main(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let cmd = match crate::args::parse(args) {
        Parse::Run(cmd) => cmd,
        Parse::Exit {
            code,
            out: o,
            err: e,
        } => {
            let _ = out.write_all(o.as_bytes());
            let _ = err.write_all(e.as_bytes());
            return code;
        }
    };
    let user = match User::current(None) {
        Ok(u) => u,
        Err(e) => {
            warn(err, format_args!("omdrop: {e}"));
            return 1;
        }
    };
    let env = Env::production(user);
    // Keep keys out of core dumps and away from same-UID ptrace, as
    // lifecycle.main did before every command. Best effort, as there.
    let _ = crate::sys::protect_process();
    run(&env, &cmd, out, err)
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;
