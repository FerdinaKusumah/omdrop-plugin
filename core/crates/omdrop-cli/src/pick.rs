//! Ask the person for a folder or files (was `bin/pick.py`).
//!
//! Nautilus first, by calling its portal backend directly. Nautilus 50
//! implements org.freedesktop.impl.portal.FileChooser itself, but Omarchy
//! routes the desktop portal to GTK, so going through
//! org.freedesktop.portal.Desktop would show the GTK chooser instead. The
//! backend interface answers the call synchronously, with no Request object
//! to watch. A desktop without Nautilus still gets the desktop portal's
//! chooser, whichever backend it routes to.
//!
//! `Ok(paths)` with an answer (empty when the person cancelled), `Err(code)`
//! for the exit status pick.py would have given: 1 cancelled, 2 no chooser.
//! `OMDROP_PICKER` stands in for the chooser the way OMDROP_SENDER does for
//! the sender, and keeps pick.py's command line: `folder|files START TITLE`,
//! answering with a line, or NUL-terminated paths.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use zbus::blocking::Connection;
use zbus::zvariant::{ObjectPath, OwnedValue, Value};

use crate::proc::{caught, trap_signals, untrap_forget};

const NAUTILUS: &str = "org.gnome.Nautilus";
const PORTAL: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const IMPL: &str = "org.freedesktop.impl.portal.FileChooser";
const APP_ID: &str = "netmojo.omdrop";

pub fn pick(kind: &str, start: &str, title: &str) -> Result<Vec<PathBuf>, i32> {
    if let Some(picker) = crate::util::env_nonempty("OMDROP_PICKER") {
        return via_command(&picker, kind, start, title);
    }
    let paths = native(kind, start, title)?;
    if paths.is_empty() {
        return Err(1);
    }
    Ok(match kind {
        "folder" => paths.into_iter().take(1).collect(),
        _ => paths,
    })
}

fn via_command(picker: &str, kind: &str, start: &str, title: &str) -> Result<Vec<PathBuf>, i32> {
    let mut cmd = Command::new(picker);
    cmd.args([kind, start, title])
        .stderr(std::process::Stdio::inherit());
    let (code, out) = crate::proc::capture_cmd(&mut cmd);
    if code != 0 {
        return Err(code);
    }
    if kind == "folder" {
        let line = crate::util::strip_trailing_newlines_bytes(&out);
        return Ok(vec![PathBuf::from(OsString::from_vec(line.to_vec()))]);
    }
    // NUL-separated, because a filename may hold a newline.
    Ok(out
        .split(|&b| b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| PathBuf::from(OsString::from_vec(p.to_vec())))
        .collect())
}

fn options(kind: &str, start: &str) -> HashMap<&'static str, Value<'static>> {
    let mut opts: HashMap<&'static str, Value<'static>> = HashMap::new();
    opts.insert("modal", Value::from(false));
    opts.insert(
        "accept_label",
        Value::from(if kind == "folder" { "Select" } else { "Send" }),
    );
    if kind == "folder" {
        opts.insert("directory", Value::from(true));
    } else {
        opts.insert("multiple", Value::from(true));
    }
    if !start.is_empty() && Path::new(start).is_dir() {
        // A NUL-terminated byte string: the portal's type for a path.
        let mut bytes = start.as_bytes().to_vec();
        bytes.push(0);
        opts.insert("current_folder", Value::from(bytes));
    }
    opts
}

/// The chosen local paths. A remote location has no path to send from.
fn paths_of(results: &HashMap<String, OwnedValue>) -> Vec<PathBuf> {
    let Some(uris) = results.get("uris").and_then(|v| v.try_clone().ok()) else {
        return Vec::new();
    };
    let uris: Vec<String> = Vec::try_from(uris).unwrap_or_default();
    uris.iter().filter_map(|u| file_uri_path(u)).collect()
}

/// `urlparse` + `unquote` for file: URIs: the path, percent-decoded, with
/// any host, query or fragment dropped.
pub fn file_uri_path(uri: &str) -> Option<PathBuf> {
    let (scheme, rest) = uri.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("file") {
        return None;
    }
    let rest = match rest.strip_prefix("//") {
        Some(after) => &after[after.find('/').unwrap_or(after.len())..],
        None => rest,
    };
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    let raw = &rest.as_bytes()[..end];
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if raw[i] == b'%' && i + 2 < raw.len() {
            if let (Some(h), Some(l)) = (hex(raw[i + 1]), hex(raw[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    if out.is_empty() {
        return None;
    }
    Some(PathBuf::from(OsString::from_vec(out)))
}

fn describe(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, detail, _) => {
            format!(
                "GDBus.Error:{}: {}",
                name.as_str(),
                detail.as_deref().unwrap_or("")
            )
        }
        other => other.to_string(),
    }
}

/// Absent or not activatable. Anything else (a Nautilus that crashed
/// mid-dialog) is not a reason to pop a second chooser at them.
fn absent(e: &zbus::Error) -> bool {
    let s = describe(e);
    s.contains("ServiceUnknown") || s.contains("UnknownMethod") || s.contains("UnknownObject")
}

fn native(kind: &str, start: &str, title: &str) -> Result<Vec<PathBuf>, i32> {
    let conn = Connection::session().map_err(|e| {
        errln!("No file chooser is available: {}", describe(&e));
        2
    })?;
    trap_signals();
    let result = match via_nautilus(&conn, kind, start, title) {
        Ok(paths) => Ok(paths),
        Err(e) if !absent(&e) => {
            errln!("The file chooser failed: {}", describe(&e));
            Err(2)
        }
        Err(_) => via_portal(&conn, kind, start, title).map_err(|e| {
            errln!("No file chooser is available: {}", describe(&e));
            2
        }),
    };
    untrap_forget();
    result
}

type Answer = zbus::Result<Option<Vec<PathBuf>>>;

/// Wait for the chooser's answer. A panel that goes away (the shell reloads,
/// or its Process is killed) must not leave a chooser on screen whose answer
/// nobody is waiting for: TERM, INT or HUP closes it, and is a cancel.
fn wait_answer(
    conn: &Connection,
    dest: &str,
    handle: &str,
    rx: &mpsc::Receiver<Answer>,
) -> zbus::Result<Vec<PathBuf>> {
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(answer) => return answer.map(Option::unwrap_or_default),
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(Vec::new()),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if caught().is_some() {
            let iface = if dest == NAUTILUS {
                "org.freedesktop.impl.portal.Request"
            } else {
                "org.freedesktop.portal.Request"
            };
            let (conn2, dest, handle) = (conn.clone(), dest.to_string(), handle.to_string());
            let (done_tx, done_rx) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = conn2.call_method(
                    Some(dest.as_str()),
                    handle.as_str(),
                    Some(iface),
                    "Close",
                    &(),
                );
                let _ = done_tx.send(());
            });
            let _ = done_rx.recv_timeout(Duration::from_millis(2000));
            let until = Instant::now() + Duration::from_millis(500);
            while Instant::now() < until {
                if rx.recv_timeout(Duration::from_millis(50)).is_ok() {
                    break;
                }
            }
            return Ok(Vec::new());
        }
    }
}

fn via_nautilus(
    conn: &Connection,
    kind: &str,
    start: &str,
    title: &str,
) -> zbus::Result<Vec<PathBuf>> {
    let handle = format!("{PORTAL_PATH}/request/1_1/omdrop_{}", std::process::id());
    let path = ObjectPath::try_from(handle.clone())?;
    let opts = options(kind, start);
    let (tx, rx) = mpsc::channel::<Answer>();
    let conn2 = conn.clone();
    let title2 = title.to_string();
    std::thread::spawn(move || {
        let answer = conn2
            .call_method(
                Some(NAUTILUS),
                PORTAL_PATH,
                Some(IMPL),
                "OpenFile",
                &(path, APP_ID, "", title2.as_str(), opts),
            )
            .and_then(|reply| {
                let (response, results): (u32, HashMap<String, OwnedValue>) =
                    reply.body().deserialize()?;
                Ok((response == 0).then(|| paths_of(&results)))
            });
        let _ = tx.send(answer);
    });
    present_when_mapped(title);
    wait_answer(conn, NAUTILUS, &handle, &rx)
}

fn via_portal(
    conn: &Connection,
    kind: &str,
    start: &str,
    title: &str,
) -> zbus::Result<Vec<PathBuf>> {
    let token = format!("omdrop_{}", std::process::id());
    let sender = conn
        .unique_name()
        .map(|n| n.as_str().trim_start_matches(':').replace('.', "_"))
        .unwrap_or_default();
    let handle = format!("{PORTAL_PATH}/request/{sender}/{token}");
    // Subscribed before the call, at the path the portal will use, so a
    // quick answer cannot arrive before anyone is listening.
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.portal.Request")?
        .member("Response")?
        .path(handle.clone())?
        .build();
    let responses = zbus::blocking::MessageIterator::for_match_rule(rule, conn, Some(8))?;
    let (tx, rx) = mpsc::channel::<Answer>();
    let tx2 = tx.clone();
    std::thread::spawn(move || {
        let mut responses = responses;
        if let Some(msg) = responses.next() {
            let answer = msg.and_then(|m| {
                let (response, results): (u32, HashMap<String, OwnedValue>) =
                    m.body().deserialize()?;
                Ok((response == 0).then(|| paths_of(&results)))
            });
            let _ = tx2.send(answer);
        }
    });
    let mut opts = options(kind, start);
    opts.insert("handle_token", Value::from(token));
    let (call_tx, call_rx) = mpsc::channel();
    let conn2 = conn.clone();
    let title2 = title.to_string();
    std::thread::spawn(move || {
        let r = conn2.call_method(
            Some(PORTAL),
            PORTAL_PATH,
            Some("org.freedesktop.portal.FileChooser"),
            "OpenFile",
            &("", title2.as_str(), opts),
        );
        let _ = call_tx.send(r.map(|_| ()));
    });
    match call_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Err(e)) => {
            let _ = tx.send(Err(e));
        }
        Ok(Ok(())) => {}
        Err(_) => {
            let _ = tx.send(Err(zbus::Error::Failure("Timeout was reached".into())));
        }
    }
    present_when_mapped(title);
    wait_answer(conn, PORTAL, &handle, &rx)
}

fn hyprctl(args: &[&str]) -> Option<String> {
    let mut child = Command::new("hyprctl")
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let mut out = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = std::io::Read::read_to_end(&mut out, &mut s);
        s
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    reader
        .join()
        .ok()
        .map(|s| String::from_utf8_lossy(&s).into_owned())
}

/// One Hyprland dispatch: the Lua config's form first, then the classic one.
fn hypr_dispatch(lua: &str, classic: &[&str]) {
    let ok = hyprctl(&["dispatch", lua]).is_some_and(|o| o.trim() == "ok");
    if !ok && !classic.is_empty() {
        let mut a = vec!["dispatch"];
        a.extend(classic);
        hyprctl(&a);
    }
}

/// Put the chooser in front, as a dialog: floating, centred, focused. A
/// chooser opened from the panel carries no parent window and no activation
/// token, so Hyprland tiled it beside whatever was open and gave it no
/// focus (measured 2026-09-23). Wait for the window with our title, then
/// the same dispatches omarchy-hyprland-window-pop uses. Anywhere else this
/// does nothing, and the compositor's own policy stands.
fn present_when_mapped(title: &str) {
    if crate::util::env_nonempty("HYPRLAND_INSTANCE_SIGNATURE").is_none()
        || !crate::util::have("hyprctl")
    {
        return;
    }
    let title = title.to_string();
    std::thread::spawn(move || {
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));
            let parse = |args: &[&str], empty: &str| -> Option<serde_json::Value> {
                let out = hyprctl(args)?;
                let text = if out.is_empty() {
                    empty.to_string()
                } else {
                    out
                };
                serde_json::from_str(&text).ok()
            };
            let (Some(clients), Some(active), Some(monitors)) = (
                parse(&["clients", "-j"], "[]"),
                parse(&["activeworkspace", "-j"], "{}"),
                parse(&["monitors", "-j"], "[]"),
            ) else {
                return;
            };
            let Some(win) = clients.as_array().and_then(|cs| {
                cs.iter()
                    .find(|c| c.get("title").and_then(|t| t.as_str()) == Some(title.as_str()))
            }) else {
                continue;
            };
            let w = format!(
                "address:{}",
                win.get("address").and_then(|a| a.as_str()).unwrap_or("")
            );
            // Two thirds of the screen, within a dialog's sensible bounds.
            let mons = monitors.as_array().cloned().unwrap_or_default();
            let mon = mons
                .iter()
                .find(|m| m.get("id").is_some() && m.get("id") == active.get("monitorID"))
                .or(mons.first())
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let num = |k: &str, d: f64| {
                mon.get(k)
                    .and_then(serde_json::Value::as_f64)
                    .filter(|v| *v != 0.0)
                    .unwrap_or(d)
            };
            let scale = num("scale", 1.0);
            let (sw, sh) = (num("width", 1600.0) / scale, num("height", 1000.0) / scale);
            let width = (sw * 0.6).clamp(720.0, 1100.0) as i64;
            let height = (sh * 0.66).clamp(520.0, 800.0) as i64;
            if !win
                .get("floating")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                hypr_dispatch(
                    &format!("hl.dsp.window.float({{ window = \"{w}\", action = \"toggle\" }})"),
                    &["togglefloating", &w],
                );
            }
            hypr_dispatch(
                &format!("hl.dsp.window.resize({{ window = \"{w}\", x = {width}, y = {height} }})"),
                &["resizewindowpixel", &format!("exact {width} {height},{w}")],
            );
            hypr_dispatch(
                &format!("hl.dsp.window.center({{ window = \"{w}\" }})"),
                &["centerwindow", &w],
            );
            hypr_dispatch(
                &format!("hl.dsp.window.alter_zorder({{ window = \"{w}\", mode = \"top\" }})"),
                &["alterzorder", &format!("top,{w}")],
            );
            hypr_dispatch(
                &format!("hl.dsp.focus({{ window = \"{w}\" }})"),
                &["focuswindow", &w],
            );
            return;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn file_uris_become_local_paths() {
        assert_eq!(
            file_uri_path("file:///home/u/a%20b.jpg"),
            Some(PathBuf::from("/home/u/a b.jpg"))
        );
        assert_eq!(
            file_uri_path("file://host/home/u/x%0Ay"),
            Some(PathBuf::from("/home/u/x\ny"))
        );
        assert_eq!(
            file_uri_path("file:///a%23b?q#f"),
            Some(PathBuf::from("/a#b"))
        );
        assert_eq!(
            file_uri_path("file:///bad%zz%2"),
            Some(PathBuf::from("/bad%zz%2"))
        );
        assert_eq!(file_uri_path("sftp://host/x"), None);
        let bytes = file_uri_path("file:///caf%C3%A9-%FF").unwrap();
        assert_eq!(bytes.as_os_str().as_bytes(), b"/caf\xc3\xa9-\xff");
    }
}
