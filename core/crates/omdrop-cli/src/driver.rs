//! What is still missing before this can receive (`doctor`, `setup`'s
//! closing list), installing the driver in a terminal the person watches,
//! and the one firewall rule Omdrop needs.

use std::path::Path;

use serde::Serialize;

use crate::ctx::ctx;
use crate::identity::{Out, id};
use crate::proc::{capture, run, run_quiet};
use crate::util::{die, have, home, is_executable, py_json, shell_quote};

const DRIVER_REPO: &str = "https://github.com/netmojo-systems/omdrop-awdl.git";
/// The package name a repository would carry it under, and the fallback source.
pub const DRIVER_PKG: &str = "brcmfmac-awdl-dkms";
/// The exact driver commit this release builds: the full 40 characters,
/// because a short SHA is not a pin, and a branch would let the built source
/// drift away from what anyone reviewed. It also appears literally in the
/// build script below, because a baseline scanner cannot resolve a variable;
/// a test keeps the two equal.
pub const DRIVER_COMMIT: &str = "fe05b2c575db063c388abb0c31c840c03b1b6412";
/// The package version that commit builds. install-driver rebuilds any older
/// installed driver: a fix inside the helper changes nothing a feature probe
/// could see.
const DRIVER_VERSION: &str = "0.9.3";
/// The first driver whose sender, send-to-peer and advertiser follow the
/// identity contract. Moving the identity into 1Password needs it.
const DRIVER_IDENTITY_VERSION: &str = "0.7.0";
/// The Python receiver's one outside import, and the kernel keyring library
/// it reads the 1Password identity cache through.
const RECEIVER_PKGS: &str = "python-libarchive-c keyutils";

/// UFW's default-drop policy sees AirDrop's TCP after the AWDL data path has
/// done its job, so a healthy radio can advertise while every SYN is
/// discarded. This is the only exception Omdrop needs: IPv6 link-local
/// peers, to our link-local address, on awdl0, TCP 8771.
const UFW_RULE: [&str; 14] = [
    "allow",
    "in",
    "on",
    "awdl0",
    "from",
    "fe80::/10",
    "to",
    "fe80::/10",
    "port",
    "8771",
    "proto",
    "tcp",
    "comment",
    "Omdrop AirDrop receiver",
];

/// awdl0 carrying an IPv6 link-local address: the only address AirDrop
/// traffic is sent from or to. Without it there is nothing to send over and
/// nothing to bind.
pub fn awdl_link_local() -> bool {
    let (_, out) = capture(
        "ip",
        &["-6", "addr", "show", "dev", "awdl0", "scope", "link"],
    );
    String::from_utf8_lossy(&out).contains("inet6")
}

/// What the receiver needs installed. The core receiver needs nothing; the
/// Python one needs its archive library, probed by the API it calls, and
/// libkeyutils.
pub fn receiver_libs_installed() -> bool {
    if ctx().receiver.is_some() {
        return true;
    }
    run_quiet("python3", &["-c", "from libarchive import stream_reader"]) == 0
        && Path::new("/usr/lib/libkeyutils.so.1").exists()
}

/// Broadcom (vendor 0x14e4) network hardware on PCI, where Apple's Wi-Fi
/// sits on Apple Silicon. A VM such as Try Omarchy has no AWDL-capable radio.
pub fn apple_broadcom_wifi() -> bool {
    let Ok(entries) = std::fs::read_dir("/sys/bus/pci/devices") else {
        return false;
    };
    entries.flatten().any(|e| {
        let read = |n: &str| crate::util::read_trimmed(&e.path().join(n)).unwrap_or_default();
        read("vendor") == "0x14e4" && read("class").starts_with("0x0280")
    })
}

/// The installed driver package's version, from pacman.
fn installed_driver() -> Option<String> {
    let (code, out) = capture("pacman", &["-Q", DRIVER_PKG]);
    if code != 0 {
        return None;
    }
    let text = crate::util::strip_trailing_newlines(&String::from_utf8_lossy(&out)).to_string();
    Some(text.rsplit(' ').next().unwrap_or_default().to_string())
}

fn vercmp(a: &str, b: &str) -> Option<i64> {
    let (_, out) = capture("vercmp", &[a, b]);
    String::from_utf8_lossy(&out).trim().parse().ok()
}

/// Whether the installed driver is at least the one this release pins.
/// Read from pacman, because a helper fix is invisible from outside it.
pub fn driver_current() -> bool {
    installed_driver()
        .and_then(|v| vercmp(&v, DRIVER_VERSION))
        .is_some_and(|c| c >= 0)
}

/// Moving the Apple identity off disk needs a driver whose sender follows the
/// identity contract: an older one finds certificate.pem missing and makes a
/// self-signed pair under the Apple identity's names.
pub fn driver_identity_ready() {
    let installed = installed_driver().unwrap_or_default();
    let too_old =
        installed.is_empty() || vercmp(&installed, DRIVER_IDENTITY_VERSION).is_some_and(|c| c < 0);
    if too_old {
        let shown = if installed.is_empty() {
            "none"
        } else {
            &installed
        };
        die(format!(
            "Keeping the identity in 1Password needs driver {DRIVER_IDENTITY_VERSION} or newer (installed: {shown}). Update it with: omdrop install-driver"
        ));
    }
}

/// What is missing, in the order it has to be fixed, one "id<TAB>sentence"
/// line each: the id is for the panel, which offers to fix the one thing it
/// can, and the sentence is for someone holding a laptop.
pub fn prereqs_missing() -> Vec<(&'static str, String)> {
    let mut missing = Vec::new();
    // First, and alone: nothing else on this list can be fixed here.
    if !apple_broadcom_wifi() {
        missing.push((
            "hardware",
            "This computer has no Apple Broadcom Wi-Fi, which AirDrop needs. Omdrop runs only on Apple Silicon Macs, not in a virtual machine.".to_string(),
        ));
        return missing;
    }
    if !receiver_libs_installed() {
        missing.push((
            "library",
            format!("Packages the receiver needs ({RECEIVER_PKGS}) are not installed. The button below installs them along with the driver."),
        ));
    }
    if !is_executable(&ctx().discoverable) {
        missing.push((
            "driver",
            "The Wi-Fi driver that makes this computer visible to Apple devices is not installed. It has to be installed as an administrator.".to_string(),
        ));
    } else if !Path::new("/sys/class/net/awdl0").exists() {
        missing.push((
            "radio",
            "The driver is installed but its Apple-compatible radio is not running yet, so nobody can see this computer. Restarting usually brings it up.".to_string(),
        ));
    }
    if !crate::status::have_unit() {
        missing.push((
            "service",
            "The service that receives files is not installed yet. Turning Omdrop on installs it."
                .to_string(),
        ));
    }
    missing
}

#[derive(Serialize)]
struct Missing<'a> {
    id: &'a str,
    say: &'a str,
}

#[derive(Serialize)]
struct Doctor<'a> {
    ready: bool,
    missing: Vec<Missing<'a>>,
}

/// The panel's version of `setup`'s answer: --json so the widget can render
/// the first blocking sentence and know whether it can offer the fix.
pub fn cmd_doctor(args: &[String]) -> i32 {
    let missing = prereqs_missing();
    if args.first().is_some_and(|a| a == "--json") {
        let d = Doctor {
            ready: missing.is_empty(),
            missing: missing
                .iter()
                .map(|(id, say)| Missing { id, say })
                .collect(),
        };
        outln!("{}", py_json(&d));
        return 0;
    }
    if missing.is_empty() {
        outln!("Ready to receive.");
    } else {
        outln!("Not ready to receive yet:");
        for (_, say) in &missing {
            outln!("  - {say}");
        }
    }
    // Which identity Apple devices will see, and anything left behind.
    // Reported, never repaired here: `omdrop off` is what clears a window.
    outln!();
    if id(&["status"], Out::Inherit, false).code != 0 {
        outln!("The identity could not be read.");
    }
    if ctx().window_file().exists() && !crate::status::receiving() {
        outln!(
            "A window's identity file remains although nothing is receiving. Clear it with: omdrop off"
        );
    }
    0
}

fn ufw_active() -> bool {
    have("ufw") && run_quiet("systemctl", &["is-active", "--quiet", "ufw.service"]) == 0
}

/// The DKMS package deliberately does not own this rule: it supplies a radio
/// other AWDL applications can use, and opening an application port belongs
/// to the application.
pub fn cmd_firewall(args: &[String]) -> i32 {
    match args.first().map(String::as_str).unwrap_or("") {
        "install" => {
            if !have("ufw") {
                outln!("UFW is not installed; no UFW rule is needed.");
                return 0;
            }
            if run_quiet("systemctl", &["is-active", "--quiet", "ufw.service"]) != 0 {
                outln!("UFW is not active; Omdrop did not change its configuration.");
                return 0;
            }
            outln!(
                "Allowing AirDrop receiver traffic only on awdl0, from IPv6 link-local peers, to TCP 8771."
            );
            let mut a = vec!["ufw"];
            a.extend(UFW_RULE);
            run("sudo", &a)
        }
        "remove" => {
            if !have("ufw") {
                outln!("UFW is not installed; there is no Omdrop UFW rule to remove.");
                return 0;
            }
            let mut a = vec!["ufw", "--force", "delete"];
            a.extend(UFW_RULE);
            run("sudo", &a)
        }
        _ => die("usage: omdrop firewall install|remove"),
    }
}

/// The script install-driver shows or runs: the receiver's packages from the
/// official repositories by exact name, the driver from a repository when
/// one carries it, else built from the pinned commit, and the firewall rule
/// in the same terminal so sudo reuses the authentication.
pub fn build_script(
    self_q: &str,
    libs_missing: bool,
    driver_needed: bool,
    repo_has_driver: bool,
    ufw: bool,
) -> String {
    let src = format!(
        "{}/omdrop/omdrop-awdl",
        crate::util::env_nonempty("XDG_CACHE_HOME").unwrap_or_else(|| format!("{}/.cache", home()))
    );
    let mut build = String::from("set -e");
    if libs_missing {
        // --needed leaves an installed copy alone; --asdeps because it is
        // there for Omdrop, not something the user asked for by name.
        build.push_str(&format!(
            "\nsudo pacman -S --needed --asdeps {RECEIVER_PKGS}"
        ));
    }
    if driver_needed {
        if repo_has_driver {
            build.push_str(&format!(
                "\nsudo pacman -S --needed --noconfirm {DRIVER_PKG}"
            ));
        } else {
            // Into the cache directory, not a temp dir: the person keeps the
            // source they built as root, /tmp is RAM on this hardware, and a
            // later version is a pull rather than a fresh clone.
            build.push_str(&format!(
                "\nmkdir -p \"$(dirname '{src}')\"\nif [ -d '{src}/.git' ]; then\n  git -C '{src}' fetch --quiet origin\nelse\n  git clone --quiet {DRIVER_REPO} '{src}'\nfi\necho 'Building driver commit {DRIVER_COMMIT}'\ngit -C '{src}' checkout --detach fe05b2c575db063c388abb0c31c840c03b1b6412 && makepkg --dir '{src}' -si"
            ));
        }
    }
    if ufw {
        build.push_str(&format!("\n{self_q} firewall install"));
    }
    build
}

/// Installing a kernel module is not something a bar widget may do quietly:
/// Omarchy's own pattern is a floating terminal running the command, the
/// user's own sudo prompt, all output visible -- not pkexec'ing a build
/// script out of a plugin clone, which would be root running user-writable code.
pub fn cmd_install_driver() -> i32 {
    let c = ctx();
    let self_q = shell_quote(&c.command_path().to_string_lossy());
    let helper = is_executable(&c.discoverable);
    if helper && driver_current() && receiver_libs_installed() {
        outln!(
            "The driver and the Python library the receiver needs are both installed and current. Nothing to do."
        );
        return 0;
    }
    if !apple_broadcom_wifi() {
        die(
            "This computer has no Apple Broadcom Wi-Fi, so the driver cannot do anything here. Omdrop runs only on Apple Silicon Macs, not in a virtual machine.",
        );
    }
    let libs_missing = !receiver_libs_installed();
    let driver_needed = !helper || !driver_current();
    // `pacman -Si` reads the sync databases already on disk and deliberately
    // does not refresh them: -Sy alone is how partial upgrades happen.
    let repo_has_driver = driver_needed && run_quiet("pacman", &["-Si", DRIVER_PKG]) == 0;
    let build = build_script(
        &self_q,
        libs_missing,
        driver_needed,
        repo_has_driver,
        ufw_active(),
    );
    const INTRO: &str = "Omdrop requires a patched wifi driver, which requires administrative privilege to install. You will be prompted for your password.";
    if !have("omarchy-launch-floating-terminal-with-presentation") {
        outln!("{INTRO}");
        outln!();
        outln!("Install the driver with:");
        outln!("\n{build}\n");
        return 0;
    }
    outln!("Opening a terminal to install the driver.");
    // A subshell, so a failed step ends the script and not the terminal, and
    // tested on its own line, not with `||`: bash ignores `set -e` inside a
    // subshell whose status a `||` is testing. Exit 130 skips the launcher's
    // "Done!", which a failure should not show.
    let script = format!(
        "( {build}\n); rc=$?; if [ $rc -ne 0 ]; then echo; echo \"Installing failed (exit $rc). The messages above say why.\"; read -rsn 1 -p 'Press any key to close...' </dev/tty; echo; exit 130; fi"
    );
    run(
        "omarchy-launch-floating-terminal-with-presentation",
        &[format!("echo '{INTRO}'; echo; {script}")],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_commit_is_a_full_sha_used_literally() {
        assert_eq!(DRIVER_COMMIT.len(), 40);
        assert!(
            DRIVER_COMMIT
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        let script = build_script("omdrop", true, true, false, true);
        assert!(
            script.contains(&format!("checkout --detach {DRIVER_COMMIT} && makepkg")),
            "{script}"
        );
        for line in script.lines().filter(|l| l.contains("makepkg")) {
            assert!(
                line.contains(&format!("checkout --detach {DRIVER_COMMIT} && makepkg")),
                "{line}"
            );
        }
    }

    #[test]
    fn packages_come_from_the_official_repositories_and_the_rule_comes_last() {
        let script = build_script("/usr/bin/omdrop", true, true, true, true);
        assert!(
            script
                .lines()
                .any(|l| l == "sudo pacman -S --needed --asdeps python-libarchive-c keyutils")
        );
        assert!(
            !script.contains("yay")
                && !script.contains("paru")
                && !script.contains("aur.archlinux.org")
        );
        assert!(script.find("sudo pacman").unwrap() < script.find("firewall install").unwrap());
        assert!(!script.contains("makepkg"));
    }
}
