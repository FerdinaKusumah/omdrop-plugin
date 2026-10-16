//! `send-to-peer`: see [`omdrop_send::send_to_peer`].

use omdrop_send::peer_env::{RealEnv, install_signal_handling, prefer_legacy_checked};

fn main() {
    if let Err(e) = prefer_legacy_checked() {
        eprintln!("send-to-peer: {e}");
        std::process::exit(2);
    }
    // Before any thread exists: the signal watcher must be the only taker.
    install_signal_handling();
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let env = RealEnv::default();
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let code = omdrop_send::send_to_peer::main(&env, &args, &mut out, &mut err);
    std::process::exit(code);
}
