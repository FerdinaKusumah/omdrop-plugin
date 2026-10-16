//! `omdrop-adv ble|mdns|announce ARGS...`: one advertiser per process.

const USAGE: &str = "usage: omdrop-adv {ble,mdns,announce} [options]\n\n  \
ble       BLE Continuity AirDrop advert (ble-airdrop-adv.py)\n  \
mdns      awdl0 mDNS responder (awdl-mdns-respond.py)\n  \
announce  AWDL _airdrop._tcp announcements (awdl-airdrop-adv.py)\n\n\
'omdrop-adv COMMAND --help' lists a command's options.\n";

fn main() {
    let mut args = Vec::new();
    for arg in std::env::args_os().skip(1) {
        match arg.into_string() {
            Ok(a) => args.push(a),
            Err(bad) => {
                eprintln!("{USAGE}omdrop-adv: error: argument is not UTF-8: {bad:?}");
                std::process::exit(2);
            }
        }
    }
    let (cmd, rest) = match args.split_first() {
        Some((cmd, rest)) => (cmd.as_str(), rest),
        None => ("", &[][..]),
    };
    let code = match cmd {
        "ble" => omdrop_adv::cli::ble(rest),
        "mdns" => omdrop_adv::cli::mdns_respond(rest),
        "announce" => omdrop_adv::cli::announce(rest),
        "-h" | "--help" => {
            print!("{USAGE}");
            0
        }
        _ => {
            eprint!("{USAGE}");
            2
        }
    };
    std::process::exit(code);
}
