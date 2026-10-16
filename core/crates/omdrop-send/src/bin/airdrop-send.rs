//! `airdrop-send`: see [`omdrop_send::airdrop_send`].

fn main() {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    std::process::exit(omdrop_send::airdrop_send::main(&args));
}
