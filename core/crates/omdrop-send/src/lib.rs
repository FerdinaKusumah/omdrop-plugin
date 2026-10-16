//! The Omdrop AirDrop sender: the library behind `airdrop-send` (drop-in for
//! omdrop-awdl's `airdrop-send.py`) and `send-to-peer` (drop-in for its
//! `send-to-peer`).
//!
//! - [`client`]: /Discover, /Ask and /Upload over one keep-alive TLS
//!   connection per receiver ([`http`]).
//! - [`airdrop_send`] and [`send_to_peer`]: the two programs' command lines,
//!   output and exit codes; [`peer_env`] is send-to-peer's real surroundings.
//! - [`mdns`], [`aflog`]: the two discovery paths besides `--direct`.

pub mod aflog;
pub mod airdrop_send;
pub mod args;
pub mod client;
pub mod error;
pub mod http;
pub mod icon;
pub mod log;
pub mod mdns;
pub mod peer_env;
pub mod pyfmt;
pub mod send_to_peer;
