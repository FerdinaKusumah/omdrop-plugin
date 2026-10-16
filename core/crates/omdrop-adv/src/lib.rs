//! Omdrop advertisers: the BLE wake advert, the AWDL mDNS responder and the
//! AWDL `_airdrop` announcements, plus the host helpers they share with the
//! radio supervisor (`host`).
//!
//! The binary `omdrop-adv` runs one of them per process:
//!
//! - `omdrop-adv ble`      replaces `ble-airdrop-adv.py`
//! - `omdrop-adv mdns`     replaces `awdl-mdns-respond.py`
//! - `omdrop-adv announce` replaces `awdl-airdrop-adv.py`
//!
//! each with its predecessor's argv and output lines.

pub mod args;
pub mod ble;
pub mod cli;
pub mod clock;
pub mod frames;
pub mod host;
pub mod mdns;
pub mod rawsock;

pub use host::{awdl_host, awdl_iface, conf_dir, infra_iface, infra_mac, knob, mac_of, switch};
