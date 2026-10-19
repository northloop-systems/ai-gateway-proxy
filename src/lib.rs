//! ai-gateway-proxy: a proxy node for the AI Gateway.
//!
//! The node lends its machine's addresses to the gateway. It reaches the
//! hub over a WireGuard tunnel, and it offers three ways out: a Tor exit, a
//! Cloudflare WARP exit, and its own address. The hub picks one per
//! request, and the node's owner is the one whose address it is.
//!
//! Everything is in small modules: `log`, `run`, `fs_util`, `cli`,
//! `os_info`, `hub/`, `socks5/`, `install/`, `uninstall/`, `watchdog/`.
//!
//! There are no dependencies. This program runs as root on a machine that
//! belongs to somebody else, so every crate in the tree would be code the
//! node's owner did not read and cannot easily audit. The only things it
//! trusts are the Rust standard library and the system's own curl.

pub mod cli;
pub mod fs_util;
pub mod hub;
pub mod install;
pub mod log;
pub mod os_info;
pub mod run;
pub mod socks5;
pub mod status;
pub mod uninstall;
pub mod watchdog;
