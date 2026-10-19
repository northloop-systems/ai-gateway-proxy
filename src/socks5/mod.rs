//! The node's own SOCKS5 proxy.
//!
//! One of the node's three ways out: the address the node itself has,
//! reached through a SOCKS5 proxy the hub can open connections through. It
//! is the exit that needs no extra program on the node, so it is the one
//! that is always there.
//!
//! The proxy is small and it is strict, because here the hub's security and
//! the node's security are the same thing: the gateway connects to
//! destinations *through* the node, so what the node refuses to forward is
//! what the gateway cannot reach. The node is a machine that belongs to
//! somebody else, and the things it must never forward to are the things on
//! that machine.
//!
//! - `auth` - the username and password exchange (RFC 1929), the only way in
//! - `filter` - which destinations may be reached at all
//! - `server` - the listener, the handshake and the relay

pub mod auth;
pub mod filter;
pub mod server;

use crate::cli::ServeOptions;

/// Run the proxy until it is stopped. Returns an error only when the
/// listener could not be started.
pub fn serve(options: &ServeOptions) -> Result<(), String> {
    server::serve(server::Config {
        listen_addr: listen_addr(&options.listen_addr),
        listen_port: options.listen_port,
        username: options.username.clone(),
        password: options.password.clone(),
        hub_ip: options.hub_ip.clone(),
    })
}

/// Where to listen when nobody said. Loopback, like the Python proxy this
/// replaces: a proxy nobody asked to expose should not end up on every
/// interface of the machine.
fn listen_addr(given: &str) -> String {
    if given.is_empty() {
        "127.0.0.1".to_string()
    } else {
        given.to_string()
    }
}
