//! What the operator is told at the end of the install.
//!
//! The install prints a lot while it works. This is the part that is read
//! afterwards, and it is the only part that says what the node can
//! actually do - so it checks rather than assumes.

use crate::install::systemd;
use crate::log;

pub struct Summary {
    pub node_name: String,
    pub assigned_ip: String,
    pub public_ip: String,
    pub ports: crate::install::ExitPorts,
    pub warp_available: bool,
    pub hub_ip: String,
}

pub fn print(summary: &Summary) {
    log::plain("");
    log::plain("==========================================");
    log::plain("  Proxy Node");
    log::plain("==========================================");
    log::plain("");
    log::plain(&format!("  Node name:     {}", summary.node_name));
    log::plain(&format!("  Public IP:     {}", summary.public_ip));
    log::plain(&format!(
        "  Tor SOCKS5:    {}:{}  ({})",
        summary.assigned_ip,
        summary.ports.tor,
        state_of("proxy-tor-redirect")
    ));
    if summary.warp_available {
        log::plain(&format!(
            "  WARP SOCKS5:   {}:{}  ({})",
            summary.assigned_ip,
            summary.ports.warp,
            state_of("proxy-warp-redirect")
        ));
    }
    log::plain(&format!(
        "  Direct SOCKS5: {}:{}  ({})",
        summary.assigned_ip,
        summary.ports.direct,
        state_of("proxy-socks5")
    ));
    log::plain(&format!("  WireGuard:     ({})", state_of("wg-quick@wg0")));
    log::plain("");
    log::plain("  Provides up to 3 egress IPs: Tor exit, WARP exit, node's own IP");
    log::plain("  Connection: WireGuard VPN (encrypted, authenticated, keypair only)");
    log::plain("");
    log::plain("  The hub can open connections to any destination through this node,");
    log::plain("  including via Tor and WARP. The direct proxy additionally restricts");
    log::plain("  connections to public hosts on port 443.");
    log::plain("");
    log::plain(&format!("  WireGuard IP: {}", summary.assigned_ip));
    log::plain("");
}

fn state_of(unit: &str) -> &'static str {
    if systemd::is_active(unit) {
        "OK"
    } else {
        "not running"
    }
}
