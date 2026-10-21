//! What the operator is told at the end of the install.
//!
//! The install prints a lot while it works. This is the part that is read
//! afterwards, and it is the only part that says what the node can
//! actually do - so it checks rather than assumes.

use crate::install::systemd;
use crate::install::warp;
use crate::log;

pub struct Summary {
    pub node_name: String,
    pub assigned_ip: String,
    pub public_ip: String,
    pub ports: crate::install::ExitPorts,
    pub warp_available: bool,
    pub warp_mode: warp::Mode,
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
    if summary.warp_available && summary.warp_mode.offers_warp_exit() {
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
    if summary.warp_available {
        match summary.warp_mode {
            warp::Mode::Proxy => {
                log::plain("  WARP: proxy mode - it serves the node a port, and the machine's");
                log::plain("        own traffic stays where it is.");
            }
            warp::Mode::Tunnel => {
                log::plain("  WARP: tunnel mode - the machine's traffic AND its DNS go through");
                log::plain("        it. The node's own address IS the WARP address, so there is");
                log::plain("        no separate WARP exit.");
            }
        }
    }
    let exits = if summary.warp_available && summary.warp_mode.offers_warp_exit() {
        "3 egress IPs: Tor exit, WARP exit, node's own IP"
    } else {
        "2 egress IPs: Tor exit, node's own IP"
    };
    log::plain(&format!("  Provides up to {exits}"));
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
