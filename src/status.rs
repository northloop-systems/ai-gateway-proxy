//! `ai-gateway-proxy status` - what is working and what is not.
//!
//! For the person who lent the machine, who wants to know whether it is
//! still doing its job without reading logs. Everything here is a question
//! with a yes or no answer, and the answers are about the machine, not
//! about the hub.

use crate::fs_util;
use crate::install::systemd;
use crate::log;
use crate::run;

const STATE_DIR: &str = "/opt/proxy-node";

pub fn run() -> Result<(), String> {
    let installed = std::path::Path::new("/usr/local/bin/ai-gateway-proxy").exists();
    log::plain(&format!("  Installed:   {}", yes_no(installed)));

    let node_name = read_state("node_name");
    log::plain(&format!(
        "  Node:        {}",
        node_name
            .clone()
            .unwrap_or_else(|| "not registered".to_string())
    ));

    let tunnel = systemd::is_active("wg-quick@wg0");
    log::plain(&format!("  Tunnel:      {}", yes_no(tunnel)));

    for (label, unit) in [
        ("Tor exit:", "proxy-tor-redirect"),
        ("WARP exit:", "proxy-warp-redirect"),
        ("Direct exit:", "proxy-socks5"),
    ] {
        log::plain(&format!(
            "  {label}    {}",
            yes_no(systemd::is_active(unit))
        ));
    }

    // The watchdog: is it even installed, and did it last have anything
    // to do? A node whose tunnel keeps flapping is a node the owner
    // should know about.
    log::plain(&format!(
        "  Watchdog:    {}",
        yes_no(systemd::is_active("proxy-tunnel-watchdog.timer"))
    ));
    if let Some(last) = run::capture(
        "journalctl",
        &[
            "-u",
            "proxy-tunnel-watchdog.service",
            "-n",
            "1",
            "--no-pager",
        ],
    ) {
        let line = last.lines().last().unwrap_or("").trim();
        if !line.is_empty() {
            log::plain(&format!("  Last check:  {line}"));
        }
    }

    // The exits, from the hub's point of view: can they be reached?
    if let Some(address) = read_state("wg_ip") {
        log::plain(&format!("  Tunnel address: {address}"));
    }
    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "running"
    } else {
        "not running"
    }
}

fn read_state(name: &str) -> Option<String> {
    let path = std::path::Path::new(STATE_DIR).join(name);
    let text = fs_util::read_to_string(&path)?;
    let trimmed = text.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}
