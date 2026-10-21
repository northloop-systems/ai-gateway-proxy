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
        match &node_name {
            Some(name) => name.clone(),
            // "not registered" is a statement about the node, and it is
            // wrong for anyone who cannot read the state: the state holds
            // the SOCKS password, so it is root-only, and a plain `status`
            // from the person's own account reads nothing. Saying
            // "not registered" sends them hunting a problem that is not
            // there.
            None => match state_unreadable() {
                true => "unknown (the state is root-only: run status as root)".to_string(),
                false => "not registered".to_string(),
            },
        }
    ));

    let tunnel = systemd::is_active("wg-quick@wg0");
    log::plain(&format!("  Tunnel:      {}", yes_no(tunnel)));

    for (label, unit) in [
        ("Tor exit:", "proxy-tor-redirect"),
        ("Direct exit:", "proxy-socks5"),
    ] {
        log::plain(&format!(
            "  {label}    {}",
            yes_no(systemd::is_active(unit))
        ));
    }

    // The WARP mode, because in tunnel mode there is no WARP exit to
    // report: the machine's own address is the WARP address. Saying
    // "WARP exit: no" there would look like a fault, and it is not one -
    // it is what the owner asked for.
    //
    // The node's own choice is read first, and the machine's ACTUAL mode
    // is the fallback, because the state file is root-only and the person
    // who lent the machine is not root.
    let warp_mode = crate::install::warp::persisted_node_mode().or_else(|| {
        crate::install::warp::current_mode().and_then(|m| crate::install::warp::Mode::parse(&m))
    });
    match warp_mode {
        Some(crate::install::warp::Mode::Proxy) => {
            log::plain(
                "  WARP mode:   proxy (the node's own WARP port; the machine's traffic stays put)",
            );
            log::plain(&format!(
                "  WARP exit:   {}",
                yes_no(systemd::is_active("proxy-warp-redirect"))
            ));
        }
        Some(crate::install::warp::Mode::Tunnel) => {
            log::plain("  WARP mode:   tunnel (the machine's traffic and its DNS go through WARP)");
        }
        None => {
            log::plain("  WARP mode:   unknown (warp-cli is not installed, or said nothing)");
        }
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
    read_state_in(STATE_DIR, name)
}

fn read_state_in(dir: &str, name: &str) -> Option<String> {
    let path = std::path::Path::new(dir).join(name);
    let text = fs_util::read_to_string(&path)?;
    let trimmed = text.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// True when the state directory is there but cannot be read.
///
/// The state holds the SOCKS password, so it is root-only on purpose. A
/// status run by the person who lent the machine cannot read it, and
/// "not registered" would be a lie about the node.
fn state_unreadable() -> bool {
    state_unreadable_in(STATE_DIR)
}

fn state_unreadable_in(dir: &str) -> bool {
    let dir = std::path::Path::new(dir);
    dir.exists() && fs_util::read_to_string(&dir.join("node_name")).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ai-gateway-proxy-status-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn a_state_that_names_a_node_is_read() {
        let dir = temp_dir("named");
        let path = dir.join("node_name");
        std::fs::write(&path, "laptop\n").unwrap();
        assert_eq!(
            read_state_in(dir.to_str().unwrap(), "node_name").as_deref(),
            Some("laptop")
        );
        assert!(!state_unreadable_in(dir.to_str().unwrap()));
    }

    #[test]
    fn a_state_directory_that_is_not_readable_is_not_a_missing_registration() {
        // The state holds the SOCKS password, so it is root-only. A status
        // run by the person who lent the machine cannot read it, and
        // "not registered" would be a lie about the node.
        let dir = temp_dir("unreadable");
        let path = dir.join("node_name");
        std::fs::write(&path, "laptop\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o000);
        let _ = std::fs::set_permissions(&dir, perms);
        let unreadable = state_unreadable_in(dir.to_str().unwrap());
        // Running as root, the 0000 directory is still readable - so the
        // check is only meaningful for an unprivileged reader.
        if unsafe { libc_geteuid() } != 0 {
            assert!(
                unreadable,
                "an unreadable state must not read as a missing node"
            );
        }
        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o700);
        let _ = std::fs::set_permissions(&dir, perms);
    }

    #[test]
    fn a_missing_state_directory_is_a_missing_registration() {
        let dir = temp_dir("missing");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!state_unreadable_in(dir.to_str().unwrap()));
        assert_eq!(read_state_in(dir.to_str().unwrap(), "node_name"), None);
    }

    #[test]
    fn the_version_is_never_empty() {
        assert!(!crate::cli::VERSION.is_empty());
    }

    unsafe fn libc_geteuid() -> u32 {
        extern "C" {
            fn geteuid() -> u32;
        }
        geteuid()
    }
}
