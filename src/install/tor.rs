//! Tor, configured for the node's exit.
//!
//! The node offers a Tor exit through the hub, and Tor itself stays
//! bound to localhost: the hub reaches it through a socat bridge on the
//! tunnel address, so nothing new is exposed on the machine's ordinary
//! network interfaces.
//!
//! Two things are changed in /etc/tor/torrc, and both of them are about
//! what the machine is willing to answer:
//!
//!   SocksPort 127.0.0.1:9050   the port, on localhost only
//!   SocksPolicy accept 127.0.0.1, reject *
//!   ControlPort 0              the control port, closed
//!
//! The control port is the one that matters most: Tor's control port
//! can read and set the configuration of the running daemon, and an open
//! one is a way into the machine that has nothing to do with the node's
//! job.
//!
//! The ORIGINAL torrc is kept at /etc/tor/torrc.bak, and it is the
//! FIRST backup that is ever taken - a re-run must not overwrite the
//! pristine original with the copy this program already modified.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::fs_util;
use crate::log;
use crate::run;

const TORRC: &str = "/etc/tor/torrc";
const TORRC_BACKUP: &str = "/etc/tor/torrc.bak";

/// Tor's own SOCKS5 port, on localhost. The socat bridge listens on the
/// tunnel address and forwards to this.
const SOCKS_PORT: &str = "SocksPort 127.0.0.1:9050";

/// Only localhost may use the SOCKS5 port. Everything else is refused.
const POLICY_ACCEPT: &str = "SocksPolicy accept 127.0.0.1";
const POLICY_REJECT: &str = "SocksPolicy reject *";

/// The control port, closed.
const CONTROL_PORT: &str = "ControlPort 0";

/// Configure /etc/tor/torrc: a SOCKS5 port, a SocksPolicy that accepts
/// only localhost, and the control port closed. The ORIGINAL torrc is
/// kept at /etc/tor/torrc.bak - the FIRST backup ever taken, so a re-run
/// cannot overwrite the pristine original with an already-modified copy.
///
/// Tor is then enabled and restarted, best effort: a configuration
/// change that nothing reloads is a configuration change that never
/// happened, and a machine whose Tor does not come back after a reboot
/// is a node with a dead exit and nothing in the logs to say why.
pub fn configure() -> Result<(), String> {
    let torrc = Path::new(TORRC);
    let backup = Path::new(TORRC_BACKUP);

    let original = if fs_util::exists(torrc) {
        match fs_util::read_to_string(torrc) {
            Some(text) => text,
            None => {
                return Err(format!(
                    "{TORRC} is there but could not be read as text; refusing to overwrite it"
                ))
            }
        }
    } else {
        // No torrc at all: Tor's own defaults are not what the node
        // wants, and there is nothing to keep a copy of.
        String::new()
    };

    // The FIRST copy ever taken. A second run finds the backup already
    // there and leaves it alone, so the pristine original survives.
    backup_once(torrc, backup)?;

    fs_util::write_file(torrc, &apply(&original), 0o644)
        .map_err(|e| format!("could not write {TORRC}: {e}"))?;

    enable_tor();
    restart_tor();
    Ok(())
}

/// Put the original torrc back and restart Tor.
///
/// When there is no backup there is nothing to restore: the torrc is
/// left as it is and a warning is logged, because a missing backup is
/// not a reason to fail an uninstall.
pub fn restore() -> Result<(), String> {
    let backup = Path::new(TORRC_BACKUP);
    let torrc = Path::new(TORRC);

    if !fs_util::exists(backup) {
        log::warn(&format!(
            "no {TORRC_BACKUP} to restore from; {TORRC} is left as it is"
        ));
        return Ok(());
    }

    std::fs::copy(backup, torrc)
        .map_err(|e| format!("could not restore {TORRC} from {TORRC_BACKUP}: {e}"))?;

    restart_tor();
    Ok(())
}

/// Keep the FIRST copy of the torrc, with the mode it had.
///
/// The mode is the reason this is not `fs_util::backup_once`: Tor reads
/// its configuration again when it is asked to reload, and by then it
/// may have dropped its privileges - a configuration file that only
/// root can read is a configuration file Tor cannot reload. The
/// distribution's own torrc is world readable for that reason, and
/// whatever the machine's was, it is put back as it was.
fn backup_once(torrc: &Path, backup: &Path) -> Result<(), String> {
    if backup.exists() || !torrc.exists() {
        return Ok(());
    }
    std::fs::copy(torrc, backup).map_err(|e| format!("could not back up {TORRC}: {e}"))?;
    if let Ok(metadata) = std::fs::metadata(torrc) {
        let mode = metadata.permissions().mode() & 0o777;
        let _ = std::fs::set_permissions(backup, std::fs::Permissions::from_mode(mode));
    }
    Ok(())
}

/// The torrc the node wants, from whatever the machine had.
fn apply(original: &str) -> String {
    let mut lines: Vec<String> = original.lines().map(|line| line.to_string()).collect();

    // The SOCKS5 port. The first existing SocksPort line is replaced and
    // any further ones are dropped: two of them means the last one wins,
    // and the node's bridge would then forward to a port nobody listens
    // on.
    let mut socks_port_seen = false;
    lines.retain_mut(|line| {
        if line.starts_with("SocksPort") {
            if socks_port_seen {
                return false;
            }
            socks_port_seen = true;
            *line = SOCKS_PORT.to_string();
        }
        true
    });
    if !socks_port_seen {
        lines.push(SOCKS_PORT.to_string());
    }

    // The policy. Every existing policy line goes, because the node's
    // policy is exactly one thing: localhost in, everything else out.
    // Leaving somebody else's policy line behind would leave the
    // node's Tor answering for addresses it should not.
    lines.retain(|line| !line.starts_with("SocksPolicy"));
    lines.push(POLICY_ACCEPT.to_string());
    lines.push(POLICY_REJECT.to_string());

    // The control port, closed. Same rule as the SOCKS port: the first
    // ControlPort line is closed and the rest are dropped, because the
    // last one is the one that counts.
    let mut control_port_seen = false;
    lines.retain_mut(|line| {
        if line.starts_with("ControlPort") {
            if control_port_seen {
                return false;
            }
            control_port_seen = true;
            *line = CONTROL_PORT.to_string();
        }
        true
    });
    if !control_port_seen {
        lines.push(CONTROL_PORT.to_string());
    }

    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Start Tor at boot, best effort.
fn enable_tor() {
    match run::run("systemctl", &["enable", "tor"]) {
        Ok(out) if !out.ok() => log::warn(&format!(
            "could not enable tor at boot ({}); it will not come back after a reboot",
            out.reason()
        )),
        Ok(_) => {}
        Err(message) => log::warn(&format!(
            "could not enable tor at boot ({message}); it will not come back after a reboot"
        )),
    }
}

/// Restart Tor, best effort.
///
/// The unit is called `tor` on most distributions. A failure here is a
/// warning and not an error: there is more to install, and the operator
/// can restart Tor by hand.
fn restart_tor() {
    match run::run("systemctl", &["restart", "tor"]) {
        Ok(out) if out.ok() => {}
        Ok(out) => log::warn(&format!(
            "could not restart tor ({}); start it by hand: systemctl restart tor",
            out.reason()
        )),
        Err(message) => log::warn(&format!(
            "could not restart tor ({message}); start it by hand: systemctl restart tor"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_socks_port_is_on_localhost() {
        let torrc = apply("");
        assert!(torrc.contains("SocksPort 127.0.0.1:9050"));
    }

    #[test]
    fn the_policy_takes_localhost_and_nothing_else() {
        let torrc = apply("");
        assert!(torrc.contains("SocksPolicy accept 127.0.0.1"));
        assert!(torrc.contains("SocksPolicy reject *"));
    }

    #[test]
    fn the_control_port_is_closed() {
        assert!(apply("").contains("ControlPort 0"));
    }

    #[test]
    fn an_existing_socks_port_is_replaced_not_added_to() {
        // Two SocksPort lines means the last one wins, and the bridge
        // would forward to a port nobody listens on.
        let torrc = apply("SocksPort 9050\nSocksPort 9999\n");
        assert_eq!(torrc.matches("SocksPort").count(), 1);
        assert!(torrc.contains("SocksPort 127.0.0.1:9050"));
    }

    #[test]
    fn an_existing_control_port_is_closed_rather_than_left_open() {
        let torrc = apply("ControlPort 9051\n");
        assert!(torrc.contains("ControlPort 0"));
        assert!(!torrc.contains("9051"));
    }

    #[test]
    fn an_existing_policy_is_replaced() {
        let torrc = apply("SocksPolicy accept 10.0.0.0/8\n");
        assert!(!torrc.contains("10.0.0.0/8"));
        assert!(torrc.contains("SocksPolicy accept 127.0.0.1"));
        assert!(torrc.contains("SocksPolicy reject *"));
    }

    #[test]
    fn what_the_machine_had_is_kept() {
        let torrc = apply("Log notice file /var/log/tor/notices.log\n");
        assert!(torrc.contains("Log notice file /var/log/tor/notices.log"));
    }

    #[test]
    fn the_file_ends_with_a_newline() {
        assert!(apply("Log notice\n").ends_with('\n'));
    }
}
