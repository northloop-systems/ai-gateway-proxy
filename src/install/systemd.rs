//! Writing the systemd units and starting them.
//!
//! The units are written to /etc/systemd/system, systemd is told to
//! reload, and each unit is enabled and started.
//!
//! Enabling is done per unit, not for the whole lot at once, because
//! the units are wanted by DIFFERENT things: the bridges are wanted by
//! the tunnel (so they follow it up and down), the SOCKS5 proxy by
//! multi-user.target, and the watchdog timer by timers.target. That is
//! what `WantedBy=` in each unit says, and `systemctl enable` follows
//! it - which is why the bridges come up with the tunnel and stop when
//! it stops.

use std::path::{Path, PathBuf};

use crate::fs_util;
use crate::run;

/// Where systemd looks for a unit that is not one of its own.
const UNIT_DIR: &str = "/etc/systemd/system";

/// The account the SOCKS5 unit runs as.
pub const PROXY_USER: &str = "proxysocks";

/// The unit files this program owns, for the uninstaller.
pub const OWNED_UNITS: &[&str] = &[
    "proxy-socks5.service",
    "proxy-tor-redirect.service",
    "proxy-warp-redirect.service",
    "proxy-tunnel-watchdog.service",
    "proxy-tunnel-watchdog.timer",
];

/// Write the units, reload systemd, enable and start them.
///
/// The units are `(name, body)` pairs. The name is the file name, with
/// its suffix: `proxy-socks5.service` - or the whole path to the file,
/// which is what the installer has, and is accepted as well.
///
/// Every unit is tried, even after one has failed: a node whose WARP
/// exit did not come up is still a node with two working exits, and
/// stopping at the first failure would leave the rest of them written
/// but never started. The failures are reported together at the end.
pub fn install_and_start(units: &[(String, String)]) -> Result<(), String> {
    for (name, body) in units {
        let path = unit_path(name);
        fs_util::write_file(&path, body, 0o644)
            .map_err(|e| format!("could not write the unit {name}: {e}"))?;
        // A unit that names a user that does not exist does not start,
        // and the node's direct exit would be the one thing that did not
        // come up.
        if body.contains(&format!("User={PROXY_USER}")) {
            ensure_proxy_user()?;
        }
    }

    daemon_reload()?;

    let mut failures: Vec<String> = Vec::new();
    for (name, body) in units {
        let unit = unit_name(name);
        // A unit with no [Install] section cannot be enabled - systemd
        // says so and exits with an error - and the watchdog's service
        // is one of them: the TIMER is what is enabled, and the timer
        // runs the service.
        if body.contains("[Install]") {
            if let Err(reason) = systemctl(&["enable", &unit]) {
                failures.push(format!("{unit} could not be enabled ({reason})"));
                continue;
            }
        }
        // restart, not start: it works for a unit that is not running
        // yet and for one that already is.
        if let Err(reason) = systemctl(&["restart", &unit]) {
            failures.push(format!("{unit} did not start ({reason})"));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "some systemd units did not come up: {}. Check them with 'systemctl status <unit>'.",
            failures.join("; ")
        ))
    }
}

/// Stop and remove the units.
///
/// A unit that is not installed is not a problem: stopping something
/// that is not there is a no-op, and the point of the uninstaller is to
/// leave the machine the way it was, not to complain about what was
/// already gone. The unit files are removed and systemd is told to
/// reload, which is the part that has to work.
pub fn remove(unit_names: &[&str]) -> Result<(), String> {
    for name in unit_names {
        let _ = run::run("systemctl", &["disable", "--now", name]);
        fs_util::remove(&unit_path(name));
    }
    daemon_reload()
}

/// Is a unit running?
pub fn is_active(unit: &str) -> bool {
    match run::run("systemctl", &["is-active", "--quiet", unit]) {
        Ok(out) => out.ok(),
        Err(_) => false,
    }
}

/// Create the account the SOCKS5 unit runs as, if it is not there.
///
/// A unit that names a user that does not exist fails to start, and the
/// node's direct exit would be the one thing that did not come up. The
/// account is a system account with no login shell: it exists to own
/// the proxy's socket and nothing else.
pub fn ensure_proxy_user() -> Result<(), String> {
    if run::capture("id", &["-u", PROXY_USER]).is_some() {
        return Ok(());
    }
    match run::run("useradd", &["-r", "-s", "/usr/sbin/nologin", PROXY_USER]) {
        Ok(out) if out.ok() => Ok(()),
        Ok(out) => Err(format!(
            "could not create the {PROXY_USER} account: {}",
            out.reason()
        )),
        Err(message) => Err(format!(
            "could not create the {PROXY_USER} account: {message}"
        )),
    }
}

/// Where a unit's file is. A name with a path in it is taken as the path
/// it names; a bare name goes into the unit directory.
fn unit_path(name: &str) -> PathBuf {
    let path = Path::new(name);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        Path::new(UNIT_DIR).join(path)
    }
}

/// The unit's name, for systemctl: the file name without its directory.
fn unit_name(name: &str) -> String {
    Path::new(name)
        .file_name()
        .map(|file| file.to_string_lossy().to_string())
        .unwrap_or_else(|| name.to_string())
}

/// Tell systemd to read the unit files again.
fn daemon_reload() -> Result<(), String> {
    systemctl(&["daemon-reload"]).map_err(|reason| {
        format!(
            "systemd did not reload its units ({reason}); the units this program wrote will not be picked up"
        )
    })
}

/// Run systemctl, and turn a failure into the reason it gave.
fn systemctl(args: &[&str]) -> Result<(), String> {
    match run::run("systemctl", args) {
        Ok(out) if out.ok() => Ok(()),
        Ok(out) => Err(out.reason()),
        Err(message) => Err(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_owned_units_are_the_four_services_and_the_timer() {
        assert_eq!(OWNED_UNITS.len(), 5);
        assert!(OWNED_UNITS.contains(&"proxy-socks5.service"));
        assert!(OWNED_UNITS.contains(&"proxy-tor-redirect.service"));
        assert!(OWNED_UNITS.contains(&"proxy-warp-redirect.service"));
        assert!(OWNED_UNITS.contains(&"proxy-tunnel-watchdog.service"));
        assert!(OWNED_UNITS.contains(&"proxy-tunnel-watchdog.timer"));
    }

    #[test]
    fn every_owned_unit_is_under_the_unit_directory() {
        for name in OWNED_UNITS {
            assert!(!name.contains('/'), "{name} should be a plain file name");
            assert!(
                name.ends_with(".service") || name.ends_with(".timer"),
                "{name} should be a systemd unit"
            );
        }
    }

    #[test]
    fn a_bare_name_goes_into_the_unit_directory() {
        assert_eq!(
            unit_path("proxy-socks5.service"),
            PathBuf::from("/etc/systemd/system/proxy-socks5.service")
        );
    }

    #[test]
    fn a_full_path_is_taken_as_it_is() {
        // The installer knows the whole path of the file it wants, and
        // writing it to /etc/systemd/system/<the whole path> would
        // quietly write it nowhere.
        assert_eq!(
            unit_path("/etc/systemd/system/proxy-socks5.service"),
            PathBuf::from("/etc/systemd/system/proxy-socks5.service")
        );
    }

    #[test]
    fn the_unit_name_is_the_file_name() {
        assert_eq!(
            unit_name("/etc/systemd/system/proxy-socks5.service"),
            "proxy-socks5.service"
        );
        assert_eq!(unit_name("proxy-socks5.service"), "proxy-socks5.service");
    }

    #[test]
    fn the_watchdog_service_is_not_enabled_but_the_timer_is() {
        // The watchdog's service has no [Install] section, so systemd
        // refuses to enable it: the TIMER is what is enabled, and the
        // timer runs the service.
        let service = crate::install::units::watchdog_unit();
        assert!(!service.contains("[Install]"));

        let timer = crate::install::units::watchdog_timer();
        assert!(timer.contains("[Install]"));
        assert!(timer.contains("WantedBy=timers.target"));
    }
}
