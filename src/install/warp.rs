//! Cloudflare WARP, as one of the node's exits.
//!
//! WARP can do two very different things. In TUNNEL mode it sends the
//! machine's OWN traffic through itself - its browsing, its streaming, its
//! games and its DNS - and in PROXY mode it serves traffic that asks for
//! it on a local port.
//!
//! Which one a node uses is the OWNER'S choice, and the two are not
//! merely different exits: they are different machines.
//!
//!   - PROXY mode is the default, because it is the one that leaves the
//!     machine's own traffic where it was. The node's exits connect to the
//!     proxy port, and the owner keeps their browsing, their streaming and
//!     their games off Cloudflare's network. Tunnel mode is what breaks
//!     people's computers, and the complaint that reaches the owner of a
//!     node is not worth a WARP exit.
//!   - TUNNEL mode is what an owner asks for when they WANT their traffic
//!     and their DNS through WARP - a laptop that is meant to be on
//!     Cloudflare's network all the time. The node then has no separate
//!     WARP-proxy exit (a tunnel-mode WARP does not listen on a port): the
//!     machine's own address IS a WARP address, and that is the exit the
//!     node offers in its place.
//!
//! The choice is remembered (see `NODE_MODE_FILE`), so a machine that was
//! set up one way stays that way across a re-install, and the uninstaller
//! still gives back the mode the machine had before the node ever touched
//! it.
//!
//! Two things about the tool itself:
//!
//!   - every call needs `--accept-tos`. The Terms of Service prompt reads
//!     standard input, and an installer that is itself being piped in
//!     would wait for an answer nobody can give.
//!   - `registration new` fails on a machine that is already registered.
//!     That is not a failure: the registration the node needs is there.
//!
//! The mode is read back afterwards, because "the mode the owner asked for
//! has to hold" has to hold even when the command claimed to have worked.

use crate::log;
use crate::run;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// The mode, in the words warp-cli uses.
///
/// This version of warp-cli calls proxy mode "WarpProxy" and an older one
/// calls it "proxy"; both mean the same thing, and the check has to
/// recognise both. A WARP that IS a proxy reported as "not a proxy" is a
/// false alarm that reads exactly like a fault, and it is the kind of thing
/// that sends someone hunting for a problem that is not there.
fn canonical_mode(mode: &str) -> &str {
    match mode {
        "proxy" | "warpproxy" => "proxy",
        "warp" => "warp",
        "dns" => "dns",
        other => other,
    }
}

/// How a node uses WARP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// WARP serves a SOCKS port and the node's exits connect to it. The
    /// machine's own traffic is left alone.
    Proxy,
    /// WARP is a real WARP: the machine's traffic AND its DNS go through
    /// it. The node has no separate WARP-proxy exit, because a
    /// tunnel-mode WARP does not listen on a port.
    Tunnel,
}

impl Mode {
    /// The name the choice is stored and printed under.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Proxy => "proxy",
            Mode::Tunnel => "tunnel",
        }
    }

    /// The mode warp-cli calls it. Tunnel mode is called "warp" there,
    /// because that is what it is: a tunnel.
    fn warp_cli_name(self) -> &'static str {
        match self {
            Mode::Proxy => "proxy",
            Mode::Tunnel => "warp",
        }
    }

    /// Read a mode out of the name it was given.
    pub fn parse(text: &str) -> Option<Mode> {
        match text.trim().to_ascii_lowercase().as_str() {
            "proxy" | "warpproxy" => Some(Mode::Proxy),
            "tunnel" | "warp" => Some(Mode::Tunnel),
            _ => None,
        }
    }

    /// Does the node offer a separate WARP exit in this mode?
    ///
    /// It does not in tunnel mode: there is no port for the hub to connect
    /// to, and offering one would advertise an exit that can never answer.
    pub fn offers_warp_exit(self) -> bool {
        matches!(self, Mode::Proxy)
    }
}

/// Where the state the uninstaller needs is kept.
const STATE_DIR: &str = "/etc/proxy-node-warp";

/// The file the mode the machine had before the switch is kept in.
const MODE_FILE: &str = "/etc/proxy-node-warp/mode";

/// The file the mode the NODE was set up with is kept in.
///
/// It is what makes the choice survive a re-install: an install that was
/// not told otherwise keeps the mode this file names, instead of quietly
/// putting a machine that was deliberately in tunnel mode back into proxy
/// mode.
const NODE_MODE_FILE: &str = "/etc/proxy-node-warp/node-mode";

/// Is WARP installed at all?
pub fn available() -> bool {
    run::have("warp-cli")
}

/// The mode this node was set up with, if it was ever set up.
pub fn persisted_node_mode() -> Option<Mode> {
    let raw = std::fs::read_to_string(NODE_MODE_FILE).ok()?;
    Mode::parse(raw.lines().next().unwrap_or(""))
}

/// Keep the mode the node was set up with, so the next install does not
/// have to be told again.
pub fn remember_node_mode(mode: Mode) -> Result<(), String> {
    write_state(NODE_MODE_FILE, &format!("{}\n", mode.as_str()))
}

/// Put WARP into the mode the node was set up with, and make sure it is
/// running. Returns an error when WARP is not installed or refuses.
///
/// "Refuses" means the tool said no: it would not switch to the mode, or
/// would not take the port. A failure to CONNECT is only a warning,
/// because the machine's resolver is usually still broken at this point
/// (that is what the resolver repair is for) and the tunnel to the hub is
/// what the node needs first. The exit comes up once the machine can
/// resolve names again.
pub fn configure(mode: Mode, port: u16) -> Result<(), String> {
    if !available() {
        return Err(
            "Cloudflare WARP is not installed (there is no warp-cli on the PATH). \
             Install the cloudflare-warp package, or install the node without the WARP exit."
                .to_string(),
        );
    }

    if !registered() {
        // A machine that already has a registration keeps it: it may be
        // the owner's own, and the node has no business throwing it away.
        if let Err(reason) = warp_cli_ok(&["registration", "new"]) {
            log::warn(&format!("WARP registration failed: {reason}"));
        }
    }

    // The mode the machine had is worth keeping: WARP's mode is the
    // machine's business, and a node that switches it and cannot switch
    // it back has changed something the owner did not ask for. It is read
    // here, because this is the last moment it is worth anything.
    remember_mode();

    if mode == Mode::Proxy {
        warp_cli_ok(&["mode", "proxy"])
            .map_err(|reason| format!("WARP would not switch to proxy mode: {reason}"))?;

        let port_arg = port.to_string();
        warp_cli_ok(&["proxy", "port", &port_arg])
            .map_err(|reason| format!("WARP would not take the proxy port {port}: {reason}"))?;
    } else {
        // Tunnel mode is what the owner asked for: the machine's traffic
        // and its DNS go through WARP. There is no proxy port to set,
        // because a tunnel-mode WARP does not serve one.
        warp_cli_ok(&["mode", "warp"])
            .map_err(|reason| format!("WARP would not switch to tunnel mode: {reason}"))?;
    }

    // The mode is checked rather than assumed: a WARP left in the other
    // mode is not what the node was set up with, and saying so is better
    // than a node that quietly does something else.
    match current_mode() {
        Some(current) if canonical_mode(&current) == mode.warp_cli_name() => {}
        Some(current) => {
            return Err(format!(
                "WARP says it is in {current} mode, not {} mode. \
                 Set it back with `warp-cli --accept-tos mode {}`.",
                mode.as_str(),
                mode.warp_cli_name()
            ));
        }
        None => {
            return Err(
                "could not read WARP's mode (`warp-cli --accept-tos settings` said nothing \
                 useful). Refusing to continue, because the mode has to be the one that was \
                 asked for."
                    .to_string(),
            );
        }
    }

    if run::have("systemctl") {
        run::try_run("systemctl", &["enable", "warp-svc"]);
        run::try_run("systemctl", &["restart", "warp-svc"]);
    }

    match warp_cli(&["connect"]) {
        Ok(out) if out.ok() => {}
        Ok(out) => log::warn(&format!(
            "WARP did not connect yet ({}). The exit comes up on its own once the \
             machine can resolve names again; the node's own tunnel does not \
             depend on it.",
            out.reason()
        )),
        Err(reason) => log::warn(&format!("could not ask WARP to connect: {reason}")),
    }

    Ok(())
}

/// The mode WARP is in, as warp-cli reports it.
///
/// The installer keeps this before it switches WARP, so the uninstaller
/// can give the machine the mode it had.
pub fn current_mode() -> Option<String> {
    let out = warp_cli(&["settings"]).ok()?;
    if !out.ok() {
        return None;
    }
    mode_from_settings(&out.stdout)
}

/// Read the mode out of warp-cli's settings output.
///
/// The output is a human-readable list of settings, one per line, and the
/// line has moved between versions ("Mode: proxy" and "default) Mode:
/// proxy" both turn up), so the line is found by its label rather than by
/// its position.
///
/// The label has to BE the mode: a setting like "Auto-connect mode: off"
/// also contains "mode:", and reading that as the mode would leave a WARP
/// in tunnel mode looking like a WARP in no mode at all.
fn mode_from_settings(text: &str) -> Option<String> {
    for line in text.lines() {
        // to_ascii_lowercase keeps the length, so an index into the
        // lowercased line is also an index into the original.
        let lower = line.to_ascii_lowercase();
        let Some(start) = lower.find("mode:") else {
            continue;
        };
        let label = lower[..start].trim();
        if !label.is_empty() && !label.ends_with(')') {
            continue;
        }
        let value = lower[start + "mode:".len()..].trim();
        let value = value.split_whitespace().next().unwrap_or("");
        let value = value.trim_end_matches(['.', ',', ';']);
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// Is WARP registered already?
fn registered() -> bool {
    match warp_cli(&["registration", "show"]) {
        Ok(out) => out.ok(),
        Err(_) => false,
    }
}

/// Keep the mode the machine had, so the uninstaller can give it back.
///
/// It is kept only the FIRST time: a re-install finds the mode the node
/// switched the machine to, and writing that down as the mode to restore
/// would leave a machine that was in tunnel mode stuck in proxy mode after
/// an uninstall.
fn remember_mode() {
    let Some(mode) = current_mode() else {
        return;
    };
    if Path::new(MODE_FILE).exists() {
        return;
    }
    if let Err(reason) = write_state(MODE_FILE, &format!("{mode}\n")) {
        log::warn(&format!(
            "could not keep WARP's previous mode for later: {reason}"
        ));
    }
}

/// Write a file in the state directory, creating the directory if it is
/// not there yet.
///
/// The directory holds what the machine gets back later, so it is kept
/// private to root.
fn write_state(path: &str, content: &str) -> Result<(), String> {
    let dir = Path::new(path).parent().unwrap_or(Path::new(STATE_DIR));
    fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    fs::write(path, content).map_err(|e| format!("could not write {path}: {e}"))
}

/// Run warp-cli with the flag every call needs.
///
/// `--accept-tos` is not optional: the prompt reads standard input, and
/// an installer that waits for an answer to a question nobody can see
/// waits for ever.
fn warp_cli(args: &[&str]) -> Result<run::Output, String> {
    let mut full: Vec<&str> = Vec::with_capacity(args.len() + 1);
    full.push("--accept-tos");
    full.extend_from_slice(args);
    run::run("warp-cli", &full)
}

/// Run warp-cli and fail when it says no.
fn warp_cli_ok(args: &[&str]) -> Result<(), String> {
    let out = warp_cli(args)?;
    if !out.ok() {
        return Err(format!(
            "warp-cli {} failed (status {}): {}",
            args.join(" "),
            out.status,
            out.reason()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mode_is_read_out_of_the_settings() {
        assert_eq!(
            mode_from_settings("Settings:\nMode: proxy\nDNS: off\n"),
            Some("proxy".to_string())
        );
    }

    #[test]
    fn the_mode_is_found_wherever_it_appears() {
        // The settings have moved between versions; the label is what
        // stays.
        assert_eq!(
            mode_from_settings("  default) Mode: warp\n  other: on\n"),
            Some("warp".to_string())
        );
        assert_eq!(mode_from_settings("Proxy Port: 40000\n"), None);
    }

    #[test]
    fn a_setting_that_merely_mentions_a_mode_is_not_the_mode() {
        // "Auto-connect mode: off" is not the mode, and reading it as one
        // would leave a tunnel-mode WARP looking like no mode at all.
        assert_eq!(
            mode_from_settings("Auto-connect mode: off\nMode: warp\n"),
            Some("warp".to_string())
        );
    }

    #[test]
    fn this_version_of_warp_cli_calls_proxy_mode_warpproxy() {
        // It says so, and it is right: "WarpProxy on port 40000" IS proxy
        // mode. Reporting it as "not proxy mode" is a false alarm that reads
        // exactly like a fault.
        assert_eq!(
            canonical_mode(
                &mode_from_settings("(user set)\tMode: WarpProxy on port 40000\n")
                    .unwrap_or_default()
            ),
            "proxy"
        );
        assert_eq!(canonical_mode("warp"), "warp");
        assert_eq!(canonical_mode("dns"), "dns");
    }

    #[test]
    fn the_mode_is_read_in_lower_case() {
        // Some versions print "Mode: Proxy"; the comparison must not
        // depend on the capitalisation.
        assert_eq!(
            mode_from_settings("Mode: Proxy\n"),
            Some("proxy".to_string())
        );
    }

    #[test]
    fn the_mode_ignores_what_is_not_a_mode() {
        assert_eq!(mode_from_settings(""), None);
        assert_eq!(mode_from_settings("Mode:\n"), None);
    }

    #[test]
    fn a_mode_is_read_from_the_name_it_was_given() {
        assert_eq!(Mode::parse("proxy"), Some(Mode::Proxy));
        assert_eq!(Mode::parse("Proxy"), Some(Mode::Proxy));
        assert_eq!(Mode::parse("warpproxy"), Some(Mode::Proxy));
        assert_eq!(Mode::parse("tunnel"), Some(Mode::Tunnel));
        assert_eq!(Mode::parse("TUNNEL"), Some(Mode::Tunnel));
        // "warp" is what warp-cli calls tunnel mode, and it is what a
        // machine in tunnel mode reports.
        assert_eq!(Mode::parse("warp"), Some(Mode::Tunnel));
        assert_eq!(Mode::parse(""), None);
        assert_eq!(Mode::parse("dns"), None);
    }

    #[test]
    fn only_proxy_mode_offers_a_separate_warp_exit() {
        // A tunnel-mode WARP does not listen on a port, so there is nothing
        // for the hub to connect to: offering one would advertise an exit
        // that can never answer.
        assert!(Mode::Proxy.offers_warp_exit());
        assert!(!Mode::Tunnel.offers_warp_exit());
    }

    #[test]
    fn the_modes_are_named_the_way_warp_cli_names_them() {
        assert_eq!(Mode::Proxy.warp_cli_name(), "proxy");
        assert_eq!(Mode::Tunnel.warp_cli_name(), "warp");
        assert_eq!(Mode::Proxy.as_str(), "proxy");
        assert_eq!(Mode::Tunnel.as_str(), "tunnel");
    }
}
