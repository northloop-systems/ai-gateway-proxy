//! Putting the machine back the way it was.
//!
//! This is what a node's owner runs when they change their mind, so it has
//! to be thorough and it has to say what it did. Two things make it more
//! than a list of deletions.
//!
//! The first is the order. The firewall rules that keep the hub off the
//! machine are wg-quick's PostUp rules, so they only go away if the
//! interface is brought down while its configuration is still in place -
//! take the configuration away first and the rules stay behind, and a
//! stale DROP on an interface that no longer exists is exactly the kind
//! of leftover somebody else should not inherit.
//!
//! The second is the hub. A node that leaves without saying so stays
//! registered: the hub keeps a route pointed at an address that no longer
//! answers, and keeps the node's entry and its SOCKS password until an
//! operator notices. The node has its own token, and that token may
//! revoke that node and nothing else, so the node can leave by itself.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::cli::UninstallOptions;
use crate::fs_util;
use crate::log;
use crate::run;

/// Where the installer left the node's state, including its token.
const STATE_DIR: &str = "/opt/proxy-node";
const TOKEN_PATH: &str = "/opt/proxy-node/token";
const NODE_NAME_PATH: &str = "/opt/proxy-node/node_name";
/// The node's own program. It is not on the machine until the node is
/// installed, so it goes when the node is uninstalled.
const BINARY_PATH: &str = "/usr/local/bin/ai-gateway-proxy";

/// Where the installer left what it remembers about the machine's WARP
/// and its resolver. Both belong to the machine rather than to the node.
const WARP_STATE_DIR: &str = "/etc/proxy-node-warp";

const TORRC: &str = "/etc/tor/torrc";
const TORRC_BACKUP: &str = "/etc/tor/torrc.bak";
const WG_CONFIG: &str = "/etc/wireguard/wg0.conf";

/// The hub, unless the environment says otherwise.
const DEFAULT_SERVER_HOST: &str = "ai-gateway.shuffled-family.com";

/// The rules the installer put on the INPUT chain, in the order they have
/// to come off. These have to stay in step with the PostUp rules in
/// `install/wireguard.rs`: a rule that is not deleted here is a rule that
/// outlives the node.
const FIREWALL_RULES: [&str; 5] = [
    "-D INPUT -i wg0 -p tcp --dport 1080 -s 10.200.0.1 -j ACCEPT",
    "-D INPUT -i wg0 -p tcp --dport 9050 -s 10.200.0.1 -j ACCEPT",
    "-D INPUT -i wg0 -p tcp --dport 40000 -s 10.200.0.1 -j ACCEPT",
    "-D INPUT -i wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    "-D INPUT -i wg0 -j DROP",
];

/// The units the installer wrote, and the files they live in.
const UNITS: [(&str, &str); 5] = [
    ("proxy-socks5", "/etc/systemd/system/proxy-socks5.service"),
    (
        "proxy-tor-redirect",
        "/etc/systemd/system/proxy-tor-redirect.service",
    ),
    (
        "proxy-warp-redirect",
        "/etc/systemd/system/proxy-warp-redirect.service",
    ),
    (
        "proxy-tunnel-watchdog",
        "/etc/systemd/system/proxy-tunnel-watchdog.service",
    ),
    (
        "proxy-tunnel-watchdog.timer",
        "/etc/systemd/system/proxy-tunnel-watchdog.timer",
    ),
];

/// The units to stop before their files go. The watchdog's service is a
/// one-shot, so only its timer needs stopping.
const UNITS_TO_STOP: [&str; 4] = [
    "proxy-socks5",
    "proxy-tor-redirect",
    "proxy-warp-redirect",
    "proxy-tunnel-watchdog.timer",
];

/// The watchdog's script, which the installer copied out of its own
/// directory.
const WATCHDOG_SCRIPT: &str = "/usr/local/bin/proxy-tunnel-watchdog.sh";

/// The account the direct proxy runs as. It belongs to the node, so it
/// goes when the node does.
const PROXY_USER: &str = "proxysocks";

/// The result of the uninstall, for the summary.
#[derive(Debug, Default, Clone)]
pub struct Removed {
    /// The hub was told the node is leaving. False when the hub could not
    /// be reached, when it refused, and when the caller asked for the node
    /// to stay registered.
    pub hub_notified: bool,
    /// The tunnel's interface is gone.
    pub tunnel_down: bool,
    /// The units that were taken away, by name.
    pub units_removed: Vec<String>,
    /// The files that were taken away, by path.
    pub files_removed: Vec<String>,
    /// /etc/tor/torrc was put back the way it was found.
    pub torrc_restored: bool,
    /// The mode WARP was returned to: "proxy", "dns" or "warp". None when
    /// there was nothing to give back.
    pub warp_mode_restored: Option<String>,
    /// The machine's resolver was put back.
    pub resolver_restored: bool,
}

/// Put the machine back. Never fails on the first problem: it does as
/// much as it can and reports what it could not.
pub fn run() -> Result<Removed, String> {
    run_with(&UninstallOptions::default())
}

/// The same, with the caller's options.
///
/// The one option that changes what happens is `keep_hub_entry`: a node
/// that is being moved rather than given up keeps its entry at the hub,
/// and the hub keeps routing to it. That is the operator's call to make,
/// not something to be inferred.
pub fn run_with(options: &UninstallOptions) -> Result<Removed, String> {
    if effective_uid() != 0 {
        return Err("this must run as root (use sudo)".to_string());
    }

    let mut removed = Removed::default();

    // 1. The hub first: it is the only step that reaches outside this
    //    machine, and it is the one that decides whether the node's
    //    credentials stop working.
    if options.keep_hub_entry {
        log::step("Leaving the node registered at the hub, as asked.");
    } else {
        removed.hub_notified = tell_the_hub();
    }

    // 2. The tunnel, while its configuration is still in place, so the
    //    firewall rules go with it.
    removed.tunnel_down = bring_tunnel_down();
    remove_firewall_rules();

    // 3. The units.
    removed.units_removed = remove_units();

    // 4. The files and the account.
    removed.files_removed = remove_files();

    // 5. The machine's own settings, which the installer borrowed.
    restore_torrc(&mut removed);
    restore_warp(&mut removed);
    restore_resolver(&mut removed);

    summary(&removed, options.keep_hub_entry);
    Ok(removed)
}

/// Tell the hub the node is leaving.
///
/// The call goes out through curl, with the token in a private config file
/// rather than on the command line: a command line is world-readable
/// through /proc for as long as the request is in flight, and this token
/// is the node's own.
///
/// Three answers have to be told apart, because they mean different things
/// to whoever is left holding the machine: the hub removed the node, the
/// hub never knew it, or the hub could not be reached. The status code is
/// what tells them apart, and a node that could not reach the hub still
/// has a live credential at the other end.
fn tell_the_hub() -> bool {
    let token = read_secret(TOKEN_PATH);
    let node = read_secret(NODE_NAME_PATH);
    let (token, node) = match (token, node) {
        (Some(token), Some(node)) => (token, node),
        _ => {
            log::warn("No stored token found; the hub still has this node registered.");
            log::warn(&format!(
                "Revoke it with: curl -X DELETE -H \"Authorization: Bearer <token>\" {}",
                deregister_url("<name>")
            ));
            return false;
        }
    };
    if !node_is_sane(&node) {
        log::warn(&format!(
            "The stored node name {node:?} is not a name this node could have registered under."
        ));
        return false;
    }
    if !run::have("curl") {
        log::warn("curl is not installed; the hub could not be told.");
        return false;
    }

    let auth = auth_config(&token);
    let url = deregister_url(&node);
    let out = run::run(
        "curl",
        &[
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "-m",
            "15",
            "--config",
            &auth,
            "-X",
            "DELETE",
            &url,
        ],
    );
    let _ = std::fs::remove_file(&auth);

    match out {
        Ok(out) => {
            let code = out.stdout.trim().to_string();
            let code = if code.len() == 3 && code.chars().all(|c| c.is_ascii_digit()) {
                code
            } else {
                "000".to_string()
            };
            match code.as_str() {
                "200" => {
                    log::step(&format!("Hub notified: node {node} deregistered"));
                    true
                }
                "404" => {
                    // The hub does not know this node, so the node is not
                    // registered: the state the call was made for.
                    log::warn("Hub did not know this node (already gone?)");
                    true
                }
                "000" => {
                    log::warn("Could not reach the hub; it will notice the node is dead");
                    false
                }
                other => {
                    log::warn(&format!(
                        "Hub returned HTTP {other}; revoke the node by hand if it stays"
                    ));
                    false
                }
            }
        }
        Err(message) => {
            log::warn(&format!("Could not reach the hub: {message}"));
            false
        }
    }
}

/// Where the hub's own interface is, when the environment does not say.
fn server_host() -> String {
    std::env::var("SERVER_HOST")
        .ok()
        .map(|host| host.trim().to_string())
        .filter(|host| !host.is_empty())
        .unwrap_or_else(|| DEFAULT_SERVER_HOST.to_string())
}

/// The address the node's own entry is at on the hub.
fn deregister_url(node: &str) -> String {
    format!("https://{}/v1/proxy/nodes/node-{node}", server_host())
}

/// A curl config file carrying the token, and nothing else.
///
/// The file is created with its mode already set, rather than created and
/// then chmod'ed: it holds a credential, and there is no reason for it to
/// be readable by anybody, not even for the moment it takes to set a mode.
fn auth_config(token: &str) -> String {
    let path = std::env::temp_dir().join(format!("proxy-node-auth-{}.conf", std::process::id()));
    let content = format!("header = \"Authorization: Bearer {token}\"\n");
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut file| file.write_all(content.as_bytes()));
    if let Err(message) = written {
        log::warn(&format!("could not write the curl auth file: {message}"));
    }
    path.to_string_lossy().to_string()
}

/// Bring the tunnel down, and say whether it is really gone.
fn bring_tunnel_down() -> bool {
    if run::have("systemctl") {
        run::try_run("systemctl", &["disable", "--now", "wg-quick@wg0"]);
    }
    // The unit normally takes the interface with it, but wg-quick can be
    // stopped by something that is not wg-quick, and an interface that is
    // left behind keeps the tunnel's address.
    if interface_exists() {
        run::try_run("ip", &["link", "delete", "wg0"]);
    }
    let gone = !interface_exists();
    if gone {
        log::step("WireGuard interface brought down");
    } else {
        log::warn("the wg0 interface is still there; try: ip link delete wg0");
    }
    gone
}

/// Is the tunnel's interface still there?
fn interface_exists() -> bool {
    run::run("ip", &["link", "show", "wg0"])
        .map(|out| out.ok())
        .unwrap_or(false)
}

/// Take the firewall rules off, in case the shutdown was not clean.
fn remove_firewall_rules() {
    if !run::have("iptables") {
        log::warn("iptables is not installed; there are no rules of ours to remove");
        return;
    }
    for rule in FIREWALL_RULES {
        let parts: Vec<&str> = rule.split_whitespace().collect();
        run::try_run("iptables", &parts);
    }
    log::step("Firewall rules removed");
}

/// Stop the units and take their files away.
fn remove_units() -> Vec<String> {
    if run::have("systemctl") {
        for unit in UNITS_TO_STOP {
            run::try_run("systemctl", &["disable", "--now", unit]);
        }
    }
    let mut removed = Vec::new();
    for (unit, path) in UNITS {
        if remove_file(Path::new(path)) {
            removed.push(unit.to_string());
        }
    }
    if run::have("systemctl") {
        run::try_run("systemctl", &["daemon-reload"]);
    }
    log::step("Services removed");
    removed
}

/// Take the node's files away.
fn remove_files() -> Vec<String> {
    let mut removed = Vec::new();
    if remove_file(Path::new(WG_CONFIG)) {
        removed.push(WG_CONFIG.to_string());
    }
    // The watchdog's own copy of the script, which the installer put in
    // the PATH. It is a file and not a unit, but it goes with them.
    if remove_file(Path::new(WATCHDOG_SCRIPT)) {
        removed.push(WATCHDOG_SCRIPT.to_string());
    }
    // The binary itself. The machine did not have it before the node did,
    // and leaving it behind is not "putting the machine back".
    if remove_file(Path::new(BINARY_PATH)) {
        removed.push(BINARY_PATH.to_string());
    }
    if remove_dir(Path::new(STATE_DIR)) {
        removed.push(STATE_DIR.to_string());
    }
    // The account belongs to the node. It has no home and no shell, so
    // there is nothing of the user's in it to keep.
    run::try_run("userdel", &[PROXY_USER]);
    log::step("Keypair, proxy files and the proxysocks account removed");
    removed
}

/// Give the machine its Tor configuration back.
fn restore_torrc(removed: &mut Removed) {
    let backup = Path::new(TORRC_BACKUP);
    if !backup.exists() {
        log::warn("No /etc/tor/torrc.bak found; torrc left as it is");
        return;
    }
    match std::fs::copy(backup, Path::new(TORRC)) {
        Ok(_) => {
            removed.torrc_restored = true;
            run::try_run("systemctl", &["restart", "tor"]);
            log::step("/etc/tor/torrc restored from the backup");
        }
        Err(message) => log::warn(&format!("could not restore /etc/tor/torrc: {message}")),
    }
}

/// Give WARP the mode it had before the installer switched it.
fn restore_warp(removed: &mut Removed) {
    let mode_file = Path::new(WARP_STATE_DIR).join("mode");
    if !mode_file.exists() || !run::have("warp-cli") {
        return;
    }
    let raw = fs_util::read_to_string(&mode_file).unwrap_or_default();
    let mode = raw.lines().next().unwrap_or("").trim().to_string();
    let lower = mode.to_ascii_lowercase();
    if lower.contains("proxy") {
        run::try_run("warp-cli", &["--accept-tos", "mode", "proxy"]);
        if let Some(port) = trailing_port(&mode) {
            run::try_run("warp-cli", &["--accept-tos", "proxy", "port", &port]);
        }
        removed.warp_mode_restored = Some("proxy".to_string());
        log::step("WARP returned to proxy mode");
    } else if lower.contains("dns") {
        run::try_run("warp-cli", &["--accept-tos", "mode", "dns"]);
        removed.warp_mode_restored = Some("dns".to_string());
        log::step("WARP returned to DNS mode");
    } else {
        run::try_run("warp-cli", &["--accept-tos", "mode", "warp"]);
        removed.warp_mode_restored = Some("warp".to_string());
        log::step("WARP returned to tunnel mode");
    }
}

/// The port a mode string ends with, when it has one. The installer
/// remembers the mode the way `warp-cli settings` prints it, and that can
/// carry the proxy port with it.
fn trailing_port(mode: &str) -> Option<String> {
    let digits: String = mode
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        Some(digits.chars().rev().collect())
    }
}

/// Give the machine its resolver back.
///
/// The logic is the install's, not a copy of it: the install knows how the
/// machine keeps its resolver - a plain file, a systemd-resolved stub, or a
/// NetworkManager link - and the uninstaller has to put it back the same
/// way it was taken away.
fn restore_resolver(removed: &mut Removed) {
    let file = Path::new(WARP_STATE_DIR).join("resolvers");
    if !file.exists() {
        return;
    }
    let text = fs_util::read_to_string(&file).unwrap_or_default();
    let servers: Vec<String> = text
        .split_whitespace()
        .map(|server| server.to_string())
        .collect();
    if servers.is_empty() {
        return;
    }
    match crate::install::warp_dns::restore(&servers) {
        crate::install::warp_dns::Verdict::Kept | crate::install::warp_dns::Verdict::Replaced => {
            removed.resolver_restored = true;
            log::step("System resolver restored");
        }
        crate::install::warp_dns::Verdict::Filled => {
            removed.resolver_restored = true;
            log::step("System resolver put back");
        }
        crate::install::warp_dns::Verdict::Unreachable => {
            log::warn("the machine's resolver could not be reached, so it was left as it is")
        }
        crate::install::warp_dns::Verdict::NoFallback => {
            log::warn("the machine's resolver could not be put back")
        }
    }
    let _ = std::fs::remove_dir_all(WARP_STATE_DIR);
}

/// A file the installer wrote, read back and trimmed.
fn read_secret(path: &str) -> Option<String> {
    let text = fs_util::read_to_string(Path::new(path))?;
    let text = text.trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// A name the node could have registered under.
fn node_is_sane(node: &str) -> bool {
    !node.is_empty()
        && node
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// Remove a file, and say whether it was there.
fn remove_file(path: &Path) -> bool {
    match std::fs::remove_file(path) {
        Ok(()) => true,
        Err(message) if message.kind() == std::io::ErrorKind::NotFound => false,
        Err(message) => {
            log::warn(&format!("could not remove {}: {message}", path.display()));
            false
        }
    }
}

/// Remove a directory and everything in it.
fn remove_dir(path: &Path) -> bool {
    match std::fs::remove_dir_all(path) {
        Ok(()) => true,
        Err(message) if message.kind() == std::io::ErrorKind::NotFound => false,
        Err(message) => {
            log::warn(&format!("could not remove {}: {message}", path.display()));
            false
        }
    }
}

/// The effective user id. There is no standard-library call for it, and
/// this program is Linux-only anyway, so it is read from procfs.
fn effective_uid() -> u32 {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let first = rest.split_whitespace().next().unwrap_or("");
                if let Ok(uid) = first.parse::<u32>() {
                    return uid;
                }
            }
        }
    }
    // procfs not readable: ask the system.
    run::capture("id", &["-u"])
        .and_then(|text| text.trim().parse::<u32>().ok())
        .unwrap_or(u32::MAX)
}

/// What was done, in the shape the operator reads.
fn summary(removed: &Removed, kept_at_the_hub: bool) {
    log::plain("");
    log::plain("==========================================");
    log::plain("  Proxy Node removed");
    log::plain("==========================================");
    log::plain("");
    log::plain(&format!(
        "  Hub notified:   {}",
        if kept_at_the_hub {
            "left registered, as asked"
        } else if removed.hub_notified {
            "yes"
        } else {
            "no - the hub may still have this node"
        }
    ));
    log::plain(&format!(
        "  Tunnel down:    {}",
        if removed.tunnel_down { "yes" } else { "no" }
    ));
    log::plain(&format!(
        "  Units removed:  {}",
        if removed.units_removed.is_empty() {
            "none".to_string()
        } else {
            removed.units_removed.join(", ")
        }
    ));
    log::plain(&format!(
        "  torrc restored: {}",
        if removed.torrc_restored { "yes" } else { "no" }
    ));
    log::plain(&format!(
        "  WARP mode:      {}",
        removed
            .warp_mode_restored
            .clone()
            .unwrap_or_else(|| "left as it was".to_string())
    ));
    log::plain(&format!(
        "  Resolver:       {}",
        if removed.resolver_restored {
            "restored"
        } else {
            "left as it was"
        }
    ));
    log::plain("");
    log::step("Uninstall complete.");
    log::step(
        "WARP's registration is still on the machine: warp-cli registration delete removes it.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_firewall_rules_cover_everything_the_installer_added() {
        // The three proxy ports, the established traffic, and the DROP.
        for port in ["1080", "9050", "40000"] {
            assert!(
                FIREWALL_RULES
                    .iter()
                    .any(|rule| rule.contains(&format!("--dport {port}"))),
                "the rule for port {port} is not deleted"
            );
        }
        assert!(FIREWALL_RULES
            .iter()
            .any(|rule| rule.contains("--ctstate ESTABLISHED,RELATED")));
        assert!(FIREWALL_RULES.iter().any(|rule| rule.ends_with("-j DROP")));
    }

    #[test]
    fn every_rule_only_ever_mentions_the_hub() {
        for rule in FIREWALL_RULES {
            assert!(
                rule.contains("-i wg0"),
                "the rule does not name the interface: {rule}"
            );
            if rule.contains("--dport") {
                assert!(
                    rule.contains("-s 10.200.0.1"),
                    "a port is open to anyone: {rule}"
                );
            }
        }
    }

    #[test]
    fn a_stored_name_has_to_be_usable() {
        assert!(node_is_sane("mudkip"));
        assert!(node_is_sane("node-01"));
        assert!(!node_is_sane(""));
        assert!(!node_is_sane("../../admin"));
        assert!(!node_is_sane("node name"));
    }

    #[test]
    fn a_mode_string_carries_its_port() {
        assert_eq!(trailing_port("proxy"), None);
        assert_eq!(trailing_port("proxy40000"), Some("40000".to_string()));
        assert_eq!(trailing_port("Proxy 40000"), Some("40000".to_string()));
    }

    #[test]
    fn the_units_are_the_ones_the_installer_wrote() {
        let names: Vec<&str> = UNITS.iter().map(|(name, _)| *name).collect();
        assert!(names.contains(&"proxy-socks5"));
        assert!(names.contains(&"proxy-tor-redirect"));
        assert!(names.contains(&"proxy-warp-redirect"));
        assert!(names.contains(&"proxy-tunnel-watchdog.timer"));
        for (_, path) in UNITS {
            assert!(path.starts_with("/etc/systemd/system/"), "{path}");
        }
    }
}
