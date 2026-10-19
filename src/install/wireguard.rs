//! The node's WireGuard keypair and its configuration.
//!
//! The tunnel is the whole point of the node: it is how the hub reaches
//! the three exits, and it is the only thing that stands between the hub
//! and the machine it was lent. Two things follow from that, and they are
//! the reason this file is careful about what it writes.
//!
//! The first is the firewall. The rules below are wg-quick's PostUp rules,
//! so they exist exactly as long as the interface does, and they are what
//! stops the hub reaching anything except the three proxy ports. The
//! filter inside the proxy is a second line of defence; this is the first.
//!
//! The second is the private key. It is written into one file, with one
//! mode, and it never leaves the machine - the hub only ever sees the
//! public half.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::fs_util;
use crate::run;

/// Where the tunnel's configuration lives. wg-quick looks here for
/// `wg0.conf` when the unit `wg-quick@wg0` starts.
pub const CONFIG_PATH: &str = "/etc/wireguard/wg0.conf";

/// The configuration holds the private key, so it is readable by root and
/// by nobody else.
const CONFIG_MODE: u32 = 0o600;

/// The node's keypair. The private key never leaves this machine.
pub struct KeyPair {
    private: String,
    public: String,
}

impl KeyPair {
    /// Generate a keypair with `wg genkey` (wireguard-tools is a
    /// dependency of the node anyway, and its key format is the
    /// canonical one).
    pub fn generate() -> Result<KeyPair, String> {
        let generated = run::run("wg", &["genkey"])
            .map_err(|e| wg_missing("could not generate a keypair", &e))?;
        if !generated.ok() {
            return Err(format!(
                "wg genkey failed (status {}): {}",
                generated.status,
                generated.reason()
            ));
        }
        let private = generated.stdout.trim().to_string();
        if private.is_empty() {
            return Err("wg genkey produced no key".to_string());
        }
        let public = public_key_of(&private)?;
        Ok(KeyPair { private, public })
    }

    /// The public key, base64.
    pub fn public_key(&self) -> &str {
        &self.public
    }

    /// The private key, base64. Only for writing the config.
    pub fn private_key(&self) -> &str {
        &self.private
    }
}

/// Derive the public key from the private one.
///
/// The private key goes in on stdin, never on the command line: a command
/// line is world-readable through /proc for as long as the process lives,
/// and this process is short-lived but not instantaneous.
fn public_key_of(private: &str) -> Result<String, String> {
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| wg_missing("could not derive the public key", &e.to_string()))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "wg pubkey would not take the private key".to_string())?;
        stdin
            .write_all(private.as_bytes())
            .map_err(|e| format!("could not give wg pubkey the private key: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("wg pubkey failed: {e}"))?;
    if !output.status.success() {
        let reason = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if reason.is_empty() {
            "wg pubkey failed".to_string()
        } else {
            format!("wg pubkey failed: {reason}")
        });
    }
    let public = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if public.is_empty() {
        return Err("wg pubkey produced no key".to_string());
    }
    Ok(public)
}

/// The configuration, exactly.
///
/// The order of the PostUp rules is not a style choice. Every one of them
/// is inserted at the TOP of the INPUT chain, so the LAST one written ends
/// up highest - and the chain is read top down, so the allows have to be
/// above the DROP for the ports to be reachable at all. Writing the DROP
/// first is what puts it at the bottom.
const CONFIG_TEMPLATE: &str = "\
[Interface]
PrivateKey = {private}
Address = {address}/24
PostUp = iptables -I INPUT 1 -i %i -j DROP
PostUp = iptables -I INPUT 1 -i %i -p tcp --dport 40000 -s 10.200.0.1 -j ACCEPT
PostUp = iptables -I INPUT 1 -i %i -p tcp --dport 9050 -s 10.200.0.1 -j ACCEPT
PostUp = iptables -I INPUT 1 -i %i -p tcp --dport 1080 -s 10.200.0.1 -j ACCEPT
PostUp = iptables -I INPUT 1 -i %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostDown = iptables -D INPUT -i %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostDown = iptables -D INPUT -i %i -p tcp --dport 1080 -s 10.200.0.1 -j ACCEPT
PostDown = iptables -D INPUT -i %i -p tcp --dport 9050 -s 10.200.0.1 -j ACCEPT
PostDown = iptables -D INPUT -i %i -p tcp --dport 40000 -s 10.200.0.1 -j ACCEPT
PostDown = iptables -D INPUT -i %i -j DROP

[Peer]
PublicKey = {hub_key}
AllowedIPs = 10.200.0.1/32
Endpoint = {endpoint}
PersistentKeepalive = 25
";

/// Write /etc/wireguard/wg0.conf (mode 0600) with the node's keypair,
/// the address the hub assigned, the hub's public key and the endpoint to
/// reach it at. The firewall rules are wg-quick's PostUp/PostDown, and
/// they are what stops the hub reaching anything except the three proxy
/// ports: the hub may only connect from 10.200.0.1, only to the three
/// ports, and everything else on the interface is dropped. The destination
/// filter inside the proxy is a second line of defence, not the first.
pub fn write_config(
    keypair: &KeyPair,
    assigned_ip: &str,
    hub_public_key: &str,
    endpoint: &str,
) -> Result<(), String> {
    write_config_to(
        Path::new(CONFIG_PATH),
        keypair,
        assigned_ip,
        hub_public_key,
        endpoint,
    )
}

/// The same, at a path of our choosing. Separate so the file's contents
/// can be tested without touching the machine's real configuration.
fn write_config_to(
    path: &Path,
    keypair: &KeyPair,
    assigned_ip: &str,
    hub_public_key: &str,
    endpoint: &str,
) -> Result<(), String> {
    check_assigned_ip(assigned_ip)?;
    check_hub_key(hub_public_key)?;
    check_endpoint(endpoint)?;
    let content = config_text(keypair, assigned_ip, hub_public_key, endpoint);
    fs_util::write_file(path, &content, CONFIG_MODE)
}

/// The configuration file's text.
///
/// The values are substituted one after another, which is safe because
/// none of them can contain a placeholder: a key is base64, an address is
/// digits and dots, and an endpoint is a host and a port - and all three
/// are checked before they get here.
fn config_text(
    keypair: &KeyPair,
    assigned_ip: &str,
    hub_public_key: &str,
    endpoint: &str,
) -> String {
    CONFIG_TEMPLATE
        .replace("{private}", keypair.private_key())
        .replace("{address}", assigned_ip)
        .replace("{hub_key}", hub_public_key)
        .replace("{endpoint}", endpoint)
}

/// Bring the tunnel up.
pub fn start() -> Result<(), String> {
    // Enabled as well as started: a node whose tunnel does not come back
    // after a reboot is a node that carries nothing.
    run::try_run("systemctl", &["enable", "wg-quick@wg0"]);
    let out = run::run("systemctl", &["restart", "wg-quick@wg0"])?;
    if !out.ok() {
        let reason = out.reason();
        let detail = if reason.is_empty() {
            format!(
                "systemctl restart wg-quick@wg0 failed (status {})",
                out.status
            )
        } else {
            reason
        };
        return Err(format!(
            "WireGuard did not start: {detail}. Check {CONFIG_PATH}."
        ));
    }
    Ok(())
}

/// The tunnel's address, as the configuration says it.
pub fn assigned_ip() -> Option<String> {
    let text = fs_util::read_to_string(Path::new(CONFIG_PATH))?;
    address_in(&text)
}

/// The address out of a configuration file's text.
fn address_in(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("Address") else {
            continue;
        };
        let Some(value) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let address = value.trim().split('/').next().unwrap_or("").trim();
        if !address.is_empty() {
            return Some(address.to_string());
        }
    }
    None
}

/// The address has to be one the hub can have handed out.
///
/// The hub numbers the nodes 10.200.0.2 and up: .0 is the network and .1
/// is the hub itself, and a node that took either of those would be
/// talking to itself or to the hub.
fn check_assigned_ip(address: &str) -> Result<(), String> {
    let parts: Vec<&str> = address.split('.').collect();
    if parts.len() != 4 {
        return Err(format!(
            "the hub assigned {address}, which is not an address inside the tunnel"
        ));
    }
    if parts[0] != "10" || parts[1] != "200" || parts[2] != "0" {
        return Err(format!(
            "the hub assigned {address}, which is not inside 10.200.0.0/24"
        ));
    }
    let last: u32 = parts[3]
        .parse()
        .map_err(|_| format!("the hub assigned {address}, whose last part is not a number"))?;
    if !(2..=255).contains(&last) {
        return Err(format!(
            "the hub assigned {address}, which is not a node's address in 10.200.0.0/24"
        ));
    }
    Ok(())
}

/// The hub's public key has to look like a key.
///
/// This is the one value that comes straight from the network and goes
/// straight into a file, and a value with a newline in it would put a
/// directive of the sender's choosing into the node's configuration.
fn check_hub_key(key: &str) -> Result<(), String> {
    let bytes = key.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' {
        return Err("the hub's WireGuard public key is not a 44-character key".to_string());
    }
    for byte in &bytes[..43] {
        let ok = byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/';
        if !ok {
            return Err(
                "the hub's WireGuard public key has characters a key cannot have".to_string(),
            );
        }
    }
    Ok(())
}

/// The endpoint has to be one host and one port, and nothing else.
fn check_endpoint(endpoint: &str) -> Result<(), String> {
    if endpoint.is_empty() {
        return Err("the hub did not say where it can be reached".to_string());
    }
    if endpoint.chars().any(|c| c.is_whitespace()) {
        return Err(format!(
            "the hub's endpoint {endpoint:?} is not a single host and port"
        ));
    }
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return Err(format!(
            "the hub's endpoint {endpoint:?} has no port to connect to"
        ));
    };
    if !host_is_sane(host) {
        return Err(format!(
            "the hub's endpoint {endpoint:?} has a host that cannot be one"
        ));
    }
    if port.is_empty() || port.len() > 5 || !port.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "the hub's endpoint {endpoint:?} has no port number"
        ));
    }
    let number: u32 = port
        .parse()
        .map_err(|_| format!("the hub's endpoint {endpoint:?} has a port that is not a number"))?;
    if number == 0 || number > 65535 {
        return Err(format!(
            "the hub's endpoint {endpoint:?} has a port that cannot exist"
        ));
    }
    Ok(())
}

/// A host name or an address, and nothing that could be a directive.
fn host_is_sane(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    // An IPv6 literal in brackets, which is how it has to be written for
    // the port to be separable from it.
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return !inner.is_empty()
            && inner
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
    }
    host.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// A word about the one thing the node cannot do without.
fn wg_missing(what: &str, error: &str) -> String {
    if error.contains("No such file or directory") {
        format!("{what}: wg is not on this machine (install wireguard-tools)")
    } else {
        format!("{what}: {error}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const HUB_KEY: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqe8Xy=";

    fn keypair() -> KeyPair {
        KeyPair {
            private: "cHJpdmF0ZSBrZXkgdGhhdCBpcyBmaWtyZWQgaW50byB0aGUgY29uZmln".to_string(),
            public: HUB_KEY.to_string(),
        }
    }

    fn text() -> String {
        config_text(&keypair(), "10.200.0.7", HUB_KEY, "hub.example.com:51820")
    }

    #[test]
    fn every_firewall_rule_is_there() {
        let config = text();
        for port in ["40000", "9050", "1080"] {
            assert!(
                config.contains(&format!("-p tcp --dport {port} -s 10.200.0.1 -j ACCEPT")),
                "the rule for port {port} is missing"
            );
        }
        assert!(config.contains("-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"));
        assert!(config.contains("-i %i -j DROP"));
    }

    #[test]
    fn the_drop_is_written_first() {
        // Every rule is inserted at the top of the chain, so the LAST one
        // written ends up highest. The DROP has to be written first for it
        // to end up at the bottom, below the allows.
        let config = text();
        let ups: Vec<&str> = config
            .lines()
            .filter(|line| line.starts_with("PostUp = iptables"))
            .collect();
        assert!(!ups.is_empty(), "no firewall rules at all");
        assert!(ups[0].contains("-j DROP"), "the DROP is not written first");
        assert!(
            !ups[ups.len() - 1].contains("-j DROP"),
            "the DROP is written last, so it ends up above the allows"
        );
    }

    #[test]
    fn the_postdown_rules_mirror_the_postup_rules() {
        // Same rules, opposite verb. The order is deliberately different:
        // deleting a rule does not care where it is.
        let normalise = |line: &str| {
            line.split("= ")
                .nth(1)
                .unwrap_or("")
                .replace("-I INPUT 1", "INPUT")
                .replace("-D INPUT", "INPUT")
                .split_whitespace()
                .collect::<Vec<&str>>()
                .join(" ")
        };
        let config = text();
        let mut ups: Vec<String> = config
            .lines()
            .filter(|line| line.starts_with("PostUp = iptables"))
            .map(normalise)
            .collect();
        let mut downs: Vec<String> = config
            .lines()
            .filter(|line| line.starts_with("PostDown = iptables"))
            .map(normalise)
            .collect();
        ups.sort();
        downs.sort();
        assert_eq!(ups, downs, "PostDown does not mirror PostUp");
    }

    #[test]
    fn only_the_hub_may_reach_the_proxy_ports() {
        let config = text();
        for line in config
            .lines()
            .filter(|l| l.starts_with("PostUp = iptables"))
        {
            if line.contains("--dport") {
                assert!(
                    line.contains("-s 10.200.0.1"),
                    "a port is open to anyone: {line}"
                );
            }
        }
    }

    #[test]
    fn the_peer_is_pinned_to_the_hub() {
        // A /24 would route the node's traffic to every other node and
        // let them reach the hub through this one.
        assert!(text().contains("AllowedIPs = 10.200.0.1/32"));
    }

    #[test]
    fn the_tunnel_keeps_itself_alive() {
        assert!(text().contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn the_config_holds_the_keypair_and_the_hub_key() {
        let config = text();
        assert!(config.contains(&format!("PrivateKey = {}", keypair().private_key())));
        assert!(config.contains(&format!("PublicKey = {HUB_KEY}")));
        assert!(config.contains("Address = 10.200.0.7/24"));
        assert!(config.contains("Endpoint = hub.example.com:51820"));
    }

    #[test]
    fn the_config_is_written_private() {
        let path = std::env::temp_dir().join(format!(
            "ai-gateway-proxy-wg-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let result = write_config_to(
            &path,
            &keypair(),
            "10.200.0.7",
            HUB_KEY,
            "hub.example.com:51820",
        );
        let mode = std::fs::metadata(&path)
            .map(|meta| meta.permissions().mode() & 0o777)
            .unwrap_or(0);
        let _ = std::fs::remove_file(&path);
        result.expect("the configuration was not written");
        assert_eq!(mode, 0o600, "the configuration is readable by other people");
    }

    #[test]
    fn the_address_comes_back_out_of_the_configuration() {
        let config = text();
        assert_eq!(address_in(&config), Some("10.200.0.7".to_string()));
        assert_eq!(address_in("[Interface]\nListenPort = 51820\n"), None);
    }

    #[test]
    fn an_address_outside_the_tunnel_is_refused() {
        assert!(check_assigned_ip("10.200.0.7").is_ok());
        assert!(
            check_assigned_ip("10.200.0.1").is_err(),
            "the hub's own address"
        );
        assert!(
            check_assigned_ip("10.200.0.0").is_err(),
            "the network address"
        );
        assert!(check_assigned_ip("10.200.0.256").is_err(), "not an address");
        assert!(
            check_assigned_ip("192.168.1.5").is_err(),
            "outside the tunnel"
        );
        assert!(check_assigned_ip("10.200.0.7/24").is_err(), "with a prefix");
    }

    #[test]
    fn a_hub_key_that_is_not_a_key_is_refused() {
        assert!(check_hub_key(HUB_KEY).is_ok());
        assert!(check_hub_key("short").is_err());
        assert!(check_hub_key(&format!("{HUB_KEY}\nPostUp = evil")).is_err());
        assert!(check_hub_key(&HUB_KEY.replace('x', " ")).is_err());
    }

    #[test]
    fn an_endpoint_that_is_not_one_is_refused() {
        assert!(check_endpoint("hub.example.com:51820").is_ok());
        assert!(check_endpoint("10.0.0.1:51820").is_ok());
        assert!(check_endpoint("[2001:db8::1]:51820").is_ok());
        assert!(check_endpoint("hub.example.com").is_err(), "no port");
        assert!(check_endpoint("hub.example.com:0").is_err(), "port zero");
        assert!(
            check_endpoint("hub.example.com:70000").is_err(),
            "no such port"
        );
        assert!(
            check_endpoint("hub.example.com:51820\nPostUp = evil").is_err(),
            "a directive could be injected through the endpoint"
        );
        assert!(check_endpoint("").is_err());
    }
}
