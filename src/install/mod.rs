//! The install, step by step.
//!
//! The order matters, and not only because it reads nicely:
//!
//!   1. the packages, so the rest of the work has tools to do it with
//!   2. Tor, which is local and cannot break anything else
//!   3. WARP, which is the step that can break the machine - so the
//!      resolver is remembered first, and put back immediately afterwards
//!   4. the keypair, then the preflight, then the registration
//!   5. the tunnel, the units, and the services
//!
//! The preflight comes before anything is written to the machine: a token
//! that is refused should cost the operator a paste, not a re-image.

use crate::cli::InstallOptions;
use crate::fs_util;
use crate::hub::{client::Hub, types::RegisterRequest};
use crate::log;
use crate::os_info;

pub mod packages;
pub mod summary;
pub mod systemd;
pub mod tor;
pub mod units;
pub mod warp;
pub mod warp_dns;
pub mod wireguard;

pub const STATE_DIR: &str = "/opt/proxy-node";
pub const BINARY_PATH: &str = "/usr/local/bin/ai-gateway-proxy";
const HUB_IP: &str = "10.200.0.1";

/// The ports the node offers the hub.
pub struct ExitPorts {
    pub tor: u16,
    pub warp: u16,
    pub direct: u16,
}

impl Default for ExitPorts {
    fn default() -> Self {
        ExitPorts {
            tor: 9050,
            warp: 40000,
            direct: 1080,
        }
    }
}

/// Do the install. Returns an error only when the node cannot work; every
/// step that can go wrong on its own says so and carries on.
pub fn run(options: &InstallOptions) -> Result<(), String> {
    if effective_uid() != 0 {
        return Err("this must run as root (use sudo)".to_string());
    }

    // The token comes from the environment when the installer script passed
    // it in, and is asked for when the binary is run on its own. It is
    // asked for VISIBLY: a masked prompt cannot be checked, and the
    // commonest failure is a token pasted with a character missing.
    //
    // A token this machine was already registered with is used as it is:
    // the installer saves it, and a node that has to be re-installed (a
    // changed hub key, a moved machine) should not have to be handed a
    // secret it already holds. Passing --token still replaces it.
    let token = if !options.token.is_empty() {
        options.token.clone()
    } else if let Ok(from_env) = std::env::var("AI_GATEWAY_PROXY_TOKEN") {
        from_env.trim().to_string()
    } else if let Some(saved) = saved_token() {
        log::step("Using the token this machine was registered with.");
        saved
    } else {
        prompt_for_token()?
    };
    if token.is_empty() {
        return Err("no token was given".to_string());
    }
    let options = InstallOptions {
        token,
        ..options.clone()
    };

    let ports = ExitPorts {
        tor: options.ports.get("tor").copied().unwrap_or(9050),
        warp: options.ports.get("warp").copied().unwrap_or(40000),
        direct: options.ports.get("direct").copied().unwrap_or(1080),
    };

    // The WARP mode is the OWNER'S choice, and it is remembered: an
    // install that was not told otherwise keeps the mode this node was set
    // up with, so a machine that was deliberately put in tunnel mode is not
    // quietly put back into proxy mode by a re-install.
    let warp_mode = options
        .warp_mode
        .or_else(warp::persisted_node_mode)
        .unwrap_or(warp::Mode::Proxy);
    if let Err(reason) = warp::remember_node_mode(warp_mode) {
        log::warn(&format!(
            "could not remember the WARP mode for later: {reason}"
        ));
    }

    log::step("Installing the packages the node needs...");
    if let Err(message) = packages::install_required() {
        log::warn(&format!("could not install every package: {message}"));
        log::warn("  the install continues; anything missing will be reported below.");
    }

    log::step("Configuring Tor...");
    if let Err(message) = tor::configure() {
        log::warn(&format!("Tor could not be configured: {message}"));
    }

    // WARP is the step that can take the machine's resolver away with it,
    // so what the machine was using is remembered BEFORE the switch - and
    // written down, because the moment it is needed again is days later,
    // when the node is uninstalled.
    log::step("Configuring WARP...");
    let mut remembered = warp_dns::remember();
    if remembered.is_empty() {
        remembered.push(warp_dns::FALLBACK_RESOLVER.to_string());
    }
    let warp_available = warp::available();
    if warp_available {
        if let Err(message) = warp::configure(warp_mode, ports.warp) {
            log::warn(&format!("WARP could not be configured: {message}"));
        }
        // The switch may have taken the resolver with it. Put the machine's
        // OWN back - not a public one: the machine's own is what it was
        // using, and it may be a resolver only it can reach.
        match warp_dns::ensure_resolvable(&remembered) {
            warp_dns::Verdict::Kept => {}
            warp_dns::Verdict::Replaced => {
                log::step("Restored the resolver WARP was providing")
            }
            warp_dns::Verdict::Filled => log::step("Put a resolver in place"),
            warp_dns::Verdict::Unreachable => log::warn(
                "no nameserver could be reached at all - the network looks down rather than \
                 the resolver, so the resolver was left alone",
            ),
            warp_dns::Verdict::NoFallback => log::warn(
                "the machine's resolver is not answering and there is no fallback to put in its place",
            ),
        }
    } else {
        log::step("WARP is not available for this distribution; skipping it.");
    }

    log::step("Generating WireGuard keypair...");
    let keypair = wireguard::KeyPair::generate()?;

    // The preflight: the token decides which node this machine is, and the
    // hub's answer is the name to register under.
    let hub = Hub::new(&options.server_host, &options.token);
    log::step("Verifying connectivity...");
    let node_name = match hub.whoami() {
        Ok(name) => {
            log::step(&format!("This token is bound to node '{name}'"));
            name
        }
        Err(message) => {
            return Err(format!(
                "the hub would not accept this token: {message}\n\
                 Check the token, and that this machine can reach {}.",
                options.server_host
            ));
        }
    };
    let node_name = options.node_name.clone().unwrap_or(node_name);

    log::step("Registering with the hub...");
    let request = RegisterRequest {
        hostname: node_name.clone(),
        wireguard_public_key: keypair.public_key().to_string(),
        version: "3.0".to_string(),
        public_ip: os_info::public_ip(),
        socks_user: generate_socks_user(),
        socks_pass: generate_socks_password(),
        ports: exit_ports(&ports, warp_mode),
    };
    let response = hub.register(&request)?;
    if response.status != "ok" {
        return Err(format!(
            "the hub refused the registration: {}",
            response.message
        ));
    }
    log::step(&format!("Assigned WireGuard IP: {}", response.wireguard_ip));

    // The hub is the authority on where it can be reached, so its answer
    // wins; the option is only a fallback for a hub that did not say.
    let advertised = response.wireguard_endpoint.trim().to_string();
    let endpoint = if !advertised.is_empty() {
        advertised
    } else {
        options.endpoint.clone().unwrap_or_default()
    };
    if endpoint.is_empty() {
        return Err("the hub did not say where to reach it, and no endpoint was given".to_string());
    }

    log::step("Configuring WireGuard...");
    wireguard::write_config(
        &keypair,
        &response.wireguard_ip,
        &response.wireguard_gateway_public_key,
        &endpoint,
    )?;
    wireguard::start()?;
    // A tunnel that has just been started has not shaken hands yet. The
    // marker an earlier run left behind would make the watchdog tear it
    // straight down again.
    crate::watchdog::reset();

    // --- The state the node needs later --------------------------------------
    // The token, the node's name, the tunnel's address and the hub's key:
    // the uninstaller and the watchdog both need them.
    log::step("Saving the node's state...");
    let state = std::path::Path::new(STATE_DIR);
    fs_util::write_file(&state.join("token"), &options.token, 0o600)?;
    fs_util::write_file(&state.join("node_name"), &node_name, 0o600)?;
    fs_util::write_file(&state.join("wg_ip"), &response.wireguard_ip, 0o644)?;
    fs_util::write_file(
        &state.join("wg_hub_public.key"),
        &response.wireguard_gateway_public_key,
        0o644,
    )?;
    // The SOCKS5 credentials, readable by the proxy's own user and by
    // nobody else. They used to live in the unit file, which is world
    // readable.
    fs_util::write_file(
        &state.join("credentials.env"),
        &format!(
            "AI_GATEWAY_PROXY_ADDR={}\nAI_GATEWAY_PROXY_PORT={}\n\
             AI_GATEWAY_PROXY_USER={}\nAI_GATEWAY_PROXY_PASSWORD={}\n\
             AI_GATEWAY_PROXY_HUB_IP={}\n",
            response.wireguard_ip, ports.direct, request.socks_user, request.socks_pass, HUB_IP
        ),
        0o640,
    )?;

    // --- The services --------------------------------------------------------
    log::step("Starting the services...");
    let mut unit_files: Vec<(String, String)> = vec![
        (
            "/etc/systemd/system/proxy-socks5.service".to_string(),
            units::socks5_unit(&response.wireguard_ip, ports.direct),
        ),
        (
            "/etc/systemd/system/proxy-tor-redirect.service".to_string(),
            units::tor_redirect_unit_on(&response.wireguard_ip, ports.tor),
        ),
    ];
    if warp_available && warp_mode.offers_warp_exit() {
        unit_files.push((
            "/etc/systemd/system/proxy-warp-redirect.service".to_string(),
            units::warp_redirect_unit_on(&response.wireguard_ip, ports.warp),
        ));
    } else if warp_available {
        // A node that was in proxy mode and is now in tunnel mode must not
        // keep the bridge: there is no WARP port for it to forward to, and
        // a bridge to a dead port is an exit the hub would keep trying.
        systemd::remove(&["proxy-warp-redirect.service"])?;
    }
    unit_files.push((
        "/etc/systemd/system/proxy-tunnel-watchdog.service".to_string(),
        units::watchdog_unit(),
    ));
    unit_files.push((
        "/etc/systemd/system/proxy-tunnel-watchdog.timer".to_string(),
        units::watchdog_timer(),
    ));
    systemd::install_and_start(&unit_files)?;

    // The tunnel is restarted by the units that want it, so it is briefly
    // not running at this point. Waiting for it means the summary tells the
    // truth rather than catching it mid-restart.
    let tunnel_ready = wait_for_tunnel();
    if !tunnel_ready {
        log::warn("the tunnel did not come up; the node is registered but carries nothing");
    }

    summary::print(&summary::Summary {
        node_name,
        assigned_ip: response.wireguard_ip,
        public_ip: request.public_ip,
        ports: ExitPorts {
            tor: ports.tor,
            warp: ports.warp,
            direct: ports.direct,
        },
        warp_available,
        warp_mode,
        hub_ip: HUB_IP.to_string(),
    });
    Ok(())
}

/// The exits the node offers the hub.
///
/// A tunnel-mode WARP does not serve a port, so there is no separate WARP
/// exit to offer: the machine's own address IS the WARP address, and
/// offering a port that can never answer would advertise an exit that
/// only ever fails.
fn exit_ports(ports: &ExitPorts, warp_mode: warp::Mode) -> Vec<(String, i64)> {
    let mut offered = vec![("tor".to_string(), ports.tor as i64)];
    if warp_mode.offers_warp_exit() {
        offered.push(("warp".to_string(), ports.warp as i64));
    }
    offered.push(("direct".to_string(), ports.direct as i64));
    offered
}

/// Wait for the tunnel to be up, for a few seconds.
///
/// The units that need the tunnel pull it in, so it is briefly down at the
/// end of the install. Reporting "not running" for that is reporting a
/// moment, not a fault - and a node whose tunnel is genuinely down should
/// say so plainly.
fn wait_for_tunnel() -> bool {
    for _ in 0..20 {
        if systemd::is_active("wg-quick@wg0") {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

/// The user name the hub authenticates to the node with. It is not a
/// secret - the password is - but it is generated rather than fixed, so
/// that two nodes never look the same on the wire.
fn generate_socks_user() -> String {
    let entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("proxy{}", entropy % 1_000_000_000)
}

/// The password, from the kernel's own randomness.
///
/// The hub only accepts letters, digits, dot and dash in this, so the
/// bytes are rendered in that alphabet rather than base64's.
fn generate_socks_password() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; 24];
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        if file.read_exact(&mut bytes).is_ok() {
            return bytes
                .iter()
                .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
                .collect();
        }
    }
    // The kernel's generator should never fail, but a password that is
    // predictable is worse than one that is short: fall back to the clock
    // and the process id rather than to a constant.
    let entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("proxy{entropy:029x}{:x}", std::process::id())
}

/// Ask for the token on the terminal, showing it as it is typed.
///
/// The token this machine was registered with, if it still has one.
///
/// It is read from the state directory, which is root-only, and it is
/// only ever used when the operator gave no token of their own: a node
/// that is being re-registered (a changed hub key, a moved machine) should
/// not have to be handed a secret it already holds.
fn saved_token() -> Option<String> {
    saved_token_in(STATE_DIR)
}

fn saved_token_in(dir: &str) -> Option<String> {
    let path = std::path::Path::new(dir).join("token");
    let text = fs_util::read_to_string(&path)?;
    let trimmed = text.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// The installer script does this itself, so that the token is read in
/// the same place the operator is looking. This is here for the case
/// where the binary is run on its own.
fn prompt_for_token() -> Result<String, String> {
    use std::io::{BufRead, Write};
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "there is no terminal to ask on; pass the token with --token".to_string())?;
    let input = std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .map_err(|_| "there is no terminal to ask on; pass the token with --token".to_string())?;
    let _ = write!(output, "  Paste your API token: ");
    let _ = output.flush();
    let mut reader = std::io::BufReader::new(input);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("could not read the token: {e}"))?;
    let _ = writeln!(output);
    Ok(line.trim().to_string())
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
    crate::run::capture("id", &["-u"])
        .and_then(|text| text.trim().parse::<u32>().ok())
        .unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ai-gateway-proxy-install-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn a_saved_token_is_found() {
        // The installer saves the token, so a node that is being
        // re-registered does not have to be handed a secret it already
        // holds.
        let dir = temp_dir("saved");
        std::fs::write(dir.join("token"), "pk-example-token\n").unwrap();
        assert_eq!(
            saved_token_in(dir.to_str().unwrap()).as_deref(),
            Some("pk-example-token")
        );
    }

    #[test]
    fn an_empty_saved_token_is_no_token() {
        let dir = temp_dir("empty");
        std::fs::write(dir.join("token"), "  \n").unwrap();
        assert_eq!(saved_token_in(dir.to_str().unwrap()), None);
    }

    #[test]
    fn no_saved_token_is_no_token() {
        let dir = temp_dir("none");
        assert_eq!(saved_token_in(dir.to_str().unwrap()), None);
    }

    #[test]
    fn a_proxy_mode_node_offers_three_exits() {
        let ports = ExitPorts::default();
        let offered = exit_ports(&ports, warp::Mode::Proxy);
        assert_eq!(offered.len(), 3);
        assert!(offered.contains(&("warp".to_string(), 40000)));
        assert!(offered.contains(&("tor".to_string(), 9050)));
        assert!(offered.contains(&("direct".to_string(), 1080)));
    }

    #[test]
    fn a_tunnel_mode_node_offers_two_exits() {
        // There is no WARP port to offer: a tunnel-mode WARP does not
        // listen on one, and the machine's own address is the WARP
        // address.
        let ports = ExitPorts::default();
        let offered = exit_ports(&ports, warp::Mode::Tunnel);
        assert_eq!(offered.len(), 2);
        assert!(!offered.iter().any(|(name, _)| name == "warp"));
        assert!(offered.contains(&("tor".to_string(), 9050)));
        assert!(offered.contains(&("direct".to_string(), 1080)));
    }
}
