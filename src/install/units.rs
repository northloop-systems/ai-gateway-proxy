//! The systemd units a node runs.
//!
//! Four of them, and each one exists because of something that went
//! wrong on a real node:
//!
//!   proxy-socks5.service        the node's own address, as an
//!                                authenticated SOCKS5 proxy
//!   proxy-tor-redirect.service  socat: the tunnel's address -> Tor
//!   proxy-warp-redirect.service socat: the tunnel's address -> WARP
//!   proxy-tunnel-watchdog.*     puts the tunnel back when it dies
//!
//! The bodies are constants and the two things that change per node -
//! the tunnel address and the ports - are filled in, so a unit can be
//! read, and tested, as the plain text it is.

/// The tunnel's address is where the hub connects to. The port is the
/// one the hub was told about when the node registered.
const TOR_LISTEN_PORT: u16 = 9050;
const WARP_LISTEN_PORT: u16 = 40000;

/// Tor's own SOCKS5 port, on localhost. The bridge forwards to it.
const TOR_BACKEND: &str = "127.0.0.1:9050";

/// Where the node's state is kept, and where the SOCKS5 credentials are
/// written. The installer owns this file; the unit only reads it.
const CREDENTIALS_FILE: &str = "/opt/proxy-node/credentials.env";

/// The authenticated SOCKS5 proxy for the node's own address.
///
/// The credentials are NOT written into this file: a unit file is world
/// readable, and the SOCKS5 password is what the hub authenticates with.
/// They come from the node's state directory instead, and systemd puts
/// them in the command line where the proxy can see them - the password
/// is on the process's command line, which is more than somebody would
/// like, but it is not on disk in a file everybody can read.
///
/// The unit runs as an unprivileged account rather than as root: the
/// proxy forwards connections and needs nothing else, and a service that
/// is root is a service that hands root to anything that can talk to it.
const SOCKS5_UNIT: &str = "\
[Unit]
Description=Proxy Node - SOCKS5 for direct IP
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
User=proxysocks
Group=proxysocks
EnvironmentFile=-{credentials}
# The proxy accepts an empty username and password as a correct pair, so
# a unit that started without credentials would be an open proxy for
# anybody who could reach the port. Refuse to start without them.
ExecStartPre=/usr/bin/test -s {credentials}
ExecStart=/usr/local/bin/ai-gateway-proxy serve --addr {listen_addr} --port {port} --user ${AI_GATEWAY_PROXY_USER} --password ${AI_GATEWAY_PROXY_PASSWORD} --hub-ip ${AI_GATEWAY_PROXY_HUB_IP}
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
";

/// socat, bridging the tunnel's address to Tor on localhost.
///
/// The comment inside the unit says why the bridge is tied to the
/// tunnel the way it is; the short version is that the bridge has to
/// follow the tunnel's whole life, not just its first start.
const TOR_REDIRECT_UNIT: &str = "\
[Unit]
Description=Proxy Node - Tor redirect (WG to localhost)
After=wg-quick@wg0.service tor.service
Requires=wg-quick@wg0.service
# The bridge has to follow the tunnel's whole life, not just its first
# start. Requires= stops this unit when the tunnel stops, and nothing
# brought it back when the tunnel came up again - so a tunnel that flapped
# left the node with its Tor and WARP exits silently gone, and only its
# direct one working. PartOf= propagates a restart, and being wanted by
# the tunnel means a tunnel that comes up brings the bridge with it.
PartOf=wg-quick@wg0.service

[Service]
Type=simple
DynamicUser=yes
ExecStart=/usr/bin/socat TCP-LISTEN:{port},bind={listen_addr},fork,max-children=32 TCP:{backend}
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict

[Install]
WantedBy=wg-quick@wg0.service
";

/// socat, bridging the tunnel's address to WARP on localhost.
///
/// The same reasoning as the Tor bridge, and the same bug if it is left
/// out.
const WARP_REDIRECT_UNIT: &str = "\
[Unit]
Description=Proxy Node - WARP redirect (WG to localhost)
After=wg-quick@wg0.service warp-svc.service
Requires=wg-quick@wg0.service
# The bridge follows the tunnel's whole life: Requires= stops it when the
# tunnel stops, PartOf= propagates a restart, and being wanted by the
# tunnel means a tunnel that comes up brings the bridge with it. Without
# all three, a tunnel that flapped left the node with its WARP exit
# silently gone.
PartOf=wg-quick@wg0.service

[Service]
Type=simple
DynamicUser=yes
ExecStart=/usr/bin/socat TCP-LISTEN:{port},bind={listen_addr},fork,max-children=32 TCP:{backend}
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict

[Install]
WantedBy=wg-quick@wg0.service
";

/// The watchdog: a oneshot that checks the tunnel and puts it back.
///
/// A node that is registered but has no tunnel carries nothing, and the
/// hub cannot tell that apart from a node that is not there.
const WATCHDOG_UNIT: &str = "\
[Unit]
Description=Proxy Node - keep the WireGuard tunnel alive
After=wg-quick@wg0.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ai-gateway-proxy watchdog
";

/// The timer that makes the watchdog run.
///
/// Every minute: a node whose tunnel died carries nothing, and the
/// longer it stays that way the more the hub has given up on it.
const WATCHDOG_TIMER: &str = "\
[Unit]
Description=Check the Proxy Node's WireGuard tunnel

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=10s
Unit=proxy-tunnel-watchdog.service

[Install]
WantedBy=timers.target
";

/// The unit for the node's own address, as an authenticated SOCKS5 proxy.
pub fn socks5_unit(listen_addr: &str, port: u16) -> String {
    render(
        SOCKS5_UNIT,
        &[
            ("listen_addr", listen_addr),
            ("port", &port.to_string()),
            ("credentials", CREDENTIALS_FILE),
        ],
    )
}

/// The unit that bridges the tunnel's address to Tor on localhost.
pub fn tor_redirect_unit(listen_addr: &str) -> String {
    tor_redirect_unit_on(listen_addr, TOR_LISTEN_PORT)
}

/// The unit that bridges the tunnel's address to Tor, on another port.
///
/// The port is the one the hub was told about when the node registered;
/// it is the port ON THE TUNNEL ADDRESS, and Tor's own port on
/// localhost is the one the bridge forwards to.
pub fn tor_redirect_unit_on(listen_addr: &str, port: u16) -> String {
    render(
        TOR_REDIRECT_UNIT,
        &[
            ("listen_addr", listen_addr),
            ("port", &port.to_string()),
            ("backend", TOR_BACKEND),
        ],
    )
}

/// The unit that bridges the tunnel's address to WARP on localhost.
pub fn warp_redirect_unit(listen_addr: &str) -> String {
    warp_redirect_unit_on(listen_addr, WARP_LISTEN_PORT)
}

/// The unit that bridges the tunnel's address to WARP, on another port.
///
/// The port is the one the hub was told about when the node registered,
/// and it is the port ON THE TUNNEL ADDRESS. WARP's own proxy port is
/// set to the same number when WARP is configured, so the bridge
/// forwards to the same number it listens on.
pub fn warp_redirect_unit_on(listen_addr: &str, port: u16) -> String {
    render(
        WARP_REDIRECT_UNIT,
        &[
            ("listen_addr", listen_addr),
            ("port", &port.to_string()),
            ("backend", &format!("127.0.0.1:{port}")),
        ],
    )
}

/// The unit that checks the tunnel and puts it back.
pub fn watchdog_unit() -> String {
    WATCHDOG_UNIT.to_string()
}

/// The timer that makes the watchdog run every minute.
pub fn watchdog_timer() -> String {
    WATCHDOG_TIMER.to_string()
}

/// Fill a unit template's placeholders.
///
/// The bodies are constants and the values are known, so this is not a
/// general templating engine: `{name}` is replaced by the value, every
/// time it appears.
fn render(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (name, value) in values {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "10.200.0.5";

    #[test]
    fn the_bridges_are_tied_to_the_tunnel() {
        for unit in [tor_redirect_unit(ADDR), warp_redirect_unit(ADDR)] {
            assert!(unit.contains("Requires=wg-quick@wg0.service"));
            assert!(unit.contains("PartOf=wg-quick@wg0.service"));
        }
    }

    #[test]
    fn the_bridges_are_wanted_by_the_tunnel_and_by_nothing_else() {
        // WantedBy=multi-user.target would start the bridge on a
        // machine whose tunnel is not up - and then stop it, and leave it
        // stopped, when the tunnel came and went.
        for unit in [tor_redirect_unit(ADDR), warp_redirect_unit(ADDR)] {
            assert!(unit.contains("WantedBy=wg-quick@wg0.service"));
            assert!(!unit.contains("WantedBy=multi-user.target"));
        }
    }

    #[test]
    fn the_bridges_listen_on_the_tunnel_address() {
        let tor = tor_redirect_unit(ADDR);
        assert!(tor.contains("TCP-LISTEN:9050,bind=10.200.0.5"));
        assert!(tor.contains("TCP:127.0.0.1:9050"));

        let warp = warp_redirect_unit(ADDR);
        assert!(warp.contains("TCP-LISTEN:40000,bind=10.200.0.5"));
        assert!(warp.contains("TCP:127.0.0.1:40000"));
    }

    #[test]
    fn a_bridge_can_listen_on_another_port() {
        // The port the hub was told about is the one on the tunnel
        // address; Tor's own port on localhost does not move.
        let tor = tor_redirect_unit_on(ADDR, 9999);
        assert!(tor.contains("TCP-LISTEN:9999,bind=10.200.0.5"));
        assert!(tor.contains("TCP:127.0.0.1:9050"));

        // WARP's own proxy port is set to the same number when WARP is
        // configured, so the bridge forwards to the number it listens on.
        let warp = warp_redirect_unit_on(ADDR, 9999);
        assert!(warp.contains("TCP-LISTEN:9999,bind=10.200.0.5"));
        assert!(warp.contains("TCP:127.0.0.1:9999"));
    }

    #[test]
    fn the_bridges_are_locked_down() {
        for unit in [tor_redirect_unit(ADDR), warp_redirect_unit(ADDR)] {
            assert!(unit.contains("DynamicUser=yes"));
            assert!(unit.contains("NoNewPrivileges=yes"));
            assert!(unit.contains("ProtectSystem=strict"));
            assert!(unit.contains("Restart=always"));
            assert!(unit.contains("RestartSec=5"));
        }
    }

    #[test]
    fn the_socks5_unit_is_unprivileged() {
        let unit = socks5_unit(ADDR, 1080);
        assert!(unit.contains("User=proxysocks"));
        assert!(unit.contains("Group=proxysocks"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("ProtectHome=true"));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("RestartSec=5"));
    }

    #[test]
    fn the_socks5_unit_serves_the_node_own_address() {
        let unit = socks5_unit(ADDR, 1080);
        assert!(unit.contains("ExecStart=/usr/local/bin/ai-gateway-proxy serve"));
        assert!(unit.contains("--addr 10.200.0.5"));
        assert!(unit.contains("--port 1080"));
    }

    #[test]
    fn the_socks5_unit_takes_its_credentials_from_the_state_directory() {
        // Not from the unit file: a unit file is world readable, and the
        // password is what the hub authenticates with.
        let unit = socks5_unit(ADDR, 1080);
        assert!(unit.contains("EnvironmentFile=-/opt/proxy-node/credentials.env"));
        assert!(unit.contains("--user ${AI_GATEWAY_PROXY_USER}"));
        assert!(unit.contains("--password ${AI_GATEWAY_PROXY_PASSWORD}"));
        assert!(unit.contains("--hub-ip ${AI_GATEWAY_PROXY_HUB_IP}"));
        assert!(!unit.contains("proxyuser"));
    }

    #[test]
    fn the_socks5_unit_refuses_to_start_without_credentials() {
        // The proxy accepts an empty username and password as a correct
        // pair, so a unit that started without credentials would be an
        // open proxy.
        let unit = socks5_unit(ADDR, 1080);
        assert!(unit.contains("ExecStartPre=/usr/bin/test -s /opt/proxy-node/credentials.env"));
    }

    #[test]
    fn the_socks5_unit_starts_when_the_machine_does() {
        // The direct exit does not depend on the tunnel: it is the
        // node's own address, and it should be up whenever the machine
        // is.
        let unit = socks5_unit(ADDR, 1080);
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn the_watchdog_is_a_oneshot_and_the_timer_runs_it_every_minute() {
        let unit = watchdog_unit();
        assert!(unit.contains("Type=oneshot"));
        assert!(unit.contains("ExecStart=/usr/local/bin/ai-gateway-proxy watchdog"));

        let timer = watchdog_timer();
        assert!(timer.contains("OnUnitActiveSec=1min"));
        assert!(timer.contains("OnBootSec=1min"));
        assert!(timer.contains("Unit=proxy-tunnel-watchdog.service"));
        assert!(timer.contains("WantedBy=timers.target"));
    }

    #[test]
    fn every_unit_is_a_whole_unit() {
        for unit in [
            socks5_unit(ADDR, 1080),
            tor_redirect_unit(ADDR),
            warp_redirect_unit(ADDR),
            watchdog_unit(),
            watchdog_timer(),
        ] {
            assert!(unit.contains("[Unit]"));
            assert!(unit.ends_with('\n'));
        }
    }
}
