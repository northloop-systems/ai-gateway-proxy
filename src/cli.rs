//! The subcommands and their options.
//!
//! Parsed by hand rather than with an argument-parsing crate: the program
//! has no dependencies, and this is the whole of it.

use std::collections::BTreeMap;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Default, Clone)]
pub struct InstallOptions {
    pub token: String,
    pub server_host: String,
    pub endpoint: Option<String>,
    pub node_name: Option<String>,
    pub ports: BTreeMap<String, u16>,
}

#[derive(Debug, Default)]
pub struct ServeOptions {
    pub listen_addr: String,
    pub listen_port: u16,
    pub username: String,
    pub password: String,
    pub hub_ip: String,
}

#[derive(Debug)]
pub enum Command {
    Install(InstallOptions),
    Uninstall(UninstallOptions),
    Status,
    Watchdog,
    Serve(ServeOptions),
    Version,
    Help,
}

#[derive(Debug, Default)]
pub struct UninstallOptions {
    /// Do not tell the hub the node is leaving.
    pub keep_hub_entry: bool,
}

pub const USAGE: &str = "\
ai-gateway-proxy - a proxy node for the AI Gateway

USAGE:
    ai-gateway-proxy <command> [options]

COMMANDS:
    install       install the node and register it with the hub
    uninstall     remove the node and everything it set up
    status        what is working and what is not
    watchdog      check the tunnel, and put it back if it is broken
    serve         run the authenticated SOCKS5 proxy for the node's own IP
    version       print the version

OPTIONS FOR install:
    --token TOKEN         the node token (prompted for when not given)
    --server HOST         the hub's host name (default: ai-gateway.shuffled-family.com)
    --endpoint HOST:PORT  the hub's WireGuard endpoint, when it does not say
    --node-name NAME      the name to register under (the hub's word wins)
    --port NAME=PORT      an exit's port, e.g. --port tor=9050

OPTIONS FOR serve:
    --addr ADDRESS        the address to listen on
    --port PORT           the port to listen on
    --user NAME           the username the hub authenticates with
    --password SECRET     the password the hub authenticates with
    --hub-ip ADDRESS      the only address allowed to connect
";

/// Parse the arguments. `Err` is a message for the operator.
pub fn parse(args: &[String]) -> Result<Command, String> {
    // The command is found FIRST, because the options mean different things
    // depending on it: `--port` is an exit's port for install and the
    // listening port for serve.
    let mut verb: Option<&str> = None;
    for arg in args {
        let candidate = match arg.as_str() {
            "install" => Some("install"),
            "uninstall" => Some("uninstall"),
            "status" => Some("status"),
            "watchdog" => Some("watchdog"),
            "serve" => Some("serve"),
            "version" => Some("version"),
            "help" | "--help" | "-h" => Some("help"),
            _ => None,
        };
        if let Some(candidate) = candidate {
            if verb.is_some() {
                return Err(format!(
                    "only one command at a time, and {arg} is the second"
                ));
            }
            verb = Some(candidate);
        }
    }
    let verb = match verb {
        Some(verb) => verb,
        None => return Ok(Command::Help),
    };

    let mut install = InstallOptions {
        server_host: "ai-gateway.shuffled-family.com".to_string(),
        ..Default::default()
    };
    let mut serve = ServeOptions {
        listen_port: 1080,
        hub_ip: "10.200.0.1".to_string(),
        ..Default::default()
    };
    let mut uninstall = UninstallOptions::default();
    let mut ports: Vec<String> = Vec::new();
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "install" | "uninstall" | "status" | "watchdog" | "serve" | "version" | "help"
            | "--help" | "-h" => {}
            "--keep-hub-entry" => uninstall.keep_hub_entry = true,
            "--token" => install.token = value(args, &mut i, "--token")?,
            "--server" => install.server_host = value(args, &mut i, "--server")?,
            "--endpoint" => install.endpoint = Some(value(args, &mut i, "--endpoint")?),
            "--node-name" => install.node_name = Some(value(args, &mut i, "--node-name")?),
            "--port" => ports.push(value(args, &mut i, "--port")?),
            "--addr" => serve.listen_addr = value(args, &mut i, "--addr")?,
            "--user" => serve.username = value(args, &mut i, "--user")?,
            "--password" => serve.password = value(args, &mut i, "--password")?,
            "--hub-ip" => serve.hub_ip = value(args, &mut i, "--hub-ip")?,
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    // The ports mean different things to the two commands, so they are
    // sorted out here rather than while scanning: for install a port is
    // NAME=PORT, for serve it is just a number.
    for port in ports {
        match port.split_once('=') {
            Some((name, value)) => {
                let number: u16 = value
                    .parse()
                    .map_err(|_| format!("{value} is not a port number"))?;
                install.ports.insert(name.to_string(), number);
            }
            None => {
                serve.listen_port = port
                    .parse()
                    .map_err(|_| format!("{port} is not a port number"))?;
            }
        }
    }

    Ok(match verb {
        "install" => Command::Install(install),
        "uninstall" => Command::Uninstall(uninstall),
        "status" => Command::Status,
        "watchdog" => Command::Watchdog,
        "serve" => Command::Serve(serve),
        "version" => Command::Version,
        _ => Command::Help,
    })
}

fn value(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}
