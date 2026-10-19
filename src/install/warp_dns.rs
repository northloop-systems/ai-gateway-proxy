//! The machine's resolver, across the WARP switch.
//!
//! WARP is usually the machine's RESOLVER: it puts 100.100.100.100 into
//! the machine's DNS configuration. Switching it to proxy mode takes that
//! resolver away with it, and a machine that cannot resolve anything
//! cannot reach the hub either - so the install dies on its first
//! request and the machine is left unable to work at all. That is not a
//! theory: it happened on a real node, and the installer said "cannot
//! reach the server", which reads like a network problem and is really a
//! dead resolver.
//!
//! So the resolver is checked, and the difference between a resolver that
//! is broken and a network that is down is kept apart:
//!
//!   - a nameserver that ANSWERS is fine, and is left exactly as it is.
//!   - a nameserver that answers with an ERROR (SERVFAIL, REFUSED,
//!     NOTIMP) is alive and broken, and replacing it is sensible.
//!   - a nameserver that cannot be REACHED at all means the network is
//!     down, not the resolver. Replacing it would be a guess, and the
//!     guess is worse than the problem: the resolver may be perfectly
//!     good, and the route to it may be what is broken.
//!
//! A timeout is tried twice before it is believed: one dropped packet is
//! not a broken resolver.
//!
//! Two more rules, both learned the hard way:
//!
//!   - a resolv.conf that is a SYMLINK is never written. systemd-resolved's
//!     stub always answers (127.0.0.53) and asks the LINK, not that file.
//!     For that case the nameservers go to the link instead, with
//!     resolvectl, and NetworkManager's own idea of them is corrected as
//!     well - it writes the file again on the next reconnect.
//!   - what the machine was using is remembered BEFORE the switch. The
//!     list belongs on disk at that point (/etc/proxy-node-warp/resolvers,
//!     the file the shell installer used), so the uninstaller can give the
//!     machine back what it had even after a reboot.

use crate::log;
use crate::run;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

/// The file the machine reads its nameservers from.
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Where the installer keeps what it has to give back later.
pub const STATE_DIR: &str = "/etc/proxy-node-warp";

/// The file in that directory the remembered resolvers belong in.
pub const RESOLVERS_FILE: &str = "/etc/proxy-node-warp/resolvers";

/// WARP's own resolver: the one the switch takes away.
const WARP_RESOLVER: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 100);

/// The resolver to fall back on when the machine has none of its own.
pub const FALLBACK_RESOLVER: &str = "1.1.1.1";

/// The name the probe asks about. It exists, always, so a resolver that
/// cannot answer for it is broken rather than merely unlucky.
const PROBE_NAME: &str = "example.com";

/// The type of record the probe asks for: an IPv4 address.
const PROBE_TYPE: u16 = 1;

/// How long to wait for a nameserver before calling it unreachable.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// How many times a nameserver is asked before a timeout is believed.
const PROBE_ATTEMPTS: usize = 2;

/// What the resolver check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The resolver works; nothing was changed.
    Kept,
    /// The resolver was broken and has been replaced.
    Replaced,
    /// The resolver could not be reached - the network, not the resolver.
    Unreachable,
    /// There was no resolver at all, and one was put in place.
    Filled,
    /// Nothing could be done (no fallback configured, or the file is not ours to write).
    NoFallback,
}

/// What one nameserver did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// It answered with the record that was asked for.
    Answer,
    /// It is alive and broken: it replied with an error, or with nothing.
    Error,
    /// It could not be reached at all.
    Timeout,
}

/// How the machine's nameservers are doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Health {
    /// At least one of them answers.
    Works,
    /// They are alive and broken.
    Broken,
    /// None of them could be reached: the network, not the resolver.
    Unreachable,
}

/// Remember what the machine is using, so it can be put back.
///
/// The list is the machine's own, in the order the machine prefers it:
/// the nameservers it has now, then the ones its connection is configured
/// with, then the ones the link carries, and a public resolver when the
/// machine has nothing else at all.
///
/// The list is also written down, to [`RESOLVERS_FILE`], because the
/// moment it is needed again is long after this process is gone: the
/// uninstaller, days later, has to give the machine back what it had.
pub fn remember() -> Vec<String> {
    let remembered = first_usable();
    let content = format!("{}\n", remembered.join(" "));
    if let Err(reason) = write_state(RESOLVERS_FILE, &content) {
        log::warn(&format!(
            "could not keep the machine's resolvers for later: {reason}"
        ));
    }
    remembered
}

/// The first list of nameservers worth saving that the machine has.
fn first_usable() -> Vec<String> {
    let from_file = worth_saving(&nameservers());
    if !from_file.is_empty() {
        return from_file;
    }
    let from_connection = worth_saving(&connection_resolvers());
    if !from_connection.is_empty() {
        return from_connection;
    }
    let from_link = worth_saving(&link_resolvers());
    if !from_link.is_empty() {
        return from_link;
    }
    vec![FALLBACK_RESOLVER.to_string()]
}

/// Check the machine's resolver and put the fallback in place if the
/// resolver is alive but broken.
///
/// This is the same work as [`restore`]: the fallback is just a list the
/// caller had in mind, where a remembered list is one the machine used
/// before. The difference that matters is which list: a machine that had
/// its own nameservers before the WARP switch should get THOSE back, not
/// a public resolver that happens to be reachable.
pub fn ensure_resolvable(fallback: &[String]) -> Verdict {
    restore(fallback)
}

/// Put the remembered resolvers back.
///
/// The machine's own resolver is left alone when it works: by the time
/// this is called the owner may have changed it, and a resolver that
/// answers is not a problem to solve.
pub fn restore(remembered: &[String]) -> Verdict {
    let current = nameservers();
    if current.is_empty() {
        log::warn(&format!("there are no nameservers in {RESOLV_CONF}"));
        if remembered.is_empty() {
            log::err("there are no nameservers to put in place; name resolution will fail");
            return Verdict::NoFallback;
        }
        return match apply(remembered) {
            Ok(()) => {
                log::warn(&format!(
                    "the resolver was empty; put {} in place",
                    remembered.join(", ")
                ));
                Verdict::Filled
            }
            Err(reason) => {
                log::err(&format!("could not put a resolver in place: {reason}"));
                Verdict::NoFallback
            }
        };
    }

    match health(&current) {
        Health::Works => Verdict::Kept,
        Health::Unreachable => {
            log::err(&format!(
                "no nameserver in {RESOLV_CONF} could be reached ({}); the network looks down, \
                 rather than the resolver, so the resolver was left alone",
                current.join(", ")
            ));
            Verdict::Unreachable
        }
        Health::Broken => {
            log::warn(&format!(
                "the nameservers in {RESOLV_CONF} do not answer ({})",
                current.join(", ")
            ));
            if remembered.is_empty() {
                log::err("there are no nameservers to put in place; name resolution will fail");
                return Verdict::NoFallback;
            }
            match apply(remembered) {
                Ok(()) => {
                    log::warn(&format!(
                        "the resolver was replaced with {}",
                        remembered.join(", ")
                    ));
                    Verdict::Replaced
                }
                Err(reason) => {
                    log::err(&format!("could not replace the resolver: {reason}"));
                    Verdict::NoFallback
                }
            }
        }
    }
}

/// The nameservers in the machine's resolv.conf, in order.
fn nameservers() -> Vec<String> {
    let Ok(text) = fs::read_to_string(RESOLV_CONF) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            if parts.next()? != "nameserver" {
                return None;
            }
            Some(parts.next()?.to_string())
        })
        .collect()
}

/// The nameservers the machine's own connection is configured with.
///
/// NetworkManager knows the resolvers the network handed it, which is
/// where they are when the file has already been emptied by something
/// else.
fn connection_resolvers() -> Vec<String> {
    let Some(out) = run::capture(
        "nmcli",
        &["-t", "-f", "ipv4.dns", "con", "show", "--active"],
    ) else {
        return Vec::new();
    };
    // The first active connection is the one the machine is using.
    let Some(line) = out.lines().next() else {
        return Vec::new();
    };
    // -t makes the fields colon-separated, so the value is everything
    // after the first colon, and the servers inside it are comma-separated.
    let value = line.split_once(':').map(|(_, rest)| rest).unwrap_or("");
    value
        .split(',')
        .map(|server| server.trim().to_string())
        .filter(|server| !server.is_empty())
        .collect()
}

/// The nameservers the machine's links carry.
fn link_resolvers() -> Vec<String> {
    let Some(out) = run::capture("resolvectl", &["dns", "--no-pager"]) else {
        return Vec::new();
    };
    let mut servers = Vec::new();
    for line in out.lines() {
        // "Link 2 (eth0): 1.1.1.1 8.8.8.8"
        let Some((_, rest)) = line.split_once(':') else {
            continue;
        };
        for token in rest.split_whitespace() {
            if token.parse::<IpAddr>().is_ok() {
                servers.push(token.to_string());
            }
        }
    }
    servers
}

/// The nameservers that are worth saving.
///
/// WARP's own resolver is the one the switch takes away, and Tailscale's
/// (fd7a::) is the tailnet's: neither is a resolver the machine had
/// before somebody else put it there, and putting one of them back would
/// leave the machine with the resolver it just lost. The loopback stub
/// (127.0.0.53) belongs to systemd-resolved and only answers while
/// resolved is running.
fn worth_saving(servers: &[String]) -> Vec<String> {
    servers
        .iter()
        .filter(|server| is_worth_saving(server))
        .take(3)
        .cloned()
        .collect()
}

/// Is this nameserver one the machine can do without?
fn is_worth_saving(server: &str) -> bool {
    let Ok(ip) = server.trim().parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => v4 != WARP_RESOLVER && !v4.is_loopback(),
        IpAddr::V6(v6) => {
            // Tailscale's MagicDNS resolver lives in fd7a::/32.
            !v6.is_loopback() && v6.segments()[0] != 0xfd7a
        }
    }
}

/// How the machine's nameservers are doing.
fn health(servers: &[String]) -> Health {
    let mut broken = false;
    let mut unreachable = false;
    for server in servers {
        match probe(server) {
            Probe::Answer => return Health::Works,
            Probe::Error => broken = true,
            Probe::Timeout => unreachable = true,
        }
    }
    if broken {
        Health::Broken
    } else if unreachable {
        Health::Unreachable
    } else {
        Health::Broken
    }
}

/// Ask one nameserver a question and see what comes back.
///
/// The three answers mean different things, so they are kept apart: an
/// ANSWER is a nameserver that works, an ERROR is one that is alive but
/// broken (it replies SERVFAIL because the one it forwards to is
/// broken), and a TIMEOUT is one that could not be reached at all.
fn probe(server: &str) -> Probe {
    let Ok(ip) = server.trim().parse::<IpAddr>() else {
        return Probe::Timeout;
    };
    let query = build_query(PROBE_NAME, PROBE_TYPE);
    for _attempt in 0..PROBE_ATTEMPTS {
        let Some(reply) = ask(ip, &query) else {
            continue;
        };
        match classify_reply(&reply) {
            Some(result) => return result,
            // A reply too short to be a DNS reply is a dropped packet as
            // far as we are concerned, so it is tried again.
            None => continue,
        }
    }
    Probe::Timeout
}

/// Send the query and wait for the reply. None when nothing came back.
fn ask(server: IpAddr, query: &[u8]) -> Option<Vec<u8>> {
    let bind = match server {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    socket.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;
    socket.send_to(query, SocketAddr::new(server, 53)).ok()?;
    let mut buffer = [0u8; 512];
    let read = socket.recv(&mut buffer).ok()?;
    Some(buffer[..read].to_vec())
}

/// Build a DNS query for one name.
///
/// A query is a 12-byte header, then the name as length-prefixed labels,
/// then the type and the class. Only what this probe needs is built: one
/// question, no EDNS, so the reply stays small and simple to parse.
fn build_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + name.len());
    out.extend_from_slice(&[0x12, 0x34]); // id
    out.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    out.extend_from_slice(&[0x00, 0x01]); // one question
    out.extend_from_slice(&[0x00, 0x00]); // no answers
    out.extend_from_slice(&[0x00, 0x00]); // no authority records
    out.extend_from_slice(&[0x00, 0x00]); // no additional records
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // end of the name
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x01]); // class IN
    out
}

/// Classify a DNS reply.
///
/// A reply that is too short to be a DNS reply at all is not classified
/// (None) and is treated like a dropped packet. A reply with an error
/// code is an ERROR: the nameserver is alive and broken. A reply with no
/// error code but no answers either is an ERROR as well - a resolver
/// that replies NOERROR and gives nothing back resolves nothing.
fn classify_reply(reply: &[u8]) -> Option<Probe> {
    if reply.len() < 12 {
        return None;
    }
    let rcode = reply[3] & 0x0f;
    if rcode != 0 {
        return Some(Probe::Error);
    }
    let answers = u16::from_be_bytes([reply[6], reply[7]]);
    if answers == 0 {
        Some(Probe::Error)
    } else {
        Some(Probe::Answer)
    }
}

/// Put a list of nameservers where the machine actually reads them.
///
/// A resolv.conf that is a plain file is written directly. One that is a
/// SYMLINK is not: systemd-resolved's stub always answers and asks the
/// LINK, so the nameservers belong to the link.
fn apply(servers: &[String]) -> Result<(), String> {
    if servers.is_empty() {
        return Err("there are no nameservers to put in place".to_string());
    }
    if is_symlink(RESOLV_CONF) {
        return apply_to_link(servers);
    }
    write_resolvers(servers)
}

/// Write the nameservers into the machine's resolv.conf.
///
/// Only the nameserver lines are replaced: the machine's search domains
/// and its options are left alone, because they are not WARP's business
/// and the owner may be relying on them.
///
/// The file is written in place rather than replaced by a rename: in a
/// container /etc/resolv.conf is a bind mount, and renaming over one
/// fails with EBUSY.
fn write_resolvers(servers: &[String]) -> Result<(), String> {
    let path = Path::new(RESOLV_CONF);
    let existing = fs::read_to_string(path).unwrap_or_default();

    let mut kept: Vec<&str> = Vec::new();
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.split_whitespace().next() == Some("nameserver") {
            continue;
        }
        kept.push(line);
    }

    let mut body = String::new();
    for server in servers {
        body.push_str("nameserver ");
        body.push_str(server);
        body.push('\n');
    }
    for line in kept {
        body.push_str(line);
        body.push('\n');
    }

    fs::write(path, body).map_err(|e| format!("could not write {RESOLV_CONF}: {e}"))
}

/// Put the nameservers where the machine reads them when the resolv.conf
/// is a symlink.
///
/// The link's own nameservers are set with resolvectl, and NetworkManager
/// is corrected as well: it writes the file again on the next reconnect,
/// so its own idea of the nameservers has to say the same thing.
fn apply_to_link(servers: &[String]) -> Result<(), String> {
    let mut done = false;
    let mut problems: Vec<String> = Vec::new();

    if run::have("resolvectl") {
        match default_interface() {
            Some(interface) => {
                let mut args: Vec<String> = vec!["dns".to_string(), interface.clone()];
                args.extend(servers.iter().cloned());
                let args: Vec<&str> = args.iter().map(|arg| arg.as_str()).collect();
                match run::run("resolvectl", &args) {
                    Ok(out) if out.ok() => done = true,
                    Ok(out) => problems.push(format!(
                        "resolvectl dns {interface} failed: {}",
                        out.reason()
                    )),
                    Err(reason) => problems.push(reason),
                }
            }
            None => {
                problems.push("there is no default interface to set the resolver on".to_string())
            }
        }
    } else {
        problems.push("resolvectl is not installed".to_string());
    }

    if run::have("nmcli") {
        if let Some(connection) = active_connection() {
            let joined = servers.join(",");
            let args = [
                "con",
                "mod",
                &connection,
                "ipv4.dns",
                &joined,
                "ipv4.ignore-auto-dns",
                "yes",
            ];
            match run::run("nmcli", &args) {
                Ok(out) if out.ok() => done = true,
                Ok(out) => problems.push(format!(
                    "nmcli con mod {connection} failed: {}",
                    out.reason()
                )),
                Err(reason) => problems.push(reason),
            }
            if let Some(device) = connection_device(&connection) {
                run::try_run("nmcli", &["device", "reapply", &device]);
            }
        }
    }

    if done {
        Ok(())
    } else {
        Err(format!(
            "the resolver file is a symlink and the nameservers could not be set on the link: {}",
            problems.join("; ")
        ))
    }
}

/// Is the path a symlink?
fn is_symlink(path: &str) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type().is_symlink(),
        Err(_) => false,
    }
}

/// Write a file in the state directory, creating the directory if it is
/// not there yet.
///
/// The directory holds what the machine gets back later, so it is kept
/// private to root.
fn write_state(path: &str, content: &str) -> Result<(), String> {
    fs::create_dir_all(STATE_DIR).map_err(|e| format!("could not create {STATE_DIR}: {e}"))?;
    let _ = fs::set_permissions(STATE_DIR, fs::Permissions::from_mode(0o700));
    fs::write(path, content).map_err(|e| format!("could not write {path}: {e}"))
}

/// The interface the machine's default route goes out of.
fn default_interface() -> Option<String> {
    let out = run::capture("ip", &["route", "show", "default"])?;
    for line in out.lines() {
        let mut tokens = line.split_whitespace();
        while let Some(token) = tokens.next() {
            if token == "dev" {
                if let Some(interface) = tokens.next() {
                    return Some(interface.to_string());
                }
            }
        }
    }
    None
}

/// The connection the machine is using.
fn active_connection() -> Option<String> {
    let out = run::capture("nmcli", &["-t", "-f", "NAME", "con", "show", "--active"])?;
    out.lines()
        .next()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
}

/// The device a connection is on.
fn connection_device(connection: &str) -> Option<String> {
    let out = run::capture("nmcli", &["-t", "-f", "DEVICE", "con", "show", connection])?;
    out.lines()
        .next()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DNS reply header with the given reply code and answer count.
    fn reply_header(rcode: u8, answers: u16) -> Vec<u8> {
        let mut header = vec![0x12, 0x34, 0x81, 0x80 | (rcode & 0x0f)];
        header.extend_from_slice(&[0x00, 0x01]); // one question
        header.extend_from_slice(&answers.to_be_bytes());
        header.extend_from_slice(&[0x00, 0x00]); // no authority records
        header.extend_from_slice(&[0x00, 0x00]); // no additional records
        header
    }

    #[test]
    fn the_query_is_a_recursive_query_for_one_name() {
        let query = build_query(PROBE_NAME, PROBE_TYPE);
        assert_eq!(query[0], 0x12, "id");
        assert_eq!(query[1], 0x34, "id");
        assert_eq!(query[2], 0x01, "standard query");
        assert_eq!(query[3], 0x00, "recursion desired");
        assert_eq!(&query[4..6], &[0x00, 0x01], "one question");
        assert_eq!(&query[6..8], &[0x00, 0x00], "no answers");
        assert_eq!(&query[8..10], &[0x00, 0x00], "no authority records");
        assert_eq!(&query[10..12], &[0x00, 0x00], "no additional records");
    }

    #[test]
    fn the_query_carries_the_name_as_length_prefixed_labels() {
        let query = build_query(PROBE_NAME, PROBE_TYPE);
        let name = &query[12..12 + 13];
        assert_eq!(
            name,
            &[0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00]
        );
        // The type and the class come after the name.
        let tail = &query[query.len() - 4..];
        assert_eq!(&tail[..2], &[0x00, 0x01], "type A");
        assert_eq!(&tail[2..], &[0x00, 0x01], "class IN");
    }

    #[test]
    fn a_reply_with_answers_is_an_answer() {
        assert_eq!(
            classify_reply(&reply_header(0, 1)),
            Some(Probe::Answer),
            "NOERROR with an answer is a working resolver"
        );
    }

    #[test]
    fn a_reply_with_an_error_code_is_an_error() {
        // SERVFAIL, REFUSED and NOTIMP all say the nameserver is there
        // and broken.
        for rcode in [2u8, 5, 4] {
            assert_eq!(
                classify_reply(&reply_header(rcode, 0)),
                Some(Probe::Error),
                "reply code {rcode} is an error, not an answer"
            );
        }
    }

    #[test]
    fn a_reply_with_no_answers_is_an_error() {
        // NOERROR with nothing in it resolves nothing.
        assert_eq!(classify_reply(&reply_header(0, 0)), Some(Probe::Error));
    }

    #[test]
    fn a_reply_that_is_too_short_is_not_classified() {
        assert_eq!(classify_reply(&[]), None);
        assert_eq!(classify_reply(&[0x12, 0x34, 0x81, 0x80]), None);
    }

    #[test]
    fn warps_own_resolver_and_the_loopback_stub_are_not_worth_saving() {
        assert!(!is_worth_saving("100.100.100.100"), "WARP's own resolver");
        assert!(!is_worth_saving("127.0.0.53"), "systemd-resolved's stub");
        assert!(!is_worth_saving("127.0.0.1"), "the loopback");
    }

    #[test]
    fn tailscales_resolver_is_not_worth_saving() {
        assert!(
            !is_worth_saving("fd7a:115c:a1e0::53"),
            "Tailscale's resolver"
        );
        assert!(
            is_worth_saving("2001:4860:4860::8888"),
            "a public IPv6 resolver"
        );
    }

    #[test]
    fn an_ordinary_resolver_is_worth_saving() {
        assert!(is_worth_saving("1.1.1.1"));
        assert!(is_worth_saving("9.9.9.9"));
        assert!(!is_worth_saving("not-an-address"));
    }
}
