//! Which destinations the node is willing to be reached at.
//!
//! The hub opens connections *through* the node, so this filter is the
//! node's half of the gateway's security: what it allows, the gateway can
//! reach, and what it refuses, the gateway cannot. The node is a machine
//! that belongs to somebody else, and the things it must never forward to
//! are the things on that machine - the tunnel, the LAN, the cloud metadata
//! service - and anything that is not on the public internet at all.
//!
//! Two rules, both from the Python proxy this replaces:
//!
//! - only port 443. The hub fetches HTTPS; it has no business asking the
//!   node for anything else.
//! - every address a name resolves to must be global. Not "one of them": a
//!   name that answers with a global address and a private one is a name
//!   that can be pointed at something private, and that is the whole of DNS
//!   rebinding.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// The only port the hub asks the node for.
const ALLOWED_PORT: u16 = 443;

/// The addresses a destination may be reached at, or why it may not.
/// An empty list means the destination is not allowed.
/// The port must be 443 and every resolved address must be global.
///
/// The first address is the one to connect to. The name is resolved once,
/// here, and the connection is made to the address that was checked, which
/// is what stops a name from answering one thing and being connected to
/// another.
pub fn allowed_targets(host: &str, port: u16) -> Vec<IpAddr> {
    if port != ALLOWED_PORT {
        return Vec::new();
    }
    permitted(resolve(host, port))
}

/// Every address must be global, or none of them is.
fn permitted(addresses: Vec<IpAddr>) -> Vec<IpAddr> {
    if addresses.is_empty() {
        return Vec::new();
    }
    if addresses.iter().all(is_global) {
        addresses
    } else {
        Vec::new()
    }
}

/// The addresses a name answers with, in the order the resolver gave them.
fn resolve(host: &str, port: u16) -> Vec<IpAddr> {
    let addresses = match (host, port).to_socket_addrs() {
        Ok(addresses) => addresses,
        Err(_) => return Vec::new(),
    };
    let mut unique: Vec<IpAddr> = Vec::new();
    for address in addresses {
        let ip = address.ip();
        if !unique.contains(&ip) {
            unique.push(ip);
        }
    }
    unique
}

/// True when the address is one the node is willing to be reached at.
///
/// The standard library has an `is_global` of its own, but it is still an
/// unstable feature, so the list is written out here: the ranges the
/// library would use, plus the ones Python's `ipaddress` module uses, which
/// is what the proxy this replaces was written against.
pub fn is_global(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => is_global_v4(addr),
        IpAddr::V6(addr) => is_global_v6(addr),
    }
}

fn is_global_v4(addr: &Ipv4Addr) -> bool {
    let o = addr.octets();
    // The private networks, the loopback, the link-local and the broadcast
    // address: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16 and
    // 255.255.255.255.
    if addr.is_private() || addr.is_loopback() || addr.is_link_local() || addr.is_broadcast() {
        return false;
    }
    // 0.0.0.0/8 - "this network". Not a harmless range: on Linux a
    // connection to 0.0.0.0 arrives at loopback.
    if o[0] == 0 {
        return false;
    }
    // 100.64.0.0/10 - shared address space, the carrier's NAT.
    if o[0] == 100 && o[1] & 0b1100_0000 == 0b0100_0000 {
        return false;
    }
    // 192.0.0.0/29 and 192.0.0.170/31 - IETF protocol assignments.
    if o[0] == 192 && o[1] == 0 && o[2] == 0 && (o[3] < 8 || o[3] == 170 || o[3] == 171) {
        return false;
    }
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 - documentation.
    if o[0] == 192 && o[1] == 0 && o[2] == 2 {
        return false;
    }
    if o[0] == 198 && o[1] == 51 && o[2] == 100 {
        return false;
    }
    if o[0] == 203 && o[1] == 0 && o[2] == 113 {
        return false;
    }
    // 198.18.0.0/15 - benchmarking.
    if o[0] == 198 && o[1] & 0xfe == 18 {
        return false;
    }
    // 240.0.0.0/4 - reserved, and the broadcast address with it.
    if o[0] & 240 == 240 {
        return false;
    }
    true
}

fn is_global_v6(addr: &Ipv6Addr) -> bool {
    let s = addr.segments();
    // The unspecified address, the loopback, the unique local and the
    // link-local addresses, and multicast: ::, ::1, fc00::/7, fe80::/10 and
    // ff00::/8.
    if addr.is_unspecified()
        || addr.is_loopback()
        || addr.is_unique_local()
        || addr.is_unicast_link_local()
        || addr.is_multicast()
    {
        return false;
    }
    // ::ffff:0:0/96 - an IPv4 address in an IPv6 wrapper. The wrapper must
    // not be a way around the IPv4 rules: ::ffff:127.0.0.1 reaches loopback.
    if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0xffff {
        return false;
    }
    // 100::/64 - discard only.
    if s[0] == 0x100 && s[1] == 0 && s[2] == 0 && s[3] == 0 {
        return false;
    }
    // 2001::/23 - IETF protocol assignments (Teredo, benchmarking, ...).
    if s[0] == 0x2001 && s[1] & 0xff00 == 0 {
        return false;
    }
    // 2001:db8::/32 - documentation.
    if s[0] == 0x2001 && s[1] == 0x0db8 && s[2] == 0 && s[3] == 0 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{allowed_targets, is_global, permitted};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(segments: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from(segments))
    }

    #[test]
    fn only_port_443_is_allowed() {
        for port in [0u16, 22, 25, 80, 8080, 8443] {
            assert!(
                allowed_targets("8.8.8.8", port).is_empty(),
                "port {port} was allowed"
            );
        }
        assert_eq!(allowed_targets("8.8.8.8", 443), vec![v4(8, 8, 8, 8)]);
    }

    #[test]
    fn a_public_address_is_allowed() {
        assert_eq!(allowed_targets("8.8.8.8", 443), vec![v4(8, 8, 8, 8)]);
        assert_eq!(allowed_targets("1.1.1.1", 443), vec![v4(1, 1, 1, 1)]);
    }

    #[test]
    fn the_machine_itself_is_refused() {
        // The addresses that are on the node, or on the network the node is
        // on, are exactly what the hub must not be able to reach through it.
        for host in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "0.0.0.0",
            "::1",
        ] {
            assert!(allowed_targets(host, 443).is_empty(), "{host} was allowed");
        }
    }

    #[test]
    fn every_address_must_be_global() {
        // A name that answers with one private address among global ones is
        // refused whole. This is the DNS rebinding case: the check has to be
        // "all of them", not "one of them".
        let mixed = vec![v4(8, 8, 8, 8), v4(127, 0, 0, 1)];
        assert!(permitted(mixed).is_empty());

        let all_global = vec![v4(8, 8, 8, 8), v4(1, 1, 1, 1)];
        assert_eq!(permitted(all_global).len(), 2);
    }

    #[test]
    fn the_special_ranges_are_not_global() {
        for addr in [
            v4(0, 0, 0, 0),
            v4(0, 1, 2, 3),
            v4(10, 0, 0, 1),
            v4(100, 64, 0, 1),
            v4(100, 127, 255, 255),
            v4(127, 0, 0, 1),
            v4(169, 254, 169, 254),
            v4(172, 16, 0, 1),
            v4(192, 0, 0, 1),
            v4(192, 0, 0, 170),
            v4(192, 0, 2, 1),
            v4(192, 168, 1, 1),
            v4(198, 18, 0, 1),
            v4(198, 51, 100, 1),
            v4(203, 0, 113, 1),
            v4(240, 0, 0, 1),
            v4(255, 255, 255, 255),
            v6([0; 8]),
            v6([0, 0, 0, 0, 0, 0, 0, 1]),
            v6([0, 0, 0, 0, 0, 0xffff, 127, 0]),
            v6([0x0100, 0, 0, 0, 0, 0, 0, 1]),
            v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]),
            v6([0x2001, 0, 0, 0, 0, 0, 0, 1]),
            v6([0xfc00, 0, 0, 0, 0, 0, 0, 1]),
            v6([0xfe80, 0, 0, 0, 0, 0, 0, 1]),
        ] {
            assert!(!is_global(&addr), "{addr} was called global");
        }
    }

    #[test]
    fn the_public_addresses_are_global() {
        assert!(is_global(&v4(8, 8, 8, 8)));
        assert!(is_global(&v4(100, 128, 0, 1)));
        assert!(is_global(&v4(172, 32, 0, 1)));
        assert!(is_global(&v4(198, 20, 0, 1)));
        assert!(is_global(&v6([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888])));
    }
}
