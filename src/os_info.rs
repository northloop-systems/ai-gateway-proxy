//! What this machine is.
//!
//! The node installs itself on somebody else's Linux box, and it needs to
//! know two things about it: which package manager will fetch WireGuard,
//! and what the machine calls itself. The name matters more than it looks -
//! the hub binds a token to a node NAME, and that name is what the node is
//! known by from then on, so it has to be something a machine can answer to
//! and a hub can match on. That is why it is reduced to letters, digits and
//! dashes: a name with a space in it is a name that has to be quoted,
//! escaped or URL-encoded somewhere, and every one of those places is a
//! place a name can be lost.

/// The distribution, as far as the node cares.
///
/// The variants are the package managers, not the products: Ubuntu and
/// Mint are Debian, Rocky and Alma are Red Hat, Manjaro is Arch. What the
/// node needs to know is which `apt`/`dnf`/`yum`/`pacman` to call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distro {
    Debian,
    Fedora,
    RedHat,
    Arch,
    Unknown,
}

impl Distro {
    /// The name to show the operator.
    pub fn name(&self) -> &'static str {
        match self {
            Distro::Debian => "Debian",
            Distro::Fedora => "Fedora",
            Distro::RedHat => "Red Hat",
            Distro::Arch => "Arch",
            Distro::Unknown => "Unknown",
        }
    }
}

/// The file every modern distribution agrees on.
const OS_RELEASE: &str = "/etc/os-release";

/// What the hub is told when the public address cannot be found. The hub
/// accepts it, and an honest "unknown" is better than a wrong address
/// that the node's own name would then have to explain.
const UNKNOWN_IP: &str = "unknown";

/// Detect the distribution from /etc/os-release (ID and ID_LIKE).
/// A missing or unreadable file is Unknown, not a crash.
pub fn detect() -> Distro {
    let text = match std::fs::read_to_string(OS_RELEASE) {
        Ok(text) => text,
        Err(_) => return Distro::Unknown,
    };
    classify(&value_of(&text, "ID"), &value_of(&text, "ID_LIKE"))
}

/// The machine's hostname, lowercased and stripped of anything that is not
/// a letter, a digit or a dash. The hub binds a token to a node NAME, and
/// the name is what the node is known by.
pub fn hostname() -> String {
    let name = sanitise(&raw_hostname());
    if name.is_empty() {
        // A machine with no usable name still has to have one, and
        // "node" is a name the hub will accept.
        "node".to_string()
    } else {
        name
    }
}

/// The machine's public IP, as the hub wants it. Ask api.ipify.org. If it
/// cannot be reached, the string "unknown" - the hub accepts that.
pub fn public_ip() -> String {
    let answer = crate::run::capture("curl", &["-s", "-m", "10", "https://api.ipify.org"]);
    match answer {
        Some(answer) => {
            let first = answer.lines().next().unwrap_or("").trim();
            if looks_like_an_ip(first) {
                first.to_string()
            } else {
                UNKNOWN_IP.to_string()
            }
        }
        None => UNKNOWN_IP.to_string(),
    }
}

/// The name the machine gives itself, before it is made safe to use.
fn raw_hostname() -> String {
    if let Some(name) = crate::run::capture("hostname", &[]) {
        if !name.trim().is_empty() {
            return name.trim().to_string();
        }
    }
    // The command is not always there, but the kernel always knows.
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(name) = std::fs::read_to_string(path) {
            if !name.trim().is_empty() {
                return name.trim().to_string();
            }
        }
    }
    String::new()
}

/// Reduce a name to what a hub, a URL and a log line can all carry.
fn sanitise(raw: &str) -> String {
    let mut name = String::with_capacity(raw.len());
    for ch in raw.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() || lower == '-' {
            name.push(lower);
        }
    }
    // A leading or trailing dash is decoration, not a name, and some
    // resolvers treat it as an option.
    name.trim_matches('-').to_string()
}

/// One field out of an os-release file.
fn value_of(text: &str, key: &str) -> String {
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix(key) else {
            continue;
        };
        let Some(value) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        return value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
    }
    String::new()
}

/// Turn an os-release ID and ID_LIKE into a distribution.
fn classify(id: &str, id_like: &str) -> Distro {
    let id = id.trim().to_ascii_lowercase();
    match id.as_str() {
        "debian" | "ubuntu" | "linuxmint" | "raspbian" | "pop" | "elementary" => {
            return Distro::Debian
        }
        "fedora" => return Distro::Fedora,
        "rhel" | "centos" | "rocky" | "almalinux" | "ol" | "oracle" | "scientific" => {
            return Distro::RedHat
        }
        "arch" | "manjaro" | "endeavouros" | "archarm" => return Distro::Arch,
        _ => {}
    }
    // ID_LIKE is a derivative saying what it is like. Red Hat comes before
    // Fedora in this list, because a Red Hat derivative lists both and is
    // not a Fedora one.
    for token in id_like.to_ascii_lowercase().split_whitespace() {
        match token {
            "debian" => return Distro::Debian,
            "rhel" => return Distro::RedHat,
            "fedora" => return Distro::Fedora,
            "arch" => return Distro::Arch,
            _ => {}
        }
    }
    Distro::Unknown
}

/// Does this look like an address rather than a message?
///
/// The answer comes back over the network, so it is checked before it is
/// handed to the hub. A refusal page or a captive portal's login screen is
/// not an address, and sending one to the hub as the node's public IP
/// would be a lie the hub believes.
fn looks_like_an_ip(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
        && text.chars().any(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_keeps_only_letters_digits_and_dashes() {
        assert_eq!(sanitise("Node_1"), "node1");
        assert_eq!(sanitise("my-node"), "my-node");
        assert_eq!(sanitise("webhead1104"), "webhead1104");
    }

    #[test]
    fn a_name_is_lowercased() {
        assert_eq!(sanitise("MUDKIP"), "mudkip");
        assert_eq!(sanitise("MiXeD"), "mixed");
    }

    #[test]
    fn everything_else_is_dropped() {
        assert_eq!(sanitise("node.example.com"), "nodeexamplecom");
        assert_eq!(sanitise("héllo"), "hllo");
        assert_eq!(sanitise("node name"), "nodename");
        assert_eq!(sanitise("node\tname"), "nodename");
    }

    #[test]
    fn a_name_does_not_start_or_end_with_a_dash() {
        assert_eq!(sanitise("-edge-"), "edge");
        assert_eq!(sanitise("---"), "");
    }

    #[test]
    fn an_empty_name_falls_back_to_something_the_hub_accepts() {
        assert_eq!(hostname_of(""), "node");
        assert_eq!(hostname_of("..."), "node");
    }

    /// The same fallback, without asking the machine what it is called.
    fn hostname_of(raw: &str) -> String {
        let name = sanitise(raw);
        if name.is_empty() {
            "node".to_string()
        } else {
            name
        }
    }

    #[test]
    fn the_id_decides() {
        assert_eq!(classify("debian", ""), Distro::Debian);
        assert_eq!(classify("ubuntu", "debian"), Distro::Debian);
        assert_eq!(classify("fedora", "fedora"), Distro::Fedora);
        assert_eq!(classify("rhel", "fedora"), Distro::RedHat);
        assert_eq!(classify("rocky", "rhel centos fedora"), Distro::RedHat);
        assert_eq!(classify("arch", ""), Distro::Arch);
        assert_eq!(classify("manjaro", "arch"), Distro::Arch);
    }

    #[test]
    fn a_derivative_falls_back_to_what_it_is_like() {
        assert_eq!(classify("nobara", "fedora"), Distro::Fedora);
        assert_eq!(classify("unknown-distro", "debian"), Distro::Debian);
        assert_eq!(classify("unknown-distro", "arch"), Distro::Arch);
    }

    #[test]
    fn a_red_hat_derivative_is_not_mistaken_for_fedora() {
        // RHEL lists both in ID_LIKE, and it is a Red Hat machine.
        assert_eq!(classify("something-new", "rhel fedora"), Distro::RedHat);
    }

    #[test]
    fn an_unrecognised_distribution_is_unknown() {
        assert_eq!(classify("plan9", "illumos"), Distro::Unknown);
        assert_eq!(classify("", ""), Distro::Unknown);
    }

    #[test]
    fn os_release_fields_are_read_out_of_the_file() {
        let text = "NAME=\"Debian GNU/Linux\"\nID=debian\nID_LIKE=\"rhel fedora\"\n";
        assert_eq!(value_of(text, "ID"), "debian");
        assert_eq!(value_of(text, "ID_LIKE"), "rhel fedora");
        assert_eq!(value_of(text, "VERSION"), "");
    }

    #[test]
    fn the_distribution_has_a_name_to_show() {
        assert_eq!(Distro::Debian.name(), "Debian");
        assert_eq!(Distro::Fedora.name(), "Fedora");
        assert_eq!(Distro::RedHat.name(), "Red Hat");
        assert_eq!(Distro::Arch.name(), "Arch");
        assert_eq!(Distro::Unknown.name(), "Unknown");
    }

    #[test]
    fn only_something_that_looks_like_an_address_is_believed() {
        assert!(looks_like_an_ip("104.28.219.196"));
        assert!(looks_like_an_ip("2606:4700::1"));
        assert!(!looks_like_an_ip(""));
        assert!(!looks_like_an_ip("unknown"));
        assert!(!looks_like_an_ip("<html>login</html>"));
    }
}
