//! The packages a node needs, and how to install them.
//!
//! A node needs four things from its distribution: Tor (the Tor exit),
//! WireGuard's tools (`wg` and `wg-quick`), socat (the bridges that put
//! Tor's and WARP's local ports on the tunnel address) and curl (the
//! program has no TLS stack of its own and shells out to curl for the
//! hub, because a TLS stack is the largest dependency tree a program
//! like this could have).
//!
//! iptables comes along with them: the tunnel's firewall rules are
//! wg-quick's PostUp/PostDown hooks, so a machine without iptables cannot
//! bring the tunnel up at all - and that shows up on the hub as a node
//! that registered and carries nothing.
//!
//! The package NAME is not the same everywhere - what Debian calls
//! `iptables` is `iptables-nft` on every other distribution - so the
//! list is per distribution rather than one list that is wrong on some
//! of them.

use std::path::Path;

use crate::fs_util;
use crate::log;
use crate::run;

/// Where the machine says what it is.
const OS_RELEASE: &str = "/etc/os-release";

/// A package, and the command it puts on the PATH.
///
/// The command is how "is it already installed?" is answered. Asking the
/// package manager would mean asking it about a name it may spell
/// differently from the way the tool was really installed (a backport, a
/// tarball), while the command is the thing that actually has to work.
pub type Package = (&'static str, &'static str);

/// Debian and Ubuntu. `wireguard-tools` is the package that provides
/// `wg` and `wg-quick`; the kernel module is in the kernel.
const DEBIAN_PACKAGES: &[Package] = &[
    ("tor", "tor"),
    ("wireguard-tools", "wg"),
    ("socat", "socat"),
    ("curl", "curl"),
    ("iptables", "iptables"),
];

/// Fedora. Everything is the same except the iptables package, which is
/// the nft-based one under that name.
const FEDORA_PACKAGES: &[Package] = &[
    ("tor", "tor"),
    ("wireguard-tools", "wg"),
    ("socat", "socat"),
    ("curl", "curl"),
    ("iptables-nft", "iptables"),
];

/// CentOS, RHEL, Rocky, AlmaLinux. The same names as Fedora's.
const REDHAT_PACKAGES: &[Package] = &[
    ("tor", "tor"),
    ("wireguard-tools", "wg"),
    ("socat", "socat"),
    ("curl", "curl"),
    ("iptables-nft", "iptables"),
];

/// Arch and Manjaro. The same names again.
const ARCH_PACKAGES: &[Package] = &[
    ("tor", "tor"),
    ("wireguard-tools", "wg"),
    ("socat", "socat"),
    ("curl", "curl"),
    ("iptables-nft", "iptables"),
];

/// What this machine is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distro {
    Debian,
    Fedora,
    RedHat,
    Arch,
    Unknown,
}

impl std::fmt::Display for Distro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Distro::Debian => "debian",
            Distro::Fedora => "fedora",
            Distro::RedHat => "rhel",
            Distro::Arch => "arch",
            Distro::Unknown => "unknown",
        };
        f.write_str(name)
    }
}

/// What this machine is.
///
/// Read from /etc/os-release, never from the kernel: the kernel says
/// what the hardware is, and the distribution says how packages are
/// installed. A machine with no os-release is an old Debian or Red Hat,
/// recognised the way the shell installer recognised it - by the
/// release file it had been carrying for decades.
pub fn detect() -> Distro {
    if let Some(text) = fs_util::read_to_string(Path::new(OS_RELEASE)) {
        return detect_from_os_release(&text);
    }
    if Path::new("/etc/debian_version").exists() {
        return Distro::Debian;
    }
    if Path::new("/etc/redhat-release").exists() {
        return Distro::RedHat;
    }
    Distro::Unknown
}

/// What this machine is, from the content of an os-release file.
///
/// The ID says what the machine is; ID_LIKE says what it is LIKE, and a
/// distribution that is like another one is installed the same way - so a
/// machine whose ID is unfamiliar but whose ID_LIKE names a known family
/// is still a machine this installer knows how to install on. The ID is
/// looked at first: it is the more specific answer.
pub fn detect_from_os_release(content: &str) -> Distro {
    let id = field(content, "ID").unwrap_or_default();
    let id_like = field(content, "ID_LIKE").unwrap_or_default();
    for token in id.split_whitespace().chain(id_like.split_whitespace()) {
        if let Some(distro) = from_token(token) {
            return distro;
        }
    }
    Distro::Unknown
}

/// The packages this node needs on this distribution.
pub fn packages_for(distro: Distro) -> &'static [Package] {
    match distro {
        Distro::Debian => DEBIAN_PACKAGES,
        Distro::Fedora => FEDORA_PACKAGES,
        Distro::RedHat => REDHAT_PACKAGES,
        Distro::Arch => ARCH_PACKAGES,
        Distro::Unknown => &[],
    }
}

/// Install the packages the node needs. Returns the list of what it ran.
///
/// Only the packages that are actually missing are installed: an
/// installer that stops on a question the operator cannot see is a bad
/// installer, and `pacman -S` on a package that is already there asks
/// whether to reinstall it.
///
/// The install is non-interactive throughout - `DEBIAN_FRONTEND` for apt,
/// `-y` for the others - because this runs from a pipe with nobody
/// watching it.
pub fn install_required() -> Result<Vec<String>, String> {
    let distro = detect();
    let packages = packages_for(distro);
    if packages.is_empty() {
        return Err(format!(
            "this machine is not a distribution this installer knows ({distro}). \
             Install these by hand and run the installer again: tor, wireguard-tools, socat, curl, iptables"
        ));
    }

    let missing: Vec<&'static str> = packages
        .iter()
        .filter(|(_, provides)| !command_present(provides))
        .map(|(name, _)| *name)
        .collect();

    if missing.is_empty() {
        log::step("the packages the node needs are already installed");
        return Ok(Vec::new());
    }

    let mut ran = Vec::new();

    // The package lists have to be current before a package that is not
    // installed yet can be found. A failed update is not fatal: the
    // lists already on the machine may well have what is needed, and
    // refusing to try is how an installer becomes the reason a node does
    // not come up.
    if distro == Distro::Debian {
        ran.push("apt-get update -qq".to_string());
        match run::run("apt-get", &["update", "-qq"]) {
            Ok(out) if !out.ok() => log::warn(&format!(
                "apt-get update did not succeed ({}); trying the install anyway",
                out.reason()
            )),
            Ok(_) => {}
            Err(message) => log::warn(&format!(
                "could not run apt-get update ({message}); trying the install anyway"
            )),
        }
    }

    let manager = package_manager(distro);
    let mut args: Vec<&str> = Vec::new();
    match distro {
        Distro::Debian => args.extend(["install", "-y", "-qq"]),
        Distro::Fedora | Distro::RedHat => args.extend(["install", "-y", "-q"]),
        // --needed: skip what is already installed instead of asking
        // whether to reinstall it.
        Distro::Arch => args.extend(["-Sy", "--noconfirm", "--needed"]),
        Distro::Unknown => {}
    }
    args.extend(missing.iter().copied());

    let command = format!("{manager} {}", args.join(" "));
    ran.push(command.clone());

    let outcome = match distro {
        // apt asks questions (which version of a package?) and a
        // non-interactive frontend is the only way to say "no, do not
        // ask" - DEBIAN_FRONTEND=noninteractive does exactly that.
        Distro::Debian => {
            let mut full: Vec<&str> = vec!["DEBIAN_FRONTEND=noninteractive", "apt-get"];
            full.extend(args.iter().copied());
            run::run("env", &full)
        }
        _ => run::run(manager, &args),
    };

    match outcome {
        Ok(out) if out.ok() => Ok(ran),
        Ok(out) => Err(format!(
            "{command} could not install {}: {}. Install them by hand with '{command}' and run the installer again.",
            missing.join(", "),
            out.reason()
        )),
        Err(message) => Err(format!(
            "{command} could not install {}: {message}. Install them by hand with '{command}' and run the installer again.",
            missing.join(", ")
        )),
    }
}

/// The package manager for this distribution.
///
/// Fedora and the Red Hat family are both dnf these days - on RHEL 7
/// and CentOS 7 it is still yum, so the other name is used when the
/// first one is not there.
fn package_manager(distro: Distro) -> &'static str {
    match distro {
        Distro::Debian => "apt-get",
        Distro::Fedora | Distro::RedHat => {
            if run::have("dnf") {
                "dnf"
            } else {
                "yum"
            }
        }
        Distro::Arch => "pacman",
        Distro::Unknown => "",
    }
}

/// Is the program this package provides already on the machine?
fn command_present(name: &str) -> bool {
    if run::have(name) {
        return true;
    }
    // The PATH of a service, a cron job or a non-login shell may not
    // include /usr/sbin, which is where iptables lives on most
    // distributions - so a package that IS installed would look missing
    // and the installer would try to install it again.
    ["/usr/bin", "/usr/sbin", "/sbin", "/bin", "/usr/local/bin"]
        .iter()
        .any(|dir| Path::new(dir).join(name).exists())
}

/// One family name from an os-release file.
fn from_token(token: &str) -> Option<Distro> {
    match token {
        "debian" | "ubuntu" => Some(Distro::Debian),
        "fedora" => Some(Distro::Fedora),
        "rhel" | "centos" | "rocky" | "almalinux" | "ol" | "oracle" => Some(Distro::RedHat),
        "arch" | "manjaro" => Some(Distro::Arch),
        _ => None,
    }
}

/// One field of an os-release file.
///
/// The file is shell-like: `KEY=value`, with the value optionally
/// quoted. Only the first match is taken, which is what the shell's own
/// sourcing of the file does.
fn field(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = match line.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };
        if name.trim() != key {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        return Some(value.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debian_and_ubuntu_are_debian() {
        assert_eq!(
            detect_from_os_release("ID=debian\nID_LIKE=debian\n"),
            Distro::Debian
        );
        assert_eq!(
            detect_from_os_release("ID=ubuntu\nID_LIKE=debian\n"),
            Distro::Debian
        );
    }

    #[test]
    fn fedora_is_fedora() {
        assert_eq!(
            detect_from_os_release("ID=fedora\nVERSION_ID=40\n"),
            Distro::Fedora
        );
    }

    #[test]
    fn the_red_hat_family_is_redhat() {
        for id in ["rhel", "centos", "rocky", "almalinux"] {
            assert_eq!(
                detect_from_os_release(&format!("ID={id}\n")),
                Distro::RedHat,
                "{id} should be recognised"
            );
        }
    }

    #[test]
    fn arch_and_manjaro_are_arch() {
        assert_eq!(detect_from_os_release("ID=arch\n"), Distro::Arch);
        assert_eq!(
            detect_from_os_release("ID=manjaro\nID_LIKE=arch\n"),
            Distro::Arch
        );
    }

    #[test]
    fn an_unknown_id_like_a_known_family_is_recognised() {
        // Pop!_OS and Linux Mint are not in the list, but they are
        // Debian machines and are installed with apt.
        assert_eq!(
            detect_from_os_release("ID=pop\nID_LIKE=\"ubuntu debian\"\n"),
            Distro::Debian
        );
        assert_eq!(
            detect_from_os_release("ID=linuxmint\nID_LIKE=ubuntu debian\n"),
            Distro::Debian
        );
    }

    #[test]
    fn the_id_wins_over_id_like() {
        // Rocky is Red Hat's rebuild; its ID_LIKE also mentions fedora,
        // and it must not end up on dnf's package list by accident.
        assert_eq!(
            detect_from_os_release("ID=rocky\nID_LIKE=\"rhel centos fedora\"\n"),
            Distro::RedHat
        );
    }

    #[test]
    fn an_unknown_machine_is_unknown() {
        assert_eq!(detect_from_os_release("ID=plan9\n"), Distro::Unknown);
        assert_eq!(detect_from_os_release(""), Distro::Unknown);
        assert_eq!(
            detect_from_os_release("NAME=\"Nothing\"\n"),
            Distro::Unknown
        );
    }

    #[test]
    fn a_quoted_field_is_unquoted() {
        assert_eq!(
            field("ID_LIKE=\"ubuntu debian\"\n", "ID_LIKE"),
            Some("ubuntu debian".to_string())
        );
    }

    #[test]
    fn a_comment_is_not_a_field() {
        assert_eq!(field("# ID=debian\n", "ID"), None);
    }

    #[test]
    fn every_distribution_gets_wireguard_tools() {
        // wireguard-tools is the package that provides `wg`; the kernel
        // module is in the kernel.
        for distro in [Distro::Debian, Distro::Fedora, Distro::RedHat, Distro::Arch] {
            let packages = packages_for(distro);
            assert!(
                packages.contains(&("wireguard-tools", "wg")),
                "{distro} should install wireguard-tools"
            );
            assert!(
                packages.contains(&("tor", "tor")),
                "{distro} should install tor"
            );
            assert!(
                packages.contains(&("socat", "socat")),
                "{distro} should install socat"
            );
            assert!(
                packages.contains(&("curl", "curl")),
                "{distro} should install curl"
            );
        }
    }

    #[test]
    fn the_iptables_package_is_named_the_way_the_distribution_names_it() {
        assert!(packages_for(Distro::Debian).contains(&("iptables", "iptables")));
        assert!(packages_for(Distro::Fedora).contains(&("iptables-nft", "iptables")));
        assert!(packages_for(Distro::RedHat).contains(&("iptables-nft", "iptables")));
        assert!(packages_for(Distro::Arch).contains(&("iptables-nft", "iptables")));
    }

    #[test]
    fn an_unknown_distribution_has_no_package_list() {
        assert!(packages_for(Distro::Unknown).is_empty());
    }
}
