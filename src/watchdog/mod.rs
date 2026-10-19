//! The tunnel watchdog.
//!
//! A node that is registered but has no tunnel carries nothing, and the
//! hub cannot tell that apart from a node that is not there: both look
//! like an unreachable address. So the node watches its own tunnel and
//! puts it back.
//!
//! This is not belt-and-braces. A real node lost its tunnel's address
//! entirely - wg-quick was stopped by something that was not wg-quick -
//! and what was left behind was an interface that LOOKED fine and carried
//! nothing, until somebody noticed the exits were down.
//!
//! Two ways the tunnel goes bad, and they are told apart:
//!
//!   - the interface is gone, or it has lost its address: the tunnel is
//!     rebuilt. Nothing about the tunnel works in this state.
//!   - the interface is up but the peer has gone quiet, so the handshake
//!     is stale: the hub is poked with a keepalive FIRST. A hub that is
//!     alive but not talking only needs the node to initiate, and a
//!     keepalive is the cheapest way to make it. If it is still stale on
//!     a later run, the tunnel is rebuilt then - the poke was not the
//!     answer, so the answer is somewhere else.
//!
//! The node's address and the hub's public key come from the files the
//! installer wrote, so the watchdog needs nothing of its own.

use crate::log;
use crate::run;
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// The interface the node's tunnel is on.
const WG_IF: &str = "wg0";

/// The address the hub assigned to this node.
const WG_IP_FILE: &str = "/opt/proxy-node/wg_ip";

/// The hub's WireGuard public key: the peer to poke.
const HUB_KEY_FILE: &str = "/opt/proxy-node/wg_hub_public.key";

/// The tunnel's own configuration. Without it there is nothing to rebuild.
const WG_CONFIG: &str = "/etc/wireguard/wg0.conf";

/// A marker saying the last run poked the hub and the handshake was
/// still stale afterwards.
const POKE_MARKER: &str = "/opt/proxy-node/watchdog.poke";

/// How old a handshake may get before the tunnel counts as stale.
const STALE_SECONDS: u64 = 180;

/// The keepalive the poke sets, in seconds.
const KEEPALIVE: u32 = 25;

/// The tag the message is filed under in the machine's own log.
const LOG_TAG: &str = "proxy-tunnel-watchdog";

/// What the check found and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// The tunnel is fine.
    Ok,
    /// The tunnel was rebuilt.
    Rebuilt,
    /// The hub was not answering, so it was poked.
    Poked,
    /// There is no tunnel to check.
    NoTunnel,
}

impl Action {
    /// The action in words, for the operator's log.
    pub fn describe(self) -> &'static str {
        match self {
            Action::Ok => "the tunnel is fine",
            Action::Rebuilt => "the tunnel was rebuilt",
            Action::Poked => "the hub was poked with a keepalive",
            Action::NoTunnel => "there is no tunnel to check",
        }
    }
}

/// What the machine says about the tunnel.
#[derive(Debug, Clone)]
struct Observation {
    /// The interface is there.
    interface: bool,
    /// The interface has the address the hub assigned.
    address: bool,
    /// The address the hub assigned, for the log.
    assigned: String,
    /// How long ago the hub last handshook, in seconds. None when there
    /// has never been a handshake.
    handshake_age: Option<u64>,
    /// The last run poked the hub, and when.
    ///
    /// The time, not just the fact: a poke needs a moment to work, and a
    /// tunnel that has just been brought up has not shaken hands yet.
    poked_at: Option<u64>,
}

/// What to do about an observation, and why.
#[derive(Debug, Clone)]
struct Decision {
    action: Action,
    reason: String,
}

/// Check the tunnel and act. The tunnel's address and the hub's public key
/// are read from /opt/proxy-node/wg_ip and /opt/proxy-node/wg_hub_public.key.
///
/// What was found is written to the machine's log, because a watchdog
/// that acts quietly is a watchdog nobody trusts.
pub fn check() -> Action {
    match assess() {
        Ok(decision) => {
            if decision.action != Action::Ok {
                log::warn(&decision.reason);
            }
            decision.action
        }
        Err(message) => {
            log::warn(&message);
            Action::NoTunnel
        }
    }
}

/// The watchdog as the systemd timer runs it: check, and say what it did
/// in the machine's own log.
///
/// A broken tunnel is a finding, not an error: it is reported, and the
/// timer comes round again in a minute. The error arm is for a watchdog
/// that could not run at all.
pub fn run() -> Result<String, String> {
    let action = check();
    let message = action.describe().to_string();
    journal(&message);
    match action {
        Action::Ok => log::step(&message),
        _ => log::warn(&message),
    }
    Ok(message)
}

/// Look at the tunnel, and do what the looking says.
fn assess() -> Result<Decision, String> {
    if !Path::new(WG_CONFIG).exists() {
        // The node was never configured, or its tunnel is not this node's
        // business any more. There is nothing to check, and nothing to
        // rebuild.
        return Ok(Decision {
            action: Action::NoTunnel,
            reason: format!("there is no {WG_CONFIG}"),
        });
    }

    let assigned = read_trimmed(WG_IP_FILE)?.unwrap_or_default();
    let observation = Observation {
        interface: interface_exists(),
        address: has_address(&assigned),
        assigned,
        handshake_age: handshake_age(),
        poked_at: poke_time(),
    };

    let decision = decide(&observation);
    match decision.action {
        Action::Ok => {
            forget_poke();
            Ok(decision)
        }
        Action::Rebuilt => {
            forget_poke();
            match rebuild() {
                Ok(()) => Ok(decision),
                Err(reason) => Ok(Decision {
                    action: Action::NoTunnel,
                    reason: format!("{} ({reason})", decision.reason),
                }),
            }
        }
        Action::Poked => match poke() {
            Ok(()) => {
                remember_poke();
                Ok(decision)
            }
            Err(reason) => {
                // The keepalive could not even be set, so the tunnel is
                // broken in a way a poke cannot fix.
                forget_poke();
                match rebuild() {
                    Ok(()) => Ok(Decision {
                        action: Action::Rebuilt,
                        reason: format!("{} ({reason})", decision.reason),
                    }),
                    Err(reason) => Ok(Decision {
                        action: Action::NoTunnel,
                        reason: format!("{} ({reason})", decision.reason),
                    }),
                }
            }
        },
        Action::NoTunnel => Ok(decision),
    }
}

/// What to do about what the machine says.
///
/// The order matters: an interface that is gone, or one that has lost
/// its address, is rebuilt whatever the handshake says, because a tunnel
/// without an address carries nothing however recently it handshook.
fn decide(observation: &Observation) -> Decision {
    if !observation.interface {
        return Decision {
            action: Action::Rebuilt,
            reason: "the tunnel interface is gone".to_string(),
        };
    }
    if !observation.address {
        return Decision {
            action: Action::Rebuilt,
            reason: format!(
                "the tunnel interface has lost its address ({})",
                observation.assigned
            ),
        };
    }

    let stale = match observation.handshake_age {
        Some(age) => age > STALE_SECONDS,
        // No handshake has ever happened: the tunnel carries nothing, and
        // it is the same problem as a stale one.
        None => true,
    };
    if !stale {
        return Decision {
            action: Action::Ok,
            reason: format!(
                "the last handshake was {}s ago",
                observation.handshake_age.unwrap_or(0)
            ),
        };
    }

    let reason = match observation.handshake_age {
        Some(age) => format!("the last handshake was {age}s ago"),
        None => "there has never been a handshake".to_string(),
    };
    // A poke is a QUESTION, not an answer: it asks the hub to start the
    // handshake, and the hub needs a moment to do it. Rebuilding the tunnel
    // because the peer has not answered YET is how a watchdog tears down a
    // tunnel that was working - the tunnel that was just brought up has not
    // had time to shake hands, and the marker left behind by an earlier run
    // says it was already poked. So the poke is given its chance, and the
    // tunnel is only rebuilt once the poke has had GRACE_SECONDS to work.
    match observation.poked_at {
        Some(at) if now_seconds().saturating_sub(at) < GRACE_SECONDS => Decision {
            action: Action::Ok,
            reason: format!(
                "{reason}, and the hub was poked {}s ago",
                now_seconds() - at
            ),
        },
        Some(at) => Decision {
            action: Action::Rebuilt,
            reason: format!(
                "{reason}, and the keepalive poke {}s ago did not help",
                now_seconds() - at
            ),
        },
        None => Decision {
            action: Action::Poked,
            reason,
        },
    }
}

/// How long a poke is given to work before the tunnel is rebuilt.
const GRACE_SECONDS: u64 = 120;

/// The current time, in seconds. A clock that jumps backwards is not a
/// reason to rebuild a tunnel, so the age is never negative.
fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Is the tunnel interface there?
fn interface_exists() -> bool {
    match run::run("ip", &["link", "show", "dev", WG_IF]) {
        Ok(out) => out.ok(),
        Err(_) => false,
    }
}

/// Does the interface have the address the hub assigned?
fn has_address(assigned: &str) -> bool {
    if assigned.is_empty() {
        // Nothing to compare against: as far as anyone can tell, the
        // address cannot be missing.
        return true;
    }
    let Some(out) = run::capture("ip", &["-4", "addr", "show", "dev", WG_IF]) else {
        return false;
    };
    let prefix = format!("{assigned}/");
    let mut after_inet = false;
    for line in out.lines() {
        for token in line.split_whitespace() {
            if after_inet {
                if token.starts_with(&prefix) {
                    return true;
                }
                break;
            }
            if token == "inet" {
                after_inet = true;
            }
        }
    }
    false
}

/// How long ago the hub last handshook, in seconds.
///
/// None when there has never been a handshake, or when the interface
/// cannot be asked.
fn handshake_age() -> Option<u64> {
    let out = run::capture("wg", &["show", WG_IF, "latest-handshakes"])?;
    let mut newest: u64 = 0;
    for line in out.lines() {
        // "PEERKEY<TAB>TIMESTAMP"
        let Some((_, stamp)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if let Ok(value) = stamp.trim().parse::<u64>() {
            if value > newest {
                newest = value;
            }
        }
    }
    if newest == 0 {
        return None;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(now.saturating_sub(newest))
}

/// Poke the hub with a keepalive.
///
/// A hub that is alive but not talking only needs the node to say
/// something: the handshake is initiated by the node, so a keepalive is
/// the cheapest way to start one.
fn poke() -> Result<(), String> {
    let key = read_trimmed(HUB_KEY_FILE)?.unwrap_or_default();
    if key.is_empty() {
        return Err("the hub's public key is not known, so there is no peer to poke".to_string());
    }
    let keepalive = KEEPALIVE.to_string();
    let out = run::run(
        "wg",
        &[
            "set",
            WG_IF,
            "peer",
            &key,
            "persistent-keepalive",
            &keepalive,
        ],
    )
    .map_err(|reason| format!("could not poke the hub: {reason}"))?;
    if !out.ok() {
        return Err(format!("could not poke the hub: {}", out.reason()));
    }
    Ok(())
}

/// Put the tunnel back.
fn rebuild() -> Result<(), String> {
    let unit = format!("wg-quick@{WG_IF}");
    let out = run::run("systemctl", &["restart", &unit])
        .map_err(|reason| format!("could not restart {unit}: {reason}"))?;
    if !out.ok() {
        return Err(format!("{unit} would not start: {}", out.reason()));
    }
    Ok(())
}

/// Note that the hub was poked, and when, so the next run knows the poke did
/// not help - and knows how long it has had to work.
fn remember_poke() {
    let _ = fs::write(POKE_MARKER, now_seconds().to_string().as_bytes());
}

/// When the hub was last poked, if it was.
fn poke_time() -> Option<u64> {
    let text = fs::read_to_string(POKE_MARKER).ok()?;
    text.trim().parse::<u64>().ok()
}

/// Forget the poke: the tunnel is working again, or it was rebuilt.
fn forget_poke() {
    let _ = fs::remove_file(POKE_MARKER);
}

/// Forget the poke, from outside.
///
/// The installer calls this when it brings the tunnel up: a tunnel that has
/// just been started has not shaken hands yet, and the marker an earlier run
/// left behind would make the watchdog tear it straight down again.
pub fn reset() {
    forget_poke();
}

/// Read a file and trim it. None when the file is not there.
fn read_trimmed(path: &str) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let trimmed = text.trim().to_string();
            Ok(if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("could not read {path}: {e}")),
    }
}

/// Say it in the machine's own log, where the operator will look.
///
/// The systemd timer runs this every minute, so what it did has to be
/// visible without the operator tailing a terminal.
fn journal(message: &str) {
    if !run::have("logger") {
        return;
    }
    run::try_run("logger", &["-t", LOG_TAG, "--", message]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(
        interface: bool,
        address: bool,
        handshake_age: Option<u64>,
        poked_at: Option<u64>,
    ) -> Observation {
        Observation {
            interface,
            address,
            assigned: "10.200.0.5".to_string(),
            handshake_age,
            poked_at,
        }
    }

    /// A poke that happened long enough ago to have had its chance.
    fn old_poke() -> Option<u64> {
        Some(now_seconds().saturating_sub(GRACE_SECONDS + 1))
    }

    /// A poke that happened just now, and has not had its chance yet.
    fn recent_poke() -> Option<u64> {
        Some(now_seconds())
    }

    #[test]
    fn a_missing_interface_is_rebuilt() {
        let decision = decide(&observation(false, false, None, None));
        assert_eq!(decision.action, Action::Rebuilt);
        assert!(decision.reason.contains("gone"), "{}", decision.reason);
    }

    #[test]
    fn an_interface_without_its_address_is_rebuilt() {
        let decision = decide(&observation(true, false, Some(1), None));
        assert_eq!(decision.action, Action::Rebuilt);
        assert!(decision.reason.contains("address"), "{}", decision.reason);
    }

    #[test]
    fn a_fresh_handshake_is_left_alone() {
        let decision = decide(&observation(true, true, Some(12), None));
        assert_eq!(decision.action, Action::Ok);
        assert!(decision.reason.contains("12s"), "{}", decision.reason);
    }

    #[test]
    fn a_stale_handshake_is_poked() {
        let decision = decide(&observation(true, true, Some(240), None));
        assert_eq!(decision.action, Action::Poked);
        assert!(decision.reason.contains("240s"), "{}", decision.reason);
    }

    #[test]
    fn a_stale_handshake_after_a_poke_is_rebuilt() {
        let decision = decide(&observation(true, true, Some(240), old_poke()));
        assert_eq!(decision.action, Action::Rebuilt);
        assert!(decision.reason.contains("poke"), "{}", decision.reason);
    }

    /// A poke is a question. Rebuilding the tunnel because the peer has not
    /// answered YET is how a watchdog tears down a tunnel that was working:
    /// the tunnel that was just brought up has not shaken hands yet, and the
    /// marker left behind by an earlier run says it was already poked.
    #[test]
    fn a_recent_poke_is_given_time_to_work() {
        let decision = decide(&observation(true, true, Some(240), recent_poke()));
        assert_eq!(decision.action, Action::Ok);
    }

    #[test]
    fn a_tunnel_that_never_handshaked_is_poked_first() {
        let decision = decide(&observation(true, true, None, None));
        assert_eq!(decision.action, Action::Poked);
        assert!(decision.reason.contains("never"), "{}", decision.reason);
    }

    #[test]
    fn a_tunnel_that_never_handshaked_after_a_poke_is_rebuilt() {
        let decision = decide(&observation(true, true, None, old_poke()));
        assert_eq!(decision.action, Action::Rebuilt);
    }

    /// A tunnel that has just been started has not shaken hands yet, and that
    /// is not a fault.
    #[test]
    fn a_tunnel_that_never_handshaked_after_a_recent_poke_is_left_alone() {
        let decision = decide(&observation(true, true, None, recent_poke()));
        assert_eq!(decision.action, Action::Ok);
    }

    #[test]
    fn a_handshake_just_under_the_limit_is_left_alone() {
        let decision = decide(&observation(true, true, Some(STALE_SECONDS), None));
        assert_eq!(decision.action, Action::Ok);
    }

    #[test]
    fn a_handshake_over_the_limit_is_stale() {
        let decision = decide(&observation(true, true, Some(STALE_SECONDS + 1), None));
        assert_eq!(decision.action, Action::Poked);
    }
}
