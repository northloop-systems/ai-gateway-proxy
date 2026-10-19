#!/usr/bin/env bash
# proxy-node uninstaller
#
# Puts the machine back the way it was:
#   - tells the hub the node is leaving, so the hub drops it and tears down
#     the WireGuard peer instead of keeping a route pointed at a dead node
#   - brings down the tunnel, which is what removes the firewall rules the
#     installer added (they are the interface's PostUp/PostDown rules)
#   - stops and removes the services, the keypair, the proxy account
#   - restores /etc/tor/torrc from the pristine backup the installer kept
#
# It DOES undo what the installer changed about WARP's mode and the machine's
# resolver, because those belong to the machine rather than to the node.
#
# It does NOT remove the WARP registration itself: WARP may have been on the
# machine before this, and the installer cannot know whether it was the
# user's WARP or its own. `warp-cli registration delete` removes the
# registration if you want that too.
#
# Usage:
#   sudo bash uninstall.sh
#
# Optional env vars:
#   SERVER_HOST  - hub hostname (default: ai-gateway.shuffled-family.com)
#
set -euo pipefail

SERVER_HOST="${SERVER_HOST:-ai-gateway.shuffled-family.com}"
SERVER_URL="https://${SERVER_HOST}/v1"
PROXY_DIR="/opt/proxy-node"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[proxy]${NC} $*"; }
warn() { echo -e "${YELLOW}[proxy]${NC} $*"; }
err() { echo -e "${RED}[proxy]${NC} $*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    err "This uninstaller must be run as root (use sudo)."
    exit 1
fi

# --- 1. Tell the hub the node is leaving -----------------------------------
# A per-node token may revoke its OWN node and nothing else, so this is the
# one call the node is allowed to make. Without it the hub keeps a route
# pointed at an address that no longer answers, and keeps the node's entry
# (and its SOCKS password) until an operator notices.
if [ -f "$PROXY_DIR/token" ] && [ -f "$PROXY_DIR/node_name" ]; then
    TOKEN=$(cat "$PROXY_DIR/token")
    NODE_NAME=$(cat "$PROXY_DIR/node_name")
    CURL_AUTH=$(mktemp)
    chmod 600 "$CURL_AUTH"
    trap 'rm -f "${CURL_AUTH:-}"' EXIT
    printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" > "$CURL_AUTH"
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 15 \
        --config "$CURL_AUTH" -X DELETE \
        "$SERVER_URL/proxy/nodes/node-${NODE_NAME}" 2>/dev/null || echo "000")
    case "$CODE" in
        200) log "Hub notified: node ${NODE_NAME} deregistered" ;;
        404) warn "Hub did not know this node (already gone?)" ;;
        000) warn "Could not reach the hub; it will notice the node is dead" ;;
        *)   warn "Hub returned HTTP ${CODE}; revoke the node by hand if it stays" ;;
    esac
else
    warn "No stored token found; the hub still has this node registered."
    warn "Revoke it with: curl -X DELETE -H \"Authorization: Bearer <token>\" \\"
    warn "  ${SERVER_URL}/proxy/nodes/node-<name>"
fi

# --- 2. Bring the tunnel down ------------------------------------------------
# This is what removes the firewall rules: they are wg-quick's PostUp/PostDown
# rules, so the interface has to go down while its config is still in place.
#
# No "is the unit installed?" test guards the systemctl call: a test built on a
# pipeline (systemctl ... | grep -q) is a trap under `set -o pipefail`, because
# grep -q exits at the first match, systemctl takes a SIGPIPE, and the whole
# pipeline reports failure - so the tunnel was never stopped and its PostDown
# never ran, leaving the firewall rules behind. Stopping a unit that does not
# exist is a no-op, so just do it.
if command -v systemctl >/dev/null; then
    systemctl disable --now wg-quick@wg0 2>/dev/null || true
fi
if ip link show wg0 >/dev/null 2>&1; then
    ip link delete wg0 2>/dev/null || true
fi

# Belt and braces: remove the rules explicitly as well. PostDown normally does
# it, but an interface deleted by hand, or a failed unit shutdown, leaves them
# behind - and a stale DROP rule on a name that no longer exists is exactly
# the kind of leftover a node owner should not inherit.
for rule in \
    "iptables -D INPUT -i wg0 -p tcp --dport 1080 -s 10.200.0.1 -j ACCEPT" \
    "iptables -D INPUT -i wg0 -p tcp --dport 9050 -s 10.200.0.1 -j ACCEPT" \
    "iptables -D INPUT -i wg0 -p tcp --dport 40000 -s 10.200.0.1 -j ACCEPT" \
    "iptables -D INPUT -i wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" \
    "iptables -D INPUT -i wg0 -j DROP"
do
    # shellcheck disable=SC2086
    $rule 2>/dev/null || true
done
log "WireGuard interface and its firewall rules removed"

# --- 3. Services -------------------------------------------------------------
for unit in proxy-socks5 proxy-tor-redirect proxy-warp-redirect; do
    systemctl disable --now "$unit" 2>/dev/null || true
done
systemctl disable --now proxy-tunnel-watchdog.timer 2>/dev/null || true
rm -f /etc/systemd/system/proxy-socks5.service \
      /etc/systemd/system/proxy-tor-redirect.service \
      /etc/systemd/system/proxy-warp-redirect.service \
      /etc/systemd/system/proxy-tunnel-watchdog.service \
      /etc/systemd/system/proxy-tunnel-watchdog.timer
rm -f /usr/local/bin/proxy-tunnel-watchdog.sh
systemctl daemon-reload 2>/dev/null || true
log "Services removed"

# --- 4. Files and the proxy account -----------------------------------------
rm -f /etc/wireguard/wg0.conf
rm -rf "$PROXY_DIR"
userdel proxysocks 2>/dev/null || true
log "Keypair, proxy files and the proxysocks account removed"

# --- 5. Restore torrc --------------------------------------------------------
# The installer keeps the pristine file as torrc.bak and never overwrites it
# with an already-modified copy, so this always restores the original.
if [ -f /etc/tor/torrc.bak ]; then
    cp -a /etc/tor/torrc.bak /etc/tor/torrc
    systemctl restart tor 2>/dev/null || true
    log "/etc/tor/torrc restored from the backup"
else
    warn "No /etc/tor/torrc.bak found; torrc left as it is"
fi

# --- 6. Give WARP and the resolver back -------------------------------------
# The installer flipped WARP into proxy mode and may have had to put the
# machine's resolver back by hand. Both belong to the machine, not to the
# node, so the uninstaller returns them.
WARP_STATE_DIR=/etc/proxy-node-warp
if [ -f "$WARP_STATE_DIR/mode" ] && command -v warp-cli &>/dev/null; then
    PRE_MODE=$(head -1 "$WARP_STATE_DIR/mode")
    case "$(printf '%s' "$PRE_MODE" | tr 'A-Z' 'a-z')" in
        *proxy*)
            warp-cli --accept-tos mode proxy >/dev/null 2>&1 || true
            PORT=$(printf '%s' "$PRE_MODE" | grep -oE '[0-9]+$' | head -1)
            [ -n "$PORT" ] && warp-cli --accept-tos proxy port "$PORT" >/dev/null 2>&1 || true
            log "WARP returned to proxy mode (port ${PORT:-40000})"
            ;;
        *dns*)
            warp-cli --accept-tos mode dns >/dev/null 2>&1 || true
            log "WARP returned to DNS mode"
            ;;
        *)
            warp-cli --accept-tos mode warp >/dev/null 2>&1 || true
            log "WARP returned to tunnel mode"
            ;;
    esac
fi
if [ -f "$WARP_STATE_DIR/resolvers" ]; then
    RESOLVERS=$(cat "$WARP_STATE_DIR/resolvers")
    if [ -n "$RESOLVERS" ] && [ ! -L /etc/resolv.conf ]; then
        printf 'nameserver %s\n' $RESOLVERS > /etc/resolv.conf
        log "System resolver restored"
    fi
fi
rm -rf "$WARP_STATE_DIR"

log "Uninstall complete."
log "WARP's registration is still on the machine: warp-cli registration delete removes it."
