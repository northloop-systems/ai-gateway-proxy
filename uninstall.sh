#!/usr/bin/env bash
# ai-gateway-proxy uninstaller.
#
# Puts the machine back the way it was. The work is in the binary, which
# knows exactly what it installed - but the binary may be the thing that
# is broken, so this script can also do the job on its own.
#
# Usage:
#   sudo ./uninstall.sh
#
#   - or, to remove a node and have the hub told:
#   sudo ./uninstall.sh --keep-hub-entry
set -euo pipefail

BINARY_PATH="/usr/local/bin/ai-gateway-proxy"
STATE_DIR="/opt/proxy-node"

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

KEEP_HUB_ENTRY=0
for arg in "$@"; do
    case "$arg" in
        --keep-hub-entry) KEEP_HUB_ENTRY=1 ;;
        --help|-h)
            echo "Usage: uninstall.sh [--keep-hub-entry]"
            echo "  --keep-hub-entry  do not tell the hub the node is leaving"
            exit 0 ;;
        *) err "Unknown argument: $arg"; exit 1 ;;
    esac
done

# --- Prefer the binary ------------------------------------------------------
# It knows what it installed, so its version of this is the careful one.
if [ -x "$BINARY_PATH" ]; then
    if [ "$KEEP_HUB_ENTRY" = "1" ]; then
        "$BINARY_PATH" uninstall --keep-hub-entry
    else
        "$BINARY_PATH" uninstall
    fi
    STATUS=$?
    if [ $STATUS -eq 0 ]; then
        log "Uninstall complete."
        exit 0
    fi
    warn "The binary's uninstall failed; finishing by hand."
fi

# --- By hand -----------------------------------------------------------------
# The binary may be gone, or may be what is broken. Either way the machine
# has to come back.
log "Removing the node by hand."

NODE_NAME=""
[ -f "$STATE_DIR/node_name" ] && NODE_NAME=$(cat "$STATE_DIR/node_name" 2>/dev/null || true)

if [ -n "$NODE_NAME" ] && [ "$KEEP_HUB_ENTRY" = "0" ] && [ -f "$STATE_DIR/token" ]; then
    TOKEN=$(cat "$STATE_DIR/token" 2>/dev/null || true)
    if [ -n "$TOKEN" ] && command -v curl >/dev/null 2>&1; then
        CURL_AUTH=$(mktemp)
        chmod 600 "$CURL_AUTH"
        trap 'rm -f "${CURL_AUTH:-}"' EXIT
        printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" > "$CURL_AUTH"
        CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 15 --config "$CURL_AUTH" \
            -X DELETE "https://${SERVER_HOST:-ai-gateway.shuffled-family.com}/v1/proxy/nodes/node-${NODE_NAME}" \
            2>/dev/null || echo "000")
        case "$CODE" in
            200) log "Hub notified: node ${NODE_NAME} deregistered" ;;
            404) warn "Hub did not know this node (already gone?)" ;;
            000) warn "Could not reach the hub; the node is still registered there" ;;
            *)   warn "The hub refused the deregistration (HTTP $CODE)" ;;
        esac
    fi
fi

# The tunnel comes down WITH its configuration still in place: the firewall
# rules are wg-quick's PostDown rules, and they only go away if the
# interface is brought down while the config is there.
if command -v wg-quick >/dev/null 2>&1; then
    wg-quick down wg0 2>/dev/null || true
fi
# ...and the rules are removed explicitly as well, in case the shutdown was
# not clean.
if command -v iptables >/dev/null 2>&1; then
    for port in 1080 9050 40000; do
        iptables -D INPUT -i wg0 -p tcp --dport "$port" -s 10.200.0.1 -j ACCEPT 2>/dev/null || true
    done
    iptables -D INPUT -i wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -i wg0 -j DROP 2>/dev/null || true
fi
log "WireGuard interface and its firewall rules removed"

for unit in proxy-socks5 proxy-tor-redirect proxy-warp-redirect proxy-tunnel-watchdog.timer proxy-tunnel-watchdog.service; do
    systemctl disable --now "$unit" 2>/dev/null || true
done
rm -f /etc/systemd/system/proxy-socks5.service \
      /etc/systemd/system/proxy-tor-redirect.service \
      /etc/systemd/system/proxy-warp-redirect.service \
      /etc/systemd/system/proxy-tunnel-watchdog.service \
      /etc/systemd/system/proxy-tunnel-watchdog.timer
systemctl daemon-reload 2>/dev/null || true
log "Services removed"

rm -f /etc/wireguard/wg0.conf
rm -rf "$STATE_DIR"
userdel proxysocks 2>/dev/null || true
log "Keypair, proxy files and the proxysocks account removed"

# The pristine torrc, never an already-modified one.
if [ -f /etc/tor/torrc.bak ]; then
    cp -a /etc/tor/torrc.bak /etc/tor/torrc
    systemctl restart tor 2>/dev/null || true
    log "/etc/tor/torrc restored from the backup"
else
    warn "No /etc/tor/torrc.bak found; torrc left as it is"
fi

# WARP goes back to the mode it had before, and the resolver with it.
if [ -f /etc/proxy-node-warp/mode ] && command -v warp-cli >/dev/null 2>&1; then
    PRE_MODE=$(head -1 /etc/proxy-node-warp/mode)
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
if [ -f /etc/proxy-node-warp/resolvers ] && [ ! -L /etc/resolv.conf ]; then
    RESOLVERS=$(cat /etc/proxy-node-warp/resolvers)
    if [ -n "$RESOLVERS" ]; then
        printf 'nameserver %s\n' $RESOLVERS > /etc/resolv.conf
        log "System resolver restored"
    fi
fi
rm -rf /etc/proxy-node-warp

log "Uninstall complete."
log "WARP's registration is still on the machine: warp-cli registration delete removes it."
