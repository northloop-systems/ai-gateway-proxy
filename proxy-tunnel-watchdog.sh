#!/bin/bash
# Watchdog for the node's WireGuard tunnel.
#
# A node that is registered but has no tunnel is a node that carries nothing,
# and nothing on the hub can tell the difference: the hub sees the routes as
# unreachable and the node looks like it is simply not there. So the node has
# to notice and fix it itself.
#
# Two ways the tunnel goes bad, both seen on a real node:
#
#   - the interface is there but has lost its address. wg-quick can be
#     stopped by things that are not wg-quick (an AppArmor-denied routing
#     read, a stray "ip addr flush", a network manager that tidied up after
#     itself), and it leaves behind an interface that LOOKS fine and carries
#     nothing.
#   - the interface is up but the peer is not answering, so the handshake is
#     stale. The hub's view is the same either way: dead.
#
# The fix is to put the tunnel back, and to say so - in the node's own log,
# where the operator of the machine will actually look.
set -u

WG_IF=wg0
STATE_DIR=/opt/proxy-node
LOG_TAG="proxy-tunnel-watchdog"

log() { logger -t "$LOG_TAG" -- "$*"; echo "[$LOG_TAG] $*" >&2; }

ASSIGNED_IP=""
[ -f "$STATE_DIR/wg_ip" ] && ASSIGNED_IP=$(cat "$STATE_DIR/wg_ip" 2>/dev/null)

hub_peer_key=""
[ -f "$STATE_DIR/wg_hub_public.key" ] && hub_peer_key=$(cat "$STATE_DIR/wg_hub_public.key" 2>/dev/null)

has_address() {
    [ -n "$ASSIGNED_IP" ] || return 0
    ip -4 addr show dev "$WG_IF" 2>/dev/null | grep -q "inet $ASSIGNED_IP/"
}

last_handshake_age() {
    # Seconds since the most recent handshake with the hub, or empty when
    # there has never been one.
    local stamp now
    stamp=$(wg show "$WG_IF" latest-handshakes 2>/dev/null | awk '{print $2}' | sort -n | tail -1)
    [ -n "$stamp" ] || return 1
    [ "$stamp" -gt 0 ] 2>/dev/null || return 1
    now=$(date +%s)
    echo $((now - stamp))
}

if ! ip link show dev "$WG_IF" >/dev/null 2>&1; then
    log "the tunnel interface is gone; starting it"
    systemctl restart "wg-quick@$WG_IF" >/dev/null 2>&1 || log "the tunnel would not start"
    exit 0
fi

if ! has_address; then
    log "the tunnel interface has no address ($ASSIGNED_IP); rebuilding it"
    systemctl restart "wg-quick@$WG_IF" >/dev/null 2>&1 || log "the tunnel would not start"
    exit 0
fi

age=$(last_handshake_age)
if [ -n "$age" ] && [ "$age" -gt 180 ]; then
    # The peer has gone quiet. A keepalive is the cheap thing to try: it
    # makes the node initiate, which is all a dead-but-listening hub needs.
    log "the last handshake was ${age}s ago; poking the hub"
    if [ -n "$hub_peer_key" ]; then
        wg set "$WG_IF" peer "$hub_peer_key" persistent-keepalive 25 2>/dev/null || true
    fi
    exit 0
fi

exit 0
