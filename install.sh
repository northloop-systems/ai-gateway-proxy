#!/usr/bin/env bash
# proxy-node installer
#
# Turns a machine into an egress node. Each node provides up to 3 egress IPs:
#   1. Cloudflare WARP  -> WARP exit IP
#   2. Tor             -> Tor exit IP
#   3. Direct          -> the node's own public IP
#
# All three are reachable from the hub only over the node's WireGuard IP, not
# on localhost: the direct SOCKS5 listens on <wg-ip>:1080, Tor on <wg-ip>:9050
# and WARP on <wg-ip>:40000 (Tor/WARP stay bound to localhost and are reached
# through socat redirects).
#
# The connection to the hub uses WireGuard — an authenticated, encrypted VPN.
# NO SSH, NO chisel. The tunnel itself uses a keypair (no shared secret), but
# the direct proxy is protected by a generated username/password.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/northloop-systems/ai-gateway-proxy/main/install.sh | bash
#
# Optional env vars:
#   API_TOKEN        - your API key (required, prompted if missing)
#   SERVER_HOST      - server hostname (default: ai-gateway.shuffled-family.com)
#   WG_ENDPOINT      - WireGuard endpoint (default: <host>:51820)
#   NODE_NAME        - friendly name for this node (default: hostname)
#
set -euo pipefail

NODE_NAME="${NODE_NAME:-$(hostname)}"
API_TOKEN="${API_TOKEN:-}"
SERVER_HOST="${SERVER_HOST:-ai-gateway.shuffled-family.com}"
WG_ENDPOINT="${WG_ENDPOINT:-${SERVER_HOST}:51820}"
SERVER_URL="https://${SERVER_HOST}/v1"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[proxy]${NC} $*"; }
warn() { echo -e "${YELLOW}[proxy]${NC} $*"; }
err() { echo -e "${RED}[proxy]${NC} $*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    err "This installer must be run as root (use sudo)."
    exit 1
fi

if [ -z "$API_TOKEN" ]; then
    echo ""
    echo "  =========================================="
    echo "   Proxy Node Installer (WireGuard)"
    echo "  =========================================="
    echo ""
    echo "  You need an API token to connect this node."
    echo "  Get one from your hub admin, then paste it here."
    echo ""
    read -rsp "  Paste your API token: " API_TOKEN </dev/tty
    echo ""
    if [ -z "$API_TOKEN" ]; then
        err "No token provided. Exiting."
        exit 1
    fi
fi

# --- Verify connectivity ---
# The token goes in a 0600 curl config file, never on the command line (ps).
CURL_AUTH=$(mktemp)
chmod 600 "$CURL_AUTH"
trap 'rm -f "${CURL_AUTH:-}"' EXIT
printf 'header = "Authorization: Bearer %s"\n' "$API_TOKEN" > "$CURL_AUTH"
log "Verifying connectivity..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 15 \
    --config "$CURL_AUTH" \
    "$SERVER_URL/models" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" != "200" ]; then
    err "Cannot reach server (HTTP $HTTP_CODE). Check API_TOKEN and network."
    exit 1
fi
log "Server OK"

# --- Detect OS ---
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    else
        err "Unsupported OS"
        exit 1
    fi
}
OS=$(detect_os)
log "OS: $OS"

# --- Install packages (WireGuard, no SSH, no chisel) ---
install_packages() {
    case "$OS" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq tor python3 curl wireguard-tools iptables socat
            ;;
        fedora)
            dnf install -y -q tor python3 curl wireguard-tools iptables-nft socat
            ;;
        centos|rhel|rocky|almalinux)
            yum install -y -q tor python3 curl wireguard-tools iptables-nft socat
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm tor python curl wireguard-tools iptables-nft socat
            ;;
        *)
            err "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}
log "Installing packages (WireGuard, no SSH, no chisel)..."
install_packages

if ! command -v iptables &>/dev/null; then
    err "iptables still not found after package install. Install iptables before continuing."
    exit 1
fi

# --- Install Cloudflare WARP ---
install_warp() {
    if command -v warp-cli &>/dev/null; then
        log "WARP already installed"
        return 0
    fi
    case "$OS" in
        ubuntu|debian)
            curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null
            . /etc/os-release
            echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $VERSION_CODENAME main" > /etc/apt/sources.list.d/cloudflare-client.list
            apt-get update -qq
            apt-get install -y -qq cloudflare-warp
            ;;
        *)
            warn "WARP not available for $OS. Skipping (only Tor + Direct)."
            return 1
            ;;
    esac
}
WARP_AVAILABLE=0
if install_warp; then
    WARP_AVAILABLE=1
    log "WARP installed"
fi

# --- Configure Tor ---
log "Configuring Tor..."
TOR_CONF="/etc/tor/torrc"
# Keep the FIRST backup we ever take (the pristine pre-install torrc), so a
# re-run can't overwrite the user's original with our already-modified copy.
if [ ! -f "$TOR_CONF.bak" ]; then
    cp -a "$TOR_CONF" "$TOR_CONF.bak" 2>/dev/null || true
fi
grep -q "^SocksPort" "$TOR_CONF" && sed -i 's/^SocksPort.*/SocksPort 127.0.0.1:9050/' "$TOR_CONF" || echo "SocksPort 127.0.0.1:9050" >> "$TOR_CONF"
grep -q "^SocksPolicy" "$TOR_CONF" || { echo "SocksPolicy accept 127.0.0.1" >> "$TOR_CONF"; echo "SocksPolicy reject *" >> "$TOR_CONF"; }
grep -q "^ControlPort" "$TOR_CONF" && sed -i 's/^ControlPort.*/ControlPort 0/' "$TOR_CONF" || echo "ControlPort 0" >> "$TOR_CONF"

if [ "$WARP_AVAILABLE" = "1" ]; then
    log "Configuring WARP..."
    warp-cli registration new 2>/dev/null || true
    warp-cli mode proxy 2>/dev/null || true
    warp-cli proxy port 40000 2>/dev/null || true
fi

log "Starting services..."
systemctl enable tor 2>/dev/null || true
systemctl restart tor 2>/dev/null || service tor restart 2>/dev/null || true

if [ "$WARP_AVAILABLE" = "1" ]; then
    systemctl enable warp-svc 2>/dev/null || true
    systemctl restart warp-svc 2>/dev/null || true
    sleep 2
    warp-cli connect 2>/dev/null || true
fi

# --- Generate WireGuard keypair ---
log "Generating WireGuard keypair..."
PROXY_DIR="/opt/proxy-node"
if ! id proxysocks &>/dev/null; then
    useradd -r -s /usr/sbin/nologin proxysocks
fi
install -d -m 0750 -o root -g proxysocks "$PROXY_DIR"
WG_PRIVATE_KEY=$(wg genkey)
WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)
echo "$WG_PUBLIC_KEY" > "$PROXY_DIR/wg_public.key"
chmod 644 "$PROXY_DIR/wg_public.key"
log "WireGuard keypair generated"

# --- Create authenticated SOCKS5 proxy for direct IP ---
log "Creating authenticated SOCKS5 proxy for direct IP..."
SOCKS_USER="proxyuser"
SOCKS_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
cat > "$PROXY_DIR/socks5.py" <<PYEOF
#!/usr/bin/env python3
"""Authenticated SOCKS5 proxy for direct (node's own) IP egress."""
import socket, threading, select, sys

LISTEN_HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
WG_HUB_IP = "10.200.0.1"
LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1080
SOCKS_USER = "${SOCKS_USER}"
SOCKS_PASS = "${SOCKS_PASS}"

import ipaddress

def _resolve_safe(host, port):
    if port != 443:
        return None
    try:
        ips = [r[4][0] for r in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
    except Exception:
        return None
    if not ips or not all(ipaddress.ip_address(i).is_global for i in ips):
        return None
    return ips[0]

def handle_client(client):
    try:
        client.settimeout(30)
        data = client.recv(262)
        if not data or data[0] != 5:
            client.close()
            return
        client.send(b'\x05\x02')
        auth = client.recv(512)
        if not auth or auth[0] != 1:
            client.close()
            return
        ulen = auth[1]
        user = auth[2:2+ulen].decode()
        plen = auth[2+ulen]
        passwd = auth[3+ulen:3+ulen+plen].decode()
        if user != SOCKS_USER or passwd != SOCKS_PASS:
            client.send(b'\x01\x01')
            client.close()
            return
        client.send(b'\x01\x00')
        data = client.recv(4)
        if len(data) < 4 or data[1] != 1:
            client.close()
            return
        atyp = data[3]
        if atyp == 1:
            addr = socket.inet_ntoa(client.recv(4))
        elif atyp == 3:
            ln = client.recv(1)[0]
            addr = client.recv(ln).decode()
        elif atyp == 4:
            addr = socket.inet_ntop(socket.AF_INET6, client.recv(16))
        else:
            client.close()
            return
        port = int.from_bytes(client.recv(2), 'big')
        resolved = _resolve_safe(addr, port)
        if resolved is None:
            client.send(b'\x05\x02\x00\x01' + socket.inet_aton('0.0.0.0') + (0).to_bytes(2, 'big'))
            client.close()
            return
        try:
            remote = socket.create_connection((resolved, port), timeout=30)
            client.send(b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + (0).to_bytes(2, 'big'))
            while True:
                r, _, _ = select.select([client, remote], [], [], 30)
                if client in r:
                    d = client.recv(65536)
                    if not d:
                        break
                    remote.sendall(d)
                if remote in r:
                    d = remote.recv(65536)
                    if not d:
                        break
                    client.sendall(d)
        except Exception:
            try:
                client.send(b'\x05\x05\x00\x01' + socket.inet_aton('0.0.0.0') + (0).to_bytes(2, 'big'))
            except Exception:
                pass
    except Exception:
        pass
    finally:
        client.close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((LISTEN_HOST, LISTEN_PORT))
s.listen(64)
MAX_CONNS = 128
active_conns = 0
conn_lock = threading.Lock()

def wrapped_handle(cl):
    global active_conns
    try:
        handle_client(cl)
    finally:
        with conn_lock:
            active_conns -= 1

while True:
    c, addr = s.accept()
    if addr[0] != WG_HUB_IP:
        c.close()
        continue
    with conn_lock:
        if active_conns >= MAX_CONNS:
            c.close()
            continue
        active_conns += 1
    threading.Thread(target=wrapped_handle, args=(c,), daemon=True).start()
PYEOF
chmod 644 "$PROXY_DIR/socks5.py"

# --- Register with server (send WireGuard public key) ---
PUBLIC_IP=$(curl -s -m 10 https://api.ipify.org 2>/dev/null || echo "unknown")
log "Registering with server (sending WireGuard public key)..."
REG_RESPONSE=$(WG_PUB="$WG_PUBLIC_KEY" NODE="$NODE_NAME" PUBIP="$PUBLIC_IP" SU="$SOCKS_USER" SP="$SOCKS_PASS" \
    python3 -c 'import json,os; print(json.dumps({"hostname":os.environ["NODE"],"version":"3.0","wireguard_public_key":os.environ["WG_PUB"],"ports":{"tor":9050,"warp":40000,"direct":1080},"public_ip":os.environ["PUBIP"],"socks_user":os.environ["SU"],"socks_pass":os.environ["SP"]}))' \
    | curl -s -m 15 -X POST --config "$CURL_AUTH" \
    -H "Content-Type: application/json" -d @- \
    "$SERVER_URL/proxy/register" 2>/dev/null || echo '{"status":"error"}')

# Extract assigned WireGuard IP and gateway's public key from response
WG_ASSIGNED_IP=$(echo "$REG_RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin).get('wireguard_ip',''))" 2>/dev/null || echo "")
WG_GATEWAY_PUBKEY=$(echo "$REG_RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin).get('wireguard_gateway_public_key',''))" 2>/dev/null || echo "")
WG_GATEWAY_ENDPOINT="$WG_ENDPOINT"

# --- Validate server-supplied values (prevent config injection) ---
# Use bash regex (not grep) to match the ENTIRE string, preventing
# multi-line injection (grep matches line-by-line, allowing embedded newlines).
if ! [[ "$WG_GATEWAY_PUBKEY" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    err "Invalid WireGuard public key from server. Aborting."
    exit 1
fi
if ! [[ "$WG_ASSIGNED_IP" =~ ^10\.200\.0\.([0-9]{1,3})$ ]] || [ "$((10#${BASH_REMATCH[1]}))" -gt 255 ] || [ "$((10#${BASH_REMATCH[1]}))" -lt 2 ]; then
    err "Invalid WireGuard IP from server. Aborting."
    exit 1
fi
if ! [[ "$WG_GATEWAY_ENDPOINT" =~ ^[a-zA-Z0-9._-]+:[0-9]{1,5}$ ]]; then
    err "Invalid WireGuard endpoint from server. Aborting."
    exit 1
fi

if [ -z "$WG_ASSIGNED_IP" ] || [ -z "$WG_GATEWAY_PUBKEY" ]; then
    warn "Server did not return WireGuard config. WireGuard tunnel will not be set up."
    warn "Registration response: [redacted to avoid leaking server-supplied data]"
    WG_CONFIGURED=0
else
    WG_CONFIGURED=1
    log "Assigned WireGuard IP: $WG_ASSIGNED_IP"
    log "Gateway WireGuard public key received"

    # --- Configure WireGuard ---
    log "Configuring WireGuard..."
    cat > /etc/wireguard/wg0.conf <<WGEOF
[Interface]
PrivateKey = $WG_PRIVATE_KEY
Address = $WG_ASSIGNED_IP/24
PostUp = iptables -I INPUT 1 -i %i -j DROP
PostUp = iptables -I INPUT 1 -i %i -p tcp --dport 40000 -s 10.200.0.1 -j ACCEPT
PostUp = iptables -I INPUT 1 -i %i -p tcp --dport 9050 -s 10.200.0.1 -j ACCEPT
PostUp = iptables -I INPUT 1 -i %i -p tcp --dport 1080 -s 10.200.0.1 -j ACCEPT
PostUp = iptables -I INPUT 1 -i %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostDown = iptables -D INPUT -i %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostDown = iptables -D INPUT -i %i -p tcp --dport 1080 -s 10.200.0.1 -j ACCEPT
PostDown = iptables -D INPUT -i %i -p tcp --dport 9050 -s 10.200.0.1 -j ACCEPT
PostDown = iptables -D INPUT -i %i -p tcp --dport 40000 -s 10.200.0.1 -j ACCEPT
PostDown = iptables -D INPUT -i %i -j DROP

[Peer]
PublicKey = $WG_GATEWAY_PUBKEY
AllowedIPs = 10.200.0.1/32
Endpoint = $WG_GATEWAY_ENDPOINT
PersistentKeepalive = 25
WGEOF
    chmod 600 /etc/wireguard/wg0.conf

    # --- Start WireGuard ---
    log "Starting WireGuard..."
    systemctl enable wg-quick@wg0 2>/dev/null || true
    if ! systemctl restart wg-quick@wg0; then
        err "WireGuard failed to start. Check config."
        exit 1
    fi

    # --- Redirect WG traffic to localhost Tor/WARP (safe for node owner) ---
    # Hub connects to WG_IP:9050/40000, redirected to 127.0.0.1
    # Keeps Tor/WARP bound to localhost (not exposed on public interfaces)
    # Required, not optional: the firewall opens these ports below, so a
    # missing socat would leave them open to nothing with no way to tell.
    if ! command -v socat &>/dev/null; then
        err "socat not found but is required to expose Tor/WARP to the hub."
        err "Install socat, or set WARP/Tor aside - the ports are opened either way."
        exit 1
    fi
    {
        cat > /etc/systemd/system/proxy-tor-redirect.service <<REDIRECT
[Unit]
Description=Proxy Node - Tor redirect (WG to localhost)
After=wg-quick@wg0.service tor.service
Requires=wg-quick@wg0.service

[Service]
Type=simple
DynamicUser=yes
ExecStart=/usr/bin/socat TCP-LISTEN:9050,bind=$WG_ASSIGNED_IP,fork,max-children=32 TCP:127.0.0.1:9050
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
REDIRECT
        if [ "$WARP_AVAILABLE" = "1" ]; then
            cat > /etc/systemd/system/proxy-warp-redirect.service <<REDIRECT
[Unit]
Description=Proxy Node - WARP redirect (WG to localhost)
After=wg-quick@wg0.service warp-svc.service
Requires=wg-quick@wg0.service

[Service]
Type=simple
DynamicUser=yes
ExecStart=/usr/bin/socat TCP-LISTEN:40000,bind=$WG_ASSIGNED_IP,fork,max-children=32 TCP:127.0.0.1:40000
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
REDIRECT
        fi
    }
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable proxy-tor-redirect 2>/dev/null || true
    systemctl restart proxy-tor-redirect 2>/dev/null || true
    if [ "$WARP_AVAILABLE" = "1" ]; then
        systemctl enable proxy-warp-redirect 2>/dev/null || true
        systemctl restart proxy-warp-redirect 2>/dev/null || true
    fi
fi

# --- Set up SOCKS5 proxy systemd service ---
cat > /etc/systemd/system/proxy-socks5.service <<UNIT
[Unit]
Description=Proxy Node - SOCKS5 for direct IP
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
User=proxysocks
Group=proxysocks
ExecStart=/usr/bin/python3 $PROXY_DIR/socks5.py 1080 $WG_ASSIGNED_IP
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload 2>/dev/null || true
systemctl enable proxy-socks5 2>/dev/null || true
systemctl restart proxy-socks5 2>/dev/null || true

# --- Verify services ---
TOR_OK=0; WARP_OK=0; WG_OK=0; SOCKS_OK=0
systemctl is-active --quiet proxy-tor-redirect && TOR_OK=1
[ "$WARP_AVAILABLE" = "1" ] && systemctl is-active --quiet proxy-warp-redirect && WARP_OK=1
systemctl is-active --quiet proxy-socks5 && SOCKS_OK=1
[ "$WG_CONFIGURED" = "1" ] && wg show wg0 2>/dev/null | grep -q "peer:" && WG_OK=1

# --- Summary ---
WG_BIND_IP="${WG_ASSIGNED_IP:-no-tunnel}"
echo ""
echo "=========================================="
echo "  Proxy Node: $NODE_NAME"
echo "=========================================="
echo ""
echo "  Public IP:     $PUBLIC_IP"
echo "  Tor SOCKS5:    $WG_BIND_IP:9050  $([ $TOR_OK = 1 ] && echo '(OK)' || echo '(DOWN)')"
echo "  WARP SOCKS5:   $WG_BIND_IP:40000 $([ $WARP_OK = 1 ] && echo '(OK)' || echo '(DOWN/not installed)')"
echo "  Direct SOCKS5: $WG_BIND_IP:1080  $([ $SOCKS_OK = 1 ] && echo '(OK)' || echo '(DOWN)')"
echo "  WireGuard:     $([ $WG_OK = 1 ] && echo '(OK)' || echo '(not configured)')"
echo ""
echo "  Registration: [redacted]"
echo ""
echo "  Provides up to 3 egress IPs: Tor exit, WARP exit, node's own IP"
echo "  Connection: WireGuard VPN (encrypted, authenticated, keypair only)"
echo ""
echo "  The hub can open connections to any destination through this node,"
echo "  including via Tor and WARP. The direct proxy additionally restricts"
echo "  connections to public hosts on port 443."
echo ""
echo "  WireGuard IP: ${WG_ASSIGNED_IP:-not assigned}"
echo ""