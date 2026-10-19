# proxy-node

Turns a Linux machine into an egress node for the [AI Gateway](https://github.com/northloop-systems/ai-gateway).

The gateway fronts several AI providers and rotates through different IPs to
avoid rate limits. Right now those IPs come from one machine. This lets anyone
lend a machine to that pool, which means more capacity and fewer rate limits for
everyone using the gateway.

Each node contributes up to three IPs:

| Path | What it is |
|---|---|
| Tor | A Tor exit IP |
| Cloudflare WARP | A Cloudflare WARP exit IP (Debian/Ubuntu only) |
| Direct | Your own public IP |

## Before you install

This makes your machine an egress node for someone else's traffic. Worth
knowing up front:

- **Your IP will be used to make requests to third-party services.** If that
  traffic trips an abuse report, the notice comes to your address.
- **The hub can send traffic to any destination through your connection.** Via
  the Tor and WARP paths there is no destination restriction. The direct path is
  limited to public addresses on port 443.
- **The installer runs as root and modifies your system.** It edits
  `/etc/tor/torrc` (keeping a copy at `/etc/tor/torrc.bak`), and on
  Debian/Ubuntu it registers Cloudflare WARP and switches it to proxy mode —
  which will replace an existing WARP registration.
- **Don't use it on a work or school machine.** The traffic is attributable to
  you.

If any of that is a problem, skip it. If you install it and change your mind,
[Uninstall](#uninstall) puts things back.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/northloop-systems/ai-gateway-proxy/main/install.sh | sudo bash
```

You'll be prompted for the hub's API token. Everything else is automatic.

To pass the token in the environment instead:

```bash
curl -fsSL https://raw.githubusercontent.com/northloop-systems/ai-gateway-proxy/main/install.sh \
  | API_TOKEN=sk-xxx sudo -E bash
```

## What it does

Installs and configures:

- **WireGuard** — an encrypted VPN tunnel to the hub. This is how the node
  connects; there's no SSH and no shared key. All three proxy paths are reached
  over this tunnel.
- **Tor** — a SOCKS5 proxy on the node's tunnel address.
- **Cloudflare WARP** — a SOCKS5 proxy on the node's tunnel address.
- **A small authenticated SOCKS5 proxy** for your own IP, restricted to public
  destinations on port 443.

Everything is managed by systemd (`proxy-socks5`, `proxy-tor-redirect`,
`proxy-warp-redirect`, `wg-quick@wg0`), so it survives reboots. Tor and WARP stay
bound to localhost and are bridged to the tunnel address, so nothing new is
exposed on your normal network interfaces.

On registration the node sends the hub its hostname, WireGuard public key, public
IP (via `api.ipify.org`), a generated SOCKS username and password, and the port
numbers.

## Options

| Variable | Default |
|---|---|
| `API_TOKEN` | prompted for |
| `SERVER_HOST` | `ai-gateway.shuffled-family.com` |
| `WG_ENDPOINT` | `<host>:51820` |
| `NODE_NAME` | your hostname |

## Uninstall

```bash
systemctl disable --now proxy-socks5 proxy-tor-redirect proxy-warp-redirect wg-quick@wg0 2>/dev/null
rm -f /etc/systemd/system/proxy-*.service /etc/wireguard/wg0.conf
systemctl daemon-reload
rm -rf /opt/proxy-node; userdel proxysocks
```

This removes the tunnel, the services and the firewall rules it added. It does
not undo the edits to `/etc/tor/torrc` or the WARP registration — restore
`/etc/tor/torrc.bak` by hand if you want your original back.

## Requirements

- Linux (Debian/Ubuntu, Fedora, CentOS/RHEL, Arch)
- Root access
- Python 3

## License

MIT
