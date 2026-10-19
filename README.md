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
- **Your DNS settings may be touched, and are put back.** WARP in tunnel or
  DNS mode is usually your machine's resolver, and switching it to proxy mode
  takes that resolver away with it — which leaves a machine that cannot
  resolve anything, including the hub. The installer remembers what you were
  using before the switch and puts it back afterwards, and says so when it
  does. If it cannot, it says that plainly and stops, rather than failing
  later with a confusing "cannot reach the server".
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
curl -fsSL https://raw.githubusercontent.com/northloop-systems/ai-gateway-proxy/main/uninstall.sh | sudo bash
```

That tells the hub the node is leaving — so it drops the node and tears down
the WireGuard peer instead of keeping a route pointed at an address that no
longer answers — then removes the tunnel, the firewall rules it added, the
services, the keypair, the proxy account, and restores `/etc/tor/torrc` from
the pristine backup the installer kept.

It also gives back what the installer changed about your own machine: WARP
goes back to the mode it was in before, and so does your resolver.

It does **not** remove the WARP registration: WARP may have been on your
machine already, and the installer cannot tell whose it was. If you want that
gone too, `warp-cli registration delete` removes it.

## Requirements

- Linux (Debian/Ubuntu, Fedora, CentOS/RHEL, Arch)
- Root access
- Python 3

## License

MIT
