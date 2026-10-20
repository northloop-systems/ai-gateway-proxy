# ai-gateway-proxy

Turns a Linux machine into an egress node for the
[AI Gateway](https://github.com/northloop-systems/ai-gateway).

Each node offers up to three addresses: a Tor exit, a Cloudflare WARP exit,
and its own. The gateway rotates through them to spread out rate limits.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/northloop-systems/ai-gateway-proxy/main/install.sh | sudo bash
```

Paste the token when asked. To uninstall:

```bash
curl -fsSL https://raw.githubusercontent.com/northloop-systems/ai-gateway-proxy/main/uninstall.sh | sudo bash
```

## Know what you are agreeing to

- **Your IP makes requests to third-party services** on the gateway's behalf.
  If that traffic trips an abuse report, the notice comes to your address.
- **The gateway can send traffic to any destination through your machine.**
  The Tor and WARP paths are unrestricted; the direct path only reaches
  public addresses on port 443.
- **The installer runs as root** and changes your system: it installs
  packages, edits `/etc/tor/torrc` (backed up), and on Debian/Ubuntu it
  registers WARP and switches it to proxy mode.
- **Don't use it on a work or school machine.** The traffic is yours.

WARP is usually your machine's resolver, and switching it to proxy mode takes
that away with it. The installer puts your resolver back and tells you when
it does.

## How it is put together

`install.sh` is the part you read before running it as root. It fetches the
`ai-gateway-proxy` binary from the latest release, checks it against the
checksum published with that release, and runs it. The binary is one static
file with no dependencies.

The rest is in `src/`, one concern per file. `ai-gateway-proxy status` says
what is working; `ai-gateway-proxy watchdog` checks the tunnel and puts it
back if it broke.

## License

MIT
