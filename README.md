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

## WARP: a proxy, or a tunnel

The installer puts WARP into **proxy mode**: it serves the node a SOCKS port,
and the node's exits connect to that port. Your own browsing, streaming and
games stay where they are, off Cloudflare's network.

If you WANT your traffic and your DNS through WARP - a laptop that is meant
to be on Cloudflare's network all the time - ask for **tunnel mode**:

```bash
sudo ai-gateway-proxy install --warp-mode tunnel
```

In tunnel mode WARP carries the machine's own traffic and its DNS, which
means two things:

- The node has **no separate WARP exit**: a tunnel-mode WARP does not listen
  on a port, so there is nothing for the gateway to connect to. The
  machine's own address *is* the WARP address, and that is the exit the node
  offers in its place. The node still offers a Tor exit and its own address.
- The choice is **remembered**, so a re-install does not quietly put a
  machine that was deliberately in tunnel mode back into proxy mode.

`ai-gateway-proxy status` says which mode the machine is in.

## Know what you are agreeing to

- **Your IP makes requests to third-party services** on the gateway's behalf.
  If that traffic trips an abuse report, the notice comes to your address.
- **The gateway can send traffic to any destination through your machine.**
  The Tor and WARP paths are unrestricted; the direct path only reaches
  public addresses on port 443.
- **The installer runs as root** and changes your system: it installs
  packages, edits `/etc/tor/torrc` (backed up), and on Debian/Ubuntu it
  registers WARP and switches it to the mode the node was set up with.
- **Don't use it on a work or school machine.** The traffic is yours.

WARP is usually your machine's resolver, and switching it to proxy mode takes
that away with it. The installer puts your resolver back and tells you when
it does. In tunnel mode the resolver stays WARP's - that is the point of it -
and the machine's own is only put back if WARP's stops answering.

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
