#!/usr/bin/env python3
"""Structural tests for install.sh.

The installer cannot be run end-to-end in CI (it needs root, a real hub, and it
mutates the machine), so these pin the parts that are pure text generation and
pure validation. They are aimed at the mistakes that actually happen: a systemd
or WireGuard directive landing in the wrong section, a firewall rule appended
instead of inserted, a secret left on a command line, a guard that silently
does nothing.

Every assertion here corresponds to a real bug found in review.

Run: python3 tests/test_installer_structure.py -v
"""

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALLER = REPO / "install.sh"
UNINSTALLER = REPO / "uninstall.sh"
SRC = INSTALLER.read_text()
UNINSTALL_SRC = UNINSTALLER.read_text()


class ShellTests(unittest.TestCase):
    def test_parses(self):
        subprocess.run(["bash", "-n", str(INSTALLER)], check=True)

    @unittest.skipUnless(
        shutil.which("shellcheck"), "shellcheck not installed",
    )
    def test_shellcheck_clean_at_warning_level(self):
        out = subprocess.run(
            ["shellcheck", "-S", "warning", str(INSTALLER)],
            capture_output=True, text=True,
        )
        self.assertEqual(out.returncode, 0, (out.stdout + out.stderr)[:2000])

    def test_strict_mode_is_on(self):
        self.assertRegex(SRC, r"(?m)^set -euo pipefail$", "strict mode missing")

    def test_root_is_required(self):
        self.assertIn("id -u", SRC)


class WireGuardConfigTests(unittest.TestCase):
    """wg-quick rejects directives outside [Interface]; a misplaced PostUp
    fails the install at 'WireGuard failed to start'."""

    def _wg_heredoc(self):
        start = SRC.index("<<WGEOF\n") + len("<<WGEOF\n")
        return SRC[start:SRC.index("\nWGEOF", start)]

    def test_config_puts_every_directive_in_a_valid_section(self):
        body = self._wg_heredoc()
        section = None
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("["):
                section = line
                self.assertIn(section, ("[Interface]", "[Peer]"), f"unknown section {section}")
            elif line and "=" in line and not line.startswith("#"):
                key = line.split("=", 1)[0].strip()
                if section == "[Peer]":
                    # PostUp/PostDown are [Interface]-only; wg-quick errors out.
                    self.assertNotIn(key, ("PostUp", "PostDown"),
                                     f"{key} in [Peer] - wg-quick will reject this")
                elif section == "[Interface]":
                    self.assertIn(key, ("PrivateKey", "Address", "PostUp", "PostDown",
                                        "ListenPort", "Table"), f"bad [Interface] key {key}")
                else:
                    self.fail(f"directive {key!r} appears before any section")

    def test_interface_block_is_complete(self):
        body = self._wg_heredoc()
        self.assertIn("[Interface]", body)
        self.assertIn("PrivateKey = $WG_PRIVATE_KEY", body)
        self.assertIn("Address = $WG_ASSIGNED_IP/", body)
        self.assertIn("[Peer]", body)
        self.assertIn("PublicKey = $WG_GATEWAY_PUBKEY", body)

    def test_firewall_lives_in_the_interface_block_not_a_later_append(self):
        # The regression: PostUp was appended after the [Peer] block via
        # `cat >>`, which wg-quick rejects outright.
        self.assertNotIn("cat >> /etc/wireguard/wg0.conf", SRC)
        self.assertIn("PostUp = iptables", self._wg_heredoc())

    def test_peer_allowed_ips_is_pinned_to_the_gateway(self):
        body = self._wg_heredoc()
        self.assertIn("AllowedIPs = 10.200.0.1/32", body)

    def test_the_endpoint_comes_from_the_hub(self):
        # The hub is the authority on where it can be reached, and it may be
        # reachable somewhere the operator never had to think about - a public
        # IPv6, a tunnel, a different hostname entirely. Making the operator
        # supply it turned a two-line install into one that needs the hub's
        # network topology spelled out.
        #
        # A hub that answered with a bogus endpoint cannot use it to redirect
        # the node's traffic: the tunnel's peer is authenticated by the hub's
        # WireGuard PUBLIC KEY, which the node verifies from the same
        # response, so a handshake to any other host simply fails.
        #
        # The earlier implementation that also read the endpoint out of the
        # response hung waiting on stdin when the pipe was lost; this one
        # parses the same way as the two extractions beside it, so it cannot.
        self.assertIn('WG_GATEWAY_ENDPOINT="${WG_ADVERTISED_ENDPOINT:-$WG_ENDPOINT}"', SRC)


class ValidationTests(unittest.TestCase):
    """Server-supplied values are validated with whole-string bash regexes.

    grep -qE matches line-by-line, so a value like
    "10.200.0.5\\nPostUp = evil" would pass a grep guard and then be written
    into the config. [[ =~ ]] matches the whole string.
    """

    def test_uses_bash_regex_not_grep(self):
        for field in ("WG_GATEWAY_PUBKEY", "WG_ASSIGNED_IP", "WG_GATEWAY_ENDPOINT"):
            with self.subTest(field=field):
                pattern = re.search(rf'\[\[ "\${field}" =~', SRC)
                # Either validated by bash regex, or no longer taken from the
                # server at all (endpoint), which is checked above.
                if pattern:
                    self.assertNotRegex(SRC, rf'grep -qE.*\${field}')

    def test_ip_octet_check_is_decimal_not_octal(self):
        # `[ 08 -gt 255 ]` is read as octal by bash and errors out, which would
        # let the guard pass. The 10# prefix forces base 10.
        self.assertIn("10#", SRC)
        self.assertNotRegex(SRC, r'\[ "\$\{BASH_REMATCH\[1\]\}" -gt')

    def test_rejects_whole_string_matches(self):
        self.assertIn('=~ ^[A-Za-z0-9+/]{43}=$', SRC)
        self.assertIn(r'=~ ^10\.200\.0\.', SRC)

    def test_ip_range_excludes_network_and_gateway(self):
        line = next(ln for ln in SRC.splitlines() if "WG_ASSIGNED_IP" in ln and "=~" in ln)
        self.assertIn("-gt 255", line, "no upper bound on the octet")
        self.assertIn("-lt 2", line, "network (.0) or gateway (.1) address is allowed")


class FirewallTests(unittest.TestCase):
    def _rules(self):
        return [ln for ln in SRC.splitlines() if ln.startswith("PostUp = iptables")]

    def test_rules_are_inserted_not_appended(self):
        # -A appends after any existing accept rule (ufw's, say); -I puts ours
        # first so they actually take effect.
        for rule in self._rules():
            self.assertIn(" -I INPUT 1 ", rule, f"appends instead of inserting: {rule}")

    def test_drop_is_ordered_after_the_allows(self):
        # Each -I 1 lands at the top, so the LAST PostUp ends up highest. For
        # the final order to be allow-then-drop, DROP must be inserted FIRST.
        rules = self._rules()
        self.assertTrue(rules, "no firewall rules found")
        self.assertIn("-j DROP", rules[0])
        self.assertNotIn("-j DROP", rules[-1])

    def test_only_proxy_ports_are_allowed_and_only_from_the_hub(self):
        allows = [r for r in self._rules() if "ACCEPT" in r]
        ports = {int(p) for r in allows for p in re.findall(r"--dport (\d+)", r)}
        self.assertEqual(ports, {9050, 40000, 1080},
                         f"unexpected ports opened on the tunnel: {sorted(ports)}")
        for rule in allows:
            if "--dport" in rule:
                self.assertIn("-s 10.200.0.1", rule,
                              f"proxy port reachable from any source: {rule}")

    def test_everything_else_on_the_interface_is_dropped(self):
        self.assertIn("-i %i -j DROP", SRC)

    def test_postdown_mirrors_postup(self):
        # Same rule set, opposite verb. PostUp inserts at INPUT 1 (no position
        # argument), PostDown just deletes by match, so normalise the "1" away
        # before comparing. Order deliberately differs: deletion order is
        # irrelevant, insertion order is not.
        def normalise(line: str) -> str:
            body = line.split("= ", 1)[1].strip()
            body = body.replace("-I INPUT 1", "INPUT").replace("-D INPUT", "INPUT")
            return " ".join(body.split())

        ups = {normalise(ln) for ln in SRC.splitlines()
               if ln.startswith("PostUp = iptables")}
        downs = {normalise(ln) for ln in SRC.splitlines()
                 if ln.startswith("PostDown = iptables")}
        self.assertTrue(ups, "no PostUp rules")
        self.assertEqual(ups, downs, "PostDown does not mirror PostUp")


class SecretHandlingTests(unittest.TestCase):
    def test_token_is_not_on_a_command_line(self):
        # curl's argv is world-readable via /proc while the request is in flight.
        for line in SRC.splitlines():
            self.assertNotRegex(line, r'-H "Authorization: Bearer \$API_TOKEN"',
                                "token passed in argv, visible in ps")
        self.assertIn("--config", SRC)
        self.assertIn("mktemp", SRC)

    def test_curl_auth_config_is_private_and_removed(self):
        self.assertRegex(SRC, r'chmod 600 "\$CURL_AUTH"')
        self.assertRegex(SRC, r"trap 'rm -f", "auth config is left behind on exit")

    def test_registration_json_is_built_without_interpolating_secrets(self):
        # Building the body by interpolating the password into a python -c
        # string puts it in the process's argv and its cmdline.
        for line in SRC.splitlines():
            if "json.dumps" in line:
                self.assertNotIn("${SOCKS_PASS}", line,
                                 "SOCKS password interpolated into a python source string")
                self.assertNotIn("$SOCKS_PASS", line)
                self.assertRegex(line, r"SP|os\.environ")

    def test_private_key_lives_only_in_a_0600_config(self):
        # The key is written into wg0.conf and chmod'ed; there is deliberately
        # no second copy at /opt/proxy-node to keep in sync.
        self.assertIn('chmod 600 /etc/wireguard/wg0.conf', SRC)
        self.assertNotIn('wg_private.key', SRC)

    def test_no_world_umask_that_breaks_the_proxy_user(self):
        # A global `umask 077` made /opt/proxy-node 0700 root, so proxysocks
        # could not read the script and the service never started.
        self.assertNotRegex(SRC, r"(?m)^umask 077$", "global umask 077 breaks the proxy user")
        self.assertIn("install -d -m 0750 -o root -g proxysocks", SRC)

    def test_proxy_script_is_not_writable_by_the_service_user(self):
        self.assertNotIn("ReadWritePaths", SRC)
        self.assertNotIn("chown proxysocks", SRC)
        self.assertIn("chmod 644 \"$PROXY_DIR/socks5.py\"", SRC)


class SystemdUnitTests(unittest.TestCase):
    def test_socks_service_runs_unprivileged(self):
        block = SRC[SRC.index("proxy-socks5.service"):]
        block = block[:block.index("UNIT", block.index("UNIT") + 1)]
        self.assertIn("User=proxysocks", block)
        self.assertIn("NoNewPrivileges=yes", block)
        self.assertIn("ProtectSystem=strict", block)
        self.assertIn("ProtectHome=true", block)

    def test_socat_redirects_are_bounded_and_unprivileged(self):
        self.assertIn("DynamicUser=yes", SRC)
        self.assertIn("max-children=32", SRC)

    def test_socat_is_required_not_optional(self):
        # It was an `if command -v socat` that silently skipped while the
        # firewall still opened the ports, leaving them open to nothing.
        self.assertIn("if ! command -v socat &>/dev/null; then", SRC)
        self.assertNotIn("if command -v socat &>/dev/null; then", SRC)


class PackageTests(unittest.TestCase):
    def test_iptables_is_installed_not_assumed(self):
        # The early `command -v iptables` check aborted on a fresh box before
        # anything was installed.
        for line in SRC.splitlines():
            if "command -v iptables" in line:
                self.assertNotIn("\n", line)
        self.assertIn("install_packages", SRC)
        for distro in ("apt-get install", "dnf install", "yum install", "pacman"):
            idx = SRC.index(distro)
            self.assertIn("iptables", SRC[idx:idx + 200], f"{distro} line lacks iptables")

    def test_socat_is_installed(self):
        for distro in ("apt-get install", "dnf install", "yum install", "pacman"):
            idx = SRC.index(distro)
            self.assertIn("socat", SRC[idx:idx + 200], f"{distro} line lacks socat")

    def test_pacman_branch_matches_the_real_os_release_id(self):
        # os-release reports ID=manjaro, so the case label must be that
        # spelling; anything else falls through to "unsupported OS".
        self.assertIn("arch|manjaro)", SRC)

    def test_no_openssh_is_installed(self):
        for line in SRC.splitlines():
            self.assertNotIn("openssh", line, "SSH server must not be installed")


class EndpointTests(unittest.TestCase):
    def test_endpoint_default_is_udp_port_not_tls(self):
        self.assertIn('WG_ENDPOINT:-${SERVER_HOST}:51820', SRC)


class PreflightTests(unittest.TestCase):
    """The installer proves its credential works before it registers.

    That check has to be reachable by the credential the installer was given.
    A per-node token is scoped to /v1/proxy and is refused with 403 on
    everything else, so probing it against a normal gateway endpoint - which
    is what the preflight used to do - fails for EVERY correct token. The
    installer then rejected the credential it had just been handed and exited,
    so no node could install at all.

    Found by running the real installer against a real hub with a real
    per-node token: "Cannot reach server (HTTP 403). Check API_TOKEN and
    network." - with a token the hub would have accepted a moment later.
    """

    def test_preflight_targets_a_proxy_scoped_path(self):
        self.assertIn('"$SERVER_URL/proxy/whoami"', SRC)

    def test_preflight_never_probes_a_non_proxy_endpoint(self):
        for bad in ('"$SERVER_URL/models"',
                    '"$SERVER_URL/chat/completions"',
                    '"$SERVER_URL/embeddings"'):
            self.assertNotIn(bad, SRC,
                             f"preflight must not use {bad}: a per-node token is "
                             f"refused outside /v1/proxy")


class EndpointDiscoveryTests(unittest.TestCase):
    """The hub tells the node where to reach it; the node listens.

    The whole install has to work as `curl ... | bash`, which means the node
    cannot need the operator to know the hub's address and pass it in as an
    environment variable. The registration response already carries the
    endpoint, so the node uses that, and the env var is only the fallback.
    """

    def test_the_advertised_endpoint_is_read_from_the_registration_response(self):
        self.assertIn("wireguard_endpoint", SRC)
        self.assertIn("WG_ADVERTISED_ENDPOINT", SRC)

    def test_the_advertised_endpoint_wins_over_the_environment(self):
        self.assertIn('WG_GATEWAY_ENDPOINT="${WG_ADVERTISED_ENDPOINT:-$WG_ENDPOINT}"', SRC)

    def test_the_advertised_endpoint_is_still_validated(self):
        """A hub that answered with something malformed must not be able to
        inject a directive into the WireGuard config."""
        self.assertRegex(
            SRC,
            r'WG_GATEWAY_ENDPOINT"\s*=~\s*\^\[a-zA-Z0-9\._-\]\+:\[0-9\]\{1,5\}\$',
        )

    def test_the_env_var_is_still_honoured_as_a_fallback(self):
        self.assertIn('WG_ENDPOINT="${WG_ENDPOINT:-${SERVER_HOST}:51820}"', SRC)


class DnsPreservationTests(unittest.TestCase):
    """Switching WARP to proxy mode must not take the machine's DNS with it.

    Found on a real node: the installer flipped WARP to proxy mode, WARP's
    resolver (100.100.100.100) went away with it, and the machine could no
    longer resolve anything. The preflight had already run - that is why it
    reported "Server OK" - and the registration, which came after the switch,
    could not reach the hub. The install died with a bare "could not reach the
    server", which reads like a network problem and is really a resolver
    problem, and the user's machine was left unable to work.
    """

    FUNCTIONS = ("warp_current_mode", "dns_candidates", "dns_works", "restore_dns")

    def _helpers(self) -> str:
        """The DNS helpers, extracted so they can be run for real."""
        parts = []
        for name in self.FUNCTIONS:
            match = re.search(rf"^{name}\(\) \{{\n.*?^\}}", SRC, re.S | re.M)
            self.assertIsNotNone(match, f"{name} not found in install.sh")
            parts.append(match.group(0))
        return "\n\n".join(parts)

    def _run(self, script: str, env: dict) -> str:
        """Run the helpers with the network tools stubbed out, so the result
        depends on the resolver file and nothing else."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "bin"
            stub.mkdir()
            for tool in ("nmcli", "resolvectl"):
                (stub / tool).write_text("#!/bin/sh\nexit 1\n")
                (stub / tool).chmod(0o755)
            full = f"set -euo pipefail\n{self._helpers()}\n{script}"
            out = subprocess.run(
                ["bash", "-c", full],
                capture_output=True, text=True, env={"PATH": f"{stub}:/usr/bin:/bin", **env},
            )
            self.assertEqual(out.returncode, 0, (out.stdout + out.stderr)[:2000])
            return out.stdout.strip()

    def test_resolvers_are_captured_before_warp_is_switched(self):
        """The whole point: what the machine was using has to be known BEFORE
        the switch removes it."""
        capture = SRC.index("DNS_CANDIDATES=$(dns_candidates)")
        switch = SRC.index("warp-cli --accept-tos mode proxy")
        self.assertLess(capture, switch,
                        "the resolvers are read after WARP already took them away")

    def test_the_dns_is_checked_before_the_registration(self):
        """The registration is the first request the node makes after the
        switch, so that is where the resolver has to be working."""
        check = SRC.index("if ! dns_works; then")
        register = SRC.index("$SERVER_URL/proxy/register")
        self.assertLess(check, register, "DNS is checked after the registration")

    def test_a_dead_resolver_is_reported_as_such(self):
        """A bare 'cannot reach the server' sends people looking at their
        network. Say what is actually wrong and how to fix it."""
        block = SRC[SRC.index("if ! dns_works; then"):]
        block = block[:block.index("fi", block.index("err \"This machine cannot resolve"))]
        self.assertIn("cannot resolve", block)
        self.assertIn("resolv.conf", block)
        self.assertIn("exit 1", block)

    def test_the_candidates_exclude_warps_own_resolver(self):
        """100.100.100.100 is the resolver the switch removes. Saving it back
        would restore the breakage."""
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "resolv.conf"
            conf.write_text("nameserver 100.100.100.100\nnameserver 192.168.1.1\n")
            out = self._run("dns_candidates", {"RESOLV_CONF": str(conf)})
        self.assertEqual(out, "192.168.1.1")

    def test_a_public_resolver_is_the_last_resort(self):
        """A machine whose only nameserver was WARP's has nothing left to
        fall back on, and a node with no DNS is a node that cannot register."""
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "resolv.conf"
            conf.write_text("nameserver 100.100.100.100\n")
            out = self._run("dns_candidates", {"RESOLV_CONF": str(conf)})
        self.assertEqual(out, "1.1.1.1")

    def test_the_resolver_file_is_restored_when_it_is_a_plain_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "resolv.conf"
            conf.write_text("nameserver 100.100.100.100\n")
            self._run('restore_dns "1.1.1.1 9.9.9.9"', {"RESOLV_CONF": str(conf)})
            self.assertEqual(
                conf.read_text().split(),
                ["nameserver", "1.1.1.1", "nameserver", "9.9.9.9"],
            )

    def test_a_resolved_stub_is_not_overwritten(self):
        """systemd-resolved's stub always answers, and it asks the LINK, not
        that file. Writing the resolvers into it breaks resolved."""
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "stub-resolv.conf"
            stub.write_text("nameserver 127.0.0.53\n")
            link = Path(tmp) / "resolv.conf"
            link.symlink_to(stub)
            self._run('restore_dns "1.1.1.1" || true', {"RESOLV_CONF": str(link)})
            self.assertTrue(link.is_symlink(), "the stub was replaced by a regular file")
            self.assertEqual(stub.read_text(), "nameserver 127.0.0.53\n")

    def test_the_previous_warp_mode_is_kept_for_the_uninstaller(self):
        """The mode belongs to the machine, not to the node, so the
        uninstaller has to be able to give it back."""
        self.assertIn("warp_current_mode", SRC)
        self.assertIn("WARP_STATE_DIR/mode", SRC)
        self.assertIn("WARP_STATE_DIR/mode", UNINSTALL_SRC)

    def test_the_uninstaller_gives_the_mode_and_resolver_back(self):
        for expected in ("mode proxy", "mode dns", "mode warp"):
            self.assertIn(expected, UNINSTALL_SRC)
        self.assertIn("WARP_STATE_DIR/resolvers", UNINSTALL_SRC)


class TokenPromptTests(unittest.TestCase):
    """The token is shown as it is typed, so it can be checked and corrected.

    A masked prompt cannot be: the commonest failure here is a token pasted
    with a character missing, and a masked prompt turns that into "the
    server refused it" and sends people looking at the wrong thing.
    """

    def test_the_token_prompt_is_not_masked(self):
        prompt = next((ln for ln in SRC.splitlines() if "API token" in ln and "read" in ln),
                      None)
        self.assertIsNotNone(prompt, "the token prompt was not found")
        self.assertNotRegex(prompt, r"read\s+-\w*s", "the token prompt is masked")

    def test_the_token_is_read_from_the_terminal_not_a_pipe(self):
        """The installer is run as `curl ... | bash`, so stdin is the script
        itself: the token has to come from the terminal."""
        prompt = next((ln for ln in SRC.splitlines() if "API token" in ln and "read" in ln),
                      None)
        self.assertIn("</dev/tty", prompt or "")

    def test_an_empty_token_is_refused(self):
        self.assertIn('if [ -z "$API_TOKEN" ]; then', SRC)


class TunnelLifecycleTests(unittest.TestCase):
    """A node's exits have to follow the tunnel's whole life.

    Found on a real node: the tunnel was stopped and started again (a
    reboot, a network change, a sleep), and the Tor and WARP bridges stayed
    down. `Requires=wg-quick@wg0` stops them when the tunnel stops, and
    nothing brought them back - so the node was left with one working exit
    out of three and no explanation anywhere.
    """

    def _unit(self, name: str) -> str:
        marker = f"/etc/systemd/system/{name}.service"
        start = SRC.index(marker)
        end = SRC.index("\nREDIRECT" if "REDIRECT" in SRC[start:start + 2000] else "\nUNIT",
                        start)
        return SRC[start:end]

    def test_the_bridges_follow_the_tunnel(self):
        for unit in ("proxy-tor-redirect", "proxy-warp-redirect"):
            with self.subTest(unit=unit):
                body = self._unit(unit)
                self.assertIn("PartOf=wg-quick@wg0.service", body,
                              f"{unit} does not follow the tunnel's restarts")

    def test_the_bridges_are_started_by_the_tunnel(self):
        """Wanted by the tunnel, not by multi-user.target: a tunnel that
        comes up has to bring the bridge with it."""
        for unit in ("proxy-tor-redirect", "proxy-warp-redirect"):
            with self.subTest(unit=unit):
                body = self._unit(unit)
                self.assertIn("WantedBy=wg-quick@wg0.service", body,
                              f"{unit} is not started by the tunnel")
                self.assertNotIn("WantedBy=multi-user.target", body)

    def test_the_bridges_still_require_the_tunnel(self):
        for unit in ("proxy-tor-redirect", "proxy-warp-redirect"):
            with self.subTest(unit=unit):
                self.assertIn("Requires=wg-quick@wg0.service", self._unit(unit))

    def test_the_direct_proxy_retries_until_the_address_is_back(self):
        """It binds the tunnel's own address, so it cannot start before the
        tunnel does - and it has to keep trying until it can."""
        body = self._unit("proxy-socks5")
        self.assertIn("Restart=always", body)
        self.assertIn("RestartSec=", body)


class UninstallerTests(unittest.TestCase):
    """uninstall.sh has to leave the machine as it found it.

    The firewall rules are wg-quick's PostUp/PostDown rules, so they only go
    away if the interface is brought down while its config is still in place.
    Getting that wrong is invisible from the unit tests and obvious on a
    friend's laptop: a stale DROP rule on an interface that no longer exists.
    """

    def test_parses(self):
        subprocess.run(["bash", "-n", str(UNINSTALLER)], check=True)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck_clean_at_warning_level(self):
        out = subprocess.run(
            ["shellcheck", "-S", "warning", str(UNINSTALLER)],
            capture_output=True, text=True,
        )
        self.assertEqual(out.returncode, 0, (out.stdout + out.stderr)[:2000])

    def test_requires_root(self):
        self.assertIn("id -u", UNINSTALL_SRC)

    def test_brings_the_tunnel_down_before_removing_its_config(self):
        # The rules are PostDown rules: the interface must be stopped while
        # /etc/wireguard/wg0.conf still exists, or they are never removed.
        down = UNINSTALL_SRC.index("wg-quick@wg0")
        rm = UNINSTALL_SRC.index("rm -f /etc/wireguard/wg0.conf")
        self.assertLess(down, rm,
                        "the tunnel must be brought down before its config is removed")

    def test_removes_the_firewall_rules_explicitly(self):
        """PostDown normally removes them, but a hand-deleted interface or a
        failed shutdown leaves them behind, so they are also removed directly."""
        for port in ("1080", "9050", "40000"):
            self.assertIn(f"--dport {port}", UNINSTALL_SRC)
        self.assertIn("iptables -D INPUT -i wg0 -j DROP", UNINSTALL_SRC)

    def test_never_guards_the_stop_behind_a_pipeline(self):
        """`systemctl ... | grep -q` under `set -o pipefail` is a trap: grep -q
        exits at the first match, systemctl takes a SIGPIPE, the pipeline reports
        failure, and the tunnel is never stopped - so its PostDown never runs
        and the firewall rules are left behind. The uninstaller must not build
        that decision out of a pipeline."""
        for line in UNINSTALL_SRC.splitlines():
            if "wg-quick@wg0" not in line:
                continue
            # "||" is a fallback, not a pipe; only a real pipe is the trap.
            if "|" in line.replace("||", ""):
                self.fail(f"the tunnel stop must not be guarded by a pipeline: {line.strip()}")

    def test_deregisters_from_the_hub_with_the_nodes_own_token(self):
        """A per-node token may revoke its OWN node, so a node can leave
        without the operator having to intervene."""
        self.assertIn("/proxy/nodes/node-", UNINSTALL_SRC)
        self.assertIn("Authorization: Bearer", UNINSTALL_SRC)

    def test_restores_torrc_from_the_pristine_backup(self):
        self.assertIn("/etc/tor/torrc.bak", UNINSTALL_SRC)

    def test_does_not_touch_the_warp_registration(self):
        """WARP may have been on the machine before the installer ran, so the
        uninstaller must not silently delete the user's registration. It may
        MENTION the command, but must never run it."""
        for line in UNINSTALL_SRC.splitlines():
            stripped = line.strip()
            if stripped.startswith("warp-cli") and "registration delete" in stripped:
                self.fail(f"the uninstaller must not run: {stripped}")


if __name__ == "__main__":
    unittest.main()
