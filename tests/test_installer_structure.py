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

    def test_endpoint_is_not_taken_from_the_server(self):
        # The server must not control where the tunnel points; it used to be
        # parsed out of the registration response, which also hung waiting on
        # stdin when the pipe was lost.
        self.assertIn('WG_GATEWAY_ENDPOINT="$WG_ENDPOINT"', SRC)
        self.assertNotIn("wireguard_endpoint',", SRC)


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
