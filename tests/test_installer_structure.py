#!/usr/bin/env python3
"""Tests for the installer's bootstrap script.

The installer used to be one shell script that did everything. It is now a
script that fetches the ai-gateway-proxy binary, checks it against a
pinned SHA-256 and runs it - and the work is in the binary, which has its
own tests (cargo test).

So these tests are about the script: that it refuses to run a binary it
cannot vouch for, that it gets the binary from somewhere the operator
would expect, that the token is handled the way the operator would want,
and that the uninstaller can still do its job when the binary is the thing
that is broken.

Run: python3 tests/test_installer_structure.py -v
"""

import re
import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALLER = REPO / "install.sh"
UNINSTALLER = REPO / "uninstall.sh"
SRC = INSTALLER.read_text()
UNINSTALL_SRC = UNINSTALLER.read_text()


class ShellTests(unittest.TestCase):
    def test_install_parses(self):
        subprocess.run(["bash", "-n", str(INSTALLER)], check=True)

    def test_uninstall_parses(self):
        subprocess.run(["bash", "-n", str(UNINSTALLER)], check=True)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck_clean_at_warning_level(self):
        for script in (INSTALLER, UNINSTALLER):
            with self.subTest(script=script.name):
                out = subprocess.run(
                    ["shellcheck", "-S", "warning", str(script)],
                    capture_output=True, text=True,
                )
                self.assertEqual(out.returncode, 0, (out.stdout + out.stderr)[:2000])

    def test_strict_mode_is_on(self):
        self.assertRegex(SRC, r"(?m)^set -euo pipefail$", "strict mode missing")

    def test_root_is_required(self):
        self.assertIn("id -u", SRC)

    def test_the_token_is_never_passed_on_a_command_line(self):
        """`ps` shows every process's arguments to every user on the machine,
        and this token grants access to the node."""
        for line in SRC.splitlines():
            self.assertNotRegex(line, r"Authorization: Bearer \$", "the token is in argv")
            self.assertNotIn("--token $", line)

    def test_the_token_is_not_echoed_by_the_script(self):
        self.assertNotIn("echo \"$AI_GATEWAY_PROXY_TOKEN\"", SRC)


class ChecksumTests(unittest.TestCase):
    """The one moment where it matters that the binary is the one the
    release published."""

    def test_the_checksum_comes_with_the_binary(self):
        self.assertIn("${RELEASE_URL}/${ASSET}.sha256", SRC)

    def test_the_binary_is_checked_before_it_is_run(self):
        checksum_at = SRC.index("sha256sum")
        run_at = SRC.index('"$INSTALL_PATH" install')
        self.assertLess(checksum_at, run_at, "the binary is run before it is checked")

    def test_a_mismatch_stops_the_install(self):
        self.assertIn("does not match", SRC)
        self.assertRegex(SRC, r"does not match[\s\S]{0,400}exit 1", "a mismatch does not stop the install")

    def test_a_missing_checksum_stops_the_install(self):
        """Without a checksum there is nothing to check the binary against,
        and the binary is what runs as root."""
        self.assertRegex(
            SRC, r"Could not download the checksum[\s\S]{0,400}exit 1",
            "a missing checksum does not stop the install",
        )

    def test_the_latest_release_is_fetched(self):
        """Nobody has to know a version number to lend a machine."""
        self.assertIn("releases/latest/download", SRC)


class DownloadTests(unittest.TestCase):
    def test_the_release_is_where_the_binary_comes_from(self):
        self.assertIn("github.com/${REPO}/releases/latest/download", SRC)

    def test_both_architectures_are_offered(self):
        self.assertIn("x86_64|amd64", SRC)
        self.assertIn("aarch64|arm64", SRC)

    def test_a_local_binary_can_be_installed_instead(self):
        """For the person who built it."""
        self.assertIn("--local", SRC)
        self.assertIn("AI_GATEWAY_PROXY_TOKEN", SRC)


class TokenPromptTests(unittest.TestCase):
    """The token is shown as it is typed: a masked prompt cannot be checked,
    and the commonest failure is a token pasted with a character missing."""

    def test_the_prompt_is_not_masked(self):
        prompt = next((ln for ln in SRC.splitlines() if "API token" in ln and "read" in ln),
                      None)
        self.assertIsNotNone(prompt, "the token prompt was not found")
        self.assertNotRegex(prompt, r"read\s+-\w*s", "the token prompt is masked")

    def test_the_token_is_read_from_the_terminal_not_the_pipe(self):
        """The installer is run as `curl ... | bash`, so stdin is the script."""
        prompt = next((ln for ln in SRC.splitlines() if "API token" in ln and "read" in ln),
                      None)
        self.assertIn("</dev/tty", prompt or "")

    def test_the_token_reaches_the_binary_in_the_environment(self):
        self.assertIn("export AI_GATEWAY_PROXY_TOKEN", SRC)

    def test_an_empty_token_is_refused(self):
        self.assertIn('if [ -z "$AI_GATEWAY_PROXY_TOKEN" ]; then', SRC)


class UninstallTests(unittest.TestCase):
    """The uninstaller has to work when the binary is the thing that is
    broken - which is exactly when it is needed."""

    def test_it_prefers_the_binary(self):
        self.assertIn("/usr/local/bin/ai-gateway-proxy", UNINSTALL_SRC)

    def test_it_can_do_the_job_without_the_binary(self):
        """Tunnel down with the configuration still in place, the firewall
        rules removed explicitly, the units removed, the torrc restored."""
        for needle in ("wg-quick down wg0", "iptables -D INPUT -i wg0",
                       "proxy-tunnel-watchdog.timer", "torrc.bak",
                       "userdel proxysocks"):
            with self.subTest(needle=needle):
                self.assertIn(needle, UNINSTALL_SRC)

    def test_the_tunnel_goes_down_before_its_configuration_is_removed(self):
        """The firewall rules are wg-quick's PostDown rules: they only go
        away if the interface is brought down while the config is there."""
        down = UNINSTALL_SRC.index("wg-quick down wg0")
        rm = UNINSTALL_SRC.index("rm -f /etc/wireguard/wg0.conf")
        self.assertLess(down, rm, "the config is removed before the tunnel is down")

    def test_the_hub_is_told_the_node_is_leaving(self):
        self.assertIn("/proxy/nodes/node-", UNINSTALL_SRC)
        self.assertIn("Authorization: Bearer", UNINSTALL_SRC)

    def test_the_warp_registration_is_not_deleted(self):
        """WARP may have been on the machine before the installer ran, so the
        uninstaller must not silently delete the user's registration. It may
        MENTION the command, but must never run it."""
        for line in UNINSTALL_SRC.splitlines():
            stripped = line.strip()
            if stripped.startswith("warp-cli") and "registration delete" in stripped:
                self.fail(f"the uninstaller must not run: {stripped}")


class RepositoryTests(unittest.TestCase):
    def test_the_binary_is_built_for_both_architectures(self):
        workflow = (REPO / ".github" / "workflows" / "build.yml").read_text()
        self.assertIn("x86_64-unknown-linux-musl", workflow)
        self.assertIn("aarch64-unknown-linux-musl", workflow)

    def test_the_release_publishes_the_checksums(self):
        workflow = (REPO / ".github" / "workflows" / "build.yml").read_text()
        self.assertIn("sha256sum", workflow)

    def test_the_readme_says_how_to_install(self):
        readme = (REPO / "README.md").read_text()
        self.assertIn("install.sh", readme)
        self.assertIn("uninstall.sh", readme)


if __name__ == "__main__":
    unittest.main()
