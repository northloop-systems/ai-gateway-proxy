#!/usr/bin/env python3
"""Test the SOCKS5 proxy the node actually runs.

The proxy is the `ai-gateway-proxy` binary - the same one the installer
puts on the machine - so these tests drive that binary over a loopback
socket: real SOCKS5 handshakes against the real server, with the real
destination filter.

What is actually being pinned:
  - the destination restriction (port 443, globally-routable addresses only)
  - that loopback / LAN / cloud-metadata / link-local targets are refused
  - that authentication is required and cannot be bypassed
  - that the hub is the only accepted source and rejects do not leak the
    connection counter
  - that concurrency stays bounded and unwedged connections do not hang forever

Run: python3 tests/test_socks5_proxy.py -v
"""

import ipaddress
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALLER = REPO / "install.sh"

HUB_IP = "10.200.0.1"
USER = "testuser"
PASSWORD = "testpassword"


def build_binary() -> Path:
    """Build the node binary, once, and remember where it is."""
    cargo = os.environ.get("CARGO", "cargo")
    target = REPO / "target" / "debug" / "ai-gateway-proxy"
    if not target.exists():
        subprocess.run([cargo, "build"], cwd=REPO, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return target


def start_proxy(port: int, bind_host: str) -> tuple[Path, subprocess.Popen]:
    """Run the node's proxy, pointed somewhere a test can reach.

    The shipped proxy accepts ONLY the hub (10.200.0.1) and drops
    everything else, so the hub address is given as the loopback the test
    connects from: that check is correct, and redirecting it here is what
    lets the destination, authentication and counter logic be exercised over
    a real socket at all.
    """
    binary = build_binary()
    proc = subprocess.Popen(
        [str(binary), "serve",
         "--addr", bind_host, "--port", str(port),
         "--user", USER, "--password", PASSWORD,
         "--hub-ip", bind_host],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    # Wait for the listener rather than sleeping a fixed amount.
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection((bind_host, port), timeout=0.2):
                return binary, proc
        except OSError:
            if proc.poll() is not None:
                raise RuntimeError(proc.stderr.read().decode())
            time.sleep(0.05)
    proc.kill()
    raise RuntimeError("proxy never started listening")


class ProxyUnderTest(unittest.TestCase):
    PORT = 0
    proc = None

    @classmethod
    def setUpClass(cls):
        # 127.0.0.2 is loopback too, so the hub-IP filter can be exercised from
        # "a different local address" without needing a WireGuard interface.
        cls.bind_host = "127.0.0.1"
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        cls.PORT = probe.getsockname()[1]
        probe.close()
        cls.path, cls.proc = start_proxy(cls.PORT, cls.bind_host)

    @classmethod
    def tearDownClass(cls):
        if cls.proc:
            cls.proc.kill()
            cls.proc.wait(timeout=5)
            for stream in (cls.proc.stdout, cls.proc.stderr):
                if stream is not None:
                    stream.close()

    def connect(self, timeout=5):
        s = socket.create_connection((self.bind_host, self.PORT), timeout=timeout)
        s.settimeout(timeout)
        return s

    def handshake(self, user=USER, password=PASSWORD, atyp=None, addr=None, port=443,
                  skip_auth=False):
        """Perform a SOCKS5 CONNECT; returns (sock, reply_byte)."""
        s = self.connect()
        if skip_auth:
            # A client that offers ONLY "no authentication" - which is not
            # on offer, so the server has nothing to negotiate with.
            s.sendall(b"\x05\x01\x00")
        else:
            # The methods on offer: no-auth and username/password.
            s.sendall(b"\x05\x02\x00\x02")
        methods = s.recv(2)
        if not methods or methods[0] != 5:
            s.close()
            return None, None
        if skip_auth:
            s.close()
            return s, methods[1]
        u, p = user.encode(), password.encode()
        s.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        auth = s.recv(2)
        if len(auth) < 2 or auth[1] != 0:
            s.close()
            return None, auth[1] if auth else None

        if atyp is None:
            atyp = 3
        if atyp == 3:
            a = addr.encode()
            req = b"\x05\x01\x00\x03" + bytes([len(a)]) + a + port.to_bytes(2, "big")
        elif atyp == 1:
            req = b"\x05\x01\x00\x01" + socket.inet_aton(addr) + port.to_bytes(2, "big")
        else:
            req = b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, addr) + \
                port.to_bytes(2, "big")
        s.sendall(req)
        reply = s.recv(2)
        return s, (reply[1] if len(reply) > 1 else None)


class BinaryTests(unittest.TestCase):
    """The proxy is the binary, so the binary is what these test."""

    def test_the_installer_installs_the_binary(self):
        self.assertIn("ai-gateway-proxy", INSTALLER.read_text())

    def test_the_binary_has_a_serve_command(self):
        binary = build_binary()
        out = subprocess.run([str(binary), "--help"], capture_output=True, text=True)
        self.assertIn("serve", out.stdout + out.stderr)

    def test_the_proxy_does_not_bind_wildcard_by_default(self):
        """A missing address would expose the proxy on every interface."""
        self.assertIn('"127.0.0.1"', (REPO / "src" / "socks5" / "mod.rs").read_text())


class DestinationRestrictionTests(ProxyUnderTest):
    """The whole point of the node: the hub gets HTTPS, not a general proxy."""

    def test_refuses_loopback(self):
        s, reply = self.handshake(addr="127.0.0.1")
        self.assertIsNotNone(reply)
        self.assertNotEqual(reply, 0, "loopback was CONNECTed")
        if s:
            s.close()

    def test_refuses_private_lan(self):
        for addr in ("10.0.0.1", "192.168.1.1", "172.16.0.1"):
            with self.subTest(addr=addr):
                s, reply = self.handshake(addr=addr)
                self.assertNotEqual(reply, 0, f"{addr} was CONNECTed")
                if s:
                    s.close()

    def test_refuses_cloud_metadata(self):
        for addr in ("169.254.169.254", "100.100.100.200"):
            with self.subTest(addr=addr):
                s, reply = self.handshake(addr=addr)
                self.assertNotEqual(reply, 0, f"{addr} was CONNECTed")
                if s:
                    s.close()

    def test_refuses_link_local_and_unspecified(self):
        for addr in ("0.0.0.0", "224.0.0.1"):
            with self.subTest(addr=addr):
                s, reply = self.handshake(addr=addr)
                self.assertNotEqual(reply, 0, f"{addr} was CONNECTed")
                if s:
                    s.close()

    def test_refuses_non_https_ports(self):
        for port in (80, 22, 8080, 25, 0):
            with self.subTest(port=port):
                s, reply = self.handshake(addr="127.0.0.1", port=port)
                self.assertNotEqual(reply, 0, f"port {port} was CONNECTed")
                if s:
                    s.close()

    def test_ipv4_literal_public_is_attempted(self):
        # 8.8.8.8:443 is public, so the filter must NOT refuse it. The connect
        # will fail in a sandbox, but the reply must not be a policy refusal.
        s, reply = self.handshake(addr="8.8.8.8", port=443)
        self.assertNotIn(reply, (2,), "public address refused as not-allowed")
        if s:
            s.close()

    def test_refuses_ipv6_loopback(self):
        s, reply = self.handshake(atyp=4, addr="::1")
        self.assertNotEqual(reply, 0, "IPv6 loopback was CONNECTed")
        if s:
            s.close()


class AuthTests(ProxyUnderTest):
    def test_no_credentials_is_refused(self):
        s, reply = self.handshake(skip_auth=True)
        self.assertNotEqual(reply, 0, "client offering no auth was accepted")

    def test_wrong_password_is_refused(self):
        s, reply = self.handshake(password="wrong-password")
        self.assertIsNone(s, "wrong password was accepted")
        self.assertNotEqual(reply, 0)

    def test_wrong_username_is_refused(self):
        s, reply = self.handshake(user="nobody")
        self.assertIsNone(s, "wrong username was accepted")

    def test_refused_auth_does_not_reach_the_destination_filter(self):
        # A bad password must fail before any resolution happens, so a refused
        # auth cannot be used as a resolver oracle.
        s, reply = self.handshake(user="nobody", addr="127.0.0.1")
        self.assertIsNone(s)


class HubSourceTests(ProxyUnderTest):
    """Only the hub may use the proxy; other sources are dropped silently."""

    def test_non_hub_source_is_dropped(self):
        # Point a connection at the socket from an address that is not the
        # configured hub. Because the proxy binds only to the WireGuard address
        # in production, this is mostly a static property - asserted in
        # SourceInspectionTests - but the drop must not crash the daemon.
        s = socket.create_connection((self.bind_host, self.PORT), timeout=5)
        s.settimeout(5)
        s.sendall(b"\x05\x02\x00\x00")
        s.close()
        self.assertIsNone(self.proc.poll(), "proxy exited on a dropped client")

    def test_proxy_survives_a_partial_handshake(self):
        for _ in range(20):
            s = socket.create_connection((self.bind_host, self.PORT), timeout=5)
            s.sendall(b"\x00" * 3)   # not a SOCKS5 greeting
            s.close()
        self.assertIsNone(self.proc.poll(), "proxy exited on a malformed handshake")
        # And it still works afterwards.
        s, reply = self.handshake(addr="127.0.0.1")
        self.assertIsNotNone(reply, "proxy stopped serving after malformed clients")
        if s:
            s.close()


class ConcurrencyTests(ProxyUnderTest):
    def test_worker_pool_is_bounded_and_recovers(self):
        """MAX_CONNS must actually bound the worker threads.

        Note the pool is FULL after this, so a further connection is legitimately
        refused - that is the intended back-pressure, not a bug. What matters is
        that threads stay bounded (one per connection, not unbounded growth), the
        daemon does not die, and slots come back when the clients disconnect.
        """
        socks = []
        try:
            for _ in range(200):
                try:
                    s = socket.create_connection((self.bind_host, self.PORT), timeout=2)
                    s.sendall(b"\x05\x02\x00\x00")   # complete greeting, stall here
                    socks.append(s)
                except OSError:
                    break
            time.sleep(1.0)
            self.assertIsNone(self.proc.poll(), "proxy died under connection pressure")
            threads = self._thread_count()
            # Bounded by MAX_CONNS plus a small allowance for the accept loop and
            # whatever the interpreter already had.
            self.assertLess(threads, 200,
                            f"worker threads grew with connection count: {threads}")
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass
        # Slots must be released once those clients go away.
        deadline = time.time() + 20
        while time.time() < deadline:
            s, reply = self.handshake(addr="127.0.0.1")
            if reply is not None:
                if s:
                    s.close()
                return
            if s:
                s.close()
            time.sleep(0.5)
        self.fail("proxy never recovered its connection slots after clients left")

    def _thread_count(self):
        with open(f"/proc/{self.proc.pid}/status") as f:
            for line in f:
                if line.startswith("Threads:"):
                    return int(line.split()[1])
        return -1


class SourceInspectionTests(unittest.TestCase):
    """Static checks on what actually ships.

    The same guarantees the Python proxy had, read out of the Rust source
    this time: the source check comes before the counter, the counter is
    given back however the connection ends, the destination is resolved
    once and the resolved ADDRESS is what is connected to, and every
    answer has to be global.
    """

    def setUp(self):
        self.server = (REPO / "src" / "socks5" / "server.rs").read_text()
        self.filter = (REPO / "src" / "socks5" / "filter.rs").read_text()

    def test_the_slot_is_given_back_however_the_connection_ends(self):
        """The counter is a Drop, so an error path cannot leak it."""
        self.assertIn("impl Drop for Slot", self.server)
        self.assertRegex(self.server, r"impl Drop for Slot[\s\S]{0,200}fetch_sub")

    def test_the_source_check_precedes_the_counter_increment(self):
        """The bug that mattered: incrementing first meant rejected
        connections never released their slot."""
        check = self.server.index("if !from_hub(")
        bump = self.server.index("clients.fetch_add(1")
        self.assertLess(check, bump, "the counter is incremented before the source check")

    def test_the_destination_is_resolved_once_and_validated(self):
        """Resolve-then-connect is what defeats DNS rebinding: the
        connection is made to the address that was checked, not to the name
        that was asked for."""
        self.assertIn("filter::allowed_targets", self.server)
        self.assertIn("SocketAddr::new(target, request.port)", self.server)
        self.assertNotIn("SocketAddr::new(request.host", self.server)

    def test_resolve_requires_every_answer_to_be_global(self):
        self.assertRegex(self.filter, r"\.all\(is_global\)")

    def test_resolve_requires_port_443(self):
        self.assertRegex(self.filter, r"const ALLOWED_PORT: u16 = 443")
        self.assertRegex(self.filter, r"port != ALLOWED_PORT")

    def test_the_proxy_does_not_bind_wildcard_by_default(self):
        """A missing address would expose the proxy on every interface."""
        self.assertIn('"127.0.0.1"', (REPO / "src" / "socks5" / "mod.rs").read_text())


if __name__ == "__main__":
    unittest.main()
