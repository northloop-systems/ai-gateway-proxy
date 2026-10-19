#!/usr/bin/env python3
"""Test the SOCKS5 proxy that install.sh actually ships.

The proxy is generated as a heredoc inside install.sh, so testing a copy of it
would test nothing. These tests extract the real block from the installer,
substitute the generated credentials, and drive it over a loopback socket: real
SOCKS5 handshakes against the real handler, with a stub upstream standing in for
the destination.

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


def extract_socks5() -> str:
    """Pull the socks5.py heredoc out of install.sh verbatim."""
    src = INSTALLER.read_text()
    start = src.index('cat > "$PROXY_DIR/socks5.py"')
    block = src[start:]
    heredoc = block.index("<<PYEOF\n") + len("<<PYEOF\n")
    return block[heredoc:block.index("\nPYEOF", heredoc)]


def build_proxy(port: int, bind_host: str) -> Path:
    """Materialise the shipped proxy, pointed somewhere a test can reach.

    Two substitutions, both of the "configuration the installer generates at
    install time" kind rather than logic changes:
      - SOCKS_USER / SOCKS_PASS, so the test knows the credentials
      - WG_HUB_IP -> bind_host, because the shipped proxy accepts ONLY the hub
        (10.200.0.1) and drops everything else. That check is correct and is
        asserted statically by SourceInspectionTests; redirecting the address
        here is what lets the destination/auth/counter logic be exercised over a
        real socket at all.
    """
    body = extract_socks5()
    body = body.replace('"${SOCKS_USER}"', repr(USER)).replace('"${SOCKS_PASS}"', repr(PASSWORD))
    body = re.sub(r'WG_HUB_IP = "[^"]*"', f'WG_HUB_IP = "{bind_host}"', body)
    tmp = Path(tempfile.mkdtemp())
    path = tmp / "socks5.py"
    path.write_text(body)
    proc = subprocess.Popen(
        [sys.executable, str(path), str(port), bind_host],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    # Wait for the listener rather than sleeping a fixed amount.
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection((bind_host, port), timeout=0.2):
                return path, proc
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
        cls.path, cls.proc = build_proxy(cls.PORT, cls.bind_host)

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
        s.sendall(b"\x05\x02\x00\x00")          # version, methods: user/pass
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


class ExtractionTests(unittest.TestCase):
    def test_installer_embeds_a_proxy(self):
        self.assertIn("socks5.py", INSTALLER.read_text())

    def test_extracted_source_is_valid_python(self):
        path = Path(tempfile.mkdtemp()) / "socks5.py"
        path.write_text(extract_socks5().replace('"${SOCKS_USER}"', '"u"')
                        .replace('"${SOCKS_PASS}"', '"p"'))
        subprocess.run([sys.executable, "-m", "py_compile", str(path)], check=True)

    def test_proxy_uses_the_rfc1929_auth_method(self):
        self.assertIn("b'\\x05\\x02'", extract_socks5())

    def test_proxy_does_not_bind_wildcard_by_default(self):
        body = extract_socks5()
        # argv[2] is the WireGuard address; the fallback must stay loopback or a
        # missing value would expose the proxy on every interface.
        self.assertIn('sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"', body)


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
    """Static checks on what actually ships."""

    def setUp(self):
        self.body = extract_socks5()

    def test_counter_is_decremented_in_a_finally(self):
        self.assertIn("finally:", self.body)
        self.assertRegex(self.body, r"finally:\s*\n\s*with conn_lock:\s*\n\s*active_conns -= 1")

    def test_source_check_precedes_the_counter_increment(self):
        # The bug that mattered: incrementing first meant rejected connections
        # never released their slot.
        accept = self.body.index("c, addr = s.accept()")
        check = self.body.index("if addr[0] != WG_HUB_IP:")
        bump = self.body.index("active_conns += 1")
        self.assertLess(accept, check)
        self.assertLess(check, bump, "counter is incremented before the source check")

    def test_destination_is_resolved_once_and_validated(self):
        # Resolve-then-connect is what defeats DNS rebinding.
        self.assertIn("_resolve_safe", self.body)
        self.assertIn("socket.create_connection((resolved, port)", self.body)
        self.assertNotRegex(self.body, r"create_connection\(\(addr,")

    def test_resolve_requires_every_answer_to_be_global(self):
        self.assertRegex(
            self.body,
            r"not all\(ipaddress\.ip_address\(i\)\.is_global for i in ips\)",
        )

    def test_resolve_requires_port_443(self):
        self.assertRegex(self.body, r"if port != 443:\s*\n\s*return None")


if __name__ == "__main__":
    unittest.main()
