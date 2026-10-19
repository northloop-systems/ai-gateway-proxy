#!/usr/bin/env python3
"""Authenticated SOCKS5 proxy for direct (node's own) IP egress."""
import socket, threading, select, sys

LISTEN_HOST = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
WG_HUB_IP = "10.200.0.1"
LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1080
SOCKS_USER = "proxyuser"
SOCKS_PASS = "s3cret-pass-value"

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
