"""Tests for core.local_proxy.LocalForwardProxy — the port-80 / Edge-update fix.

The corporate proxy 403s CONNECT on :80 but serves plaintext HTTP as a normal
forward-proxy GET. These tests stand up a FAKE upstream proxy and assert the shim:
  * relays a forward-proxy GET with the request line preserved,
  * strips the client's hop-by-hop proxy headers and injects OUR Basic auth,
  * tunnels CONNECT (with auth) and splices bytes,
  * relays an upstream CONNECT refusal back to the client.
"""

import os
import sys
import socket
import base64
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import local_proxy
from core.local_proxy import LocalForwardProxy


class _FakeUpstream:
    """A one-shot fake upstream proxy. Captures the first request head it receives,
    then runs `responder(conn, head, overflow)` to drive the rest of the exchange."""

    def __init__(self, responder):
        self._responder = responder
        self.captured_head = b""
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            conn, _ = self._srv.accept()
        except OSError:
            return
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        except Exception:
            pass
        head, _, overflow = data.partition(b"\r\n\r\n")
        self.captured_head = head + b"\r\n\r\n"
        try:
            self._responder(conn, self.captured_head, overflow)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self):
        try:
            self._srv.close()
        except Exception:
            pass


def _client_to(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(5)
    return s


def _recv_all(sock):
    out = b""
    try:
        while True:
            c = sock.recv(4096)
            if not c:
                break
            out += c
    except Exception:
        pass
    return out


class ForwardGetTests(unittest.TestCase):
    def setUp(self):
        # keep failures fast
        self._orig = (local_proxy._IDLE_TIMEOUT, local_proxy._CONNECT_TIMEOUT)
        local_proxy._IDLE_TIMEOUT = 5
        local_proxy._CONNECT_TIMEOUT = 5

    def tearDown(self):
        local_proxy._IDLE_TIMEOUT, local_proxy._CONNECT_TIMEOUT = self._orig

    def test_forward_get_rewrites_and_injects_auth(self):
        def responder(conn, head, overflow):
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")

        up = _FakeUpstream(responder)
        self.addCleanup(up.close)
        shim = LocalForwardProxy("127.0.0.1", up.port, username="user", password="pw")
        port = shim.start()
        self.addCleanup(shim.stop)

        c = _client_to(port)
        c.sendall(b"GET http://example.com/path HTTP/1.1\r\n"
                  b"Host: example.com\r\n"
                  b"Proxy-Connection: keep-alive\r\n"
                  b"Proxy-Authorization: Basic STALECLIENTVALUE\r\n"
                  b"Accept: */*\r\n\r\n")
        body = _recv_all(c)
        c.close()

        head = up.captured_head.decode("latin1")
        # request line preserved (absolute-URI forward form)
        self.assertTrue(head.startswith("GET http://example.com/path HTTP/1.1\r\n"), head)
        # our auth injected, client's stale one gone
        want = "Proxy-Authorization: Basic " + base64.b64encode(b"user:pw").decode()
        self.assertIn(want, head)
        self.assertNotIn("STALECLIENTVALUE", head)
        # hop-by-hop proxy header from the client stripped; we force close
        self.assertNotIn("Proxy-Connection: keep-alive", head)
        self.assertIn("Connection: close", head)
        # a benign end-to-end header is preserved
        self.assertIn("Accept: */*", head)
        # the upstream response reached the client
        self.assertTrue(body.endswith(b"hi"), body)

    def test_no_auth_when_no_credentials(self):
        def responder(conn, head, overflow):
            conn.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")

        up = _FakeUpstream(responder)
        self.addCleanup(up.close)
        shim = LocalForwardProxy("127.0.0.1", up.port)  # auth_type none
        port = shim.start()
        self.addCleanup(shim.stop)

        c = _client_to(port)
        c.sendall(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        _recv_all(c)
        c.close()
        self.assertNotIn("Proxy-Authorization", up.captured_head.decode("latin1"))


class ConnectTests(unittest.TestCase):
    def setUp(self):
        self._orig = (local_proxy._IDLE_TIMEOUT, local_proxy._CONNECT_TIMEOUT)
        local_proxy._IDLE_TIMEOUT = 5
        local_proxy._CONNECT_TIMEOUT = 5

    def tearDown(self):
        local_proxy._IDLE_TIMEOUT, local_proxy._CONNECT_TIMEOUT = self._orig

    def test_connect_tunnels_and_injects_auth(self):
        def responder(conn, head, overflow):
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            # echo one chunk to prove the tunnel splices
            data = conn.recv(4096)
            if data:
                conn.sendall(b"ECHO:" + data)

        up = _FakeUpstream(responder)
        self.addCleanup(up.close)
        shim = LocalForwardProxy("127.0.0.1", up.port, username="user", password="pw")
        port = shim.start()
        self.addCleanup(shim.stop)

        c = _client_to(port)
        c.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        # read the shim's CONNECT response head
        resp = b""
        while b"\r\n\r\n" not in resp:
            resp += c.recv(256)
        self.assertIn(b"200 Connection established", resp)
        c.sendall(b"PING")
        echoed = c.recv(64)
        c.close()
        self.assertEqual(echoed, b"ECHO:PING")

        head = up.captured_head.decode("latin1")
        self.assertTrue(head.startswith("CONNECT example.com:443 HTTP/1.1\r\n"), head)
        self.assertIn("Proxy-Authorization: Basic " + base64.b64encode(b"user:pw").decode(),
                      head)

    def test_connect_refusal_relayed(self):
        def responder(conn, head, overflow):
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")

        up = _FakeUpstream(responder)
        self.addCleanup(up.close)
        shim = LocalForwardProxy("127.0.0.1", up.port, username="user", password="pw")
        port = shim.start()
        self.addCleanup(shim.stop)

        c = _client_to(port)
        c.sendall(b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n")
        resp = _recv_all(c)
        c.close()
        self.assertIn(b"403 Forbidden", resp)
        self.assertNotIn(b"200 Connection established", resp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
