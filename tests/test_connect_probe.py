"""
Real-CONNECT proxy probe tests (v2.2.0).

Guards the fix for "Test Proxy" only ever doing a bare TCP handshake to the
proxy's own port and declaring success — which passes even against a proxy
that 403s every single CONNECT (diagnosed 2026-08-07: Outlook's IMAPS/SMTPS
couldn't connect while ProxyForce ran because the corporate proxy only permits
CONNECT to :443; the old test could never have revealed that). `probe_connect`
sends one real CONNECT and parses the proxy's actual status line.

Also guards `_scan_upstream_rejections`, the sibling of
`_scan_upstream_dial_failures` (see test_proxy_reachability.py) that
distinguishes "the proxy answered and refused" from "the proxy could not be
reached at all" — the two need different verdicts and different fixes.

Run:  python tests/test_connect_probe.py
"""

import os
import sys
import socket
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.singbox_controller import probe_connect, SingBoxController

reject_scan = SingBoxController._scan_upstream_rejections


class _ScriptedProxyServer:
    """A one-shot local TCP server that reads a single request and replies with
    a scripted response, standing in for an upstream HTTP proxy's CONNECT
    handling without touching any real network."""

    def __init__(self, response: bytes):
        self._response = response
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
            with conn:
                conn.settimeout(5)
                try:
                    conn.recv(4096)   # the CONNECT request; content doesn't matter here
                except Exception:
                    pass
                conn.sendall(self._response)
        except Exception:
            pass

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass


class ConnectProbeTests(unittest.TestCase):

    def test_200_is_parsed_as_success(self):
        srv = _ScriptedProxyServer(b"HTTP/1.1 200 Connection established\r\n\r\n")
        try:
            code, reason = probe_connect("127.0.0.1", srv.port, "example.com", 443, timeout=3)
        finally:
            srv.close()
        self.assertEqual(code, 200)
        self.assertIn("Connection established", reason)

    def test_403_is_parsed_as_a_refusal_not_an_error(self):
        srv = _ScriptedProxyServer(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        try:
            code, reason = probe_connect("127.0.0.1", srv.port, "imaps.example.com", 993, timeout=3)
        finally:
            srv.close()
        self.assertEqual(code, 403)
        self.assertIn("Forbidden", reason)

    def test_unreachable_proxy_returns_zero_code_with_error_text(self):
        # Nothing listening on this port — the TCP connect itself must fail.
        free = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        free.bind(("127.0.0.1", 0))
        port = free.getsockname()[1]
        free.close()
        code, reason = probe_connect("127.0.0.1", port, "example.com", 443, timeout=2)
        self.assertEqual(code, 0)
        self.assertTrue(reason)

    def test_basic_auth_header_is_sent_when_credentials_given(self):
        srv = _ScriptedProxyServer(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
        try:
            code, _reason = probe_connect(
                "127.0.0.1", srv.port, "example.com", 443,
                username="astumfold", password="Enough!", timeout=3)
        finally:
            srv.close()
        self.assertEqual(code, 407)   # scripted server always answers the same way;
        # this test's real job is exercising the auth-header code path without raising.


class UpstreamRejectionScanTests(unittest.TestCase):
    """_scan_upstream_rejections must catch a REAL refusal (proxy answered, said
    no) and stay silent on ordinary log noise — the counterpart of
    test_proxy_reachability.py's dial-failure scanner tests."""

    def test_403_rejection_line_is_detected(self):
        lines = [
            "INFO outbound/http[proxy-out]: outbound connection to "
            "imaps.example.com:993",
            "ERROR connection: open connection to imaps.example.com:993 using "
            "outbound/http[proxy-out]: unexpected status: 403 Forbidden",
        ]
        self.assertEqual(reject_scan(lines), [lines[-1]])

    def test_clean_log_yields_no_rejections(self):
        lines = [
            "INFO router: sniffed example.com",
            "INFO outbound/http[proxy-out]: CONNECT example.com:443",
        ]
        self.assertEqual(reject_scan(lines), [])

    def test_dial_timeout_is_not_a_rejection(self):
        """A dial failure (proxy unreachable) is a DIFFERENT signal from a
        rejection (proxy reachable, refused) — must not cross-trigger."""
        lines = ["ERROR outbound/http[proxy-out]: dial tcp 203.0.113.10:800: i/o timeout"]
        self.assertEqual(reject_scan(lines), [])

    def test_empty_and_none_inputs_are_safe(self):
        self.assertEqual(reject_scan([]), [])
        self.assertEqual(reject_scan(None), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
