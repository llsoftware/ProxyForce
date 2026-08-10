"""
Proxy-reachability scanner tests (v2.1.10).

Guards the fix for the FALSE "PROXY UNREACHABLE" diagnostic verdict. The old
heuristic flagged a failure whenever "proxy-out" AND any timeout keyword both
appeared ANYWHERE in the last 80 sing-box log lines — so a single ordinary
per-site timeout, or a stale startup dial from before the /32 server-exclude
took hold, produced a false alarm even while the proxy was plainly reachable.

`_scan_upstream_dial_failures` is the precise replacement: a log line counts as
a genuine UPSTREAM-proxy dial failure (the v2.1.7 routing-loop symptom) only when
it BOTH reports a connection failure AND names the proxy server itself (its host,
or `:<proxy_port>:` in a "dial …" line). Ordinary per-site timeouts name the
destination (:443/:80), not the proxy, and must NOT trip it.

Run:  python tests/test_proxy_reachability.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.singbox_controller import SingBoxController

HOST = "203.0.113.10"
PORT = 800
scan = SingBoxController._scan_upstream_dial_failures


class UpstreamDialFailureScanTests(unittest.TestCase):

    def test_genuine_proxy_loop_is_detected(self):
        """The real loop symptom: a dial to the proxy host:port times out."""
        lines = [
            "INFO inbound/tun[tun-in]: example.com:443",
            "ERROR outbound/http[proxy-out]: dial tcp 203.0.113.10:800: i/o timeout",
        ]
        self.assertEqual(scan(lines, HOST, PORT), [lines[-1]])

    def test_per_site_timeout_is_NOT_a_proxy_failure(self):
        """A destination timeout (port 443, not the proxy) must be ignored."""
        lines = [
            "INFO outbound/http[proxy-out]: outbound connection to slow.example:443",
            "ERROR dial tcp 93.184.216.34:443: i/o timeout",
        ]
        self.assertEqual(scan(lines, HOST, PORT), [])

    def test_proxy_out_mention_without_proxy_address_is_ignored(self):
        """The old false trigger: 'proxy-out' present AND a timeout present, but on
        unrelated lines that never name the proxy server — must NOT flag."""
        lines = [
            "DEBUG outbound/http[proxy-out]: CONNECT cdn.example.com:443",
            "DEBUG inbound/tun[tun-in]: context deadline exceeded for 10.20.30.40:443",
        ]
        self.assertEqual(scan(lines, HOST, PORT), [])

    def test_clean_log_yields_no_failures(self):
        lines = [
            "INFO router: sniffed example.com",
            "INFO outbound/http[proxy-out]: CONNECT example.com:443",
        ]
        self.assertEqual(scan(lines, HOST, PORT), [])

    def test_matches_by_proxy_port_when_host_is_a_name(self):
        """If the proxy is configured by hostname, the dial line shows the resolved
        IP — so we still catch it via the proxy :port: in a dial line."""
        lines = ["ERROR dial tcp 10.1.2.3:800: connection refused"]
        self.assertEqual(scan(lines, "proxy.corp.local", PORT), lines)

    def test_refused_and_unreachable_keywords(self):
        lines = [
            "ERROR dial tcp 203.0.113.10:800: connection refused",
            "ERROR dial tcp 203.0.113.10:800: network is unreachable",
        ]
        self.assertEqual(scan(lines, HOST, PORT), lines)

    def test_empty_and_none_inputs_are_safe(self):
        self.assertEqual(scan([], HOST, PORT), [])
        self.assertEqual(scan(None, HOST, PORT), [])
        self.assertEqual(scan(["dial tcp 203.0.113.10:800: i/o timeout"], None, None), [])


REJECTION_LINE = (
    "-0700 2026-08-08 10:25:56 ERROR [1929908630 614ms] connection: open connection "
    "to docker.illo.secure:1688 using outbound/http[proxy-out]: unexpected status: "
    "403 Forbidden")

DIAL_TIMEOUT_LINE = (
    "-0700 2026-08-08 10:25:07 ERROR [3918389240 5.0s] connection: open connection "
    "to 192.168.48.76:7680 using outbound/direct[direct]: dial tcp "
    "192.168.48.76:7680: i/o timeout")

extract = SingBoxController._extract_rejections


class ExtractRejectionsTests(unittest.TestCase):
    """Guards _extract_rejections, used by diagnostics to name the destination
    an upstream proxy explicitly refused (distinct from an unreachable proxy,
    covered above)."""

    def test_extracts_host_port_code_from_a_real_rejection_line(self):
        self.assertEqual(extract([REJECTION_LINE]),
                         [("docker.illo.secure", 1688, 403)])

    def test_dial_timeout_line_is_not_a_rejection(self):
        """A dial timeout is a DIFFERENT failure mode (unreachable, not refused) —
        must never be mistaken for an explicit policy refusal."""
        self.assertEqual(extract([DIAL_TIMEOUT_LINE]), [])

    def test_multiple_lines_all_extracted(self):
        other = REJECTION_LINE.replace("docker.illo.secure:1688", "other.host:9999") \
                              .replace("403 Forbidden", "407 Proxy Authentication Required")
        result = extract([REJECTION_LINE, other])
        self.assertEqual(result, [("docker.illo.secure", 1688, 403),
                                  ("other.host", 9999, 407)])

    def test_empty_and_none_inputs_are_safe(self):
        self.assertEqual(extract([]), [])
        self.assertEqual(extract(None), [])

    def test_unrelated_line_yields_nothing(self):
        self.assertEqual(extract(["INFO: all fine here"]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
