"""
Config-rendering regression tests.

The most important is the IPv6 leak guard (v2.1.5): an IPv4-only TUN that lets
AAAA queries resolve to real IPv6 addresses leaks all dual-stack traffic around
the proxy (browsers prefer IPv6 via Happy Eyeballs). The generated DNS rules
must answer AAAA with NODATA so apps fall back to the A → fakeip → proxy path.

The schema itself is validated against the real sing-box binary by main.py's
--selftest step in CI; these tests guard the *intent* so the rule can't be
quietly dropped or mis-ordered.

Run:  python tests/test_config_render.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.singbox_controller import SingBoxController, ProxyConfig


def _rules(bypass_list=None):
    cfg = ProxyConfig(host="203.0.113.10", port=800, bypass_list=bypass_list or [])
    return SingBoxController(cfg)._render_config(12345)["dns"]["rules"]


def _route_rules(bypass_list=None):
    cfg = ProxyConfig(host="203.0.113.10", port=800, bypass_list=bypass_list or [])
    return SingBoxController(cfg)._render_config(12345)["route"]["rules"]


def _tun_inbound(bypass_list=None):
    cfg = ProxyConfig(host="203.0.113.10", port=800, bypass_list=bypass_list or [])
    inbounds = SingBoxController(cfg)._render_config(12345)["inbounds"]
    return next(i for i in inbounds if i.get("type") == "tun")


class SplitRouteGuardTests(unittest.TestCase):
    """v2.1.7: the decisive Win 10 fix. auto_route's default 0.0.0.0/0 on the TUN
    only ties the physical NIC's 0.0.0.0/0 and then loses the metric tiebreak, so
    nothing enters the tunnel ("green but no capture"). The TUN must request the
    SPLIT routes (0.0.0.0/1 + 128.0.0.0/1) via `route_address` — they are more
    specific than any /0, so Windows longest-prefix-match always picks the TUN.
    `route_address` is the modern 1.13 field; the legacy `inet4_route_address` is
    FATAL. Validated against sing-box 1.13.12 by --selftest.
    """

    def test_tun_requests_split_default_routes(self):
        tun = _tun_inbound()
        self.assertEqual(tun.get("route_address"), ["0.0.0.0/1", "128.0.0.0/1"],
                         "TUN must request the split-default routes, not a bare /0")

    def test_no_legacy_route_address_field(self):
        """inet4_route_address is removed in 1.12 and FATAL in 1.13 — never emit it."""
        tun = _tun_inbound()
        self.assertNotIn("inet4_route_address", tun)


class LocalProxyInboundTests(unittest.TestCase):
    """Part of the Edge-update fix: a local mixed inbound the Windows system proxy
    points at for HTTPS, so proxy-aware apps (incl. the Edge updater) reach the
    corporate proxy via TCP CONNECT through sing-box. (Plaintext HTTP takes a separate
    local forward-proxy — see tests/test_local_proxy — because the corporate proxy
    403s CONNECT on :80, the real cause of error 0x80072EFE.)"""

    def _config(self):
        cfg = ProxyConfig(host="203.0.113.10", port=800)
        c = SingBoxController(cfg)
        c._local_proxy_port = 18080
        return c._render_config(12345)

    def test_local_mixed_inbound_present(self):
        inbounds = self._config()["inbounds"]
        local = [i for i in inbounds if i.get("tag") == "local-in"]
        self.assertEqual(len(local), 1, "exactly one local-in inbound expected")
        self.assertEqual(local[0].get("type"), "mixed")
        self.assertEqual(local[0].get("listen"), "127.0.0.1")
        self.assertEqual(local[0].get("listen_port"), 18080)

    def test_tun_still_present(self):
        # The TUN must remain the catch-all alongside the new local inbound.
        inbounds = self._config()["inbounds"]
        self.assertTrue(any(i.get("type") == "tun" for i in inbounds))

    def test_route_final_is_proxy_out(self):
        # local-in traffic must egress through the corporate proxy.
        self.assertEqual(self._config()["route"]["final"], "proxy-out")


class IPv6LeakGuardTests(unittest.TestCase):

    def test_aaaa_is_suppressed_to_nodata(self):
        """AAAA must be answered with NODATA (predefined NOERROR, no records)."""
        aaaa = [r for r in _rules() if r.get("query_type") == ["AAAA"]]
        self.assertEqual(len(aaaa), 1, "exactly one AAAA-suppression rule expected")
        r = aaaa[0]
        self.assertEqual(r.get("action"), "predefined")
        self.assertEqual(r.get("rcode"), "NOERROR")
        self.assertNotIn("answer", r, "must return NODATA — no answer records")

    def test_a_still_goes_to_fakeip(self):
        """The IPv4 path that actually works must remain: A → fakeip."""
        a = [r for r in _rules() if r.get("query_type") == ["A"]]
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].get("server"), "fakeip")

    def test_bypass_domains_keep_real_resolution_before_aaaa_rule(self):
        """Bypass-domain rule must precede the AAAA rule so those keep real AAAA."""
        rules = _rules(bypass_list=["intranet.local"])
        bypass_idx = next(i for i, r in enumerate(rules)
                          if r.get("domain_suffix") == ["intranet.local"])
        aaaa_idx = next(i for i, r in enumerate(rules)
                        if r.get("query_type") == ["AAAA"])
        self.assertLess(bypass_idx, aaaa_idx,
                        "bypass domains must match before AAAA is suppressed")
        # The bypass rule has no query_type filter → matches A and AAAA alike.
        self.assertNotIn("query_type", rules[bypass_idx])


class DnsHijackFallbackTests(unittest.TestCase):
    """v2.1.6: DNS must be hijacked by PORT 53 even if the sniffer fails to tag it,
    and that hijack must come BEFORE the udp-reject rule so a DNS query is never
    silently dropped (which would leave apps resolving real IPs and bypassing
    fakeip / CONNECT-by-hostname). Validated against sing-box 1.13.12 by --selftest.
    """

    def test_port53_hijack_present_for_udp_and_tcp(self):
        rules = _route_rules()
        port53 = [r for r in rules
                  if r.get("port") == 53 and r.get("action") == "hijack-dns"]
        nets = sorted(r.get("network") for r in port53)
        self.assertEqual(nets, ["tcp", "udp"],
                         "expected udp:53 and tcp:53 hijack-dns fallback rules")

    def test_port53_hijack_precedes_udp_reject(self):
        rules = _route_rules()
        udp_reject_idx = next(i for i, r in enumerate(rules)
                              if r.get("network") == "udp" and r.get("action") == "reject")
        for i, r in enumerate(rules):
            if r.get("port") == 53 and r.get("action") == "hijack-dns":
                self.assertLess(i, udp_reject_idx,
                                "DNS hijack must precede the udp-reject rule")


if __name__ == "__main__":
    unittest.main(verbosity=2)
