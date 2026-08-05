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


class LogLevelTests(unittest.TestCase):
    """The sing-box log level must come from ProxyConfig.log_level (validated), not
    be hardcoded — "debug" is verbose and grows singbox.log on long runs, so it must
    be opt-in with "info" as the safe default."""

    def _level(self, log_level=None):
        kw = {} if log_level is None else {"log_level": log_level}
        cfg = ProxyConfig(host="203.0.113.10", port=800, **kw)
        return SingBoxController(cfg)._render_config(12345)["log"]["level"]

    def test_default_is_info(self):
        self.assertEqual(self._level(), "info")

    def test_debug_is_honored(self):
        self.assertEqual(self._level("debug"), "debug")

    def test_warn_is_honored(self):
        self.assertEqual(self._level("warn"), "warn")

    def test_unknown_level_falls_back_to_info(self):
        self.assertEqual(self._level("trace"), "info")   # not in the whitelist
        self.assertEqual(self._level(""), "info")


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


class NoProxyBypassConsistencyTests(unittest.TestCase):
    """_build_no_proxy() (env-var takeover) and _build_proxy_bypass() (WinINET/WinHTTP
    takeover) must exclude the SAME hosts, just rendered in each mechanism's own
    syntax — NO_PROXY is comma-separated and glob-free, ProxyOverride is ';'/'*'-
    globbed. A drift between them would make a CLI tool (env vars) and a browser
    (registry) disagree on what's direct vs proxied."""

    @staticmethod
    def _controller(bypass_list=None, exclude_private=True):
        cfg = ProxyConfig(host="203.0.113.10", port=800,
                          bypass_list=bypass_list or [], exclude_private=exclude_private)
        return SingBoxController(cfg)

    def test_no_proxy_is_comma_separated_and_glob_free(self):
        no_proxy = self._controller()._build_no_proxy()
        self.assertNotIn(";", no_proxy)
        self.assertNotIn("*", no_proxy)
        parts = no_proxy.split(",")
        self.assertIn("localhost", parts)
        self.assertIn("127.0.0.1", parts)

    def test_default_private_ranges_match_between_both_builders(self):
        c = self._controller(exclude_private=True)
        bypass = c._build_proxy_bypass()
        no_proxy = c._build_no_proxy()
        # Every 172.16-31 octet covered by ProxyOverride's globs must have a
        # corresponding glob-free prefix in NO_PROXY.
        for n in range(16, 32):
            self.assertIn(f"172.{n}.*", bypass)
            self.assertIn(f"172.{n}.", no_proxy.split(","))
        self.assertIn("10.*", bypass)
        self.assertIn("10.", no_proxy.split(","))
        self.assertIn("192.168.*", bypass)
        self.assertIn("192.168.", no_proxy.split(","))

    def test_exclude_private_false_omits_private_ranges_from_both(self):
        c = self._controller(exclude_private=False)
        bypass = c._build_proxy_bypass()
        no_proxy = c._build_no_proxy()
        self.assertNotIn("10.*", bypass)
        self.assertNotIn("10.", no_proxy.split(","))

    def test_bypass_domain_entries_appear_in_both(self):
        c = self._controller(bypass_list=["intranet.local"])
        self.assertIn("intranet.local", c._build_proxy_bypass())
        self.assertIn("intranet.local", c._build_no_proxy().split(","))

    def test_bypass_ip_cidr_entries_are_excluded_from_both(self):
        """ProxyOverride uses host wildcards, not CIDR — an IP/CIDR bypass entry is
        handled by the route rules instead, so it must NOT leak into either builder's
        host list (that already-existing exclusion in _build_proxy_bypass must hold
        for _build_no_proxy too)."""
        c = self._controller(bypass_list=["10.55.0.0/16"])
        self.assertNotIn("10.55.0.0/16", c._build_proxy_bypass())
        self.assertNotIn("10.55.0.0/16", c._build_no_proxy())


if __name__ == "__main__":
    unittest.main(verbosity=2)
