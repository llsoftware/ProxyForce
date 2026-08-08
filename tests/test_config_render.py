"""
Config-rendering regression tests.

The most important is the IPv6 leak guard (v2.1.5): an IPv4-only TUN that lets
AAAA queries resolve to real IPv6 addresses leaks all dual-stack traffic around
the proxy (browsers prefer IPv6 via Happy Eyeballs). The generated DNS rules
must answer AAAA with NODATA so apps fall back to the A → fakeip → proxy path.

A close second is bypass-domain routing (v2.2.0): a Bypass List hostname must
route DIRECT deterministically for ANY TCP protocol/port, not just ones sing-box
can sniff a hostname off of. That means bypass domains stay on fakeip (see
IPv6LeakGuardTests.test_bypass_domains_stay_on_fakeip) rather than getting real
DNS, and each entry must be normalized before it reaches sing-box's
domain_suffix matcher — a raw "*.example.com" or "example.com:993" is valid
JSON but matches nothing.

The schema itself is validated against the real sing-box binary by main.py's
--selftest step in CI; these tests guard the *intent* so the rule can't be
quietly dropped or mis-ordered.

Run:  python tests/test_config_render.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import singbox_controller
from core.singbox_controller import SingBoxController, ProxyConfig, normalize_bypass_entry


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
        """The IPv4 path that actually works must remain: A → fakeip. There is a
        second query_type=["A"] rule now (the NCSI predefined-answer rule, see
        NcsiFixTests) so this filters specifically for the fakeip server."""
        a = [r for r in _rules() if r.get("query_type") == ["A"] and r.get("server") == "fakeip"]
        self.assertEqual(len(a), 1)

    def test_bypass_domains_stay_on_fakeip(self):
        """v2.2.0 (diagnosed 2026-08-07, Outlook IMAPS/SMTPS): bypass domains must
        NOT get a real-DNS rule. Real resolution destroys the fakeip -> domain
        reverse map, leaving the route-side domain_suffix direct rule dependent on
        sniffing a hostname off the wire — which fails for server-speaks-first
        protocols (SMTP/587 STARTTLS) and clients that omit SNI, so the exception
        was silently never taken and the corporate proxy 403'd the CONNECT.
        Keeping bypass domains on fakeip makes the route rule match
        deterministically for ANY protocol/port; the `direct` outbound resolves
        the real IP itself via route.default_domain_resolver."""
        rules = _rules(bypass_list=["intranet.local"])
        self.assertFalse(any("domain_suffix" in r for r in rules),
                          "no dns.rules entry may key off bypass domains")
        self.assertEqual(len(rules), 3,
                          "exactly the AAAA-NODATA, NCSI predefined-answer, and "
                          "A-fakeip rules, regardless of the bypass list")


class NcsiFixTests(unittest.TestCase):
    """v2.2.1 (diagnosed 2026-08-07): Windows' NCSI (Network Connectivity Status
    Indicator) decides whether the OS itself believes it has internet
    (Get-NetConnectionProfile's IPv4Connectivity). Its DNS probe requires an EXACT
    literal answer that fakeip can't provide, and its web probe ignores the
    WinINET/WinHTTP proxy split entirely so it was being captured by the TUN and
    403'd by sing-box's CONNECT-only outbound. Both failures made Windows report
    "no internet", which silently starved everything gating on connectivity level
    (Windows Spotlight, Store, Widgets, Teams presence) with no visible error."""

    def setUp(self):
        self._orig = singbox_controller._ncsi_dns_probe
        singbox_controller._ncsi_dns_probe = lambda: ("probe.example", "203.0.113.99")

    def tearDown(self):
        singbox_controller._ncsi_dns_probe = self._orig

    def test_ncsi_predefined_rule_present_between_aaaa_and_fakeip(self):
        rules = _rules()
        aaaa_idx = next(i for i, r in enumerate(rules) if r.get("query_type") == ["AAAA"])
        fakeip_idx = next(i for i, r in enumerate(rules)
                          if r.get("query_type") == ["A"] and r.get("server") == "fakeip")
        ncsi_idx = next(i for i, r in enumerate(rules) if r.get("domain") == ["probe.example"])
        self.assertLess(aaaa_idx, ncsi_idx)
        self.assertLess(ncsi_idx, fakeip_idx)

    def test_ncsi_predefined_rule_answers_the_exact_literal(self):
        rules = _rules()
        r = next(r for r in rules if r.get("domain") == ["probe.example"])
        self.assertEqual(r.get("action"), "predefined")
        self.assertEqual(r.get("answer"), ["probe.example. IN A 203.0.113.99"])

    def test_port80_route_rule_present_and_targets_local_forward_proxy(self):
        cfg = ProxyConfig(host="203.0.113.10", port=800)
        c = SingBoxController(cfg)
        c._http_proxy_port = 55123
        rules = c._render_config(12345)["route"]["rules"]
        r = next(r for r in rules if r.get("port") == 80 and r.get("network") == "tcp")
        self.assertEqual(r.get("action"), "route")
        self.assertEqual(r.get("outbound"), "direct")
        self.assertEqual(r.get("override_address"), "127.0.0.1")
        self.assertEqual(r.get("override_port"), 55123)

    def test_port80_route_rule_precedes_udp_reject_and_follows_direct_rules(self):
        rules = _route_rules(bypass_list=["intranet.local"])
        port80_idx = next(i for i, r in enumerate(rules)
                          if r.get("port") == 80 and r.get("network") == "tcp")
        udp_reject_idx = next(i for i, r in enumerate(rules)
                              if r.get("network") == "udp" and r.get("action") == "reject")
        bypass_domain_idx = next(i for i, r in enumerate(rules)
                                 if r.get("domain_suffix") == ["intranet.local"])
        self.assertLess(port80_idx, udp_reject_idx)
        self.assertLess(bypass_domain_idx, port80_idx)

    def test_proxy_ip_guard_covers_resolved_hostname_ip_too(self):
        """When cfg.host is a hostname, start() pre-resolves it into
        _proxy_connect_host before fakeip hijacks DNS. That resolved IP must ALSO
        be excluded from the port-80 redirect, or the local forward-proxy's own
        upstream socket to a hostname-configured proxy could loop into itself."""
        cfg = ProxyConfig(host="proxy.corp.local", port=800)
        c = SingBoxController(cfg)
        c._proxy_connect_host = "203.0.113.55"
        rules = c._render_config(12345)["route"]["rules"]
        r = next(r for r in rules if r.get("ip_cidr") == ["203.0.113.55/32"])
        self.assertEqual(r.get("outbound"), "direct")


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


class BypassDomainRoutingTests(unittest.TestCase):
    """v2.2.0: the route-side half of the Outlook/IMAPS/SMTPS fix — the
    domain_suffix direct rule for bypass domains must fire for UDP too (not
    just the sniffable TCP case), and route.default_domain_resolver must pick
    IPv4 deterministically since dial-time resolution for the `direct` outbound
    skips dns.rules (so the AAAA-NODATA rule doesn't apply to it)."""

    def test_bypass_domain_route_rule_precedes_udp_reject(self):
        rules = _route_rules(bypass_list=["intranet.local"])
        bypass_idx = next(i for i, r in enumerate(rules)
                          if r.get("domain_suffix") == ["intranet.local"])
        udp_reject_idx = next(i for i, r in enumerate(rules)
                              if r.get("network") == "udp" and r.get("action") == "reject")
        self.assertLess(bypass_idx, udp_reject_idx,
                        "a bypass domain must be routed direct before UDP is "
                        "rejected, or UDP to a bypassed host is silently dropped")

    def test_default_domain_resolver_prefers_ipv4(self):
        route = SingBoxController(
            ProxyConfig(host="203.0.113.10", port=800)
        )._render_config(12345)["route"]
        resolver = route.get("default_domain_resolver", {})
        self.assertEqual(resolver.get("server"), "local")
        self.assertEqual(resolver.get("strategy"), "prefer_ipv4",
                         "dial-time resolution for the direct outbound bypasses "
                         "dns.rules entirely, so without an explicit strategy an "
                         "IPv6-capable box costs a Happy-Eyeballs stall per "
                         "bypassed connection")


class BypassEntryNormalizationTests(unittest.TestCase):
    """v2.2.0: a Bypass List entry is free-form user input rendered into THREE
    different syntaxes (sing-box domain_suffix, WinINET ProxyOverride, NO_PROXY).
    Verified empirically against the bundled sing-box 1.13.12's `rule-set match`:
    domain_suffix is label/dot-boundary aware ("scientology.net" matches its
    subdomains but never "notscientology.net"), while "*.scientology.net" is
    valid JSON that matches NOTHING — the exact trap this normalizer exists to
    catch before it reaches sing-box."""

    def test_wildcard_star_normalizes_to_bare_apex_form(self):
        base, apex_included, err = normalize_bypass_entry("*.scientology.net")
        self.assertIsNone(err)
        self.assertEqual(base, "scientology.net")
        self.assertTrue(apex_included, "*.host is treated as host + subdomains")

    def test_leading_dot_means_subdomains_only(self):
        base, apex_included, err = normalize_bypass_entry(".scientology.net")
        self.assertIsNone(err)
        self.assertEqual(base, "scientology.net")
        self.assertFalse(apex_included)

    def test_port_and_scheme_are_stripped(self):
        for entry in ("imaps.email.scientology.net:993",
                      "https://imaps.email.scientology.net/"):
            base, _apex, err = normalize_bypass_entry(entry)
            self.assertIsNone(err, f"{entry!r} should normalize cleanly")
            self.assertEqual(base, "imaps.email.scientology.net")

    def test_cidr_and_ip_pass_through_unchanged(self):
        base, apex_included, err = normalize_bypass_entry("10.0.0.0/8")
        self.assertIsNone(err)
        self.assertEqual(base, "10.0.0.0/8")
        self.assertTrue(apex_included)

    def test_junk_entry_is_rejected_with_a_reason(self):
        base, _apex, err = normalize_bypass_entry("not a host!!")
        self.assertIsNone(base)
        self.assertIsNotNone(err)

    def test_render_config_never_emits_a_dead_wildcard_rule(self):
        """The trap this whole class exists to catch: "*.host" must never reach
        sing-box verbatim, since domain_suffix: ["*.host"] is valid JSON that
        matches nothing."""
        rules = _route_rules(bypass_list=["*.scientology.net"])
        bypass_rules = [r for r in rules if "domain_suffix" in r]
        self.assertEqual(len(bypass_rules), 1)
        self.assertEqual(bypass_rules[0]["domain_suffix"], ["scientology.net"])

    def test_proxy_override_gets_both_bare_and_wildcard_forms(self):
        """WinINET ProxyOverride has NO implicit suffix matching — a bare host is
        exact-match only, so the wildcard form must be added alongside it or
        subdomains stay silently proxied."""
        cfg = ProxyConfig(host="203.0.113.10", port=800,
                          bypass_list=["scientology.net"])
        bypass = SingBoxController(cfg)._build_proxy_bypass()
        self.assertIn("scientology.net", bypass.split(";"))
        self.assertIn("*.scientology.net", bypass.split(";"))

    def test_no_proxy_strips_wildcard_and_keeps_dot_boundary_form(self):
        cfg = ProxyConfig(host="203.0.113.10", port=800,
                          bypass_list=["*.scientology.net"])
        no_proxy = SingBoxController(cfg)._build_no_proxy().split(",")
        self.assertIn("scientology.net", no_proxy)
        self.assertNotIn("*.scientology.net", no_proxy)


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
