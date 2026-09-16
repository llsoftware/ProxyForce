"""
Tests for core/netprobe — the OS-networking seam.

Most of this module shells out to the live system, which a unit test cannot
meaningfully assert against. What IS testable, and what actually breaks when
someone edits it, is the PARSING: netprobe turns `ip route show table all` and
`ip route show default` output into the two answers the controller branches on —
"are both capture prefixes present" and "which gateway does the proxy /32 pin
to". Both are exercised here against captured real-world output, on any platform,
by stubbing the command layer.

The live calls are covered only by "does not raise and returns a string", which
is the real contract: diagnostics must never crash the engine because a distro
ships without `nft`.
"""

import unittest

from core import netprobe, hostos


# Real `ip route show table all` output from a box running ProxyForce, trimmed.
# Note what makes this the interesting case: the split prefixes are NOT in the
# main table — sing-box's auto_route puts them in its own policy-routing table,
# which is exactly why capture_route_count looks across all tables on Linux.
IP_ROUTE_ALL = """\
default via 192.168.1.1 dev enp3s0 proto dhcp src 192.168.1.42 metric 100
192.168.1.0/24 dev enp3s0 proto kernel scope link src 192.168.1.42 metric 100
0.0.0.0/1 dev ProxyForce table 2022 scope link
128.0.0.0/1 dev ProxyForce table 2022 scope link
172.19.0.0/30 dev ProxyForce table 2022 proto kernel scope link src 172.19.0.1
broadcast 127.0.0.0 dev lo table local proto kernel scope link src 127.0.0.1
"""

IP_ROUTE_ONLY_ONE = """\
default via 192.168.1.1 dev enp3s0 proto dhcp metric 100
0.0.0.0/1 dev ProxyForce table 2022 scope link
"""

# The prefixes exist but belong to a DIFFERENT interface — a competing VPN. This
# must NOT count as ProxyForce capturing, or the diagnostics would report a
# healthy engine while every packet went to the other tunnel.
IP_ROUTE_OTHER_TUN = """\
0.0.0.0/1 dev wg0 table 51820 scope link
128.0.0.0/1 dev wg0 table 51820 scope link
"""

IP_ROUTE_DEFAULT = """\
default via 192.168.1.1 dev enp3s0 proto dhcp src 192.168.1.42 metric 100
default via 10.8.0.1 dev ProxyForce metric 50
"""


class _StubIp:
    """Replaces netprobe._ip with canned output, recording what was asked for."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append(args)
        for key, value in self.mapping.items():
            if key == args[:len(key)]:
                return value
        return ""


class CaptureRouteCountTests(unittest.TestCase):
    """Linux path, exercised on any platform by forcing the branch."""

    def setUp(self):
        self._orig_win = netprobe.hostos.IS_WINDOWS
        self._orig_ip = netprobe._ip
        netprobe.hostos.IS_WINDOWS = False

    def tearDown(self):
        netprobe.hostos.IS_WINDOWS = self._orig_win
        netprobe._ip = self._orig_ip

    def _stub(self, table_output):
        netprobe._ip = _StubIp({("route", "show", "table", "all"): table_output})

    def test_both_prefixes_on_the_tun_count_as_two(self):
        self._stub(IP_ROUTE_ALL)
        self.assertEqual(netprobe.capture_route_count("ProxyForce"), 2)

    def test_one_prefix_counts_as_one(self):
        self._stub(IP_ROUTE_ONLY_ONE)
        self.assertEqual(netprobe.capture_route_count("ProxyForce"), 1)

    def test_prefixes_on_another_interface_do_not_count(self):
        self._stub(IP_ROUTE_OTHER_TUN)
        self.assertEqual(netprobe.capture_route_count("ProxyForce"), 0)

    def test_empty_table_counts_as_zero(self):
        self._stub("")
        self.assertEqual(netprobe.capture_route_count("ProxyForce"), 0)

    def test_a_prefix_is_never_double_counted(self):
        # Two tables can legitimately carry the same prefix for the same device;
        # the answer is still "this prefix is present", i.e. 1, not 2.
        self._stub(IP_ROUTE_ALL + "0.0.0.0/1 dev ProxyForce table 99 scope link\n")
        self.assertEqual(netprobe.capture_route_count("ProxyForce"), 2)

    def test_a_longer_interface_name_is_not_matched_by_prefix(self):
        self._stub("0.0.0.0/1 dev ProxyForceOld table 2022 scope link\n"
                   "128.0.0.0/1 dev ProxyForceOld table 2022 scope link\n")
        self.assertEqual(netprobe.capture_route_count("ProxyForce"), 0)


class DefaultGatewayTests(unittest.TestCase):

    def setUp(self):
        self._orig_win = netprobe.hostos.IS_WINDOWS
        self._orig_ip = netprobe._ip
        netprobe.hostos.IS_WINDOWS = False
        netprobe._ip = _StubIp({("route", "show", "default"): IP_ROUTE_DEFAULT})

    def tearDown(self):
        netprobe.hostos.IS_WINDOWS = self._orig_win
        netprobe._ip = self._orig_ip

    def test_picks_the_physical_gateway_and_skips_the_tun(self):
        # This is the whole point of the exclusion: pinning the proxy's /32 via
        # the TUN would route sing-box's own upstream connection back into its
        # own tunnel — the v2.1.8 "dial ...: i/o timeout" loop.
        gw, dev = netprobe.default_gateway(exclude_dev="ProxyForce")
        self.assertEqual((gw, dev), ("192.168.1.1", "enp3s0"))

    def test_returns_empty_when_there_is_no_usable_default(self):
        netprobe._ip = _StubIp({("route", "show", "default"): ""})
        self.assertEqual(netprobe.default_gateway("ProxyForce"), ("", ""))

    def test_returns_empty_when_only_the_tun_has_a_default(self):
        netprobe._ip = _StubIp({
            ("route", "show", "default"): "default via 10.8.0.1 dev ProxyForce\n"})
        self.assertEqual(netprobe.default_gateway("ProxyForce"), ("", ""))


class TunSupportTests(unittest.TestCase):

    def test_windows_always_supports_tun(self):
        if hostos.IS_WINDOWS:
            ok, why = netprobe.tun_supported()
            self.assertTrue(ok)
            self.assertEqual(why, "")

    def test_an_unsupported_reason_names_the_fix(self):
        """A refusal has to be actionable — 'cannot create TUN' on its own sends
        the user nowhere."""
        orig = netprobe.hostos.IS_WINDOWS
        netprobe.hostos.IS_WINDOWS = False
        try:
            ok, why = netprobe.tun_supported()
            if not ok:
                self.assertTrue("modprobe" in why or "iproute2" in why, why)
        finally:
            netprobe.hostos.IS_WINDOWS = orig


class LiveCallsDoNotRaiseTests(unittest.TestCase):
    """Diagnostics run inside the engine's steady state. A distro without `nft`,
    or a Windows box with a locked-down PowerShell, must degrade to a string —
    never an exception that takes the run down with it."""

    def test_read_only_probes_return_strings(self):
        for fn, args in (
            (netprobe.os_info, ()),
            (netprobe.route_table, ("ProxyForce",)),
            (netprobe.listening_ports, ()),
            (netprobe.competing_agents, ()),
            (netprobe.dns_servers, ()),
            (netprobe.connectivity_detail, ()),
            (netprobe.getaddrinfo_unspec, ("localhost",)),
        ):
            with self.subTest(fn=fn.__name__):
                self.assertIsInstance(fn(*args), str)

    def test_tun_queries_are_safe_for_an_absent_interface(self):
        name = "proxyforce-no-such-if"
        self.assertFalse(netprobe.tun_exists(name))
        self.assertEqual(netprobe.tun_index(name), "")
        self.assertEqual(netprobe.capture_route_count(name), 0)

    def test_enforce_declines_cleanly_when_there_is_no_interface(self):
        count, note = netprobe.enforce_capture_routes("proxyforce-no-such-if")
        self.assertEqual(count, 0)
        self.assertIn("not found", note)


if __name__ == "__main__":
    unittest.main(verbosity=2)
