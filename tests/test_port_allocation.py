"""
Fixed-port-first allocation tests (v2.2.2).

Diagnosed 2026-08-08: ProxyForce always picked fresh OS-ephemeral ports on every
restart, so the HTTP_PROXY/HTTPS_PROXY env vars and the WinINET/WinHTTP proxy
string changed every time — and Windows never propagates an env-var change to an
already-running process, so an already-open shell (Claude Code, PowerShell, …)
silently broke on every ProxyForce restart. _bind_ports_preferring keeps the same
port numbers across an ordinary restart (nothing else squatting on them) and only
falls back to ephemeral for a genuinely conflicting slot.

These tests deliberately do NOT use _DEFAULT_PORTS as live bind targets
(2026-09-15): on any machine where ProxyForce is actually running, sing-box and
the GUI hold 18089/18080/18081, so every slot legitimately degrades to ephemeral
and exact-port assertions fail for reasons that have nothing to do with the code
under test. Instead each test probes for ports that are free *right now* and
feeds those in as the preferred set — the behaviour being tested (prefer these,
fall back per-slot) is independent of which specific numbers they are.
_DEFAULT_PORTS is still covered, by a pure constant check that binds nothing.

Run:  python tests/test_port_allocation.py
"""

import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.singbox_controller import _bind_ports_preferring, _DEFAULT_PORTS

# Scan window for probe ports: static (well below Windows' 49152+ ephemeral
# range) so a probe port can't be handed out as an ephemeral fallback mid-test,
# and clear of ProxyForce's own 18080-18089 defaults.
_PROBE_START = 18500
_PROBE_SPAN = 500


def _free_ports(count):
    """Return `count` distinct ports in the static probe range that are free at
    this instant. All candidates are held open until the full set is found, so
    the returned ports are guaranteed distinct; they're then released for the
    caller to bind. Skips the test rather than failing if the range is full."""
    socks, found = [], []
    try:
        for port in range(_PROBE_START, _PROBE_START + _PROBE_SPAN):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                s.close()
                continue
            socks.append(s)
            found.append(port)
            if len(found) == count:
                return found
        raise unittest.SkipTest(
            f"fewer than {count} free ports in "
            f"{_PROBE_START}-{_PROBE_START + _PROBE_SPAN}")
    finally:
        for s in socks:
            s.close()


class DefaultPortsConstantTests(unittest.TestCase):
    """Binds nothing — asserts only the shape of the constant, so it holds
    whether or not ProxyForce happens to be running."""

    def test_defaults_are_three_distinct_non_ephemeral_ports(self):
        self.assertEqual(len(_DEFAULT_PORTS), 3)
        self.assertEqual(len(set(_DEFAULT_PORTS)), 3)
        for port in _DEFAULT_PORTS:
            # Below 49152 (Windows' default dynamic range start), so the OS
            # never hands one of these out as an ephemeral port behind our back.
            self.assertTrue(1024 < port < 49152, f"{port} is not a fixed port")


class FixedPortsFreeTests(unittest.TestCase):

    def test_all_free_returns_the_exact_preferred_ports_in_order(self):
        preferred = _free_ports(3)
        self.assertEqual(_bind_ports_preferring(preferred), preferred)

    def test_distinct_ports_returned(self):
        ports = _bind_ports_preferring(_free_ports(3))
        self.assertEqual(len(set(ports)), len(ports))

    def test_defaults_are_honoured_when_actually_free(self):
        """The real-world case the fixed-port design exists for. Skips when
        something (usually a running ProxyForce) already owns the defaults."""
        for port in _DEFAULT_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                raise unittest.SkipTest(
                    f"port {port} is in use — ProxyForce running?")
            finally:
                s.close()
        self.assertEqual(_bind_ports_preferring(_DEFAULT_PORTS),
                         list(_DEFAULT_PORTS))


class FixedPortConflictTests(unittest.TestCase):
    """A genuinely occupied preferred port must fall back to ephemeral for JUST
    that slot — the other slots must still get their fixed ports."""

    def setUp(self):
        self.preferred = _free_ports(3)
        # Occupy the middle preferred port so it's unavailable.
        self._blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._blocker.bind(("127.0.0.1", self.preferred[1]))
        self._blocker.listen(1)

    def tearDown(self):
        self._blocker.close()

    def test_conflicting_slot_falls_back_others_stay_fixed(self):
        ports = _bind_ports_preferring(self.preferred)
        self.assertEqual(ports[0], self.preferred[0])
        self.assertNotEqual(ports[1], self.preferred[1])   # blocked -> ephemeral
        self.assertEqual(ports[2], self.preferred[2])
        self.assertEqual(len(set(ports)), len(ports))       # still all distinct

    def test_conflict_is_logged(self):
        logs = []
        _bind_ports_preferring(self.preferred,
                               log=lambda msg, level="info": logs.append(msg))
        self.assertTrue(any(str(self.preferred[1]) in m for m in logs))


class StabilityAcrossCallsTests(unittest.TestCase):
    """The whole point: calling this repeatedly (simulating restarts) with
    nothing else contending for the ports must return the SAME numbers every
    time."""

    def test_repeated_calls_return_the_same_ports(self):
        preferred = _free_ports(3)
        first = _bind_ports_preferring(preferred)
        second = _bind_ports_preferring(preferred)
        self.assertEqual(first, second)
        self.assertEqual(first, preferred)


if __name__ == "__main__":
    unittest.main(verbosity=2)
