"""
Fixed-port-first allocation tests (v2.2.2).

Diagnosed 2026-08-08: ProxyForce always picked fresh OS-ephemeral ports on every
restart, so the HTTP_PROXY/HTTPS_PROXY env vars and the WinINET/WinHTTP proxy
string changed every time — and Windows never propagates an env-var change to an
already-running process, so an already-open shell (Claude Code, PowerShell, …)
silently broke on every ProxyForce restart. _bind_ports_preferring keeps the same
port numbers across an ordinary restart (nothing else squatting on them) and only
falls back to ephemeral for a genuinely conflicting slot.

Run:  python tests/test_port_allocation.py
"""

import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.singbox_controller import _bind_ports_preferring, _DEFAULT_PORTS


class FixedPortsFreeTests(unittest.TestCase):

    def test_all_free_returns_the_exact_preferred_ports_in_order(self):
        ports = _bind_ports_preferring(_DEFAULT_PORTS)
        self.assertEqual(ports, list(_DEFAULT_PORTS))

    def test_distinct_ports_returned(self):
        ports = _bind_ports_preferring(_DEFAULT_PORTS)
        self.assertEqual(len(set(ports)), len(ports))


class FixedPortConflictTests(unittest.TestCase):
    """A genuinely occupied preferred port must fall back to ephemeral for JUST
    that slot — the other slots must still get their fixed defaults."""

    def setUp(self):
        # Occupy the middle preferred port (18080) so it's unavailable.
        self._blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._blocker.bind(("127.0.0.1", _DEFAULT_PORTS[1]))
        self._blocker.listen(1)

    def tearDown(self):
        self._blocker.close()

    def test_conflicting_slot_falls_back_others_stay_fixed(self):
        ports = _bind_ports_preferring(_DEFAULT_PORTS)
        self.assertEqual(ports[0], _DEFAULT_PORTS[0])
        self.assertNotEqual(ports[1], _DEFAULT_PORTS[1])   # blocked -> ephemeral
        self.assertEqual(ports[2], _DEFAULT_PORTS[2])
        self.assertEqual(len(set(ports)), len(ports))       # still all distinct

    def test_conflict_is_logged(self):
        logs = []
        _bind_ports_preferring(_DEFAULT_PORTS,
                               log=lambda msg, level="info": logs.append(msg))
        self.assertTrue(any(str(_DEFAULT_PORTS[1]) in m for m in logs))


class StabilityAcrossCallsTests(unittest.TestCase):
    """The whole point: calling this repeatedly (simulating restarts) with
    nothing else contending for the ports must return the SAME numbers every
    time."""

    def test_repeated_calls_return_the_same_ports(self):
        first = _bind_ports_preferring(_DEFAULT_PORTS)
        second = _bind_ports_preferring(_DEFAULT_PORTS)
        self.assertEqual(first, second)
        self.assertEqual(first, list(_DEFAULT_PORTS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
