"""
System-proxy takeover tests (v2.1.9).

These exercise ONLY the safe, side-effect-free paths: serialization, the backup
file round-trip, the "was a proxy set?" logic, and the read-only snapshot/state
readers. We deliberately do NOT call take_over()/restore()/_disable()/_restore()
in a unit test — those mutate the real machine's system-proxy settings.

Run:  python tests/test_system_proxy.py
"""

import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import system_proxy


class WinINetEnabledLogicTests(unittest.TestCase):

    def test_detects_enabled_proxy_server(self):
        snap = {"wininet": {"ProxyEnable": [1, 4], "ProxyServer": ["10.0.0.1:8080", 1]}}
        self.assertEqual(system_proxy._wininet_proxy_on(snap), "10.0.0.1:8080")

    def test_disabled_proxy_reports_empty(self):
        snap = {"wininet": {"ProxyEnable": [0, 4], "ProxyServer": ["10.0.0.1:8080", 1]}}
        self.assertEqual(system_proxy._wininet_proxy_on(snap), "")

    def test_pac_url_reported_when_no_server(self):
        snap = {"wininet": {"ProxyEnable": [0, 4],
                            "AutoConfigURL": ["http://x/proxy.pac", 1]}}
        self.assertEqual(system_proxy._wininet_proxy_on(snap), "PAC http://x/proxy.pac")

    def test_empty_snapshot_is_safe(self):
        self.assertEqual(system_proxy._wininet_proxy_on({}), "")


class BackupRoundTripTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = system_proxy._data_dir
        system_proxy._data_dir = lambda: self._tmp   # redirect backup to a temp dir

    def tearDown(self):
        system_proxy._data_dir = self._orig

    def test_backup_write_read_clear(self):
        snap = {"wininet": {"ProxyEnable": [1, 4], "ProxyServer": ["p:1", 1],
                            "ProxyOverride": None, "AutoConfigURL": None},
                "winhttp": ["deadbeef", 3]}
        self.assertIsNone(system_proxy._read_backup())
        system_proxy._write_backup(snap)
        self.assertEqual(system_proxy._read_backup(), snap)
        system_proxy._clear_backup()
        self.assertIsNone(system_proxy._read_backup())

    def test_winhttp_blob_hex_is_json_safe(self):
        """The WinHTTP REG_BINARY blob must survive a hex→JSON→hex→bytes round-trip."""
        original = bytes([0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
        snap = {"winhttp": [original.hex(), 3]}
        system_proxy._write_backup(snap)
        restored = system_proxy._read_backup()
        self.assertEqual(bytes.fromhex(restored["winhttp"][0]), original)


class ReadOnlyReadersTests(unittest.TestCase):
    """Snapshot + current_state only READ the registry — safe to call live."""

    def test_snapshot_shape(self):
        snap = system_proxy._snapshot()
        self.assertIn("wininet", snap)
        self.assertIn("winhttp", snap)
        self.assertIsInstance(snap["wininet"], dict)

    def test_current_state_returns_string(self):
        self.assertIsInstance(system_proxy.current_state(), str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
