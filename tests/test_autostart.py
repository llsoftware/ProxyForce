"""
Autostart (Scheduled Task) tests.

Autostart moved from an HKCU\\...\\Run entry to a Scheduled Task so it launches
ALREADY elevated (no UAC prompt) at logon — the fix that lets an unattended box
come up connected. These tests verify save_autostart() builds the right schtasks
command and always clears the legacy Run entry, WITHOUT touching the real Task
Scheduler or registry (subprocess.run + the legacy-cleanup helper are stubbed).

Run:  python tests/test_autostart.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import config_store


class SaveAutostartTests(unittest.TestCase):

    def setUp(self):
        # Capture schtasks invocations instead of running them; skip the real
        # registry cleanup (asserted separately via a counter).
        self._orig_run    = config_store.subprocess.run
        self._orig_legacy = config_store._remove_legacy_run_entry
        self._calls   = []
        self._legacy  = []
        config_store.subprocess.run       = lambda *a, **k: self._calls.append((a, k))
        config_store._remove_legacy_run_entry = lambda: self._legacy.append(True)

    def tearDown(self):
        config_store.subprocess.run            = self._orig_run
        config_store._remove_legacy_run_entry  = self._orig_legacy

    def _last_argv(self):
        # subprocess.run(argv_list, ...) — first positional arg is the command list.
        return self._calls[-1][0][0]

    def test_enable_creates_elevated_onlogon_task(self):
        exe = r"C:\Tools\ProxyForce\ProxyForce.exe"
        config_store.save_autostart(True, exe)
        argv = self._last_argv()
        self.assertEqual(argv[:5], ["schtasks", "/Create", "/F", "/TN", "ProxyForce"])
        self.assertIn("/SC", argv)
        self.assertIn("ONLOGON", argv)
        self.assertIn("/RL", argv)
        self.assertIn("HIGHEST", argv)
        # The target command quotes the exe path and passes --minimized.
        self.assertIn(f'"{exe}" --minimized', argv)
        # Legacy Run-key entry is always cleared so upgrades don't double-launch.
        self.assertTrue(self._legacy)

    def test_disable_deletes_task(self):
        config_store.save_autostart(False, "irrelevant")
        self.assertEqual(self._last_argv(),
                         ["schtasks", "/Delete", "/F", "/TN", "ProxyForce"])
        self.assertTrue(self._legacy)

    def test_creation_failure_never_raises(self):
        def boom(*a, **k):
            raise OSError("schtasks missing")
        config_store.subprocess.run = boom
        # Must not propagate — Save should never crash on an autostart failure.
        config_store.save_autostart(True, "x")


if __name__ == "__main__":
    unittest.main(verbosity=2)
