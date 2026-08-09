"""Regression tests for the Windows Spotlight/NCSI startup path."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import ncsi, system_proxy
from core import singbox_controller as controller_mod
from core.singbox_controller import (
    ProxyConfig, SingBoxController, _ncsi_event_reason,
)


class EventReasonTests(unittest.TestCase):
    def test_known_reasons(self):
        for reason in ("ActiveHttpProbeFailedButDnsSucceeded",
                       "SuspectDnsProbeFailed", "ActiveDnsProbeSucceeded"):
            self.assertEqual(_ncsi_event_reason(
                f"Capability: Local ChangeReason: {reason}"), reason)

    def test_missing_reason(self):
        self.assertEqual(_ncsi_event_reason("unrelated event"), "")


class ActiveProbeStartupTests(unittest.TestCase):
    def setUp(self):
        self.cfg = ProxyConfig(host="203.0.113.10", port=800)
        self.c = SingBoxController(self.cfg)
        self.orig_wait = self.c._stop_event.wait
        self.orig_refresh = system_proxy.refresh
        self.orig_diag = self.c._run_diagnostics
        self.orig_settle = controller_mod._NCSI_SETTLE_SECONDS
        self.orig_retry = controller_mod._NCSI_REFRESH_SECONDS
        controller_mod._NCSI_SETTLE_SECONDS = 0
        controller_mod._NCSI_REFRESH_SECONDS = 0
        self.waits = []
        self.refreshes = []
        self.diags = []
        self.c._stop_event.wait = lambda seconds: self.waits.append(seconds) or False
        system_proxy.refresh = lambda: self.refreshes.append(True)
        self.c._run_diagnostics = lambda: self.diags.append(True)

    def tearDown(self):
        self.c._stop_event.wait = self.orig_wait
        system_proxy.refresh = self.orig_refresh
        self.c._run_diagnostics = self.orig_diag
        controller_mod._NCSI_SETTLE_SECONDS = self.orig_settle
        controller_mod._NCSI_REFRESH_SECONDS = self.orig_retry

    def test_internet_after_quiet_window_runs_diagnostics_without_refresh(self):
        self.c._proxyforce_connectivity = lambda: "Internet"
        self.c._run_diagnostics_after_ncsi_settle()
        self.assertEqual(self.waits, [0])
        self.assertEqual(self.refreshes, [])
        self.assertEqual(self.diags, [True])

    def test_local_profile_gets_one_refresh_and_second_quiet_window(self):
        self.c._proxyforce_connectivity = lambda: "LocalNetwork"
        self.c._run_diagnostics_after_ncsi_settle()
        self.assertEqual(self.waits, [0, 0])
        self.assertEqual(self.refreshes, [True])
        self.assertEqual(self.diags, [True])

    def test_stop_during_first_window_skips_everything(self):
        self.c._stop_event.wait = lambda seconds: True
        self.c._run_diagnostics_after_ncsi_settle()
        self.assertEqual(self.refreshes, [])
        self.assertEqual(self.diags, [])

    def test_legacy_config_key_is_ignored(self):
        from core.singbox_controller import make_proxy_config
        cfg = make_proxy_config({"host": "proxy", "port": 8080,
                                 "ncsi_fallback": False})
        self.assertFalse(hasattr(cfg, "ncsi_fallback"))


class LegacyRecoveryTests(unittest.TestCase):
    def test_takeover_path_contains_restore_but_not_suppression(self):
        import inspect
        source = inspect.getsource(SingBoxController._takeover_system_proxy)
        self.assertIn("ncsi.restore()", source)
        self.assertNotIn("suppress_active_probing", source)


class ReadOnlyReadersTests(unittest.TestCase):
    def test_current_state_returns_string(self):
        self.assertIsInstance(ncsi.current_state(), str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
