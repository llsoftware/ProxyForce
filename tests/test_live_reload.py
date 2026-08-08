"""
Live-reload change-detection tests.

When Settings are saved while the engine is running, ProxyForce restarts the
connection ONLY if a proxy-affecting field changed (so a freshly added bypass
entry is applied, but a theme toggle never disconnects). This exercises
ProxyForceApp._proxy_settings_changed in isolation — no GUI is constructed; the
method is called with a stub `self` carrying just the attributes it reads.

Run:  python tests/test_live_reload.py
"""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gui.app import ProxyForceApp
from core.singbox_controller import make_proxy_config


class _StubEngine:
    def __init__(self, cfg_dict):
        self.config = make_proxy_config(cfg_dict)


def _changed(engine_cfg: dict, new_vals: dict) -> bool:
    """Call the real detector with a minimal stub self (engine + field list)."""
    stub = types.SimpleNamespace(
        _engine=_StubEngine(engine_cfg),
        _PROXY_FIELDS=ProxyForceApp._PROXY_FIELDS,
    )
    return ProxyForceApp._proxy_settings_changed(stub, new_vals)


BASE = {
    "host": "proxy.corp.local", "port": 8080, "auth_type": "basic",
    "username": "u", "password": "p", "exclude_private": True,
    "exclude_loopback": True, "bypass_list": ["10.0.0.0/8"], "log_level": "info",
}


class ProxyChangeDetectionTests(unittest.TestCase):

    def test_new_bypass_entry_triggers_restart(self):
        new = dict(BASE, bypass_list=["10.0.0.0/8", "intranet.local"])
        self.assertTrue(_changed(BASE, new))

    def test_host_change_triggers_restart(self):
        self.assertTrue(_changed(BASE, dict(BASE, host="other.corp.local")))

    def test_ncsi_fallback_change_triggers_restart(self):
        """v2.2.1: ncsi_fallback is read at runtime by _run_diagnostics, so a
        toggle must restart the engine like any other proxy-affecting field —
        otherwise a running engine keeps using the stale value indefinitely."""
        self.assertTrue(_changed(dict(BASE, ncsi_fallback=True),
                                 dict(BASE, ncsi_fallback=False)))

    def test_identical_config_no_restart(self):
        self.assertFalse(_changed(BASE, dict(BASE)))

    def test_cosmetic_only_change_no_restart(self):
        # appearance / start_minimized aren't proxy fields → no reconnect.
        new = dict(BASE, appearance="dark", start_minimized=True)
        self.assertFalse(_changed(BASE, new))

    def test_no_engine_no_restart(self):
        stub = types.SimpleNamespace(
            _engine=None, _PROXY_FIELDS=ProxyForceApp._PROXY_FIELDS)
        self.assertFalse(ProxyForceApp._proxy_settings_changed(stub, BASE))


if __name__ == "__main__":
    unittest.main(verbosity=2)
