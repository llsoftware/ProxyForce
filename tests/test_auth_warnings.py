"""
Auth-type / credential mismatch warning tests.

Diagnosed 2026-08-08 (and again while removing the auto-bypass feature that
caused it): a config can end up with Auth Type "None" while a username/
password are still populated, so the engine silently never sends credentials
(SingBoxController only does so when auth_type == "basic") and the proxy
answers 407 with nothing telling the user why. core.config_store.auth_config_
warnings() is the single source of truth for detecting that mismatch (and its
siblings — Basic with a missing field, or NTLM which ProxyForce doesn't
implement), reused by both the GUI's live inline note and its Log-tab
warnings on Save/Connect/startup.

The second class guards the actual mechanism that caused the incident: the
auto-bypass feature called SettingsPanel.set_values() with a PARTIAL dict
(just {"bypass_list": ...}), and set_values() read d.get("auth_type", "none")
unconditionally for the "_auth_display" pseudo-key — so a partial call reset
Auth Type (and Update Channel, Log Level) to their defaults every time. Auto-
bypass is gone, but the landmine in set_values() is the reusable regression
guard: any future partial caller must not be able to touch fields it didn't
pass.

Run:  python tests/test_auth_warnings.py
"""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config_store import auth_config_warnings
from gui.app import SettingsPanel, _AUTH_DISPLAY, _AUTH_INTERNAL


class AuthConfigWarningsTests(unittest.TestCase):

    def test_none_with_no_credentials_is_clean(self):
        self.assertEqual(auth_config_warnings(
            {"auth_type": "none", "username": "", "password": ""}), [])

    def test_basic_with_both_credentials_is_clean(self):
        self.assertEqual(auth_config_warnings(
            {"auth_type": "basic", "username": "u", "password": "p"}), [])

    def test_none_with_username_warns(self):
        warnings = auth_config_warnings(
            {"auth_type": "none", "username": "u", "password": ""})
        self.assertEqual(len(warnings), 1)
        self.assertIn("Auth Type is \"None\"", warnings[0])

    def test_none_with_password_warns(self):
        warnings = auth_config_warnings(
            {"auth_type": "none", "username": "", "password": "p"})
        self.assertEqual(len(warnings), 1)
        self.assertIn("Auth Type is \"None\"", warnings[0])

    def test_basic_with_no_username_warns_about_407(self):
        warnings = auth_config_warnings(
            {"auth_type": "basic", "username": "", "password": "p"})
        self.assertEqual(len(warnings), 1)
        self.assertIn("407", warnings[0])

    def test_basic_with_no_password_warns_about_407(self):
        warnings = auth_config_warnings(
            {"auth_type": "basic", "username": "u", "password": ""})
        self.assertEqual(len(warnings), 1)
        self.assertIn("407", warnings[0])

    def test_ntlm_with_credentials_warns_not_implemented(self):
        warnings = auth_config_warnings(
            {"auth_type": "ntlm", "username": "u", "password": "p"})
        self.assertEqual(len(warnings), 1)
        self.assertIn("NTLM", warnings[0])

    def test_ntlm_with_no_credentials_is_clean(self):
        self.assertEqual(auth_config_warnings(
            {"auth_type": "ntlm", "username": "", "password": ""}), [])

    def test_missing_keys_default_like_a_fresh_config(self):
        self.assertEqual(auth_config_warnings({}), [])

    def test_case_insensitive_auth_type(self):
        warnings = auth_config_warnings(
            {"auth_type": "NONE", "username": "u", "password": ""})
        self.assertEqual(len(warnings), 1)


class _FakeVar:
    """Minimal stand-in for tk.StringVar/BooleanVar — duck-types .get()/.set()
    without needing a real Tk root."""
    def __init__(self, value=""):
        self._value = value

    def get(self):
        return self._value

    def set(self, value):
        self._value = value


def _stub_settings_panel(auth="Basic", channel="Stable", loglevel="Info",
                         username="corpuser", password="hunter2"):
    """Builds a stub carrying just what SettingsPanel.set_values/_refresh_auth_
    warning read — no real Tk widgets, so this runs headless."""
    return types.SimpleNamespace(
        _vars={
            "_auth_display": _FakeVar(auth),
            "_channel_display": _FakeVar(channel),
            "_loglevel_display": _FakeVar(loglevel),
            "username": _FakeVar(username),
            "password": _FakeVar(password),
            "host": _FakeVar("proxy.corp.local"),
        },
        _bypass_text=None,
        _refresh_auth_warning=lambda: None,
    )


class SetValuesPartialDictGuardTests(unittest.TestCase):
    """Regression guard for the incident: set_values({"bypass_list": [...]})
    (or any other partial dict) must leave Auth Type / Update Channel / Log
    Level exactly as they were when the dict doesn't mention them."""

    def test_partial_dict_leaves_auth_type_untouched(self):
        stub = _stub_settings_panel(auth="Basic")
        SettingsPanel.set_values(stub, {"bypass_list": ["10.0.0.0/8"]})
        self.assertEqual(stub._vars["_auth_display"].get(), "Basic")

    def test_partial_dict_leaves_update_channel_untouched(self):
        stub = _stub_settings_panel(channel="Development")
        SettingsPanel.set_values(stub, {"bypass_list": []})
        self.assertEqual(stub._vars["_channel_display"].get(), "Development")

    def test_partial_dict_leaves_log_level_untouched(self):
        stub = _stub_settings_panel(loglevel="Debug (verbose)")
        SettingsPanel.set_values(stub, {"bypass_list": []})
        self.assertEqual(stub._vars["_loglevel_display"].get(), "Debug (verbose)")

    def test_full_dict_still_updates_auth_type(self):
        """The guard must not break the legitimate full-dict case (e.g. the
        normal load_config() -> set_values() call at startup)."""
        stub = _stub_settings_panel(auth="Basic")
        SettingsPanel.set_values(stub, {"auth_type": "none"})
        self.assertEqual(stub._vars["_auth_display"].get(), "None")

    def test_username_and_password_untouched_by_bypass_only_update(self):
        stub = _stub_settings_panel(username="corpuser", password="hunter2")
        SettingsPanel.set_values(stub, {"bypass_list": ["10.0.0.0/8"]})
        self.assertEqual(stub._vars["username"].get(), "corpuser")
        self.assertEqual(stub._vars["password"].get(), "hunter2")


if __name__ == "__main__":
    unittest.main(verbosity=2)
