"""
Tests for the reputation settings in core/config_store.

Two things are easy to get wrong when adding settings here and both are silent
failures: an API key stored in clear text alongside the proxy password that IS
obfuscated, and a list value that does not survive the JSON fallback store.

The registry is never touched — winreg.OpenKey is stubbed to miss so the
ProgramData JSON path is exercised, and CONFIG_FILE_FALLBACK is redirected into
a temp directory.

Run:  python tests/test_rep_config.py
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
import winreg

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import config_store
from core.config_store import _DEFAULTS, _SECRET_KEYS, rep_config_warnings


class DefaultsTests(unittest.TestCase):

    def test_scanning_is_off_by_default(self):
        """It sends the names of visited sites to a third party, so it must be
        an explicit choice, not a surprise."""
        self.assertIs(_DEFAULTS["rep_scan"], False)

    def test_free_feeds_are_on_by_default(self):
        """They need no key and make no per-host request, so they are the one
        tier that can sensibly default to on."""
        self.assertIs(_DEFAULTS["rep_feeds"], True)

    def test_api_keys_default_to_empty(self):
        self.assertEqual(_DEFAULTS["rep_gsb_key"], "")
        self.assertEqual(_DEFAULTS["rep_vt_key"], "")

    def test_api_keys_are_treated_as_secrets(self):
        self.assertIn("rep_gsb_key", _SECRET_KEYS)
        self.assertIn("rep_vt_key", _SECRET_KEYS)
        self.assertIn("password", _SECRET_KEYS)


class FallbackStoreRoundTripTests(unittest.TestCase):

    def setUp(self):
        self._root = tempfile.mkdtemp(prefix="pf_cfg_")
        self._real_path = config_store.CONFIG_FILE_FALLBACK
        config_store.CONFIG_FILE_FALLBACK = os.path.join(self._root,
                                                         "config.json")
        # Force the JSON fallback path: pretend HKLM has no ProxyForce key.
        self._real_open = winreg.OpenKey
        self._real_create = winreg.CreateKey

        def _miss(*_a, **_k):
            raise FileNotFoundError()

        winreg.OpenKey = _miss
        winreg.CreateKey = _miss

    def tearDown(self):
        winreg.OpenKey = self._real_open
        winreg.CreateKey = self._real_create
        config_store.CONFIG_FILE_FALLBACK = self._real_path
        shutil.rmtree(self._root, ignore_errors=True)

    def _raw(self) -> dict:
        with open(config_store.CONFIG_FILE_FALLBACK, encoding="utf-8") as f:
            return json.load(f)

    def test_api_keys_round_trip(self):
        self.assertTrue(config_store.save_config(
            dict(_DEFAULTS, rep_gsb_key="GSB123", rep_vt_key="VT456")))
        loaded = config_store.load_config()
        self.assertEqual(loaded["rep_gsb_key"], "GSB123")
        self.assertEqual(loaded["rep_vt_key"], "VT456")

    def test_api_keys_are_not_stored_in_clear_text(self):
        config_store.save_config(dict(_DEFAULTS, rep_gsb_key="GSB123",
                                      rep_vt_key="VT456"))
        blob = json.dumps(self._raw())
        self.assertNotIn("GSB123", blob)
        self.assertNotIn("VT456", blob)

    def test_blocklist_round_trips(self):
        config_store.save_config(
            dict(_DEFAULTS, rep_blocklist=["evil.example", "bad.example"]))
        self.assertEqual(config_store.load_config()["rep_blocklist"],
                         ["evil.example", "bad.example"])

    def test_empty_key_is_left_alone(self):
        """Obfuscating "" would turn an unset key into a non-empty string and
        make `if cfg.get("rep_gsb_key")` true for a key that does not exist."""
        config_store.save_config(dict(_DEFAULTS, rep_gsb_key=""))
        self.assertEqual(self._raw()["rep_gsb_key"], "")
        self.assertEqual(config_store.load_config()["rep_gsb_key"], "")


class RepConfigWarningsTests(unittest.TestCase):

    def test_disabled_scanning_warns_about_nothing(self):
        self.assertEqual(rep_config_warnings({"rep_scan": False}), [])

    def test_enabled_with_no_sources_warns(self):
        warnings = rep_config_warnings(
            {"rep_scan": True, "rep_feeds": False, "rep_gsb_key": "",
             "rep_vt_key": "", "rep_block": True})
        self.assertEqual(len(warnings), 1)
        self.assertIn("ever be checked", warnings[0])

    def test_feeds_and_safe_browsing_is_clean(self):
        self.assertEqual(rep_config_warnings(
            {"rep_scan": True, "rep_feeds": True, "rep_gsb_key": "k",
             "rep_vt_key": "", "rep_block": True}), [])

    def test_virustotal_alone_warns_about_the_rate_limit(self):
        """4 lookups/minute cannot keep up with browsing, so a user who has
        configured only VirusTotal is not covered the way they think."""
        warnings = rep_config_warnings(
            {"rep_scan": True, "rep_feeds": False, "rep_gsb_key": "",
             "rep_vt_key": "k", "rep_block": True})
        self.assertTrue(any("4 lookups/minute" in w for w in warnings))

    def test_feeds_only_warns_that_coverage_is_offline(self):
        warnings = rep_config_warnings(
            {"rep_scan": True, "rep_feeds": True, "rep_gsb_key": "",
             "rep_vt_key": "", "rep_block": True})
        self.assertTrue(any("Safe Browsing" in w for w in warnings))

    def test_blocking_disabled_is_called_out(self):
        warnings = rep_config_warnings(
            {"rep_scan": True, "rep_feeds": True, "rep_gsb_key": "k",
             "rep_vt_key": "", "rep_block": False})
        self.assertTrue(any("still" in w for w in warnings))


if __name__ == "__main__":
    unittest.main(verbosity=2)
