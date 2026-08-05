"""
Proxy-environment-variable takeover tests (v2.1.25 — the yt-dlp "getaddrinfo
failed" fix).

WHY THIS MODULE EXISTS: a large class of CLI/dev tools (yt-dlp, curl, git, pip,
node, ffmpeg, …) resolves its proxy from the environment instead of WinINET/
WinHTTP. Python's own urllib.request.getproxies() is
`getproxies_environment() or getproxies_registry()` — ANY *_proxy variable,
INCLUDING A BARE `no_proxy`, makes the environment lookup truthy and the registry
proxy (what core.system_proxy sets) is never consulted. core.env_proxy closes
that gap by exporting HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY (both cases,
user + machine scope) for the duration of a run, and restoring exactly what was
there before — including a stray pre-existing `no_proxy`, whose presence is
precisely what caused the original report.

Like test_system_proxy.py, these exercise ONLY the safe, side-effect-free paths:
serialization, the backup file round-trip, and point_at()/restore() with `_set`/
`_restore` stubbed out — never the real registry.

Run:  python tests/test_env_proxy.py
"""

import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import env_proxy


class DescribeTests(unittest.TestCase):

    def test_empty_snapshot_describes_as_empty(self):
        empty = {"user": {n: None for n in env_proxy._ALL_VAR_NAMES},
                 "machine": {n: None for n in env_proxy._ALL_VAR_NAMES}}
        self.assertEqual(env_proxy._describe(empty), "")

    def test_describe_reports_scope_and_name(self):
        snap = {"user": {"no_proxy": ["localhost", 1],
                          **{n: None for n in env_proxy._ALL_VAR_NAMES if n != "no_proxy"}},
                "machine": {n: None for n in env_proxy._ALL_VAR_NAMES}}
        desc = env_proxy._describe(snap)
        self.assertIn("user:no_proxy=localhost", desc)

    def test_describe_skips_falsy_values(self):
        """An entry present but empty-string must not be reported as 'set'."""
        snap = {"user": {"NO_PROXY": ["", 1],
                         **{n: None for n in env_proxy._ALL_VAR_NAMES if n != "NO_PROXY"}},
                "machine": {n: None for n in env_proxy._ALL_VAR_NAMES}}
        self.assertEqual(env_proxy._describe(snap), "")


class BackupRoundTripTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = env_proxy._data_dir
        env_proxy._data_dir = lambda: self._tmp   # redirect backup to a temp dir

    def tearDown(self):
        env_proxy._data_dir = self._orig

    def test_backup_write_read_clear(self):
        snap = {"user": {"HTTP_PROXY": ["http://127.0.0.1:1", 1],
                         **{n: None for n in env_proxy._ALL_VAR_NAMES if n != "HTTP_PROXY"}},
                "machine": {n: None for n in env_proxy._ALL_VAR_NAMES}}
        self.assertIsNone(env_proxy._read_backup())
        env_proxy._write_backup(snap)
        self.assertEqual(env_proxy._read_backup(), snap)
        env_proxy._clear_backup()
        self.assertIsNone(env_proxy._read_backup())

    def test_backup_is_json_safe(self):
        """REG_SZ values round-trip through JSON with no encoding surprises."""
        snap = {"user": {"NO_PROXY": ["a,b,c", 1],
                         **{n: None for n in env_proxy._ALL_VAR_NAMES if n != "NO_PROXY"}},
                "machine": {n: None for n in env_proxy._ALL_VAR_NAMES}}
        env_proxy._write_backup(snap)
        with open(env_proxy._backup_path(), "r", encoding="utf-8") as f:
            json.load(f)   # must not raise
        self.assertEqual(env_proxy._read_backup()["user"]["NO_PROXY"], ["a,b,c", 1])


class PointAtTests(unittest.TestCase):
    """point_at() must SET the four variables (both cases) and keep the crash-safe
    backup semantics. _set/_snapshot are stubbed so the real registry is never
    touched — matching PointAtTests in test_system_proxy.py."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_dir = env_proxy._data_dir
        self._orig_set = env_proxy._set
        self._orig_snapshot = env_proxy._snapshot
        env_proxy._data_dir = lambda: self._tmp
        self._set_calls = []
        env_proxy._set = lambda http_url, https_url, no_proxy: \
            self._set_calls.append((http_url, https_url, no_proxy))
        # A stray pre-existing no_proxy — reproduces the exact bug report: some
        # process/user/machine no_proxy was ALREADY set before ProxyForce started.
        self._fake_prior = {
            "user": {"no_proxy": ["localhost", 1],
                     **{n: None for n in env_proxy._ALL_VAR_NAMES if n != "no_proxy"}},
            "machine": {n: None for n in env_proxy._ALL_VAR_NAMES},
        }
        env_proxy._snapshot = lambda: self._fake_prior

    def tearDown(self):
        env_proxy._data_dir = self._orig_dir
        env_proxy._set = self._orig_set
        env_proxy._snapshot = self._orig_snapshot

    def test_points_at_urls_and_writes_backup(self):
        env_proxy.point_at("http://127.0.0.1:1", "http://127.0.0.1:2", "localhost,127.0.0.1")
        self.assertEqual(self._set_calls[-1],
                         ("http://127.0.0.1:1", "http://127.0.0.1:2", "localhost,127.0.0.1"))
        self.assertIsNotNone(env_proxy._read_backup())   # original snapshotted

    def test_prior_stray_no_proxy_is_reported_and_snapshotted(self):
        """This is the exact scenario from the report: a stray no_proxy elsewhere on
        the box. point_at() must surface it (for the log) and preserve it in the
        backup so it comes back on restore, rather than being silently dropped."""
        prev = env_proxy.point_at("http://127.0.0.1:1", "http://127.0.0.1:2", "")
        self.assertIn("user:no_proxy=localhost", prev)
        self.assertEqual(env_proxy._read_backup(), self._fake_prior)

    def test_crash_safe_keeps_first_backup(self):
        env_proxy.point_at("http://127.0.0.1:1", "http://127.0.0.1:2", "b1")
        first = env_proxy._read_backup()
        prev = env_proxy.point_at("http://127.0.0.1:9", "http://127.0.0.1:9", "b2")
        self.assertEqual(prev, "")                                  # doesn't re-snapshot
        self.assertEqual(self._set_calls[-1],
                         ("http://127.0.0.1:9", "http://127.0.0.1:9", "b2"))  # but still re-asserts
        self.assertEqual(env_proxy._read_backup(), first)           # true original preserved


class RestoreTests(unittest.TestCase):
    """restore() must write back the group atomically (Step-2 invariant: NO_PROXY
    is never left set without HTTP_PROXY/HTTPS_PROXY, in either direction) using the
    exact stored value/type, and delete variables that were not originally set."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_dir = env_proxy._data_dir
        self._orig_restore = env_proxy._restore
        env_proxy._data_dir = lambda: self._tmp
        self._restore_calls = []
        env_proxy._restore = lambda snap: self._restore_calls.append(snap)

    def tearDown(self):
        env_proxy._data_dir = self._orig_dir
        env_proxy._restore = self._orig_restore

    def test_no_backup_is_a_noop(self):
        self.assertFalse(env_proxy.restore())
        self.assertEqual(self._restore_calls, [])

    def test_restore_passes_the_exact_snapshot_and_clears_backup(self):
        snap = {"user": {"HTTP_PROXY": ["http://127.0.0.1:1", 1],
                         **{n: None for n in env_proxy._ALL_VAR_NAMES if n != "HTTP_PROXY"}},
                "machine": {n: None for n in env_proxy._ALL_VAR_NAMES}}
        env_proxy._write_backup(snap)
        self.assertTrue(env_proxy.restore())
        self.assertEqual(self._restore_calls[-1], snap)
        self.assertIsNone(env_proxy._read_backup())   # cleared after restore


class ReadOnlyReadersTests(unittest.TestCase):
    """Snapshot + current_state only READ the registry — safe to call live."""

    def test_snapshot_shape(self):
        snap = env_proxy._snapshot()
        self.assertIn("user", snap)
        self.assertIn("machine", snap)
        for scope in ("user", "machine"):
            for name in env_proxy._ALL_VAR_NAMES:
                self.assertIn(name, snap[scope])

    def test_current_state_returns_string(self):
        self.assertIsInstance(env_proxy.current_state(), str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
