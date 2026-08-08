"""
NCSI active-probing fallback tests (v2.2.1).

Mirrors tests/test_system_proxy.py's approach: exercise the crash-safe snapshot /
backup / restore contract with the actual registry mutation (_set_disabled /
_write_entry) STUBBED OUT, so these tests never touch the real machine's NlaSvc
setting. The read-only snapshot/state readers are safe to call live.

Run:  python tests/test_ncsi.py
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import ncsi


class BackupRoundTripTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_dir = ncsi._data_dir
        ncsi._data_dir = lambda: self._tmp   # redirect backup to a temp dir

    def tearDown(self):
        ncsi._data_dir = self._orig_dir

    def test_backup_write_read_clear(self):
        snap = {"value": [1, 4]}
        self.assertIsNone(ncsi._read_backup())
        ncsi._write_backup(snap)
        self.assertEqual(ncsi._read_backup(), snap)
        ncsi._clear_backup()
        self.assertIsNone(ncsi._read_backup())

    def test_value_none_round_trips(self):
        """The value never having existed is itself meaningful state (Windows
        treats absence as enabled=1) — must round-trip as None, not 0/absent-key
        confusion."""
        snap = {"value": None}
        ncsi._write_backup(snap)
        self.assertEqual(ncsi._read_backup(), snap)


class SuppressAndRestoreTests(unittest.TestCase):
    """suppress_active_probing()/restore() must snapshot before the first mutation
    and preserve a true original across a crash (existing backup kept). The actual
    registry write (_set_disabled/_write_entry) is stubbed so no real mutation
    happens."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_dir = ncsi._data_dir
        self._orig_set = ncsi._set_disabled
        self._orig_write = ncsi._write_entry
        self._orig_snapshot = ncsi._snapshot
        ncsi._data_dir = lambda: self._tmp
        self._set_calls = []
        self._write_calls = []
        ncsi._set_disabled = lambda: self._set_calls.append(True)
        ncsi._write_entry = lambda entry: self._write_calls.append(entry)
        ncsi._snapshot = lambda: {"value": [1, 4]}   # pretend probing was enabled

    def tearDown(self):
        ncsi._data_dir = self._orig_dir
        ncsi._set_disabled = self._orig_set
        ncsi._write_entry = self._orig_write
        ncsi._snapshot = self._orig_snapshot

    def test_suppress_writes_backup_before_mutating(self):
        self.assertTrue(ncsi.suppress_active_probing())
        self.assertEqual(ncsi._read_backup(), {"value": [1, 4]})
        self.assertEqual(len(self._set_calls), 1)

    def test_crash_safe_keeps_first_backup(self):
        ncsi.suppress_active_probing()
        first = ncsi._read_backup()
        ncsi._snapshot = lambda: {"value": [0, 4]}   # a second run would see it already off
        ncsi.suppress_active_probing()               # mid-takeover from a previous run
        self.assertEqual(ncsi._read_backup(), first)  # true original preserved, not re-snapshot
        self.assertEqual(len(self._set_calls), 2)      # but still re-asserts the mutation

    def test_restore_writes_back_the_snapshotted_value_and_clears_backup(self):
        ncsi.suppress_active_probing()
        self.assertTrue(ncsi.restore())
        self.assertEqual(self._write_calls[-1], [1, 4])
        self.assertIsNone(ncsi._read_backup())

    def test_restore_deletes_the_value_if_it_never_existed(self):
        ncsi._snapshot = lambda: {"value": None}
        ncsi.suppress_active_probing()
        ncsi.restore()
        self.assertIsNone(self._write_calls[-1])

    def test_restore_with_no_backup_is_a_noop(self):
        self.assertFalse(ncsi.restore())
        self.assertEqual(self._write_calls, [])


class ReadOnlyReadersTests(unittest.TestCase):
    """Snapshot + current_state only READ the registry — safe to call live."""

    def test_snapshot_shape(self):
        snap = ncsi._snapshot()
        self.assertIn("value", snap)

    def test_current_state_returns_string(self):
        self.assertIsInstance(ncsi.current_state(), str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
