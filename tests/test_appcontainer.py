"""
Store/UWP loopback-exemption tests (v2.1.27 — the "Microsoft Store won't load" fix).

WHY THIS MODULE EXISTS: ProxyForce's system-proxy takeover points WinINET/WinHTTP
at 127.0.0.1. Every Store/UWP app runs in an AppContainer, and Windows blocks an
AppContainer's connections to loopback unless the package holds a loopback
exemption — so without this module, the Microsoft Store (and every other UWP app)
fails outright while ProxyForce runs, and the TUN catch-all can't rescue it (the
app obeys the now-unreachable proxy rather than falling back to direct).
core.appcontainer grants `CheckNetIsolation LoopbackExempt` for every installed
package on start and revokes exactly what it added on stop, using the same
snapshot/backup-file contract as core.env_proxy and core.system_proxy.

Like test_env_proxy.py / test_system_proxy.py, these exercise ONLY the safe,
side-effect-free paths: output parsing, the one-process-per-package invocation
shape, and the backup-file round trip, with `_ps`/`_checknetisolation` stubbed
out — never the real CheckNetIsolation tool or registry.

Run:  python tests/test_appcontainer.py
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import appcontainer


class ListExemptParsingTests(unittest.TestCase):
    """_list_exempt() must pull package family names out of `CheckNetIsolation
    LoopbackExempt -s` output WITHOUT depending on any particular label/layout.

    Regression: an earlier version anchored on a literal "Name:" label. On a real
    Windows 11 (build 26200) dev machine, exempt_installed() reported "122 of 122"
    granted (every `-a` call genuinely exited 0 — confirmed separately, a real
    failure DOES surface as a non-zero exit) while a readback via THIS function
    moments later found only "1" exempt — because the label text this function was
    matching against didn't match what that build's CheckNetIsolation actually
    prints. The fix: match the package-family-name SHAPE itself
    (`<name>_<13-char publisher id>`, a fixed Windows convention independent of
    labels), not a label. These tests deliberately exercise several PLAUSIBLE
    real-world layouts, not just the one sample the original regex was written
    against, so this exact bug class can't silently recur."""

    _LABELED = """
List Loopback Exempted AppContainers

[1] -----------------------------------------------------------------
Name: microsoft.windowsstore_8wekyb3d8bbwe
SID: S-1-15-2-1609473798-1231923017-684268153-4268514328-882773646-2760585773-1760938157

[2] -----------------------------------------------------------------
Name: microsoft.xboxidentityprovider_8wekyb3d8bbwe
SID: S-1-15-2-424268864-2020486118-1811575806-1888856205-2769478682-1043813619-3428097430

OK.
"""

    # A plausible alternate layout: name + SID on ONE line, no "Name:"/"SID:" labels
    # at all — this is exactly the shape the old label-anchored regex could never
    # have matched, and the new shape-based one must.
    _TABLE_LIKE = """
Loopback Exempted AppContainers
--------------------------------
PackageFamilyName                             SID
Microsoft.WindowsStore_8wekyb3d8bbwe           S-1-15-2-1609473798-1231923017
Microsoft.XboxIdentityProvider_8wekyb3d8bbwe   S-1-15-2-424268864-2020486118
OK.
"""

    _BARE_INDENTED = """
   microsoft.windowsstore_8wekyb3d8bbwe
   microsoft.xboxidentityprovider_8wekyb3d8bbwe
OK.
"""

    def setUp(self):
        self._orig_ps = appcontainer._ps

    def tearDown(self):
        appcontainer._ps = self._orig_ps

    def _expect_both(self):
        return {"microsoft.windowsstore_8wekyb3d8bbwe",
                "microsoft.xboxidentityprovider_8wekyb3d8bbwe"}

    def test_extracts_from_labeled_blocks(self):
        appcontainer._ps = lambda *a, **k: self._LABELED
        self.assertEqual(appcontainer._list_exempt(), self._expect_both())

    def test_extracts_from_table_layout_with_no_labels(self):
        """The exact regression shape: no "Name:"/"SID:" labels at all, mixed case,
        SID printed on the SAME line right after the PFN."""
        appcontainer._ps = lambda *a, **k: self._TABLE_LIKE
        names = {n.lower() for n in appcontainer._list_exempt()}
        self.assertEqual(names, self._expect_both())

    def test_extracts_from_bare_indented_names(self):
        appcontainer._ps = lambda *a, **k: self._BARE_INDENTED
        self.assertEqual(appcontainer._list_exempt(), self._expect_both())

    def test_sid_lines_never_match(self):
        """SIDs use hyphens, never an underscore — must not be mistaken for a PFN."""
        appcontainer._ps = lambda *a, **k: (
            "SID: S-1-15-2-1609473798-1231923017-684268153-4268514328\nOK.")
        self.assertEqual(appcontainer._list_exempt(), set())

    def test_empty_list_parses_to_empty_set(self):
        appcontainer._ps = lambda *a, **k: "\nList Loopback Exempted AppContainers \n\nOK."
        self.assertEqual(appcontainer._list_exempt(), set())

    def test_is_exempt_is_case_insensitive(self):
        appcontainer._ps = lambda *a, **k: self._LABELED
        self.assertTrue(appcontainer.is_exempt("Microsoft.WindowsStore_8wekyb3d8bbwe"))
        self.assertFalse(appcontainer.is_exempt("Microsoft.Not.Installed_abc123"))


class BackupRoundTripTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig = appcontainer._data_dir
        appcontainer._data_dir = lambda: self._tmp   # redirect backup to a temp dir

    def tearDown(self):
        appcontainer._data_dir = self._orig

    def test_backup_write_read_clear(self):
        snap = ["microsoft.windowscommunicationsapps_8wekyb3d8bbwe"]
        self.assertIsNone(appcontainer._read_backup())
        appcontainer._write_backup(snap)
        self.assertEqual(appcontainer._read_backup(), snap)
        appcontainer._clear_backup()
        self.assertIsNone(appcontainer._read_backup())


class ExemptInstalledTests(unittest.TestCase):
    """exempt_installed() must snapshot BEFORE the first mutation (crash-safe,
    like env_proxy.point_at), keep an existing backup as the true original on a
    second call, and — the actual bug this module was rewritten to fix — grant
    each package via its OWN separate `_checknetisolation` call, never a single
    batched script with an internal loop. That batched-loop pattern was verified
    live (on two different machines, different Windows versions) to report
    success on every call while the real exemption list ended up with exactly
    one unresolvable entry sharing an IDENTICAL SID across both machines — proof
    the corruption came from the loop/redirect pattern itself, not from
    anything about the packages, permissions, or either machine."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_dir = appcontainer._data_dir
        self._orig_ps = appcontainer._ps
        self._orig_cni = appcontainer._checknetisolation
        self._orig_installed = appcontainer._installed_package_family_names
        appcontainer._data_dir = lambda: self._tmp
        appcontainer._ps = lambda *a, **k: "\nOK."   # empty -s snapshot by default
        appcontainer._installed_package_family_names = lambda: [
            "Microsoft.WindowsStore_8wekyb3d8bbwe", "Microsoft.XboxApp_8wekyb3d8bbwe"]
        self._cni_calls = []

    def tearDown(self):
        appcontainer._data_dir = self._orig_dir
        appcontainer._ps = self._orig_ps
        appcontainer._checknetisolation = self._orig_cni
        appcontainer._installed_package_family_names = self._orig_installed

    def _stub_cni(self, exit_code=0):
        def fake(*args, timeout=15):
            self._cni_calls.append(args)
            return (exit_code, "OK." if exit_code == 0 else "Access Denied")
        appcontainer._checknetisolation = fake

    def test_writes_backup_and_returns_added_total(self):
        self._stub_cni(exit_code=0)
        added, total = appcontainer.exempt_installed()
        self.assertEqual((added, total), (2, 2))
        self.assertEqual(appcontainer._read_backup(), [])   # nothing exempt beforehand

    def test_calls_one_process_per_package_not_a_batched_loop(self):
        """The regression test for the actual bug: exactly one _checknetisolation
        call per package, each carrying that package's own -n= value — never one
        call with all packages embedded in a script-level loop."""
        self._stub_cni(exit_code=0)
        appcontainer.exempt_installed()
        self.assertEqual(len(self._cni_calls), 2)
        for call in self._cni_calls:
            self.assertEqual(call[0], "LoopbackExempt")
            self.assertEqual(call[1], "-a")
        pfns_called = {c[2].split("=", 1)[1] for c in self._cni_calls}
        self.assertEqual(pfns_called, {
            "Microsoft.WindowsStore_8wekyb3d8bbwe", "Microsoft.XboxApp_8wekyb3d8bbwe"})

    def test_no_installed_packages_is_a_noop(self):
        appcontainer._installed_package_family_names = lambda: []
        appcontainer.exempt_installed()
        self.assertIsNone(appcontainer._read_backup())

    def test_existing_backup_is_kept_as_true_original(self):
        """Second call (e.g. the periodic re-sweep) must NOT re-snapshot over a
        backup left by a prior crashed/incomplete run."""
        appcontainer._write_backup(["already.exempt_abc"])
        self._stub_cni(exit_code=0)
        appcontainer.exempt_installed()
        self.assertEqual(appcontainer._read_backup(), ["already.exempt_abc"])

    def test_failed_add_does_not_count_as_added(self):
        """A real failure (e.g. non-elevation) surfaces as a non-zero exit code
        — confirmed against the real tool — and must not be counted as added."""
        self._stub_cni(exit_code=5)   # the exact code observed for Access Denied
        added, total = appcontainer.exempt_installed()
        self.assertEqual(added, 0)
        self.assertEqual(total, 2)


class RestoreTests(unittest.TestCase):
    """restore() must revoke only packages exempt now but absent from the
    pre-takeover snapshot — never an exemption the user granted themselves —
    must be a no-op when no backup exists, and — like exempt_installed() —
    must issue one _checknetisolation call per package to delete, not a
    batched script with an internal -d loop."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_dir = appcontainer._data_dir
        self._orig_ps = appcontainer._ps
        self._orig_cni = appcontainer._checknetisolation
        appcontainer._data_dir = lambda: self._tmp
        self._cni_calls = []

    def tearDown(self):
        appcontainer._data_dir = self._orig_dir
        appcontainer._ps = self._orig_ps
        appcontainer._checknetisolation = self._orig_cni

    def _stub_cni(self):
        def fake(*args, timeout=15):
            self._cni_calls.append(args)
            return (0, "OK.")
        appcontainer._checknetisolation = fake

    def test_no_backup_is_a_noop(self):
        self.assertFalse(appcontainer.restore())
        self.assertEqual(self._cni_calls, [])

    def test_revokes_only_what_was_added_and_clears_backup(self):
        appcontainer._write_backup(["preexisting.app_abc"])
        # current state: the pre-existing entry PLUS the one we added
        appcontainer._ps = lambda *a, **k: (
            "Name: preexisting.app_abc\nName: microsoft.windowsstore_8wekyb3d8bbwe\nOK.")
        self._stub_cni()

        self.assertTrue(appcontainer.restore())
        self.assertEqual(len(self._cni_calls), 1)
        call = self._cni_calls[0]
        self.assertEqual(call[:2], ("LoopbackExempt", "-d"))
        self.assertIn("microsoft.windowsstore_8wekyb3d8bbwe", call[2])
        self.assertNotIn("preexisting.app_abc", call[2])
        self.assertIsNone(appcontainer._read_backup())

    def test_nothing_added_skips_delete_but_still_clears_backup(self):
        appcontainer._write_backup(["preexisting.app_abc"])
        appcontainer._ps = lambda *a, **k: "Name: preexisting.app_abc\nOK."
        self._stub_cni()
        self.assertTrue(appcontainer.restore())
        self.assertEqual(self._cni_calls, [])
        self.assertIsNone(appcontainer._read_backup())


class ReadOnlyReadersTests(unittest.TestCase):
    """current_state()/is_exempt() only READ — safe to call live."""

    def test_current_state_returns_string(self):
        self.assertIsInstance(appcontainer.current_state(), str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
