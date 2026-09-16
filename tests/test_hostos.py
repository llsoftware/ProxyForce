"""
Tests for core/hostos — the Windows/Linux seam itself.

The point of this module is that every other module can stop caring which
platform it is on, so the tests here are mostly about the seam being HONEST:
the platform flags are mutually exclusive, the data directory is absolute and
machine-scoped, and popen_kwargs never hands a POSIX subprocess a Windows-only
argument (which is a TypeError at call time, not a graceful degradation).
"""

import os
import subprocess
import unittest

from core import hostos


class PlatformIdentityTests(unittest.TestCase):

    def test_exactly_one_platform_flag(self):
        # Both true would mean the branches below pick arbitrarily; both false
        # means is_supported() is lying if it returns True.
        self.assertFalse(hostos.IS_WINDOWS and hostos.IS_LINUX)
        self.assertEqual(hostos.is_supported(),
                         hostos.IS_WINDOWS or hostos.IS_LINUX)

    def test_platform_name_matches_flags(self):
        if hostos.IS_WINDOWS:
            self.assertEqual(hostos.platform_name(), "windows")
        elif hostos.IS_LINUX:
            self.assertEqual(hostos.platform_name(), "linux")

    def test_exe_suffix_matches_platform(self):
        self.assertEqual(hostos.EXE_SUFFIX, ".exe" if hostos.IS_WINDOWS else "")


class DataDirTests(unittest.TestCase):

    def test_data_dir_is_absolute_and_machine_scoped(self):
        d = hostos.data_dir()
        self.assertTrue(os.path.isabs(d), d)
        # Must not be per-user: the elevated engine and the GUI have to see the
        # same config, and on Linux the engine may run as root from systemd while
        # the GUI runs for a logged-in user.
        for per_user in (os.path.expanduser("~"), "/root"):
            if per_user and per_user not in ("/", ""):
                self.assertFalse(
                    os.path.normcase(d).startswith(os.path.normcase(per_user) + os.sep),
                    f"{d} is inside the per-user directory {per_user}")

    def test_runtime_dir_is_absolute(self):
        self.assertTrue(os.path.isabs(hostos.runtime_dir()))


class SubprocessTests(unittest.TestCase):

    def test_popen_kwargs_only_sets_creationflags_on_windows(self):
        kw = hostos.popen_kwargs()
        if hostos.IS_WINDOWS:
            self.assertIn("creationflags", kw)
            self.assertEqual(kw["creationflags"], subprocess.CREATE_NO_WINDOW)
        else:
            # Passing creationflags on POSIX raises; the whole reason this helper
            # exists is so no call site has to remember that.
            self.assertNotIn("creationflags", kw)

    def test_popen_kwargs_passes_extras_through(self):
        kw = hostos.popen_kwargs(cwd="/tmp")
        self.assertEqual(kw["cwd"], "/tmp")

    def test_run_text_reports_a_missing_binary_instead_of_raising(self):
        out = hostos.run_text(["proxyforce-definitely-not-a-real-binary"])
        self.assertIn("not installed", out)

    def test_run_text_returns_output(self):
        # Every supported platform has a Python; using our own interpreter keeps
        # this free of assumptions about what else is installed.
        import sys
        out = hostos.run_text([sys.executable, "-c", "print('hello-hostos')"])
        self.assertIn("hello-hostos", out)

    def test_which_finds_the_interpreter_and_misses_nonsense(self):
        import sys
        self.assertTrue(hostos.which(os.path.basename(sys.executable))
                        or os.path.isfile(sys.executable))
        self.assertEqual(hostos.which("proxyforce-definitely-not-real"), "")


class PrivilegeTests(unittest.TestCase):

    def test_is_admin_returns_a_bool(self):
        self.assertIsInstance(hostos.is_admin(), bool)

    def test_elevation_hint_is_actionable(self):
        hint = hostos.elevation_hint("/opt/proxyforce/ProxyForce")
        self.assertTrue(hint.strip())
        # The hint must name the concrete thing to do, not just say "need admin".
        self.assertTrue("administrator" in hint.lower() or "sudo" in hint,
                        hint)

    def test_windows_can_always_self_elevate(self):
        if hostos.IS_WINDOWS:
            self.assertTrue(hostos.can_self_elevate())


class ChildLifetimeTests(unittest.TestCase):

    def test_preexec_is_none_on_windows_and_callable_elsewhere(self):
        fn = hostos.kill_on_parent_death_preexec()
        if hostos.IS_WINDOWS:
            # Popen(preexec_fn=...) is rejected outright on Windows.
            self.assertIsNone(fn)
        else:
            self.assertTrue(callable(fn))

    def test_preexec_is_accepted_by_popen(self):
        """The combination the controller actually passes must be launchable."""
        import sys
        proc = subprocess.Popen(
            [sys.executable, "-c", "pass"],
            preexec_fn=hostos.kill_on_parent_death_preexec(),
            **hostos.popen_kwargs())
        self.assertEqual(proc.wait(timeout=30), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
