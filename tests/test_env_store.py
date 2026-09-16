"""
Tests for core/env_store — persistent environment variables across platforms.

The Linux file backend is exercised on EVERY platform, by pointing the module's
path constants at a temp tree. That is deliberate: the file-rewriting logic is
where the real risk lives (it edits /etc/environment, a file that belongs to the
system and holds unrelated variables), and it must not go untested just because
development happens on Windows.

What the rewrite has to guarantee, and what these tests pin down:
  * a variable we do not manage is never dropped, reordered, or reformatted
  * comments survive
  * setting a variable that is already present edits that line in place
  * clearing a variable removes the line rather than writing an empty value —
    an empty NO_PROXY is the exact thing that trips Python's
    getproxies_environment() truthiness trap (see core/env_proxy)
"""

import os
import shutil
import tempfile
import unittest

from core import env_store, hostos


ETC_ENVIRONMENT_SAMPLE = """\
# This file is managed by the distribution.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EDITOR=vim

LANG=en_US.UTF-8
"""


class EnvFileParsingTests(unittest.TestCase):
    """_parse_env_file has to cope with what real /etc/environment files hold."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "environment")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, text):
        with open(self.path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    def test_parses_plain_quoted_and_exported_forms(self):
        self._write('A=1\nB="two"\nexport C=three\n')
        vals = env_store._parse_env_file(self.path)
        self.assertEqual(vals, {"A": "1", "B": "two", "C": "three"})

    def test_ignores_comments_and_blank_lines(self):
        self._write("# comment\n\n   \nA=1\n")
        self.assertEqual(env_store._parse_env_file(self.path), {"A": "1"})

    def test_missing_file_is_empty_not_an_error(self):
        self.assertEqual(env_store._parse_env_file(self.path + ".nope"), {})

    def test_value_containing_an_equals_sign_survives(self):
        # A proxy URL with credentials, or a NO_PROXY list, can contain '='.
        self._write("NO_PROXY=a=b,c\n")
        self.assertEqual(env_store._parse_env_file(self.path)["NO_PROXY"], "a=b,c")


class EnvFileRewriteTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "environment")
        with open(self.path, "w", encoding="utf-8", newline="\n") as f:
            f.write(ETC_ENVIRONMENT_SAMPLE)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _read(self):
        with open(self.path, encoding="utf-8") as f:
            return f.read()

    def test_unrelated_variables_and_comments_survive(self):
        env_store._rewrite_env_file(self.path, {"HTTP_PROXY": "http://127.0.0.1:18081"})
        out = self._read()
        self.assertIn("# This file is managed by the distribution.", out)
        self.assertIn('PATH="/usr/local/sbin', out)
        self.assertIn("EDITOR=vim", out)
        self.assertIn("LANG=en_US.UTF-8", out)
        self.assertIn('HTTP_PROXY="http://127.0.0.1:18081"', out)

    def test_existing_variable_is_edited_in_place_not_duplicated(self):
        env_store._rewrite_env_file(self.path, {"EDITOR": "nano"})
        out = self._read()
        self.assertEqual(out.count("EDITOR="), 1)
        self.assertIn('EDITOR="nano"', out)

    def test_clearing_a_variable_removes_the_line(self):
        env_store._rewrite_env_file(self.path, {"EDITOR": None})
        out = self._read()
        self.assertNotIn("EDITOR", out)
        # An empty assignment would still be "set" to a reader — that is the bug
        # this behaviour exists to avoid.
        self.assertNotIn("EDITOR=\n", out)
        self.assertNotIn('EDITOR=""', out)

    def test_empty_string_is_treated_as_a_delete(self):
        env_store._rewrite_env_file(self.path, {"EDITOR": ""})
        self.assertNotIn("EDITOR", self._read())

    def test_export_prefix_is_applied_when_asked(self):
        env_store._rewrite_env_file(self.path, {"HTTP_PROXY": "x"}, export=True)
        self.assertIn('export HTTP_PROXY="x"', self._read())

    def test_roundtrip_set_then_restore_leaves_the_file_equivalent(self):
        before = env_store._parse_env_file(self.path)
        env_store._rewrite_env_file(self.path, {"HTTP_PROXY": "http://127.0.0.1:1"})
        env_store._rewrite_env_file(self.path, {"HTTP_PROXY": None})
        after = env_store._parse_env_file(self.path)
        self.assertEqual(before, after)


class LinuxBackendTests(unittest.TestCase):
    """The machine-scope read/write pair, driven against a temp tree so it runs
    on any platform."""

    NAMES = ("HTTP_PROXY", "http_proxy", "NO_PROXY")

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig_env = env_store._LINUX_ETC_ENVIRONMENT
        self._orig_profile = env_store._LINUX_PROFILE_D
        env_store._LINUX_ETC_ENVIRONMENT = os.path.join(self.tmp, "environment")
        env_store._LINUX_PROFILE_D = os.path.join(self.tmp, "profile.d", "proxyforce.sh")
        with open(env_store._LINUX_ETC_ENVIRONMENT, "w", encoding="utf-8",
                  newline="\n") as f:
            f.write(ETC_ENVIRONMENT_SAMPLE)

    def tearDown(self):
        env_store._LINUX_ETC_ENVIRONMENT = self._orig_env
        env_store._LINUX_PROFILE_D = self._orig_profile
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_read_reports_unset_as_none(self):
        entry = env_store._linux_read("machine", self.NAMES)
        self.assertEqual(set(entry), set(self.NAMES))
        self.assertTrue(all(v is None for v in entry.values()))

    def test_write_then_read_roundtrips_with_the_windows_value_shape(self):
        env_store._linux_write("machine", {"HTTP_PROXY": "http://127.0.0.1:18081"})
        entry = env_store._linux_read("machine", self.NAMES)
        # [value, type] — the same shape winreg produces, so the backup JSON and
        # the restore code are identical on both platforms.
        self.assertEqual(entry["HTTP_PROXY"],
                         ["http://127.0.0.1:18081", env_store.TYPE_STRING])
        self.assertIsNone(entry["NO_PROXY"])

    def test_profile_d_mirror_is_written_and_removed_with_the_values(self):
        env_store._linux_write("machine", {"HTTP_PROXY": "http://127.0.0.1:18081"})
        self.assertTrue(os.path.isfile(env_store._LINUX_PROFILE_D))
        body = open(env_store._LINUX_PROFILE_D, encoding="utf-8").read()
        # /etc/environment is read only by PAM; the tools this exists for are run
        # from non-login shells, which read profile.d instead.
        self.assertIn('export HTTP_PROXY="http://127.0.0.1:18081"', body)

        env_store._linux_write("machine", {"HTTP_PROXY": None})
        self.assertFalse(os.path.isfile(env_store._LINUX_PROFILE_D),
                         "the mirror must not outlive the values it exports")

    def test_write_accepts_the_value_type_pair_form_used_by_restore(self):
        env_store._linux_write("machine", {"HTTP_PROXY": ["http://x:1",
                                                          env_store.TYPE_STRING]})
        entry = env_store._linux_read("machine", ("HTTP_PROXY",))
        self.assertEqual(entry["HTTP_PROXY"][0], "http://x:1")


class DescribeTests(unittest.TestCase):

    NAMES = ("HTTP_PROXY", "NO_PROXY")

    def test_describe_lists_only_non_empty_values(self):
        snap = {
            "user": {"HTTP_PROXY": ["http://a:1", 1], "NO_PROXY": None},
            "machine": {"HTTP_PROXY": None, "NO_PROXY": ["", 1]},
        }
        out = env_store.describe(snap, self.NAMES)
        self.assertIn("user:HTTP_PROXY=http://a:1", out)
        self.assertNotIn("NO_PROXY", out)

    def test_describe_of_an_empty_snapshot_is_empty(self):
        self.assertEqual(env_store.describe({}, self.NAMES), "")

    def test_storage_description_names_the_real_locations(self):
        desc = env_store.storage_description()
        if hostos.IS_WINDOWS:
            self.assertIn("HKLM", desc)
            self.assertIn("HKCU", desc)
        else:
            self.assertIn("/etc/environment", desc)


class PublicApiShapeTests(unittest.TestCase):
    """snapshot() must cover both scopes whatever the platform, because a
    per-user value overrides a machine one in a process's merged environment."""

    def test_snapshot_covers_every_scope(self):
        snap = env_store.snapshot(("HTTP_PROXY",))
        self.assertEqual(set(snap), set(env_store.SCOPES))
        for scope in env_store.SCOPES:
            self.assertIn("HTTP_PROXY", snap[scope])


if __name__ == "__main__":
    unittest.main(verbosity=2)
