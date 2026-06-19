"""Tests for the self-update pipeline: version precedence, channel selection,
and signature/checksum verification (the security-critical path)."""

import os
import sys
import base64
import hashlib
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import updater, _ed25519


class TestVersionCompare(unittest.TestCase):
    def test_precedence(self):
        gt = updater.version_gt
        self.assertTrue(gt("v2.1.11", "2.1.10"))
        self.assertTrue(gt("v2.2.0", "v2.1.99"))
        self.assertTrue(gt("v2.1.11-beta.1", "2.1.10"))      # newer core beats final
        self.assertTrue(gt("v2.1.11", "v2.1.11-beta.1"))      # final beats its pre-release
        self.assertTrue(gt("v2.1.11-beta.2", "v2.1.11-beta.1"))
        self.assertTrue(gt("v2.1.11-beta.10", "v2.1.11-beta.2"))  # numeric, not lexical
        self.assertFalse(gt("v2.1.10", "v2.1.10"))
        self.assertFalse(gt("v2.1.9", "v2.1.10"))
        self.assertFalse(gt("v2.1.11-beta.1", "v2.1.11"))


def _release(tag, prerelease, draft=False):
    """A GitHub release JSON with the three signed assets the updater requires."""
    zip_name = f"ProxyForce-{tag}-win64.zip"
    base = f"https://example/dl/{tag}/"
    return {
        "tag_name": tag, "prerelease": prerelease, "draft": draft,
        "assets": [
            {"name": zip_name, "browser_download_url": base + zip_name},
            {"name": "SHA256SUMS", "browser_download_url": base + "SHA256SUMS"},
            {"name": zip_name + ".sig", "browser_download_url": base + zip_name + ".sig"},
        ],
    }


class TestChannelSelection(unittest.TestCase):
    def setUp(self):
        self._orig = updater.APP_VERSION
        updater.APP_VERSION = "2.1.10"
        self._stable = _release("v2.1.10", False)         # == current
        self._newstable = _release("v2.1.11", False)
        self._beta = _release("v2.1.12-beta.1", True)
        self._draft = _release("v2.1.13", False, draft=True)

    def tearDown(self):
        updater.APP_VERSION = self._orig
        updater._api_get = self._real_api_get if hasattr(self, "_real_api_get") else updater._api_get

    def _patch(self, latest, listing):
        self._real_api_get = updater._api_get

        def fake(opener, url):
            return latest if url.endswith("/releases/latest") else listing
        updater._api_get = fake

    def test_stable_channel_ignores_prerelease(self):
        # /releases/latest returns the newest non-prerelease.
        self._patch(self._newstable, [self._beta, self._newstable, self._stable])
        info = updater.check_latest({"update_channel": "stable", "host": "p", "port": 1})
        self.assertIsNotNone(info)
        self.assertEqual(info.tag, "v2.1.11")
        self.assertFalse(info.prerelease)

    def test_dev_channel_takes_newest_including_prerelease(self):
        self._patch(self._newstable, [self._beta, self._newstable, self._stable, self._draft])
        info = updater.check_latest({"update_channel": "dev", "host": "p", "port": 1})
        self.assertIsNotNone(info)
        self.assertEqual(info.tag, "v2.1.12-beta.1")   # beta is newest; draft excluded

    def test_no_update_when_not_newer(self):
        self._patch(self._stable, [self._stable])
        info = updater.check_latest({"update_channel": "stable", "host": "p", "port": 1})
        self.assertIsNone(info)


class TestVerify(unittest.TestCase):
    def setUp(self):
        self._orig_pub = updater.RELEASE_PUBKEY_B64
        self._seed = os.urandom(32)
        updater.RELEASE_PUBKEY_B64 = base64.b64encode(
            _ed25519.publickey(self._seed)).decode()
        self._dir = tempfile.mkdtemp(prefix="pf_upd_")
        self._tag = "v9.9.9"
        self._info = updater.UpdateInfo(
            self._tag, True, "z", "s", "g")
        # Fake "zip", its SHA256SUMS line, and a real signature over SHA256SUMS.
        self._zip = os.path.join(self._dir, self._info.zip_name)
        with open(self._zip, "wb") as f:
            f.write(b"pretend-this-is-a-onedir-zip" * 100)
        with open(self._zip, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        self._sums = os.path.join(self._dir, "SHA256SUMS")
        with open(self._sums, "wb") as f:
            f.write(f"{digest}  {self._info.zip_name}\n".encode())
        with open(self._sums, "rb") as f:
            sig = _ed25519.sign(self._seed, f.read())
        self._sig = os.path.join(self._dir, self._info.sig_name)
        with open(self._sig, "wb") as f:
            f.write(sig)

    def tearDown(self):
        updater.RELEASE_PUBKEY_B64 = self._orig_pub

    def test_valid_bundle_passes(self):
        self.assertTrue(updater.verify(self._info, self._dir))

    def test_tampered_zip_fails(self):
        with open(self._zip, "ab") as f:
            f.write(b"malware")
        self.assertFalse(updater.verify(self._info, self._dir))

    def test_bad_signature_fails(self):
        with open(self._sig, "r+b") as f:
            data = bytearray(f.read())
            data[0] ^= 0xFF
            f.seek(0)
            f.write(data)
        self.assertFalse(updater.verify(self._info, self._dir))

    def test_wrong_key_fails(self):
        updater.RELEASE_PUBKEY_B64 = base64.b64encode(
            _ed25519.publickey(os.urandom(32))).decode()
        self.assertFalse(updater.verify(self._info, self._dir))

    def test_empty_key_fails_closed(self):
        updater.RELEASE_PUBKEY_B64 = ""
        self.assertFalse(updater.verify(self._info, self._dir))


class _FakeProc:
    def __init__(self, alive=True):
        self._alive = alive

    def poll(self):
        return None if self._alive else 1


class TestApplySwap(unittest.TestCase):
    """Exercise the install swap + rollback with a stubbed relaunch (no real exe)."""

    def setUp(self):
        self._root = tempfile.mkdtemp(prefix="pf_swap_")
        self._install = os.path.join(self._root, "ProxyForce")
        self._staged = os.path.join(self._root, "staged")
        for d, marker in ((self._install, b"OLD"), (self._staged, b"NEW")):
            os.makedirs(os.path.join(d, "_internal"))
            with open(os.path.join(d, "ProxyForce.exe"), "wb") as f:
                f.write(b"MZ")
            with open(os.path.join(d, "_internal", "version.txt"), "wb") as f:
                f.write(marker)
        self._real_spawn = updater._spawn
        self._real_checks = updater._HEALTH_CHECKS
        self._real_interval = updater._HEALTH_INTERVAL
        # Keep _applog() out of the REAL %ProgramData%\ProxyForce\update\apply.log:
        # _apply_swap logs via update_dir(), so without this the test pollutes live
        # state and its "did not stay up" line looks like a real failed auto-update.
        self._real_update_dir = updater.update_dir
        updater.update_dir = lambda: self._root
        updater._HEALTH_CHECKS = 2
        updater._HEALTH_INTERVAL = 0.01

    def tearDown(self):
        updater._spawn = self._real_spawn
        updater.update_dir = self._real_update_dir
        updater._HEALTH_CHECKS = self._real_checks
        updater._HEALTH_INTERVAL = self._real_interval

    def _marker(self):
        with open(os.path.join(self._install, "_internal", "version.txt"), "rb") as f:
            return f.read()

    def test_healthy_swap_commits(self):
        updater._spawn = lambda exe, relaunch: _FakeProc(alive=True)
        ok = updater._apply_swap(self._staged, self._install, "--minimized")
        self.assertTrue(ok)
        self.assertEqual(self._marker(), b"NEW")                       # new build installed
        self.assertFalse(os.path.isdir(self._install + ".old"))        # backup cleaned

    def test_dead_new_build_rolls_back(self):
        updater._spawn = lambda exe, relaunch: _FakeProc(alive=False)  # new build dies
        ok = updater._apply_swap(self._staged, self._install, "--minimized")
        self.assertFalse(ok)
        self.assertEqual(self._marker(), b"OLD")                       # rolled back


class TestArgParse(unittest.TestCase):
    def test_apply_kv(self):
        kv = updater._parse_kv(
            ["--apply-update", "--target", r"C:\Tools\ProxyForce", "--wait-pid", "1234"])
        self.assertEqual(kv["target"], r"C:\Tools\ProxyForce")
        self.assertEqual(kv["wait-pid"], "1234")


if __name__ == "__main__":
    unittest.main()
