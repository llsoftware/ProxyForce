"""Tests for the self-update pipeline: version precedence, channel selection,
and signature/checksum verification (the security-critical path)."""

import os
import sys
import time
import base64
import hashlib
import tempfile
import threading
import unittest
import json
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import updater, _ed25519


class TestEd25519Vectors(unittest.TestCase):
    def test_rfc8032_empty_message_vector(self):
        public_key = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertTrue(_ed25519.verify(public_key, b"", signature))

    def test_identity_public_key_is_rejected(self):
        self.assertFalse(_ed25519.verify(b"\x01" + b"\x00" * 31, b"x", b"\x00" * 64))


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

    def test_manifest_filename_must_match_exactly(self):
        with open(self._sums, "rb") as f:
            line = f.read().decode().replace(self._info.zip_name, "prefix-" + self._info.zip_name)
        with open(self._sums, "wb") as f:
            f.write(line.encode())
        with open(self._sums, "rb") as f:
            sig = _ed25519.sign(self._seed, f.read())
        with open(self._sig, "wb") as f:
            f.write(sig)
        self.assertFalse(updater.verify(self._info, self._dir))

    def test_noncanonical_s_is_rejected(self):
        with open(self._sig, "rb") as f:
            sig = f.read()
        s = int.from_bytes(sig[32:], "little") + _ed25519._l
        if s < 2 ** 256:
            with open(self._sig, "wb") as f:
                f.write(sig[:32] + s.to_bytes(32, "little"))
            self.assertFalse(updater.verify(self._info, self._dir))


class TestSafeExtraction(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pf_extract_")
        self.real_update_dir = updater.update_dir
        self.real_harden = updater._harden_acl
        updater.update_dir = lambda: self.root
        updater._harden_acl = lambda _p: None
        self.info = updater.UpdateInfo("v9.9.9", True, "", "", "")
        self.ddir = os.path.join(self.root, "a" * 32)
        os.mkdir(self.ddir)

    def tearDown(self):
        updater.update_dir = self.real_update_dir
        updater._harden_acl = self.real_harden

    def _zip(self, entries):
        path = os.path.join(self.ddir, self.info.zip_name)
        with zipfile.ZipFile(path, "w") as z:
            for name, data in entries:
                z.writestr(name, data)

    def test_expected_layout_extracts(self):
        self._zip([("ProxyForce.exe", b"MZ"), ("_internal/version.txt", b"x")])
        staged = updater.stage(self.info, self.ddir)
        self.assertTrue(os.path.isfile(os.path.join(staged, "ProxyForce.exe")))

    def test_traversal_is_rejected(self):
        self._zip([("ProxyForce.exe", b"MZ"), ("_internal/x", b"x"), ("../evil", b"x")])
        with self.assertRaises(ValueError):
            updater.stage(self.info, self.ddir)

    def test_case_colliding_names_are_rejected(self):
        self._zip([("ProxyForce.exe", b"MZ"), ("proxyforce.EXE", b"MZ"),
                   ("_internal/x", b"x")])
        with self.assertRaises(ValueError):
            updater.stage(self.info, self.ddir)

    def test_apply_transaction_token_and_target_are_bound(self):
        staged = os.path.join(self.ddir, "staged")
        os.mkdir(staged)
        token = "b" * 64
        target = os.path.join(self.root, "install")
        with open(os.path.join(self.ddir, "transaction.json"), "w") as f:
            json.dump({"apply_token": token, "target": os.path.abspath(target)}, f)
        self.assertTrue(updater._validate_apply_transaction(staged, target, token))
        self.assertFalse(updater._validate_apply_transaction(staged, target, "c" * 64))
        self.assertFalse(updater._validate_apply_transaction(staged, target + "-other", token))


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
            os.makedirs(os.path.join(d, "_internal", "singbox"))
            with open(os.path.join(d, "ProxyForce.exe"), "wb") as f:
                f.write(b"MZ")
            with open(os.path.join(d, "_internal", "version.txt"), "wb") as f:
                f.write(marker)
            with open(os.path.join(d, "_internal", "singbox", "sing-box.exe"), "wb") as f:
                f.write(b"MZ")
        self._real_spawn = updater._spawn
        self._real_checks = updater._HEALTH_CHECKS
        self._real_interval = updater._HEALTH_INTERVAL
        self._real_started_timeout = updater._STARTED_TIMEOUT
        self._real_ready_timeout = updater._READY_TIMEOUT
        self._real_record = updater._record_apply_result
        # Keep _applog() out of the REAL %ProgramData%\ProxyForce\update\apply.log:
        # _apply_swap logs via update_dir(), so without this the test pollutes live
        # state and its "did not stay up" line looks like a real failed auto-update.
        self._real_update_dir = updater.update_dir
        updater.update_dir = lambda: self._root
        updater._HEALTH_CHECKS = 2
        updater._HEALTH_INTERVAL = 0.01
        updater._STARTED_TIMEOUT = 0.05
        updater._READY_TIMEOUT = 0.05
        # _apply_swap itself doesn't call _record_apply_result (only apply_worker
        # does), so this is inert for these tests unless a test calls it directly.
        updater._record_apply_result = lambda *_a, **_k: None

    def tearDown(self):
        updater._spawn = self._real_spawn
        updater.update_dir = self._real_update_dir
        updater._HEALTH_CHECKS = self._real_checks
        updater._HEALTH_INTERVAL = self._real_interval
        updater._STARTED_TIMEOUT = self._real_started_timeout
        updater._READY_TIMEOUT = self._real_ready_timeout
        updater._record_apply_result = self._real_record

    def _marker(self):
        with open(os.path.join(self._install, "_internal", "version.txt"), "rb") as f:
            return f.read()

    def test_healthy_swap_commits(self):
        # Write "ready" as a side effect of the (fake) relaunch itself, not before
        # _apply_swap runs — _apply_swap clears stale started/ready markers from
        # any earlier attempt on the same transaction right before spawning, so a
        # marker written before that point wouldn't reflect THIS relaunch anyway.
        ready_path = os.path.join(self._root, "ready")

        def fake_spawn(exe, relaunch):
            with open(ready_path, "w") as f:
                f.write("ok")
            return _FakeProc(alive=True)

        updater._spawn = fake_spawn
        ok = updater._apply_swap(self._staged, self._install, "--minimized")
        self.assertTrue(ok)
        self.assertEqual(self._marker(), b"NEW")                       # new build installed
        self.assertFalse(os.path.isdir(self._install + ".old"))        # backup cleaned

    def test_dead_new_build_rolls_back(self):
        updater._spawn = lambda exe, relaunch: _FakeProc(alive=False)  # new build dies
        ok = updater._apply_swap(self._staged, self._install, "--minimized")
        self.assertFalse(ok)
        self.assertEqual(self._marker(), b"OLD")                       # rolled back

    def test_marker_written_late_still_commits(self):
        """Regression for the reported "installs, then relaunches the OLD build"
        bug: a new process that is merely SLOW to write "ready" (antivirus
        first-scan of a freshly-written onedir build, cold CustomTkinter import,
        icacls calls before hardening was memoized) must not be rolled back just
        because it missed a fixed few-second window. Only actually dying, or
        never even proving it started, should roll back."""
        updater._STARTED_TIMEOUT = 5.0
        updater._READY_TIMEOUT = 5.0
        updater._spawn = lambda exe, relaunch: _FakeProc(alive=True)
        ready_path = os.path.join(self._root, "ready")

        def write_ready_late():
            time.sleep(0.2)
            with open(ready_path, "w") as f:
                f.write("ok")

        threading.Thread(target=write_ready_late, daemon=True).start()
        ok = updater._apply_swap(self._staged, self._install, "--minimized")
        self.assertTrue(ok)
        self.assertEqual(self._marker(), b"NEW")

    def test_wedged_before_started_rolls_back_promptly(self):
        """A build that's alive but never even proves it reached main() (no
        "started" marker) is wedged, not just slow — the health check must
        report that specifically (started_timeout) at the SHORT started
        deadline, rather than silently waiting out the full ready budget.
        Exercises _await_new_build_health directly to avoid the real
        _free_install_dir subprocess calls a full rollback would trigger."""
        updater._STARTED_TIMEOUT = 0.05
        updater._READY_TIMEOUT = 5.0
        reason = updater._await_new_build_health(_FakeProc(alive=True), self._root)
        self.assertEqual(reason, "started_timeout")

    def test_partial_copy_missing_other_file_rolls_back(self):
        """Regression: the original completeness check verified exactly ONE file
        (sing-box.exe). Any other file lost to the same AV-lock/quarantine problem
        (a .pyd, a DLL) used to sail through as "swap ok". _verify_tree must catch
        ANY missing/mismatched file, not just that one, even when copytree itself
        raises no exception."""
        rel = os.path.join("_internal", "engine_helper.pyd")
        for d in (self._install, self._staged):
            with open(os.path.join(d, rel), "wb") as f:
                f.write(b"PYD-DATA")

        real_copytree = updater.shutil.copytree
        real_copy2 = updater.shutil.copy2

        def flaky_copytree(src, dst, **kwargs):
            real_copytree(src, dst, **kwargs)
            os.remove(os.path.join(dst, rel))          # AV quarantines it post-copy

        def blocked_copy2(src, dst, *a, **k):
            if os.path.basename(src) == "engine_helper.pyd":
                raise PermissionError("simulated persistent AV lock")
            return real_copy2(src, dst, *a, **k)

        updater.shutil.copytree = flaky_copytree
        updater.shutil.copy2 = blocked_copy2
        updater._spawn = lambda exe, relaunch: _FakeProc(alive=True)
        real_sleep = time.sleep
        time.sleep = lambda *_a, **_k: None
        try:
            ok = updater._apply_swap(self._staged, self._install, "--minimized")
        finally:
            updater.shutil.copytree = real_copytree
            updater.shutil.copy2 = real_copy2
            time.sleep = real_sleep
        self.assertFalse(ok)
        self.assertEqual(self._marker(), b"OLD")

    def test_partial_copy_missing_singbox_rolls_back(self):
        """Regression: a copytree that raises AFTER copying most files (e.g. AV
        real-time scanning locks/quarantines the freshly-written sing-box.exe) must
        not be mistaken for "nothing to roll back" just because `target` exists —
        it exists, just incomplete, and must still be discarded in favor of .old."""
        real_copytree = updater.shutil.copytree

        def flaky_copytree(src, dst, **kwargs):
            real_copytree(src, dst, **kwargs)
            os.remove(os.path.join(dst, "_internal", "singbox", "sing-box.exe"))
            raise PermissionError("simulated AV lock on sing-box.exe")

        updater.shutil.copytree = flaky_copytree
        updater._spawn = lambda exe, relaunch: _FakeProc(alive=True)
        real_sleep = time.sleep
        time.sleep = lambda *_a, **_k: None   # skip _retry's real delay
        try:
            ok = updater._apply_swap(self._staged, self._install, "--minimized")
        finally:
            updater.shutil.copytree = real_copytree
            time.sleep = real_sleep
        self.assertFalse(ok)
        self.assertEqual(self._marker(), b"OLD")                       # rolled back
        self.assertTrue(os.path.isfile(
            os.path.join(self._install, "_internal", "singbox", "sing-box.exe")))
        self.assertFalse(os.path.isdir(self._install + ".old"))        # backup consumed

    def test_rollback_retries_through_transient_lock(self):
        """Regression: the broken build we just relaunched may still be holding a
        lock under `target` (e.g. its own auto-started sing-box.exe) by the moment
        the health check fails and rollback tries to rename .old back into place.
        A single unretried rename must not be treated as "rollback done" — it has
        to free the dir and retry, recovering once the lock clears."""
        updater._spawn = lambda exe, relaunch: _FakeProc(alive=False)  # triggers rollback
        backup_path = self._install + ".old"
        real_rename = os.rename
        attempts = {"n": 0}

        def flaky_rename(src, dst):
            if (os.path.abspath(src) == os.path.abspath(backup_path)
                    and os.path.abspath(dst) == os.path.abspath(self._install)):
                attempts["n"] += 1
                if attempts["n"] < 3:
                    raise PermissionError("simulated lock on target during rollback")
            real_rename(src, dst)

        real_free = updater._free_install_dir
        updater._free_install_dir = lambda target, timeout=30.0: True  # no real taskkill/powershell
        os.rename = flaky_rename
        real_sleep = time.sleep
        time.sleep = lambda *_a, **_k: None
        try:
            ok = updater._apply_swap(self._staged, self._install, "--minimized")
        finally:
            os.rename = real_rename
            time.sleep = real_sleep
            updater._free_install_dir = real_free
        self.assertFalse(ok)
        self.assertGreaterEqual(attempts["n"], 3)
        self.assertEqual(self._marker(), b"OLD")                       # rolled back
        self.assertFalse(os.path.isdir(backup_path))                   # backup consumed

    def test_rollback_falls_back_to_file_copy_when_rename_never_succeeds(self):
        """Regression: if the rename onto `target` never succeeds (a handle that
        never releases), the rollback must still restore the old build file-by-file
        rather than silently leaving `target` half-deleted and `backup` orphaned —
        the exact bug reported in production (missing sing-box/interpreter files in
        the "current" install plus a leftover .old folder)."""
        updater._spawn = lambda exe, relaunch: _FakeProc(alive=False)  # triggers rollback
        backup_path = self._install + ".old"
        real_rename = os.rename

        def always_fails(src, dst):
            if (os.path.abspath(src) == os.path.abspath(backup_path)
                    and os.path.abspath(dst) == os.path.abspath(self._install)):
                raise PermissionError("simulated permanent lock on target")
            real_rename(src, dst)

        real_free = updater._free_install_dir
        updater._free_install_dir = lambda target, timeout=30.0: True  # no real taskkill/powershell
        os.rename = always_fails
        real_sleep = time.sleep
        time.sleep = lambda *_a, **_k: None
        try:
            ok = updater._apply_swap(self._staged, self._install, "--minimized")
        finally:
            os.rename = real_rename
            time.sleep = real_sleep
            updater._free_install_dir = real_free
        self.assertFalse(ok)
        # Rename never worked, but the file-level fallback still restored the old
        # build's contents and cleaned up the now-redundant backup.
        self.assertEqual(self._marker(), b"OLD")
        self.assertTrue(os.path.isfile(
            os.path.join(self._install, "_internal", "singbox", "sing-box.exe")))
        self.assertFalse(os.path.isdir(backup_path))


class TestArgParse(unittest.TestCase):
    def test_apply_kv(self):
        kv = updater._parse_kv(
            ["--apply-update", "--target", r"C:\Tools\ProxyForce", "--wait-pid", "1234"])
        self.assertEqual(kv["target"], r"C:\Tools\ProxyForce")
        self.assertEqual(kv["wait-pid"], "1234")


class TestApplyWorkerFreesDir(unittest.TestCase):
    """Regression: the worker must FREE the install dir (kill stragglers locking it)
    BEFORE swapping — otherwise os.rename(install -> .old) hits PermissionError(13)
    'being used by another process' and the update silently rolls back (the real
    failure observed on the box)."""

    def setUp(self):
        self._orig = (updater._wait_pid_exit, updater._free_install_dir,
                      updater._apply_swap, updater._applog,
                      updater._validate_apply_transaction, updater._record_apply_result,
                      time.sleep)
        self.calls = []
        updater._applog = lambda m: None
        updater._wait_pid_exit = lambda pid, timeout=0: self.calls.append("wait") or True
        updater._free_install_dir = lambda target, timeout=30.0: (
            self.calls.append(("free", target)) or True)
        updater._apply_swap = lambda staged, target, relaunch: (
            self.calls.append(("swap", target)) or True)
        updater._validate_apply_transaction = lambda staged, target, token: True
        # Real _record_apply_result touches %ProgramData% via save_state(); irrelevant
        # to what this test is checking (call ordering), so keep it inert.
        updater._record_apply_result = lambda *_a, **_k: None
        time.sleep = lambda *_a, **_k: None

    def tearDown(self):
        (updater._wait_pid_exit, updater._free_install_dir,
         updater._apply_swap, updater._applog,
         updater._validate_apply_transaction, updater._record_apply_result,
         time.sleep) = self._orig

    def test_frees_dir_between_wait_and_swap(self):
        updater.apply_worker(
            ["--apply-update", "--target", r"C:\X\ProxyForce", "--wait-pid", "42",
             "--apply-token", "a" * 64])
        self.assertEqual([c if isinstance(c, str) else c[0] for c in self.calls],
                         ["wait", "free", "swap"])
        self.assertEqual(self.calls[1], ("free", r"C:\X\ProxyForce"))
        self.assertEqual(self.calls[2], ("swap", r"C:\X\ProxyForce"))


class TestLegacyApplyBridge(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pf_legacy_bridge_")
        self.legacy = os.path.join(self.root, "update")
        self.secure = os.path.join(self.root, "update-v2")
        self.target = os.path.join(self.root, "install")
        self.tag = "v" + updater.APP_VERSION
        self.ddir = os.path.join(self.legacy, self.tag)
        self.staged = os.path.join(self.ddir, "staged")
        os.makedirs(self.staged)
        os.makedirs(self.target)
        with open(os.path.join(self.target, "ProxyForce.exe"), "wb") as f:
            f.write(b"MZ")

        self.info = updater.UpdateInfo(self.tag, True, "", "", "")
        zip_path = os.path.join(self.ddir, self.info.zip_name)
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("ProxyForce.exe", b"MZ")
            z.writestr("_internal/version.txt", updater.APP_VERSION.encode())
        digest = updater._sha256(zip_path)
        sums = f"{digest}  {self.info.zip_name}\n".encode()
        with open(os.path.join(self.ddir, "SHA256SUMS"), "wb") as f:
            f.write(sums)
        self.seed = os.urandom(32)
        with open(os.path.join(self.ddir, self.info.sig_name), "wb") as f:
            f.write(_ed25519.sign(self.seed, sums))
        with open(os.path.join(self.legacy, "state.json"), "w") as f:
            json.dump({"resume_proxy": True}, f)

        self.orig = (updater._legacy_update_dir, updater.update_dir, updater._harden_acl,
                     updater.RELEASE_PUBKEY_B64, updater._wait_pid_exit,
                     updater.selftest_staged, updater.begin_apply)
        updater._legacy_update_dir = lambda: self.legacy
        updater.update_dir = lambda: self.secure
        updater._harden_acl = lambda _p: None
        updater.RELEASE_PUBKEY_B64 = base64.b64encode(
            _ed25519.publickey(self.seed)).decode()
        updater._wait_pid_exit = lambda *_a, **_k: None
        updater.selftest_staged = lambda _p: True
        self.launched = []
        updater.begin_apply = lambda stage, target, pid: self.launched.append(
            (stage, target, pid))

    def tearDown(self):
        (updater._legacy_update_dir, updater.update_dir, updater._harden_acl,
         updater.RELEASE_PUBKEY_B64, updater._wait_pid_exit,
         updater.selftest_staged, updater.begin_apply) = self.orig

    def test_old_updater_invocation_is_imported_and_relaunched_securely(self):
        self.assertTrue(updater._bridge_legacy_apply(self.staged, self.target, 42))
        self.assertEqual(len(self.launched), 1)
        stage, target, _pid = self.launched[0]
        self.assertTrue(stage.startswith(self.secure + os.sep))
        self.assertEqual(target, os.path.abspath(self.target))
        state = updater.load_state()
        self.assertEqual(state["staged_tag"], self.tag)
        self.assertTrue(state["resume_proxy"])

    def test_wrong_version_is_rejected(self):
        wrong = os.path.join(self.legacy, "v0.0.1", "staged")
        os.makedirs(wrong)
        self.assertFalse(updater._bridge_legacy_apply(wrong, self.target, 42))
        self.assertFalse(self.launched)


class TestCleanupStaging(unittest.TestCase):
    """Regression: cleanup_staging(keep_txid=None) used to remove EVERY directory
    under update-v2 unconditionally — including a live transaction a just-relaunched
    instance still needs (transaction.json, started/ready markers) if state.json
    hadn't recorded that transaction_id yet. It must only sweep stale (old) dirs."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pf_cleanup_")
        self.real_update_dir = updater.update_dir
        updater.update_dir = lambda: self.root
        self.real_age = updater._STALE_TRANSACTION_AGE

    def tearDown(self):
        updater.update_dir = self.real_update_dir
        updater._STALE_TRANSACTION_AGE = self.real_age

    def _mkdir(self, name, age_seconds=0):
        path = os.path.join(self.root, name)
        os.mkdir(path)
        if age_seconds:
            old = time.time() - age_seconds
            os.utime(path, (old, old))
        return path

    def test_none_keep_txid_preserves_fresh_dir(self):
        fresh = self._mkdir("a" * 32)
        updater.cleanup_staging(keep_txid=None)
        self.assertTrue(os.path.isdir(fresh))

    def test_none_keep_txid_removes_stale_dir(self):
        updater._STALE_TRANSACTION_AGE = 1.0
        stale = self._mkdir("b" * 32, age_seconds=10)
        updater.cleanup_staging(keep_txid=None)
        self.assertFalse(os.path.isdir(stale))

    def test_explicit_keep_txid_is_always_preserved_regardless_of_age(self):
        updater._STALE_TRANSACTION_AGE = 1.0
        keep = self._mkdir("c" * 32, age_seconds=10)
        updater.cleanup_staging(keep_txid="c" * 32)
        self.assertTrue(os.path.isdir(keep))


class TestApplyAttempts(unittest.TestCase):
    """Regression: a transaction that fails to apply used to be re-offered forever
    with no attempt counter. _record_apply_result must accumulate apply_attempts
    across repeated failures of the SAME tag, and reset it on success or on a
    different tag, so the GUI can stop auto-offering after a few failures."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="pf_attempts_")
        self.real_update_dir = updater.update_dir
        self.real_harden = updater._harden_acl
        updater.update_dir = lambda: self.root
        updater._harden_acl = lambda _p: None    # save_state() hardens the dir; irrelevant here
        self.txdir = os.path.join(self.root, "a" * 32)
        os.mkdir(self.txdir)
        with open(os.path.join(self.txdir, "transaction.json"), "w") as f:
            json.dump({"tag": "v9.9.9"}, f)

    def tearDown(self):
        updater.update_dir = self.real_update_dir
        updater._harden_acl = self.real_harden

    def test_attempts_accumulate_on_repeated_failure(self):
        for expected in (1, 2, 3):
            updater._record_apply_result(False, self.txdir)
            st = updater.load_state()
            self.assertEqual(st["apply_attempts"], expected)
            self.assertEqual(st["apply_attempts_tag"], "v9.9.9")
            self.assertEqual(st["last_apply_tag"], "v9.9.9")

    def test_success_clears_attempts(self):
        updater._record_apply_result(False, self.txdir)
        updater._record_apply_result(True, self.txdir)
        st = updater.load_state()
        self.assertNotIn("apply_attempts", st)
        self.assertNotIn("last_apply_error", st)

    def test_new_tag_resets_counter(self):
        updater._record_apply_result(False, self.txdir)
        updater._record_apply_result(False, self.txdir)
        other_txdir = os.path.join(self.root, "b" * 32)
        os.mkdir(other_txdir)
        with open(os.path.join(other_txdir, "transaction.json"), "w") as f:
            json.dump({"tag": "v9.9.10"}, f)
        updater._record_apply_result(False, other_txdir)
        st = updater.load_state()
        self.assertEqual(st["apply_attempts"], 1)
        self.assertEqual(st["apply_attempts_tag"], "v9.9.10")


if __name__ == "__main__":
    unittest.main()
