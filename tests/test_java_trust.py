"""
Java truststore tests (the half core.env_certs cannot reach).

WHY THIS MODULE EXISTS: every other runtime ProxyForce fixes for TLS inspection
has an environment variable that overrides its CA bundle. Java has none — the JVM
reads a binary keystore (`<java-home>/lib/security/cacerts`), so the corporate CA
must be imported with `keytool`. That is a real mutation of an installed JDK, so
it carries the same contract as every other takeover in this codebase: record what
was changed before changing it, and undo exactly that — never more.

The invariant these tests defend is the "never more" half. ProxyForce must delete
ONLY aliases it created, identified by its own prefix and recorded in the backup
file. An alias that already existed under the same name was not ours and must
survive a stop; deleting it would silently remove a CA the machine's owner put
there deliberately.

`keytool` is stubbed throughout — no JDK is required to run these, and no real
keystore is ever touched. (The machine this was written on has no Java at all,
which is exactly why the invocation shape is pinned here rather than left to
manual testing.)

Run:  python tests/test_java_trust.py
"""

import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import java_trust
from core import env_certs


def _corporate_pem_text():
    ders = env_certs._read_pem_ders(env_certs.shipped_corporate_ca())
    if not ders:
        raise unittest.SkipTest("shipped corporate CA asset is missing")
    return "".join(env_certs._to_pem(d) for d in ders)


class FakeJdk:
    """A directory tree shaped like a JDK, with a stub keytool that records every
    invocation instead of touching a real keystore."""

    def __init__(self, root, layout="modern"):
        self.root = root
        self.calls = []
        self.aliases = set()
        self.bin = os.path.join(root, "bin")
        os.makedirs(self.bin, exist_ok=True)
        self.keytool = os.path.join(self.bin, "keytool.exe")
        open(self.keytool, "wb").close()
        rel = ("lib", "security") if layout == "modern" else ("jre", "lib", "security")
        sec = os.path.join(root, *rel)
        os.makedirs(sec, exist_ok=True)
        self.keystore = os.path.join(sec, "cacerts")
        open(self.keystore, "wb").close()

    def run(self, args, timeout=60):
        """Stands in for java_trust._run."""
        self.calls.append(list(args))
        if "-list" in args:
            return 0, "".join(f"{a}, Jan 1, 2026, trustedCertEntry\n"
                              for a in sorted(self.aliases))
        if "-importcert" in args:
            self.aliases.add(args[args.index("-alias") + 1])
            return 0, "Certificate was added to keystore"
        if "-delete" in args:
            self.aliases.discard(args[args.index("-alias") + 1])
            return 0, ""
        return 1, "unexpected"


class _JdkCase(unittest.TestCase):
    """Base: point java_trust at a fake JDK and a temp ProgramData."""

    layout = "modern"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.jdk = FakeJdk(os.path.join(self._tmp.name, "jdk"), self.layout)
        self._orig = (java_trust._data_dir, java_trust.find_keystores, java_trust._run)
        java_trust._data_dir = lambda: self._tmp.name
        java_trust.find_keystores = lambda: [(self.jdk.keystore, self.jdk.keytool)]
        java_trust._run = self.jdk.run
        self.pem = os.path.join(self._tmp.name, "corp.pem")
        with open(self.pem, "w") as f:
            f.write(_corporate_pem_text())

    def tearDown(self):
        (java_trust._data_dir, java_trust.find_keystores, java_trust._run) = self._orig
        self._tmp.cleanup()


class ApplyTests(_JdkCase):

    def test_imports_the_certificate(self):
        r = java_trust.apply(self.pem)
        self.assertEqual(r["stores"], 1)
        self.assertEqual(r["imported"], 1)
        self.assertEqual(r["skipped"], [])
        self.assertEqual(len(self.jdk.aliases), 1)

    def test_alias_carries_the_proxyforce_prefix(self):
        java_trust.apply(self.pem)
        alias = next(iter(self.jdk.aliases))
        self.assertTrue(alias.startswith(java_trust._ALIAS_PREFIX), alias)

    def test_import_uses_noprompt_and_trustcacerts(self):
        """Without -noprompt keytool blocks on stdin forever; this runs headless."""
        java_trust.apply(self.pem)
        imp = [c for c in self.jdk.calls if "-importcert" in c][0]
        self.assertIn("-noprompt", imp)
        self.assertIn("-trustcacerts", imp)
        self.assertIn(self.jdk.keystore, imp)

    def test_writes_a_backup_recording_what_it_created(self):
        java_trust.apply(self.pem)
        with open(java_trust._backup_path()) as f:
            recorded = json.load(f)
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0]["keystore"], self.jdk.keystore)
        self.assertIn(recorded[0]["alias"], self.jdk.aliases)

    def test_is_idempotent(self):
        java_trust.apply(self.pem)
        r2 = java_trust.apply(self.pem)
        self.assertEqual(r2["imported"], 0)
        self.assertEqual(len(self.jdk.aliases), 1)

    def test_no_certificate_is_a_noop(self):
        empty = os.path.join(self._tmp.name, "empty.pem")
        open(empty, "w").close()
        r = java_trust.apply(empty)
        self.assertEqual(r["imported"], 0)
        self.assertEqual(self.jdk.calls, [])

    def test_multi_cert_chain_imports_every_certificate(self):
        """keytool -importcert reads only the FIRST cert in a file, so a chain has
        to be split — otherwise an intermediate is silently dropped."""
        der = env_certs._read_pem_ders(env_certs.shipped_corporate_ca())[0]
        chain = os.path.join(self._tmp.name, "chain.pem")
        with open(chain, "w") as f:
            f.write(env_certs._to_pem(der) + env_certs._to_pem(der[:-1] + b"\x00"))
        r = java_trust.apply(chain)
        self.assertEqual(r["imported"], 2)
        self.assertEqual(len(self.jdk.aliases), 2)

    def test_non_default_keystore_password_is_skipped_not_fatal(self):
        def refuse(args, timeout=60):
            self.jdk.calls.append(list(args))
            return (1, "keytool error: password was incorrect") if "-list" in args \
                else (0, "")
        java_trust._run = refuse
        r = java_trust.apply(self.pem)
        self.assertEqual(r["imported"], 0)
        self.assertEqual(len(r["skipped"]), 1)
        self.assertIn("password", r["skipped"][0])

    def test_no_java_installed_is_a_clean_noop(self):
        java_trust.find_keystores = lambda: []
        r = java_trust.apply(self.pem)
        self.assertEqual(r, {"stores": 0, "imported": 0, "skipped": [], "details": []})


class RestoreTests(_JdkCase):

    def test_restore_removes_what_apply_added(self):
        java_trust.apply(self.pem)
        self.assertTrue(java_trust.restore())
        self.assertEqual(self.jdk.aliases, set())
        self.assertFalse(os.path.exists(java_trust._backup_path()))

    def test_restore_is_a_noop_without_a_backup(self):
        self.assertFalse(java_trust.restore())

    def test_restore_is_idempotent(self):
        java_trust.apply(self.pem)
        java_trust.restore()
        self.assertFalse(java_trust.restore())

    def test_never_deletes_an_alias_it_did_not_create(self):
        """THE load-bearing invariant: a CA the machine's owner imported under our
        alias name must survive a stop."""
        preexisting = f"{java_trust._ALIAS_PREFIX}-somebodyelse"
        self.jdk.aliases.add(preexisting)
        java_trust.apply(self.pem)
        java_trust.restore()
        self.assertIn(preexisting, self.jdk.aliases)

    def test_refuses_to_delete_a_foreign_alias_from_a_tampered_backup(self):
        java_trust._write_backup(
            [{"keystore": self.jdk.keystore, "alias": "corporate-root-ca"}])
        self.jdk.aliases.add("corporate-root-ca")
        java_trust.restore()
        self.assertIn("corporate-root-ca", self.jdk.aliases)
        self.assertEqual([c for c in self.jdk.calls if "-delete" in c], [])

    def test_uninstalled_jdk_does_not_raise(self):
        java_trust.apply(self.pem)
        os.remove(self.jdk.keystore)
        java_trust.restore()    # must not raise
        self.assertFalse(os.path.exists(java_trust._backup_path()))


class Java8LayoutRestoreTests(_JdkCase):
    """Java 8 keeps the store at jre/lib/security/cacerts — one level deeper — so
    restore()'s walk back to bin/keytool.exe has a second branch."""

    layout = "legacy"

    def test_restore_finds_keytool_in_the_legacy_layout(self):
        java_trust.apply(self.pem)
        java_trust._run = self.jdk.run     # real path walk, stubbed executor
        self.assertTrue(java_trust.restore())
        self.assertEqual(self.jdk.aliases, set())


class DiscoveryTests(unittest.TestCase):
    """find_keystores touches the real filesystem but never writes."""

    def test_returns_pairs_of_existing_files(self):
        for keystore, keytool in java_trust.find_keystores():
            self.assertTrue(os.path.isfile(keystore))
            self.assertTrue(os.path.isfile(keytool))

    def test_current_state_returns_string(self):
        self.assertIsInstance(java_trust.current_state(), str)

    def test_alias_is_stable_and_cert_specific(self):
        a = env_certs._to_pem(b"\x01" * 64)
        b = env_certs._to_pem(b"\x02" * 64)
        self.assertEqual(java_trust._alias_for(a, 0), java_trust._alias_for(a, 9))
        self.assertNotEqual(java_trust._alias_for(a, 0), java_trust._alias_for(b, 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
