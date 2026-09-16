"""
CA-trust environment-variable tests (the "SSL inspection" fix, reported
2026-09-15).

WHY THIS MODULE EXISTS: on a TLS-inspecting network the certificate an app sees
is minted by the inspection appliance's CA. Windows' trust store usually has that
CA (GPO), so browsers are fine — but docker, pip, npm, git, curl, Go, cargo and
friends read their own BUNDLED CA list and reject the handshake. core.env_certs
closes that gap the same way core.env_proxy closes the proxy one: it merges a
complete public-trust baseline, the live Windows ROOT store, and the corporate CA
into one bundle and points the CA-bundle environment variables at it, restoring
exactly what was there before.

The load-bearing invariant, and the reason the merge exists at all: Windows ships
only a SEED set of roots and pulls the rest on demand, so the live store is a
strict subset of public trust (36 vs 150 on the machine this was written
against). Since SSL_CERT_FILE and friends REPLACE a tool's bundle rather than
extend it, emitting the Windows store alone would revoke trust for ~114 public
CAs — a far worse outage than the one being fixed. Several tests below exist
specifically to keep that from regressing.

Like test_env_proxy.py / test_system_proxy.py, these exercise ONLY safe,
side-effect-free paths: PEM parsing, the merge/dedupe, fail-closed behaviour, and
the backup round-trip with `_set`/`_restore` stubbed — never the real registry.

Run:  python tests/test_env_certs.py
"""

import os
import ssl
import sys
import json
import base64
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import env_certs


# The corporate certificate is NOT committed (public repository), so a clean
# clone -- CI included -- has no assets/ca/corporate-ca.pem. Tests that need one
# skip rather than fail; the feature itself is required to work without it, and
# that requirement has its own tests below.
HAVE_SHIPPED = bool(env_certs._read_pem_ders(env_certs.shipped_corporate_ca()))
_needs_shipped = unittest.skipUnless(
    HAVE_SHIPPED, "no shipped corporate CA in this checkout (not committed)")


def _shipped_der():
    ders = env_certs._read_pem_ders(env_certs.shipped_corporate_ca())
    if not ders:
        raise unittest.SkipTest("shipped corporate CA asset is missing")
    return ders[0]


class PemParsingTests(unittest.TestCase):
    """A user-supplied CA file is routinely a hand-assembled thing: comments from
    an export tool, CRLF line endings, several concatenated certs. All of that
    must parse, and one malformed block must not discard the valid ones."""

    @_needs_shipped
    def test_reads_shipped_certificate(self):
        ders = env_certs._read_pem_ders(env_certs.shipped_corporate_ca())
        self.assertEqual(len(ders), 1)
        self.assertGreater(len(ders[0]), 100)

    def test_tolerates_comments_and_crlf(self):
        der = _shipped_der()
        pem = env_certs._to_pem(der).replace("\n", "\r\n")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.pem")
            with open(p, "w", newline="") as f:
                f.write("# exported by some tool\r\nBag Attributes: junk\r\n" + pem)
            self.assertEqual(env_certs._read_pem_ders(p), [der])

    def test_reads_multiple_concatenated_certs(self):
        der = _shipped_der()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "chain.pem")
            with open(p, "w") as f:
                f.write(env_certs._to_pem(der) + "# intermediate\n"
                        + env_certs._to_pem(der[:-1] + b"\x00"))
            self.assertEqual(len(env_certs._read_pem_ders(p)), 2)

    def test_malformed_block_does_not_discard_valid_ones(self):
        der = _shipped_der()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "mixed.pem")
            with open(p, "w") as f:
                f.write("-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n"
                        "-----END CERTIFICATE-----\n" + env_certs._to_pem(der))
            self.assertEqual(env_certs._read_pem_ders(p), [der])

    def test_missing_file_is_empty_not_an_exception(self):
        self.assertEqual(env_certs._read_pem_ders(r"C:\nope\missing.pem"), [])
        self.assertEqual(env_certs._read_pem_ders(""), [])

    def test_roundtrip_pem_is_loadable_by_openssl(self):
        der = _shipped_der()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "rt.pem")
            with open(p, "w") as f:
                f.write(env_certs._to_pem(der))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(cafile=p)     # raises if malformed
            self.assertEqual(len(ctx.get_ca_certs()), 1)


class AsciiHeaderTests(unittest.TestCase):
    """The bundle is written as ASCII, but its header quotes the certificate
    subject — which can hold non-Latin characters. This blew up in development on
    an em-dash in our own wording, so it is pinned."""

    def test_non_ascii_is_sanitized(self):
        out = env_certs._ascii("Fu\u00dfball \u2014 \u4e2d\u6587")
        self.assertEqual(out, out.encode("ascii", "strict").decode("ascii"))
        self.assertIn("-", out)     # em-dash became a plain hyphen, not '?'


class DescribeCertTests(unittest.TestCase):

    @_needs_shipped
    def test_shipped_certificate_validates(self):
        ok, summary = env_certs.describe_cert_file(env_certs.shipped_corporate_ca())
        self.assertTrue(ok, summary)
        self.assertIn("certificate", summary)

    def test_missing_path_is_rejected(self):
        ok, summary = env_certs.describe_cert_file(r"C:\nope\missing.pem")
        self.assertFalse(ok)
        self.assertIn("not found", summary.lower())

    def test_empty_path_is_rejected(self):
        ok, _ = env_certs.describe_cert_file("")
        self.assertFalse(ok)

    def test_der_binary_is_rejected_with_a_useful_message(self):
        """The single most likely user mistake: exporting DER instead of Base-64."""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "binary.cer")
            with open(p, "wb") as f:
                f.write(_shipped_der())
            ok, summary = env_certs.describe_cert_file(p)
            self.assertFalse(ok)
            self.assertIn("Base-64", summary)

    def test_garbage_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "notes.txt")
            with open(p, "w") as f:
                f.write("this is not a certificate\n")
            ok, _ = env_certs.describe_cert_file(p)
            self.assertFalse(ok)


class BundleMergeTests(unittest.TestCase):
    """The merge is the whole point of the module: union, deduplicated, and never
    narrower than the public baseline."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_data_dir = env_certs._data_dir
        env_certs._data_dir = lambda: self._tmp.name

    def tearDown(self):
        env_certs._data_dir = self._orig_data_dir
        self._tmp.cleanup()

    def test_bundle_contains_corporate_and_public_baseline(self):
        st = env_certs.build_bundle()
        self.assertTrue(st["ok"], st["error"])
        self.assertEqual(st["corporate"], 1 if HAVE_SHIPPED else 0)
        self.assertGreaterEqual(st["base"], 100)
        self.assertEqual(st["total"], st["base"] + st["system"] + st["corporate"])

    def test_bundle_is_never_smaller_than_the_public_baseline(self):
        """The regression guard: a bundle narrower than the shipped baseline would
        mean SSL_CERT_FILE had REMOVED public trust."""
        st = env_certs.build_bundle()
        baseline = len(env_certs._read_pem_ders(env_certs.base_bundle()))
        self.assertGreaterEqual(st["total"], baseline)

    def test_emitted_bundle_loads_in_openssl_and_holds_the_corporate_ca(self):
        st = env_certs.build_bundle()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=st["bundle"])
        self.assertGreaterEqual(len(ctx.get_ca_certs()), 100)
        der = _shipped_der()
        self.assertIn(env_certs._fp(der),
                      {env_certs._fp(d) for d in
                       env_certs._read_pem_ders(st["bundle"])})

    def test_duplicates_are_collapsed_by_fingerprint(self):
        """Feeding a cert that is already in the Windows store must not double it."""
        st = env_certs.build_bundle()
        ders = env_certs._read_pem_ders(st["bundle"])
        fps = [env_certs._fp(d) for d in ders]
        self.assertEqual(len(fps), len(set(fps)))

    def test_node_extra_file_holds_private_roots_not_the_full_union(self):
        """NODE_EXTRA_CA_CERTS *extends* Node's built-ins, so it must get only the
        roots that are NOT already public trust — never the full union."""
        st = env_certs.build_bundle()
        extras = env_certs._read_pem_ders(st["corporate_file"])
        baseline = {env_certs._fp(d)
                    for d in env_certs._read_pem_ders(env_certs.base_bundle())}
        self.assertTrue(extras)
        self.assertLess(len(extras), st["total"])
        for d in extras:
            self.assertNotIn(env_certs._fp(d), baseline)
        self.assertIn(env_certs._fp(_shipped_der()),
                      {env_certs._fp(d) for d in extras})

    def test_builds_without_any_shipped_certificate(self):
        """A build from a clean clone has no assets/ca/corporate-ca.pem (it is not
        committed — public repo). The feature must still work, taking the
        inspection CA from the Windows store."""
        orig = env_certs.shipped_corporate_ca
        env_certs.shipped_corporate_ca = lambda: ""
        try:
            st = env_certs.build_bundle()
            self.assertTrue(st["ok"], st["error"])
            self.assertEqual(st["corporate"], 0)
            self.assertEqual(st["cert_path"], "")
            self.assertIn("Windows trust store", st["cert_summary"])
            self.assertGreaterEqual(st["total"], st["base"])
            self.assertTrue(os.path.exists(st["corporate_file"]))
        finally:
            env_certs.shipped_corporate_ca = orig

    def test_broken_shipped_certificate_degrades_instead_of_failing(self):
        """A corrupt SHIPPED asset must not take the feature down — unlike a path
        the user typed, which must fail loudly."""
        orig = env_certs.shipped_corporate_ca
        env_certs.shipped_corporate_ca = lambda: os.path.join(
            "C:", "nope", "missing.pem")
        try:
            st = env_certs.build_bundle()
            self.assertTrue(st["ok"], st["error"])
            self.assertIn("Windows trust store", st["cert_summary"])
        finally:
            env_certs.shipped_corporate_ca = orig

    def test_replacement_certificate_is_honoured(self):
        der = _shipped_der()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "replacement.pem")
            with open(p, "w") as f:
                f.write("# a different appliance\n" + env_certs._to_pem(der))
            st = env_certs.build_bundle(p)
            self.assertTrue(st["ok"], st["error"])
            self.assertEqual(st["cert_path"], p)

    def test_bad_certificate_fails_closed(self):
        """A bad cert must NOT produce a bundle: pointing SSL_CERT_FILE at a
        missing/empty file breaks TLS for every tool that reads it."""
        st = env_certs.build_bundle(r"C:\nope\missing.pem")
        self.assertFalse(st["ok"])
        self.assertIn("unusable", st["error"])
        self.assertFalse(os.path.exists(st["bundle"]))

    def test_refuses_to_build_from_a_sparse_windows_store_alone(self):
        """If the shipped baseline is missing, a 36-cert Windows store must NOT be
        emitted as a replace-semantics bundle."""
        orig_base, orig_win = env_certs.base_bundle, env_certs._system_root_ders
        env_certs.base_bundle = lambda: ""
        env_certs._system_root_ders = lambda: [_shipped_der()]
        try:
            st = env_certs.build_bundle()
            self.assertFalse(st["ok"])
            self.assertIn("refusing", st["error"])
        finally:
            env_certs.base_bundle, env_certs._system_root_ders = orig_base, orig_win


class ApplyRestoreTests(unittest.TestCase):
    """point_at/restore bookkeeping, with the registry stubbed out."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_data_dir = env_certs._data_dir
        env_certs._data_dir = lambda: self._tmp.name
        self.set_calls, self.restore_calls = [], []
        self._orig_set, self._orig_restore = env_certs._set, env_certs._restore
        self._orig_snapshot = env_certs._snapshot
        env_certs._set = lambda b, c: self.set_calls.append((b, c))
        env_certs._restore = lambda snap: self.restore_calls.append(snap)
        env_certs._snapshot = lambda: {
            "user": {n: None for n in env_certs._ALL_VAR_NAMES},
            "machine": {n: None for n in env_certs._ALL_VAR_NAMES}}

    def tearDown(self):
        env_certs._data_dir = self._orig_data_dir
        env_certs._set, env_certs._restore = self._orig_set, self._orig_restore
        env_certs._snapshot = self._orig_snapshot
        self._tmp.cleanup()

    def test_apply_sets_both_paths_and_writes_a_backup(self):
        st = env_certs.apply()
        self.assertTrue(st["ok"], st["error"])
        self.assertEqual(len(self.set_calls), 1)
        bundle, corporate = self.set_calls[0]
        self.assertEqual(bundle, env_certs.bundle_path())
        self.assertEqual(corporate, env_certs.corporate_path())
        self.assertNotEqual(bundle, corporate)
        self.assertTrue(os.path.exists(env_certs._backup_path()))

    def test_apply_never_touches_the_environment_when_the_cert_is_bad(self):
        st = env_certs.apply(r"C:\nope\missing.pem")
        self.assertFalse(st["ok"])
        self.assertEqual(self.set_calls, [])
        self.assertFalse(os.path.exists(env_certs._backup_path()))

    def test_restore_is_a_noop_without_a_backup(self):
        self.assertFalse(env_certs.restore())
        self.assertEqual(self.restore_calls, [])

    def test_apply_then_restore_round_trips_and_clears_the_backup(self):
        env_certs.apply()
        self.assertTrue(env_certs.restore())
        self.assertEqual(len(self.restore_calls), 1)
        self.assertFalse(os.path.exists(env_certs._backup_path()))
        self.assertFalse(env_certs.restore())    # idempotent

    def test_second_apply_keeps_the_original_backup(self):
        """A restart mid-takeover must not snapshot our OWN values as the user's."""
        env_certs.apply()
        with open(env_certs._backup_path()) as f:
            first = json.load(f)
        env_certs._snapshot = lambda: {
            "user": {n: ["OURS", 1] for n in env_certs._ALL_VAR_NAMES},
            "machine": {n: ["OURS", 1] for n in env_certs._ALL_VAR_NAMES}}
        env_certs.apply()
        with open(env_certs._backup_path()) as f:
            self.assertEqual(json.load(f), first)


class VariableSetTests(unittest.TestCase):

    def test_bundle_and_extra_vars_are_disjoint(self):
        """A var cannot both replace and extend — the two lists must not overlap."""
        self.assertFalse(set(env_certs._BUNDLE_VARS) & set(env_certs._EXTRA_VARS))

    def test_covers_the_common_toolchains(self):
        """Docker was the reported symptom; the same CA breaks all of these."""
        for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
                     "GIT_SSL_CAINFO", "PIP_CERT", "AWS_CA_BUNDLE",
                     "CARGO_HTTP_CAINFO", "NODE_EXTRA_CA_CERTS"):
            self.assertIn(name, env_certs._ALL_VAR_NAMES)

    def test_snapshot_shape(self):
        snap = env_certs._snapshot()
        for scope in ("user", "machine"):
            self.assertIn(scope, snap)
            for name in env_certs._ALL_VAR_NAMES:
                self.assertIn(name, snap[scope])

    def test_current_state_returns_string(self):
        self.assertIsInstance(env_certs.current_state(), str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
