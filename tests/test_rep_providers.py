"""
Tests for core/rep_providers — the three reputation sources.

Network is never touched: each test swaps the module-level _api_post/_api_get/
_download for a fake and restores it in tearDown, the pattern used by
tests/test_updater.py.

Run:  python tests/test_rep_providers.py
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import rep_providers as rp


def _http_error(code):
    return urllib.error.HTTPError("http://x", code, "err", {}, None)


def _gsb_match(url, threat="SOCIAL_ENGINEERING", cache="300.000s"):
    return {"threatType": threat, "platformType": "ANY_PLATFORM",
            "threatEntryType": "URL", "threat": {"url": url},
            "cacheDuration": cache}


def _vt_report(malicious=0, suspicious=0, harmless=70, undetected=20):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious,
        "harmless": harmless, "undetected": undetected}}}}


class _PatchCase(unittest.TestCase):

    def setUp(self):
        self._real_post = rp._api_post
        self._real_get = rp._api_get
        self._real_download = rp._download

    def tearDown(self):
        rp._api_post = self._real_post
        rp._api_get = self._real_get
        rp._download = self._real_download


class SafeBrowsingTests(_PatchCase):

    CFG = {"rep_gsb_key": "test-key"}

    def _patch(self, matches=None, raises=None):
        self.posted = []

        def fake(opener, url, payload):
            self.posted.append((url, payload))
            if raises:
                raise raises
            return {"matches": matches} if matches else {}

        rp._api_post = fake

    def test_no_key_means_unavailable_and_no_call(self):
        self._patch()
        p = rp.SafeBrowsingProvider()
        self.assertFalse(p.available({"rep_gsb_key": ""}))
        self.assertEqual(p.lookup(["a.example"], {"rep_gsb_key": ""}), {})
        self.assertEqual(self.posted, [])

    def test_empty_response_marks_every_host_clean(self):
        """GSB returns only matches, so a clean verdict is inferred from absence
        — getting that backwards would report everything as malicious."""
        self._patch()
        out = rp.SafeBrowsingProvider().lookup(["a.example", "b.example"],
                                               self.CFG)
        self.assertEqual(out["a.example"][0], "clean")
        self.assertEqual(out["b.example"][0], "clean")

    def test_a_match_is_reported_as_malicious(self):
        self._patch(matches=[_gsb_match("https://evil.example/")])
        out = rp.SafeBrowsingProvider().lookup(["evil.example", "ok.example"],
                                               self.CFG)
        self.assertEqual(out["evil.example"][0], "malicious")
        self.assertIn("Social Engineering", out["evil.example"][1])
        self.assertEqual(out["ok.example"][0], "clean")

    def test_cache_duration_becomes_a_ttl(self):
        self._patch(matches=[_gsb_match("https://evil.example/", cache="600.000s")])
        out = rp.SafeBrowsingProvider().lookup(["evil.example"], self.CFG)
        self.assertEqual(out["evil.example"][2], 600.0)

    def test_match_url_without_a_scheme_still_yields_a_host(self):
        self._patch(matches=[_gsb_match("evil.example/path")])
        out = rp.SafeBrowsingProvider().lookup(["evil.example"], self.CFG)
        self.assertEqual(out["evil.example"][0], "malicious")

    def test_hosts_are_submitted_as_urls(self):
        """A bare hostname is not a URL; submitting https://host/ is what makes
        GSB apply its host-suffix expansion."""
        self._patch()
        rp.SafeBrowsingProvider().lookup(["evil.example"], self.CFG)
        entries = self.posted[0][1]["threatInfo"]["threatEntries"]
        self.assertEqual(entries, [{"url": "https://evil.example/"}])

    def test_key_is_sent_in_the_query_string_not_the_body(self):
        self._patch()
        rp.SafeBrowsingProvider().lookup(["a.example"], self.CFG)
        self.assertIn("key=test-key", self.posted[0][0])
        self.assertNotIn("test-key", json.dumps(self.posted[0][1]))

    def test_large_input_is_split_into_500_host_requests(self):
        self._patch()
        hosts = [f"h{i}.example" for i in range(1200)]
        out = rp.SafeBrowsingProvider().lookup(hosts, self.CFG)
        self.assertEqual(len(self.posted), 3)
        for _url, payload in self.posted:
            self.assertLessEqual(
                len(payload["threatInfo"]["threatEntries"]), 500)
        self.assertEqual(len(out), 1200)

    def test_429_raises_rate_limited_so_the_caller_requeues(self):
        self._patch(raises=_http_error(429))
        with self.assertRaises(rp.RateLimited):
            rp.SafeBrowsingProvider().lookup(["a.example"], self.CFG)

    def test_other_http_errors_propagate(self):
        self._patch(raises=_http_error(500))
        with self.assertRaises(urllib.error.HTTPError):
            rp.SafeBrowsingProvider().lookup(["a.example"], self.CFG)


class VirusTotalTests(_PatchCase):

    CFG = {"rep_vt_key": "vt-key"}

    def _patch(self, payload=None, raises=None):
        self.requests = []

        def fake(opener, url, headers=None):
            self.requests.append((url, headers or {}))
            if raises:
                raise raises
            return payload or {}

        rp._api_get = fake

    def test_no_key_means_unavailable_and_no_call(self):
        self._patch()
        p = rp.VirusTotalProvider()
        self.assertFalse(p.available({"rep_vt_key": ""}))
        self.assertIsNone(p.lookup_one("a.example", {"rep_vt_key": ""}))
        self.assertEqual(self.requests, [])

    def test_key_is_sent_as_the_x_apikey_header(self):
        self._patch(payload=_vt_report())
        rp.VirusTotalProvider().lookup_one("a.example", self.CFG)
        self.assertEqual(self.requests[0][1].get("x-apikey"), "vt-key")

    def test_clean_below_the_detection_threshold(self):
        self._patch(payload=_vt_report(malicious=1))
        status, detail = rp.VirusTotalProvider().lookup_one("a.example", self.CFG)
        self.assertEqual(status, "clean")
        self.assertIn("1/", detail)

    def test_malicious_at_the_detection_threshold(self):
        """One fringe engine is noise; the threshold exists so a single
        low-quality detection does not get a site blocked."""
        self._patch(payload=_vt_report(malicious=2))
        status, _detail = rp.VirusTotalProvider().lookup_one("a.example", self.CFG)
        self.assertEqual(status, "malicious")

    def test_suspicious_counts_toward_the_threshold(self):
        self._patch(payload=_vt_report(malicious=1, suspicious=1))
        status, _detail = rp.VirusTotalProvider().lookup_one("a.example", self.CFG)
        self.assertEqual(status, "malicious")

    def test_empty_stats_is_unknown_not_clean(self):
        self._patch(payload={"data": {"attributes": {}}})
        status, _detail = rp.VirusTotalProvider().lookup_one("a.example", self.CFG)
        self.assertEqual(status, "unknown")

    def test_404_is_unknown(self):
        self._patch(raises=_http_error(404))
        status, _detail = rp.VirusTotalProvider().lookup_one("a.example", self.CFG)
        self.assertEqual(status, "unknown")

    def test_429_raises_rate_limited(self):
        self._patch(raises=_http_error(429))
        with self.assertRaises(rp.RateLimited):
            rp.VirusTotalProvider().lookup_one("a.example", self.CFG)


class LocalFeedParsingTests(unittest.TestCase):

    def test_hostfile_format(self):
        text = ("# comment\n"
                "127.0.0.1\tevil.example\n"
                "0.0.0.0 bad.example  # trailing\n"
                "127.0.0.1 localhost\n"
                "\n"
                "bare.example\n")
        hosts = rp.LocalFeedProvider._parse_hostfile(text)
        self.assertEqual(hosts, {"evil.example", "bad.example", "bare.example"})

    def test_hostfile_drops_the_placeholder_entries(self):
        hosts = rp.LocalFeedProvider._parse_hostfile("127.0.0.1 localhost\n")
        self.assertEqual(hosts, set())

    def test_url_list_keeps_only_hostnames(self):
        text = ("# comment\n"
                "http://evil.example/a/b?c=d\n"
                "https://Phish.Example:8443/login\n"
                "not a url\n")
        hosts = rp.LocalFeedProvider._parse_urllist(text)
        self.assertEqual(hosts, {"evil.example", "phish.example"})


class LocalFeedMatchTests(unittest.TestCase):

    def setUp(self):
        self.p = rp.LocalFeedProvider()
        self.p._hosts = {"evil.example", "deep.sub.bad.example"}
        self.p._loaded = True

    def test_exact_host_matches(self):
        self.assertEqual(self.p._match("evil.example"), "evil.example")

    def test_subdomain_of_a_listed_domain_matches(self):
        """A feed listing a malware domain should also catch its CDN
        subdomains, which is how the operators actually serve payloads."""
        self.assertEqual(self.p._match("cdn.evil.example"), "evil.example")

    def test_unrelated_host_does_not_match(self):
        self.assertIsNone(self.p._match("good.example"))

    def test_parent_of_a_listed_host_does_not_match(self):
        """Listing deep.sub.bad.example must not blocklist bad.example."""
        self.assertIsNone(self.p._match("bad.example"))

    def test_suffix_lookalike_does_not_match(self):
        """notevil.example merely ends with the same text; it is a different
        domain and must not be caught."""
        self.assertIsNone(self.p._match("notevil.example"))

    def test_lookup_reports_only_hits(self):
        out = self.p.lookup(["evil.example", "good.example"], {"rep_feeds": True})
        self.assertEqual(list(out), ["evil.example"])
        self.assertEqual(out["evil.example"][0], "malicious")


class LocalFeedRefreshTests(_PatchCase):

    def setUp(self):
        super().setUp()
        self._root = tempfile.mkdtemp(prefix="pf_feed_")
        self._real_feed_dir = rp._feed_dir
        rp._feed_dir = lambda: self._root

    def tearDown(self):
        rp._feed_dir = self._real_feed_dir
        shutil.rmtree(self._root, ignore_errors=True)
        super().tearDown()

    def test_refresh_downloads_caches_and_loads(self):
        rp._download = lambda opener, url, max_bytes=None: (
            "127.0.0.1 evil.example\n" if "urlhaus" in url
            else "http://phish.example/x\n")
        p = rp.LocalFeedProvider()
        count = p.refresh({"rep_feeds": True}, force=True)
        self.assertEqual(count, 2)
        self.assertTrue(os.path.exists(os.path.join(self._root, "urlhaus.txt")))
        self.assertEqual(p._match("evil.example"), "evil.example")

    def test_cached_feed_is_loaded_without_any_download(self):
        """An offline machine keeps matching against the last good feed."""
        with open(os.path.join(self._root, "urlhaus.txt"), "w",
                  encoding="utf-8") as f:
            f.write("127.0.0.1 evil.example\n")

        def boom(*_a, **_k):
            raise AssertionError("should not download")

        rp._download = boom
        p = rp.LocalFeedProvider()
        p._load_cached()
        self.assertEqual(p._match("evil.example"), "evil.example")

    def test_a_failing_feed_does_not_raise_or_wipe_the_old_data(self):
        p = rp.LocalFeedProvider()
        p._hosts = {"evil.example"}
        p._loaded = True

        def boom(*_a, **_k):
            raise urllib.error.URLError("offline")

        rp._download = boom
        p.refresh({"rep_feeds": True}, force=True)
        self.assertEqual(p._match("evil.example"), "evil.example")

    def test_an_empty_download_is_treated_as_a_failure(self):
        """A feed that returns nothing is far more likely to be a broken fetch
        than a genuinely empty threat list; keep what we had."""
        p = rp.LocalFeedProvider()
        p._hosts = {"evil.example"}
        p._loaded = True
        rp._download = lambda *_a, **_k: ""
        p.refresh({"rep_feeds": True}, force=True)
        self.assertEqual(p._match("evil.example"), "evil.example")

    def test_disabled_feeds_do_not_download(self):
        def boom(*_a, **_k):
            raise AssertionError("should not download")

        rp._download = boom
        p = rp.LocalFeedProvider()
        p.refresh({"rep_feeds": False}, force=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
