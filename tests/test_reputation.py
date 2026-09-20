"""
Tests for core/reputation — the scan-once-and-remember scanner.

The behaviours that matter here are the ones the feature was asked for:

  * EVERY hostname is scanned — there are no allowlist exemptions.
  * Each host is scanned exactly ONCE, then served from cache, including
    across a restart. This is what stops a reputation check turning into
    constant traffic to a third party.
  * The scanner must not recurse on the provider API hostnames its own
    lookups connect to.
  * VirusTotal's 4/min + 500/day budget is never exceeded, and the daily
    counter survives a restart.

Run:  python tests/test_reputation.py
"""

import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import reputation as rep
from core.rep_providers import RateLimited


CFG_ALL = {"rep_scan": True, "rep_feeds": True,
           "rep_gsb_key": "gsb-key", "rep_vt_key": ""}


class _FakeFeeds:
    name = "feeds"

    def __init__(self, bad=()):
        self.bad = set(bad)
        self.calls = 0

    def available(self, cfg):
        return bool(cfg.get("rep_feeds"))

    def lookup(self, hosts, cfg):
        self.calls += 1
        return {h: ("malicious", "listed in feeds") for h in hosts
                if h in self.bad}

    def entry_count(self):
        return len(self.bad)

    def last_refresh(self):
        return time.time()

    def sources(self):
        return [("urlhaus", time.time(), False)]

    def refresh(self, cfg, force=False):
        return len(self.bad)

    def _match(self, host):
        return host if host in self.bad else None


class _FakeGSB:
    name = "safebrowsing"

    def __init__(self, bad=(), raises=None):
        self.bad = set(bad)
        self.raises = raises
        self.calls = 0
        self.batches = []

    def available(self, cfg):
        return bool((cfg.get("rep_gsb_key") or "").strip())

    def lookup(self, hosts, cfg):
        self.calls += 1
        self.batches.append(list(hosts))
        if self.raises:
            raise self.raises
        return {h: (("malicious", "Social Engineering") if h in self.bad
                    else ("clean", "not listed")) for h in hosts}


class _FakeVT:
    name = "virustotal"

    def __init__(self, answers=None, raises=None):
        self.answers = answers or {}
        self.raises = raises
        self.calls = 0
        self.seen = []

    def available(self, cfg):
        return bool((cfg.get("rep_vt_key") or "").strip())

    def lookup_one(self, host, cfg):
        self.calls += 1
        self.seen.append(host)
        if self.raises:
            raise self.raises
        return self.answers.get(host)


class _ScannerCase(unittest.TestCase):
    """Redirects the on-disk cache away from the real %ProgramData% and shrinks
    the timing constants, the same approach tests/test_updater.py uses."""

    def setUp(self):
        self._root = tempfile.mkdtemp(prefix="pf_rep_")
        self._real_rep_dir = rep._rep_dir
        rep._rep_dir = lambda: self._root
        self._real_batch_wait = rep._BATCH_WAIT
        self._real_vt_interval = rep._VT_MIN_INTERVAL
        self._real_vt_idle = rep._VT_IDLE_WAIT
        rep._BATCH_WAIT = 0.02
        rep._VT_MIN_INTERVAL = 0.01
        rep._VT_IDLE_WAIT = 0.02
        self._scanners = []

    def tearDown(self):
        for s in self._scanners:
            try:
                s.stop()
            except Exception:
                pass
        rep._rep_dir = self._real_rep_dir
        rep._BATCH_WAIT = self._real_batch_wait
        rep._VT_MIN_INTERVAL = self._real_vt_interval
        rep._VT_IDLE_WAIT = self._real_vt_idle
        shutil.rmtree(self._root, ignore_errors=True)

    def _scanner(self, cfg=None, feeds=None, gsb=None, vt=None, updates=None):
        cfg = dict(cfg or CFG_ALL)
        scanner = rep.ReputationScanner(
            lambda: cfg,
            on_update=(updates.append if updates is not None else None))
        scanner._feeds = feeds or _FakeFeeds()
        scanner._gsb = gsb or _FakeGSB()
        scanner._vt = vt or _FakeVT()
        self._scanners.append(scanner)
        return scanner

    def _settle(self, scanner, timeout=3.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            st = scanner.stats()
            if st["queued"] == 0 and st["inflight"] == 0:
                time.sleep(0.05)
                return
            time.sleep(0.01)
        self.fail("scanner did not settle")


class NormalizeHostTests(unittest.TestCase):

    def test_lowercases_and_strips_trailing_dot(self):
        self.assertEqual(rep.normalize_host("Example.COM."), "example.com")

    def test_strips_port(self):
        self.assertEqual(rep.normalize_host("evil.example:443"), "evil.example")

    def test_rejects_ip_literals(self):
        for value in ("8.8.8.8", "127.0.0.1", "10.1.2.3", "[::1]"):
            self.assertEqual(rep.normalize_host(value), "", value)

    def test_rejects_the_fakeip_range(self):
        """sing-box hands out 198.18.0.0/15 as DNS placeholders; they are never
        real destinations, so a reputation lookup on one is meaningless."""
        self.assertEqual(rep.normalize_host("198.18.0.7"), "")

    def test_rejects_single_label_names(self):
        for value in ("localhost", "fileserver", ""):
            self.assertEqual(rep.normalize_host(value), "", value)


class ScanOnceTests(_ScannerCase):

    def test_repeat_visits_scan_only_once(self):
        gsb = _FakeGSB()
        s = self._scanner(gsb=gsb)
        s.start()
        for _ in range(25):
            s.observe("example.com", 443, "proxy", "c1")
        self._settle(s)
        self.assertEqual(gsb.calls, 1)
        self.assertEqual(s.stats()["known_good"], 1)
        self.assertEqual(s.sites()[0].conns, 25)

    def test_a_batch_is_one_call_for_many_hosts(self):
        gsb = _FakeGSB()
        s = self._scanner(gsb=gsb)
        s.start()
        for i in range(20):
            s.observe(f"host{i}.example", 443, "proxy", f"c{i}")
        self._settle(s)
        self.assertEqual(gsb.calls, 1)
        self.assertEqual(len(gsb.batches[0]), 20)

    def test_no_host_is_exempt_from_scanning(self):
        """There is no bundled allowlist: a household-name domain is looked up
        exactly like anything else."""
        gsb = _FakeGSB()
        s = self._scanner(gsb=gsb)
        s.start()
        s.observe("www.google.com", 443, "proxy", "c1")
        s.observe("www.microsoft.com", 443, "proxy", "c2")
        self._settle(s)
        self.assertEqual(sorted(gsb.batches[0]),
                         ["www.google.com", "www.microsoft.com"])

    def test_provider_hostnames_do_not_recurse(self):
        """The scanner's own API traffic shows up as connections. Marking a host
        in-flight before the lookup is issued is what keeps that from queueing a
        second lookup, and a third, forever."""
        gsb = _FakeGSB()
        s = self._scanner(gsb=gsb)
        s.start()
        for _ in range(10):
            s.observe("safebrowsing.googleapis.com", 443, "proxy", "c1")
        self._settle(s)
        self.assertEqual(gsb.calls, 1)
        self.assertEqual(gsb.batches[0], ["safebrowsing.googleapis.com"])

    def test_ip_only_connections_are_not_scanned(self):
        gsb = _FakeGSB()
        s = self._scanner(gsb=gsb)
        s.start()
        s.observe("10.0.0.5", 443, "direct", "c1")
        s.observe("127.0.0.1", 8080, "direct", "c2")
        time.sleep(0.2)
        self.assertEqual(gsb.calls, 0)
        self.assertEqual(s.stats()["sites"], 0)


class TieringTests(_ScannerCase):

    def test_feed_hit_short_circuits_safe_browsing(self):
        """A host the free feeds already condemned must not also spend a cloud
        lookup on it."""
        feeds = _FakeFeeds(bad={"evil.example"})
        gsb = _FakeGSB()
        s = self._scanner(feeds=feeds, gsb=gsb)
        s.start()
        s.observe("evil.example", 443, "proxy", "c1")
        s.observe("ok.example", 443, "proxy", "c2")
        self._settle(s)
        self.assertEqual(gsb.batches[0], ["ok.example"])
        verdicts = {r.host: r.verdict for r in s.sites()}
        self.assertEqual(verdicts["evil.example"].status, rep.MALICIOUS)
        self.assertEqual(verdicts["evil.example"].source, "feeds")
        self.assertEqual(verdicts["ok.example"].status, rep.CLEAN)

    def test_host_is_unknown_when_no_source_can_answer(self):
        s = self._scanner(cfg={"rep_scan": True, "rep_feeds": False,
                               "rep_gsb_key": "", "rep_vt_key": ""})
        s.start()
        s.observe("mystery.example", 443, "proxy", "c1")
        self._settle(s)
        self.assertEqual(s.sites()[0].verdict.status, rep.UNKNOWN)

    def test_safe_browsing_failure_records_an_error_not_a_clean_verdict(self):
        """Failing open as 'clean' would cache a lie for 30 days."""
        gsb = _FakeGSB(raises=RuntimeError("network down"))
        s = self._scanner(gsb=gsb)
        s.start()
        s.observe("example.com", 443, "proxy", "c1")
        self._settle(s)
        self.assertEqual(s.sites()[0].verdict.status, rep.ERROR)

    def test_scanning_disabled_still_lists_sites_but_never_looks_them_up(self):
        gsb = _FakeGSB()
        s = self._scanner(cfg=dict(CFG_ALL, rep_scan=False), gsb=gsb)
        s.start()
        s.observe("example.com", 443, "proxy", "c1")
        time.sleep(0.2)
        self.assertEqual(gsb.calls, 0)
        self.assertEqual(s.stats()["sites"], 1)
        self.assertIsNone(s.sites()[0].verdict)


class CacheTests(_ScannerCase):

    def test_verdict_survives_a_restart_without_a_second_lookup(self):
        gsb = _FakeGSB()
        s = self._scanner(gsb=gsb)
        s.start()
        s.observe("example.com", 443, "proxy", "c1")
        self._settle(s)
        s.stop()
        self.assertEqual(gsb.calls, 1)

        gsb2 = _FakeGSB()
        s2 = self._scanner(gsb=gsb2)
        s2.start()
        s2.observe("example.com", 443, "proxy", "c2")
        time.sleep(0.2)
        self.assertEqual(gsb2.calls, 0)
        self.assertEqual(s2.sites()[0].verdict.status, rep.CLEAN)

    def test_expired_entry_is_rescanned(self):
        gsb = _FakeGSB()
        s = self._scanner(gsb=gsb)
        s.start()
        s.observe("example.com", 443, "proxy", "c1")
        self._settle(s)
        s._cache["example.com"].expires_at = time.time() - 1
        s.observe("example.com", 443, "proxy", "c2")
        self._settle(s)
        self.assertEqual(gsb.calls, 2)

    def test_expired_entries_are_dropped_on_load(self):
        s = self._scanner()
        s._cache["stale.example"] = rep.Verdict(
            "stale.example", rep.CLEAN, expires_at=time.time() - 10)
        s._cache_dirty = True
        s._save_cache(force=True)
        s2 = self._scanner()
        s2._load_cache()
        self.assertNotIn("stale.example", s2._cache)

    def test_rescan_all_queues_hosts_seen_while_scanning_was_off(self):
        gsb = _FakeGSB()
        cfg = dict(CFG_ALL, rep_scan=False)
        s = rep.ReputationScanner(lambda: cfg)
        s._feeds, s._gsb, s._vt = _FakeFeeds(), gsb, _FakeVT()
        self._scanners.append(s)
        s.start()
        s.observe("example.com", 443, "proxy", "c1")
        time.sleep(0.15)
        self.assertEqual(gsb.calls, 0)
        cfg["rep_scan"] = True
        s.rescan_all()
        self._settle(s)
        self.assertEqual(gsb.calls, 1)


class VirusTotalBackfillTests(_ScannerCase):

    def _vt_cfg(self):
        return dict(CFG_ALL, rep_vt_key="vt-key")

    def test_clean_hosts_are_queued_for_a_second_opinion(self):
        vt = _FakeVT()
        s = self._scanner(cfg=self._vt_cfg(), vt=vt)
        s.start()
        s.observe("example.com", 443, "proxy", "c1")
        deadline = time.time() + 3
        while time.time() < deadline and not vt.seen:
            time.sleep(0.01)
        self.assertEqual(vt.seen, ["example.com"])

    def test_already_flagged_hosts_do_not_spend_virustotal_quota(self):
        """500/day is scarce; re-confirming a known-bad host wastes it."""
        feeds = _FakeFeeds(bad={"evil.example"})
        vt = _FakeVT()
        s = self._scanner(cfg=self._vt_cfg(), feeds=feeds, vt=vt)
        s.start()
        s.observe("evil.example", 443, "proxy", "c1")
        time.sleep(0.3)
        self.assertEqual(vt.seen, [])

    def test_virustotal_can_escalate_a_clean_verdict(self):
        vt = _FakeVT(answers={"example.com": ("malicious", "9/94 engines flagged it")})
        s = self._scanner(cfg=self._vt_cfg(), vt=vt)
        s.start()
        s.observe("example.com", 443, "proxy", "c1")
        deadline = time.time() + 3
        while time.time() < deadline:
            sites = s.sites()
            if sites and sites[0].verdict is not None                     and sites[0].verdict.status == rep.MALICIOUS:
                break
            time.sleep(0.01)
        self.assertEqual(s.sites()[0].verdict.status, rep.MALICIOUS)
        self.assertEqual(s.sites()[0].verdict.source, "virustotal")

    def test_virustotal_clean_does_not_downgrade_a_malicious_verdict(self):
        feeds = _FakeFeeds(bad={"evil.example"})
        s = self._scanner(cfg=self._vt_cfg(), feeds=feeds,
                          vt=_FakeVT(answers={"evil.example": ("clean", "0/94")}))
        s.start()
        s.observe("evil.example", 443, "proxy", "c1")
        time.sleep(0.3)
        self.assertEqual(s.sites()[0].verdict.status, rep.MALICIOUS)

    def test_daily_cap_is_enforced_and_persisted(self):
        s = self._scanner(cfg=self._vt_cfg())
        real_cap = rep._VT_DAILY_CAP
        try:
            rep._VT_DAILY_CAP = 2
            self.assertTrue(s._vt_take_quota())
            self.assertTrue(s._vt_take_quota())
            self.assertFalse(s._vt_take_quota())
            # A restart must not hand out a fresh budget.
            s2 = self._scanner(cfg=self._vt_cfg())
            s2._load_quota()
            self.assertFalse(s2._vt_take_quota())
        finally:
            rep._VT_DAILY_CAP = real_cap

    def test_rate_limited_host_is_requeued_not_dropped(self):
        vt = _FakeVT(raises=RateLimited("429"))
        real_backoff = rep._VT_BACKOFF
        try:
            rep._VT_BACKOFF = 0.01
            s = self._scanner(cfg=self._vt_cfg(), vt=vt)
            s.start()
            s.observe("example.com", 443, "proxy", "c1")
            deadline = time.time() + 3
            while time.time() < deadline and vt.calls < 2:
                time.sleep(0.01)
            self.assertGreaterEqual(vt.calls, 2)
        finally:
            rep._VT_BACKOFF = real_backoff


class AlertTests(_ScannerCase):

    def test_a_flag_is_recorded_once_and_logged(self):
        logs = []
        feeds = _FakeFeeds(bad={"evil.example"})
        s = self._scanner(feeds=feeds)
        s._on_log = lambda m, l: logs.append((l, m))
        s.start()
        for _ in range(5):
            s.observe("evil.example", 443, "proxy", "c1")
        self._settle(s)
        self.assertEqual([f["host"] for f in s.recent_flags()], ["evil.example"])
        self.assertEqual([l for l, _m in logs if l == "error"], ["error"])

    def test_conn_ids_are_tracked_so_live_connections_can_be_closed(self):
        s = self._scanner()
        s.start()
        s.observe("evil.example", 443, "proxy", "conn-1")
        s.observe("evil.example", 443, "proxy", "conn-2")
        self.assertEqual(s.conn_ids_for("evil.example"), {"conn-1", "conn-2"})


class FeedAccessorTests(_ScannerCase):
    """verdict_for/is_pending back the dashboard's live connection feed, which
    calls them once per connection — so they must answer from cache only and
    never block or trigger a lookup."""

    def test_verdict_for_returns_none_for_an_unseen_host(self):
        s = self._scanner()
        self.assertIsNone(s.verdict_for("nothing.example"))

    def test_verdict_for_returns_a_cached_verdict(self):
        s = self._scanner()
        s._cache["a.example"] = rep.Verdict("a.example", rep.CLEAN, "gsb", "ok")
        self.assertEqual(s.verdict_for("a.example").status, rep.CLEAN)

    def test_verdict_for_normalizes_the_host(self):
        """The feed passes whatever sing-box reported, ports and all."""
        s = self._scanner()
        s._cache["a.example"] = rep.Verdict("a.example", rep.CLEAN, "gsb", "ok")
        self.assertIsNotNone(s.verdict_for("A.Example.:443"))

    def test_verdict_for_ignores_an_expired_entry(self):
        s = self._scanner()
        s._cache["a.example"] = rep.Verdict(
            "a.example", rep.CLEAN, "gsb", "ok", expires_at=time.time() - 1)
        self.assertIsNone(s.verdict_for("a.example"))

    def test_is_pending_is_true_only_while_in_flight(self):
        s = self._scanner()
        self.assertFalse(s.is_pending("a.example"))
        s._inflight.add("a.example")
        self.assertTrue(s.is_pending("a.example"))

    def test_accessors_do_not_queue_a_lookup(self):
        gsb = _FakeGSB()
        s = self._scanner(gsb=gsb)
        s.start()
        s.verdict_for("never.example")
        s.is_pending("never.example")
        time.sleep(0.2)
        self.assertEqual(gsb.calls, 0)
        self.assertEqual(s.stats()["sites"], 0)


class ProviderStatusTests(_ScannerCase):

    def test_states_reflect_configuration(self):
        s = self._scanner(cfg={"rep_scan": True, "rep_feeds": True,
                               "rep_gsb_key": "", "rep_vt_key": ""})
        by_name = {p["name"]: p for p in s.provider_status()}
        self.assertNotEqual(by_name["feeds"]["state"], rep.P_OFF)
        self.assertEqual(by_name["safebrowsing"]["state"], rep.P_OFF)
        self.assertEqual(by_name["virustotal"]["state"], rep.P_OFF)

    def test_everything_is_off_when_scanning_is_disabled(self):
        s = self._scanner(cfg=dict(CFG_ALL, rep_scan=False))
        self.assertTrue(all(p["state"] == rep.P_OFF
                            for p in s.provider_status()))
        self.assertEqual(s.overall_state()[0], rep.P_OFF)

    def test_overall_reports_a_problem_when_nothing_is_configured(self):
        s = self._scanner(cfg={"rep_scan": True, "rep_feeds": False,
                               "rep_gsb_key": "", "rep_vt_key": ""})
        self.assertEqual(s.overall_state()[0], rep.P_ERROR)


if __name__ == "__main__":
    unittest.main(verbosity=2)
