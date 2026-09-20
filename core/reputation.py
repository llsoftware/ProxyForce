"""
ProxyForce - Site reputation scanning

Watches the hostname of every new connection, checks each one ONCE, and
remembers the answer. A host that comes back clean is recorded as known-good and
never looked up again until its entry expires, so ordinary browsing generates
almost no traffic to the reputation providers after the first few days.

What is scanned
---------------
Every hostname. There are no exemptions: the scanner's own calls to the provider
APIs are hostnames too, and they are handled by the same mechanism as everything
else — a host is marked in-flight BEFORE its lookup is issued, so the connection
that lookup creates is deduplicated rather than queuing another lookup. Once the
verdict lands the provider's own host is cached clean like any other.

Only things that are not hostnames are skipped: raw IPs, loopback, private
ranges, and sing-box's fakeip range (a fakeip address is an internal placeholder,
never a real destination).

HTTPS is covered. sing-box hijacks DNS to fakeip, so it knows the destination
hostname for every connection including HTTPS, and the Clash API reports it.
What is NOT visible for HTTPS is the URL path, because ProxyForce never
terminates TLS — blocking a flagged host blocks every URL under it, but a
malicious path on an otherwise-reputable host cannot be seen. Plaintext HTTP on
port 80 does pass through core/local_proxy.py, where full URLs are available.

Provider contract
-----------------
A provider returns {host: (status, detail)} or {host: (status, detail, ttl)},
where ttl overrides the default cache lifetime for that verdict. Hosts a
provider says nothing about are omitted from its result — absence is not a clean
verdict, only the absence of a listing.

Threading
---------
observe() is called from SingBoxController's supervisor thread and must be cheap
and never raise: it takes a lock, updates a dict, and returns. All network work
happens on this module's own daemon threads, which report back through the
on_update callback. The GUI callback marshals onto the Tk thread via its queue —
see gui/app.py:_poll_queue.
"""

import ipaddress
import json
import os
import secrets
import threading
import time
from collections import deque

from core.rep_providers import (LocalFeedProvider, RateLimited,
                                SafeBrowsingProvider, VirusTotalProvider)

# Verdict states. "unknown" means every configured provider was asked and none
# of them had anything to say, which is different from "not yet checked" (no
# verdict at all).
CLEAN = "clean"
MALICIOUS = "malicious"
UNKNOWN = "unknown"
ERROR = "error"

# Cache lifetimes, in seconds. Module-level so tests can shrink them, matching
# the convention at core/updater.py:_HEALTH_INTERVAL.
_TTL = {
    # Long: the whole point is that a known-good site is never re-scanned. Safe
    # Browsing is cheap enough that this could be shorter, but VirusTotal is not.
    CLEAN: 30 * 86400,
    # Short: sites get cleaned up and delisted, and a stale block is worse than a
    # stale allow because the user notices it as breakage.
    MALICIOUS: 86400,
    UNKNOWN: 3600,
    ERROR: 900,
}

# Fast path: how many hosts to accumulate before flushing to Safe Browsing, and
# how long to wait for stragglers. GSB's hard limit is 500 per request; batching
# smaller keeps a page load's worth of hosts moving quickly.
_BATCH_SIZE = 100
_BATCH_WAIT = 2.0

# VirusTotal free tier: 4 requests/minute, 500/day. 15.5s leaves margin against
# the minute window so a burst cannot trip 429.
_VT_MIN_INTERVAL = 15.5
_VT_DAILY_CAP = 500
_VT_BACKOFF = 60.0      # after a 429, before trying again
_VT_IDLE_WAIT = 5.0     # backstop when the backlog is empty; _vt_wake is the
                        # normal path, so this only covers a missed signal

_FEED_CHECK_INTERVAL = 900      # how often to consider refreshing the feeds
_CACHE_FLUSH_INTERVAL = 30      # coalesce cache writes rather than one per host
_MAX_CACHE_ENTRIES = 50000      # bound the on-disk cache on very long runs

# sing-box hands out addresses from this range as DNS placeholders; they are
# never real destinations. See FAKEIP_V4 in core/singbox_controller.py.
_FAKEIP_V4 = ipaddress.ip_network("198.18.0.0/15")


def _data_dir() -> str:
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "ProxyForce")


def _rep_dir() -> str:
    return os.path.join(_data_dir(), "reputation")


def _cache_path() -> str:
    return os.path.join(_rep_dir(), "cache.json")


def _quota_path() -> str:
    return os.path.join(_rep_dir(), "quota.json")


def normalize_host(host) -> str:
    """Canonical scan key, or "" if this is not a scannable hostname.

    Rejects raw IPs (including the fakeip placeholders, loopback and private
    ranges) because a reputation lookup on them is meaningless, and callers hand
    us whatever sing-box reported — which is an IP whenever no name was sniffed.
    """
    if not host:
        return ""
    host = str(host).strip().lower()
    if not host or " " in host:
        return ""
    # Strip a :port and unwrap a bracketed IPv6 literal. This must happen
    # BEFORE the trailing dot is removed: a rooted FQDN with a port reads
    # "example.com.:443", where the dot is not at the end of the string.
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    host = host.rstrip(".")
    if not host:
        return ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass    # not an IP literal, so it is a hostname — the case we want
    else:
        return ""   # loopback, private, fakeip, public: none are scannable
    if "." not in host:
        return ""   # single-label (intranet shortname, "localhost"): not public
    return host


def _is_unscannable_ip(host) -> bool:
    """True for addresses that should not even appear in the Sites list."""
    try:
        ip = ipaddress.ip_address(str(host).strip())
    except ValueError:
        return False
    return (ip.is_loopback or ip.is_private or ip.is_link_local
            or ip.is_multicast or ip.is_unspecified or ip in _FAKEIP_V4)


class Verdict(object):
    """One provider's answer about one host, plus when it expires."""

    __slots__ = ("host", "status", "source", "detail", "checked_at", "expires_at")

    def __init__(self, host, status, source="", detail="", checked_at=None,
                 expires_at=None):
        self.host = host
        self.status = status
        self.source = source
        self.detail = detail
        self.checked_at = time.time() if checked_at is None else checked_at
        if expires_at is None:
            expires_at = self.checked_at + _TTL.get(status, _TTL[UNKNOWN])
        self.expires_at = expires_at

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at

    def to_dict(self) -> dict:
        return {"status": self.status, "source": self.source,
                "detail": self.detail, "checked_at": self.checked_at,
                "expires_at": self.expires_at}

    @classmethod
    def from_dict(cls, host, d):
        try:
            return cls(host, str(d["status"]), str(d.get("source") or ""),
                       str(d.get("detail") or ""), float(d.get("checked_at") or 0),
                       float(d["expires_at"]))
        except Exception:
            return None

    def __repr__(self):
        return f"<Verdict {self.host} {self.status} via {self.source}>"


class SiteRecord(object):
    """What the Sites view shows for one host. Populated whether or not scanning
    is enabled — the list of sites you connected to is useful on its own."""

    __slots__ = ("host", "conns", "first_seen", "last_seen", "route",
                 "verdict", "pending", "conn_ids")

    def __init__(self, host):
        self.host = host
        self.conns = 0
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.route = ""
        self.verdict = None
        self.pending = False
        self.conn_ids = set()

    @property
    def status(self) -> str:
        if self.verdict is not None:
            return self.verdict.status
        return "pending" if self.pending else ""


# Provider states, in ascending order of "something is wrong". The Scanning tab
# renders each as a coloured beacon.
P_OFF = "off"           # not configured / switched off — grey
P_IDLE = "idle"         # configured, nothing asked of it yet — blue
P_OK = "ok"             # answering normally — green
P_LIMITED = "limited"   # working but rationed (quota reached, stale feed) — amber
P_ERROR = "error"       # failing — red


class ProviderStatus(object):
    """Live health of one provider, for the Scanning tab."""

    __slots__ = ("name", "label", "role", "state", "detail", "last_ok",
                 "last_error", "calls", "hosts", "extra")

    def __init__(self, name, label, role):
        self.name = name
        self.label = label
        self.role = role
        self.state = P_OFF
        self.detail = ""
        self.last_ok = 0.0
        self.last_error = ""
        self.calls = 0
        self.hosts = 0
        self.extra = {}

    def to_dict(self) -> dict:
        return {"name": self.name, "label": self.label, "role": self.role,
                "state": self.state, "detail": self.detail,
                "last_ok": self.last_ok, "last_error": self.last_error,
                "calls": self.calls, "hosts": self.hosts, "extra": dict(self.extra)}


class ReputationScanner(object):
    """Owns the dedupe set, the verdict cache, the queues and the worker threads.

    `load_cfg` is a callable returning the current config dict, re-read each
    cycle so toggling a setting takes effect without a restart. `on_update` is
    called with a SiteRecord whenever a row changes; it must be cheap and
    thread-safe (the GUI's puts it on a queue)."""

    def __init__(self, load_cfg, on_update=None, on_log=None):
        self._load_cfg = load_cfg
        self._on_update = on_update
        self._on_log = on_log

        self._lock = threading.RLock()
        self._sites = {}            # host -> SiteRecord
        self._cache = {}            # host -> Verdict
        self._inflight = set()      # hosts queued or being looked up
        self._pending = deque()     # fast path: feeds + Safe Browsing
        self._vt_backlog = deque()  # VirusTotal backfill, oldest first
        self._vt_done = set()       # hosts VirusTotal has already answered on

        self._feeds = LocalFeedProvider()
        self._gsb = SafeBrowsingProvider()
        self._vt = VirusTotalProvider()

        self._pstatus = {
            self._feeds.name: ProviderStatus(
                self._feeds.name, "Malware & phishing feeds", "every host"),
            self._gsb.name: ProviderStatus(
                self._gsb.name, "Google Safe Browsing", "every host"),
            self._vt.name: ProviderStatus(
                self._vt.name, "VirusTotal", "backfill, 4/min"),
        }
        self._flagged = deque(maxlen=50)    # recent hits, newest first

        self._quota = {}
        self._cache_dirty = False
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._vt_wake = threading.Event()
        self._threads = []

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self):
        if self._threads:
            return
        self._load_cache()
        self._load_quota()
        self._stop.clear()
        for target in (self._fast_loop, self._vt_loop):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        self._stop.set()
        self._wake.set()
        self._vt_wake.set()
        for t in self._threads:
            try:
                t.join(timeout=5)
            except Exception:
                pass
        self._threads = []
        self._save_cache(force=True)

    def _log(self, msg, level="info"):
        if self._on_log:
            try:
                self._on_log(msg, level)
            except Exception:
                pass

    def _emit(self, record):
        if self._on_update:
            try:
                self._on_update(record)
            except Exception:
                pass

    # ── the hot path ─────────────────────────────────────────────────────────
    def observe(self, host, port=None, route="", conn_id=None):
        """Record a new connection. Called from the sing-box supervisor thread
        on every new connection, so it does no I/O and never raises."""
        try:
            self._observe(host, port, route, conn_id)
        except Exception:
            pass

    def _observe(self, host, port, route, conn_id):
        raw = str(host or "").strip().lower().rstrip(".")
        if not raw or _is_unscannable_ip(raw):
            return
        key = normalize_host(raw) or raw
        with self._lock:
            record = self._sites.get(key)
            if record is None:
                record = SiteRecord(key)
                self._sites[key] = record
            record.conns += 1
            record.last_seen = time.time()
            if route:
                record.route = route
            if conn_id:
                record.conn_ids.add(conn_id)

            queued = self._consider(key, record)
        self._emit(record)
        if queued:
            self._wake.set()

    def _consider(self, key, record) -> bool:
        """Decide whether this host needs a lookup. Caller holds the lock.

        Marking in-flight here — before any request is issued — is what stops the
        scanner from recursing on the provider API hostnames its own lookups
        connect to."""
        cfg = self._cfg()
        if not cfg.get("rep_scan"):
            return False
        if not normalize_host(key):
            return False
        if key in self._inflight:
            return False
        cached = self._cache.get(key)
        if cached is not None and not cached.expired:
            # The common case once warmed up: the host is already known-good, so
            # nothing queues and no provider is contacted. This is what "scanned
            # once, then remembered" means in practice.
            if record.verdict is not cached:
                record.verdict = cached
                record.pending = False
            return False
        self._inflight.add(key)
        record.pending = True
        self._pending.append(key)
        return True

    def _cfg(self) -> dict:
        try:
            return self._load_cfg() or {}
        except Exception:
            return {}

    # ── fast path: feeds + Safe Browsing ─────────────────────────────────────
    def _fast_loop(self):
        last_feed_check = 0.0
        last_flush = time.time()
        while not self._stop.is_set():
            cfg = self._cfg()
            now = time.time()
            if cfg.get("rep_scan") and now - last_feed_check >= _FEED_CHECK_INTERVAL:
                last_feed_check = now
                try:
                    count = self._feeds.refresh(cfg)
                    if count:
                        self._log(f"Reputation feeds loaded: {count:,} known-bad hosts.",
                                  "debug")
                except Exception:
                    pass

            batch = self._take_batch()
            if batch:
                try:
                    self._scan_batch(batch, cfg)
                except RateLimited:
                    self._requeue(batch)
                    self._stop.wait(_VT_BACKOFF)
                except Exception as e:
                    self._fail_batch(batch, str(e))
            else:
                self._wake.wait(_BATCH_WAIT)
                self._wake.clear()

            if time.time() - last_flush >= _CACHE_FLUSH_INTERVAL:
                last_flush = time.time()
                self._save_cache()

    def _take_batch(self):
        with self._lock:
            batch = []
            while self._pending and len(batch) < _BATCH_SIZE:
                batch.append(self._pending.popleft())
            return batch

    def _requeue(self, hosts):
        with self._lock:
            for h in reversed(hosts):
                self._pending.appendleft(h)

    def _fail_batch(self, hosts, detail):
        for host in hosts:
            self._record(host, Verdict(host, ERROR, "scanner", detail))

    def _scan_batch(self, batch, cfg):
        remaining = list(batch)
        results = {}        # host -> (status, detail, ttl, source)

        # Tier 0 — local feeds. Free and instant, so it sees every host.
        if self._feeds.available(cfg):
            try:
                hits = self._feeds.lookup(remaining, cfg)
                for host, value in hits.items():
                    status, detail, ttl = _unpack(value)
                    results[host] = (status, detail, ttl, self._feeds.name)
                self._mark(self._feeds.name, ok=True, hosts=len(remaining),
                           entries=self._feeds.entry_count(),
                           refreshed=self._feeds.last_refresh())
            except Exception as e:
                self._mark(self._feeds.name, error=str(e))
            remaining = [h for h in remaining if h not in results]

        # Tier 1 — Safe Browsing. Batched and effectively unlimited, so it also
        # sees every host the feeds did not already condemn.
        if remaining and self._gsb.available(cfg):
            try:
                hits = self._gsb.lookup(remaining, cfg)
                for host, value in hits.items():
                    status, detail, ttl = _unpack(value)
                    results[host] = (status, detail, ttl, self._gsb.name)
                self._mark(self._gsb.name, ok=True, hosts=len(remaining), calls=1)
            except RateLimited:
                self._mark(self._gsb.name, limited="daily quota exceeded")
                raise
            except Exception as e:
                self._mark(self._gsb.name, error=str(e))
                raise
            remaining = [h for h in remaining if h not in results]

        # Anything nobody could answer: recorded as unknown, retried when the
        # short UNKNOWN ttl lapses.
        for host in remaining:
            results[host] = (UNKNOWN, "no reputation source could answer",
                             None, "scanner")

        for host, (status, detail, ttl, source) in results.items():
            expires = time.time() + ttl if ttl else None
            self._record(host, Verdict(host, status, source, detail,
                                       expires_at=expires))
            # Tier 2 — queue VirusTotal for a second opinion on anything not
            # already condemned. It cannot keep up with live traffic at 4/min, so
            # it drains in its own time, oldest first. Spending a 500/day budget
            # re-confirming a host the feeds already condemned is waste.
            if status != MALICIOUS and self._vt.available(cfg):
                with self._lock:
                    if host not in self._vt_done:
                        self._vt_backlog.append(host)
                        self._vt_wake.set()

    # ── backfill: VirusTotal ─────────────────────────────────────────────────
    def _vt_loop(self):
        while not self._stop.is_set():
            cfg = self._cfg()
            if not (cfg.get("rep_scan") and self._vt.available(cfg)):
                self._stop.wait(_VT_IDLE_WAIT)
                continue
            host = self._next_vt_host()
            if host is None:
                # Woken as soon as the fast path queues something, so a new host
                # is picked up immediately rather than after a fixed poll.
                self._vt_wake.wait(_VT_IDLE_WAIT)
                self._vt_wake.clear()
                continue
            if not self._vt_take_quota():
                # Daily cap reached: hold the host and try again after the reset.
                self._mark(self._vt.name,
                           limited=f"daily cap reached ({_VT_DAILY_CAP})")
                with self._lock:
                    self._vt_backlog.appendleft(host)
                self._stop.wait(60)
                continue
            try:
                result = self._vt.lookup_one(host, cfg)
                self._mark(self._vt.name, ok=True, calls=1, hosts=1)
            except RateLimited:
                # Requeue rather than drop: a 429 means "later", not "no".
                self._mark(self._vt.name, limited="rate limited (429), backing off")
                with self._lock:
                    self._vt_backlog.appendleft(host)
                self._stop.wait(_VT_BACKOFF)
                continue
            except Exception as e:
                self._mark(self._vt.name, error=str(e))
                result = None
            with self._lock:
                self._vt_done.add(host)
            if result:
                status, detail, ttl = _unpack(result)
                prior = self._cache.get(host)
                # Only overwrite with something more severe, or when nothing
                # better is known. A VT "clean" must not downgrade a Safe
                # Browsing "malicious".
                if status == MALICIOUS or prior is None or prior.status != MALICIOUS:
                    self._record(host, Verdict(
                        host, status, self._vt.name, detail,
                        expires_at=time.time() + ttl if ttl else None))
            self._stop.wait(_VT_MIN_INTERVAL)

    def _next_vt_host(self):
        with self._lock:
            while self._vt_backlog:
                host = self._vt_backlog.popleft()
                if host not in self._vt_done:
                    return host
            return None

    def _vt_take_quota(self) -> bool:
        """Consume one VirusTotal daily-quota token. Persisted, so restarting the
        app cannot reset the counter and blow through the 500/day cap."""
        today = time.strftime("%Y-%m-%d")
        with self._lock:
            slot = self._quota.get("vt") or {}
            if slot.get("date") != today:
                slot = {"date": today, "count": 0}
            if slot["count"] >= _VT_DAILY_CAP:
                self._quota["vt"] = slot
                return False
            slot["count"] += 1
            self._quota["vt"] = slot
            self._save_quota()
            return True

    # ── verdict bookkeeping ──────────────────────────────────────────────────
    def _record(self, host, verdict):
        with self._lock:
            prior = self._cache.get(host)
            self._cache[host] = verdict
            self._cache_dirty = True
            self._inflight.discard(host)
            record = self._sites.get(host)
            if record is None:
                record = SiteRecord(host)
                self._sites[host] = record
            record.verdict = verdict
            record.pending = False
            newly_bad = (verdict.status == MALICIOUS
                         and (prior is None or prior.status != MALICIOUS))
            if newly_bad:
                self._flagged.appendleft(
                    {"host": host, "source": verdict.source,
                     "detail": verdict.detail, "at": verdict.checked_at})
        if newly_bad:
            self._log(f"⚠ {host} flagged by {verdict.source}: "
                      f"{verdict.detail}", "error")
        self._emit(record)

    def rescan_all(self):
        """Re-queue every known site. Used when scanning is switched on, so the
        hosts seen while it was off get checked rather than sitting blank."""
        with self._lock:
            for host, record in self._sites.items():
                if not normalize_host(host) or host in self._inflight:
                    continue
                cached = self._cache.get(host)
                if cached is not None and not cached.expired:
                    record.verdict = cached
                    continue
                self._inflight.add(host)
                record.pending = True
                self._pending.append(host)
        self._wake.set()

    def _mark(self, name, ok=False, error="", limited="", calls=0, hosts=0,
              **extra):
        """Record one provider interaction for the Scanning tab. Never raises."""
        try:
            with self._lock:
                st = self._pstatus.get(name)
                if st is None:
                    return
                st.calls += calls
                st.hosts += hosts
                if error:
                    st.state = P_ERROR
                    st.last_error = error
                    st.detail = error
                elif limited:
                    st.state = P_LIMITED
                    st.detail = limited
                elif ok:
                    st.state = P_OK
                    st.last_ok = time.time()
                    st.last_error = ""
                    st.detail = ""
                for k, v in extra.items():
                    st.extra[k] = v
        except Exception:
            pass

    def provider_status(self) -> list:
        """Live per-provider health, ordered as traffic flows through them."""
        cfg = self._cfg()
        scanning = bool(cfg.get("rep_scan"))
        now = time.time()
        with self._lock:
            feeds, gsb, vt = (self._pstatus[self._feeds.name],
                              self._pstatus[self._gsb.name],
                              self._pstatus[self._vt.name])

            feeds.extra["entries"] = self._feeds.entry_count()
            feeds.extra["refreshed"] = self._feeds.last_refresh()
            feeds.extra["sources"] = self._feeds.sources()

            slot = self._quota.get("vt") or {}
            used = int(slot.get("count") or 0) if slot.get(
                "date") == time.strftime("%Y-%m-%d") else 0
            vt.extra["used_today"] = used
            vt.extra["cap"] = _VT_DAILY_CAP
            vt.extra["queued"] = len(self._vt_backlog)
            vt.extra["interval"] = _VT_MIN_INTERVAL
            gsb.extra["queued"] = len(self._pending)

            out = []
            for provider, st in ((self._feeds, feeds), (self._gsb, gsb),
                                 (self._vt, vt)):
                available = provider.available(cfg)
                if not scanning:
                    st.state = P_OFF
                    st.detail = "scanning is off"
                elif not available:
                    st.state = P_OFF
                    st.detail = ("no API key" if provider is not self._feeds
                                 else "disabled in settings")
                elif st.state in (P_OFF, P_IDLE):
                    st.state = P_IDLE
                    st.detail = "waiting for a new site"
                # A feed that has not refreshed within its TTL is still matching,
                # just against ageing data — worth showing as rationed, not OK.
                if (provider is self._feeds and st.state == P_OK
                        and any(stale for _n, _t, stale in self._feeds.sources())):
                    st.state = P_LIMITED
                    st.detail = "feed data is stale"
                if (provider is self._vt and st.state in (P_OK, P_IDLE)
                        and used >= _VT_DAILY_CAP):
                    st.state = P_LIMITED
                    st.detail = f"daily cap reached ({used}/{_VT_DAILY_CAP})"
                out.append(st.to_dict())
            return out

    def overall_state(self) -> tuple:
        """(state, headline) for the Scanning tab's hero line."""
        cfg = self._cfg()
        if not cfg.get("rep_scan"):
            return P_OFF, "Scanning is off"
        statuses = self.provider_status()
        live = [s for s in statuses if s["state"] not in (P_OFF,)]
        if not live:
            return P_ERROR, "No reputation source is configured"
        if any(s["state"] == P_ERROR for s in live):
            failing = ", ".join(s["label"] for s in live if s["state"] == P_ERROR)
            return P_ERROR, f"Not reachable: {failing}"
        if any(s["state"] == P_LIMITED for s in live):
            return P_LIMITED, "Scanning, with one source rationed"
        st = self.stats()
        return P_OK, (f"Scanning · {st['known_good']:,} known good, "
                      f"{st['flagged']:,} flagged")

    def recent_flags(self) -> list:
        with self._lock:
            return list(self._flagged)

    def verdict_for(self, host):
        """The cached verdict for a host, or None if it has not been checked.
        Cheap enough to call once per connection as the live feed renders."""
        key = normalize_host(host) or str(host or "").strip().lower()
        with self._lock:
            verdict = self._cache.get(key)
            if verdict is not None and not verdict.expired:
                return verdict
            if key in self._inflight:
                return None
            return None

    def is_pending(self, host) -> bool:
        key = normalize_host(host) or str(host or "").strip().lower()
        with self._lock:
            return key in self._inflight

    def sites(self):
        with self._lock:
            return list(self._sites.values())

    def stats(self) -> dict:
        with self._lock:
            known_good = sum(1 for v in self._cache.values() if v.status == CLEAN)
            flagged = sum(1 for v in self._cache.values() if v.status == MALICIOUS)
            unknown = sum(1 for v in self._cache.values()
                          if v.status in (UNKNOWN, ERROR))
            unscanned = sum(1 for r in self._sites.values()
                            if r.verdict is None and not r.pending)
            vt = self._quota.get("vt") or {}
            used = int(vt.get("count") or 0) if vt.get(
                "date") == time.strftime("%Y-%m-%d") else 0
            return {"sites": len(self._sites), "known_good": known_good,
                    "flagged": flagged, "unknown": unknown,
                    "unscanned": unscanned, "queued": len(self._pending),
                    "inflight": len(self._inflight),
                    "vt_queued": len(self._vt_backlog), "vt_used_today": used,
                    "vt_cap": _VT_DAILY_CAP,
                    "feed_entries": self._feeds.entry_count()}

    def conn_ids_for(self, host):
        with self._lock:
            record = self._sites.get(host)
            return set(record.conn_ids) if record else set()

    # ── persistence ──────────────────────────────────────────────────────────
    def _load_cache(self):
        data = _read_json(_cache_path())
        now = time.time()
        with self._lock:
            for host, d in (data.get("hosts") or {}).items():
                verdict = Verdict.from_dict(host, d)
                if verdict is not None and verdict.expires_at > now:
                    self._cache[host] = verdict

    def _save_cache(self, force=False):
        with self._lock:
            if not (self._cache_dirty or force):
                return
            now = time.time()
            items = [(h, v) for h, v in self._cache.items() if v.expires_at > now]
            if len(items) > _MAX_CACHE_ENTRIES:
                items.sort(key=lambda kv: kv[1].checked_at, reverse=True)
                items = items[:_MAX_CACHE_ENTRIES]
            payload = {"hosts": {h: v.to_dict() for h, v in items}}
            self._cache_dirty = False
        _write_json(_cache_path(), payload)

    def _load_quota(self):
        self._quota = _read_json(_quota_path()) or {}

    def _save_quota(self):
        _write_json(_quota_path(), self._quota)


def _unpack(value):
    """Normalise a provider result to (status, detail, ttl_or_None)."""
    if isinstance(value, (tuple, list)):
        if len(value) >= 3:
            return value[0], value[1], value[2]
        if len(value) == 2:
            return value[0], value[1], None
    return UNKNOWN, str(value), None


def _read_json(path) -> dict:
    """Returns {} on any failure, matching core/updater.py:load_state."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_json(path, payload):
    """Atomic replace via a randomly-named temp file, the same shape as
    core/updater.py:save_state. Best-effort: a cache we cannot write is a
    performance problem, not a correctness one."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.{secrets.token_hex(8)}.tmp"
        try:
            with open(tmp, "x", encoding="utf-8") as f:
                json.dump(payload, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
    except Exception:
        pass
