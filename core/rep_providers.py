"""
ProxyForce - Reputation providers

Three interchangeable sources of a verdict for a hostname, ordered by how much
traffic each can realistically cover:

  LocalFeedProvider   free malware/phishing feeds, matched locally against an
                      in-memory set. No key, no quota, instant. Checks EVERY
                      host. Only as fresh as the last feed download.

  SafeBrowsingProvider  Google Safe Browsing v4. Batches up to 500 hosts per
                      request against a ~10k requests/day quota, so it also
                      checks every host and is the primary filter. Needs a free
                      API key.

  VirusTotalProvider  VirusTotal v3 domain reports, 70+ engines aggregated. The
                      free tier is 4 lookups/minute and 500/day, which cannot
                      keep up with live browsing — so it is a BACKFILL tier that
                      works through hosts as quota allows and raises a flag when
                      it disagrees with the tiers above.

Stdlib only (see core/updater.py: "Stdlib only."). requirements.txt has no
`requests`, and the offline build hardcodes its wheel set in
STEP1_DOWNLOAD_WHEELS.bat / STEP2_BUILD_OFFLINE.bat, so a new pip dependency
would have to be added in five places. urllib.request is sufficient.

All outbound calls egress through the CONFIGURED CORPORATE PROXY via _opener(),
the same approach core/updater.py uses: while ProxyForce runs, the system proxy
points at its own loopback listeners and the TUN captures everything, so an
opener that honoured ambient settings would loop back into the tunnel it is
trying to report on.
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

_UA = "ProxyForce-Reputation"

# Tunable at import time so tests can shrink them (the convention used by
# core/updater.py's _HEALTH_INTERVAL / _STARTED_TIMEOUT).
_TIMEOUT = 30           # seconds, every API call
_FEED_TIMEOUT = 60      # seconds, feed downloads are larger

# Google Safe Browsing accepts at most 500 URLs per threatMatches:find request.
_GSB_MAX_BATCH = 500
_GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_GSB_THREATS = ["MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]

_VT_ENDPOINT = "https://www.virustotal.com/api/v3/domains/"
# A single fringe engine flagging a host is noise; VirusTotal aggregates 70+ of
# them and the low-quality ones produce steady false positives. Require two.
_VT_MIN_DETECTIONS = 2

# abuse.ch asks callers not to refetch more often than every 5 minutes; these are
# well inside that. OpenPhish's community feed updates roughly twice a day.
_FEED_SOURCES = (
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/hostfile/", 6 * 3600),
    ("openphish", "https://openphish.com/feed.txt", 12 * 3600),
)
# A corrupt or hostile feed should not exhaust memory.
_FEED_MAX_BYTES = 32 * 1024 * 1024


def _data_dir() -> str:
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "ProxyForce")


def _feed_dir() -> str:
    return os.path.join(_data_dir(), "reputation", "feeds")


# ── HTTP via the configured corporate proxy ───────────────────────────────────
def _opener(cfg: dict):
    """A urllib opener that egresses through the configured corporate proxy.

    Copied deliberately from core/updater.py:_opener rather than shared: the two
    have the same shape today but answer to different failure modes, and the
    updater's is load-bearing for self-update."""
    host = (cfg.get("host") or "").strip()
    port = cfg.get("port")
    if not host:
        return urllib.request.build_opener()
    auth = ""
    if cfg.get("auth_type") == "basic" and cfg.get("username"):
        u = urllib.parse.quote(str(cfg.get("username")), safe="")
        p = urllib.parse.quote(str(cfg.get("password") or ""), safe="")
        auth = f"{u}:{p}@"
    proxy = f"http://{auth}{host}:{port}"
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))


class RateLimited(Exception):
    """Provider answered 429. The caller must requeue, not drop, the hosts."""


def _api_get(opener, url, headers=None):
    req = urllib.request.Request(
        url, headers=dict({"User-Agent": _UA, "Accept": "application/json"},
                          **(headers or {})))
    with opener.open(req, timeout=_TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def _api_post(opener, url, payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"User-Agent": _UA, "Content-Type": "application/json"})
    with opener.open(req, timeout=_TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def _download(opener, url, max_bytes=_FEED_MAX_BYTES) -> str:
    """Fetch a text feed with a hard size cap, mirroring the running-total check
    core/updater.py:download applies to release zips."""
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    chunks = []
    total = 0
    with opener.open(req, timeout=_FEED_TIMEOUT) as r:
        declared = r.headers.get("Content-Length")
        if declared and int(declared) > max_bytes:
            raise ValueError(f"feed too large: {declared} bytes")
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("feed exceeded size cap mid-download")
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


# ── Tier 0: local feeds ───────────────────────────────────────────────────────
class LocalFeedProvider:
    """Known-bad hosts from free feeds, matched against an in-memory set.

    Costs one download per feed every few hours and nothing per host, so it runs
    for every hostname regardless of how much traffic there is."""

    name = "feeds"

    def __init__(self):
        self._hosts = set()
        self._fetched_at = {}     # source name -> epoch seconds
        self._loaded = False

    def available(self, cfg) -> bool:
        return bool(cfg.get("rep_feeds"))

    def entry_count(self) -> int:
        return len(self._hosts)

    def last_refresh(self) -> float:
        """Epoch seconds of the most recent successful feed fetch, or 0."""
        return max(self._fetched_at.values()) if self._fetched_at else 0.0

    def sources(self) -> list:
        """Per-feed detail for the status view: (name, fetched_at, stale)."""
        now = time.time()
        return [(name, self._fetched_at.get(name, 0.0),
                 now - self._fetched_at.get(name, 0.0) > ttl)
                for name, _url, ttl in _FEED_SOURCES]

    # Feed parsing ------------------------------------------------------------
    @staticmethod
    def _parse_hostfile(text: str) -> set:
        """A hosts-file feed: `127.0.0.1 evil.example`, with # comments."""
        out = set()
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            # Tolerate both "0.0.0.0 host" and a bare host per line.
            host = parts[1] if len(parts) >= 2 else parts[0]
            host = host.strip().lower().rstrip(".")
            if host and host not in ("localhost", "0.0.0.0", "127.0.0.1"):
                out.add(host)
        return out

    @staticmethod
    def _parse_urllist(text: str) -> set:
        """A URL-per-line feed: keep the hostname only, since HTTPS paths are
        never visible to us anyway (see the module docstring in core/reputation)."""
        out = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                host = urllib.parse.urlsplit(line).hostname
            except Exception:
                continue
            if host:
                out.add(host.lower().rstrip("."))
        return out

    def _parse(self, source: str, text: str) -> set:
        if source == "urlhaus":
            return self._parse_hostfile(text)
        return self._parse_urllist(text)

    # Refresh -----------------------------------------------------------------
    def _cache_path(self, source: str) -> str:
        return os.path.join(_feed_dir(), f"{source}.txt")

    def _load_cached(self):
        """Populate from disk so a restart is instantly useful and an offline
        machine keeps the last good feed."""
        for source, _url, _ttl in _FEED_SOURCES:
            path = self._cache_path(source)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self._hosts |= self._parse(source, f.read())
                self._fetched_at[source] = os.path.getmtime(path)
            except Exception:
                continue
        self._loaded = True

    def refresh(self, cfg, force=False) -> int:
        """Download any feed whose cache is older than its TTL. Returns the
        number of hosts now loaded. Never raises — a feed being unreachable must
        not take the scanner down."""
        if not self._loaded:
            self._load_cached()
        if not self.available(cfg):
            return len(self._hosts)
        now = time.time()
        opener = None
        for source, url, ttl in _FEED_SOURCES:
            if not force and now - self._fetched_at.get(source, 0) < ttl:
                continue
            try:
                if opener is None:
                    opener = _opener(cfg)
                text = _download(opener, url)
                hosts = self._parse(source, text)
                if not hosts:
                    continue    # empty parse = treat as a failed fetch, keep old
                os.makedirs(_feed_dir(), exist_ok=True)
                path = self._cache_path(source)
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write(text)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, path)
                self._hosts |= hosts
                self._fetched_at[source] = now
            except Exception:
                continue
        return len(self._hosts)

    def lookup(self, hosts, cfg) -> dict:
        """Return {host: (status, detail)} for hosts this feed knows are bad.
        Hosts it says nothing about are omitted — absence is not a clean verdict,
        only the absence of a known-bad listing."""
        if not self._loaded:
            self._load_cached()
        out = {}
        for host in hosts:
            hit = self._match(host)
            if hit:
                out[host] = ("malicious", f"listed in {self.name} ({hit})")
        return out

    def _match(self, host: str):
        """Exact host, then parent domains — a feed listing `evil.example` should
        also catch `cdn.evil.example`."""
        if host in self._hosts:
            return host
        parts = host.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._hosts:
                return parent
        return None


# ── Tier 1: Google Safe Browsing ──────────────────────────────────────────────
class SafeBrowsingProvider:
    """Google Safe Browsing v4 Lookup API.

    One POST carries up to 500 URLs against a ~10k requests/day quota, i.e. some
    millions of host checks a day — effectively unlimited for one machine, so it
    checks every host rather than being rationed."""

    name = "safebrowsing"

    def available(self, cfg) -> bool:
        return bool((cfg.get("rep_gsb_key") or "").strip())

    def lookup(self, hosts, cfg) -> dict:
        key = (cfg.get("rep_gsb_key") or "").strip()
        hosts = list(hosts)
        if not key or not hosts:
            return {}
        out = {}
        opener = _opener(cfg)
        for i in range(0, len(hosts), _GSB_MAX_BATCH):
            batch = hosts[i:i + _GSB_MAX_BATCH]
            out.update(self._lookup_batch(opener, key, batch))
        return out

    def _lookup_batch(self, opener, key, batch) -> dict:
        # Submitting "https://<host>/" makes GSB apply its normal host-suffix
        # expansion, so a listing on the bare domain matches too.
        payload = {
            "client": {"clientId": "proxyforce", "clientVersion": "1"},
            "threatInfo": {
                "threatTypes": _GSB_THREATS,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": f"https://{h}/"} for h in batch],
            },
        }
        url = f"{_GSB_ENDPOINT}?key={urllib.parse.quote(key, safe='')}"
        try:
            data = _api_post(opener, url, payload)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                raise RateLimited("safe browsing quota exceeded")
            raise
        out = {}
        # An empty object means nothing in the batch is listed. Only matched
        # entries come back, so a clean verdict is inferred from absence.
        for match in (data.get("matches") or []):
            threat = match.get("threat") or {}
            matched = threat.get("url") or ""
            host = urllib.parse.urlsplit(
                matched if "//" in matched else "https://" + matched).hostname
            if not host:
                continue
            host = host.lower().rstrip(".")
            kind = match.get("threatType") or "THREAT"
            ttl = _parse_cache_duration(match.get("cacheDuration"))
            out[host] = ("malicious", kind.replace("_", " ").title(), ttl)
        for host in batch:
            if host not in out:
                out[host] = ("clean", "not listed by Safe Browsing")
        return out


def _parse_cache_duration(value):
    """GSB returns e.g. "300.000s". Returns seconds as a float, or None."""
    if not value:
        return None
    try:
        return float(str(value).rstrip("s"))
    except ValueError:
        return None


# ── Tier 2: VirusTotal ────────────────────────────────────────────────────────
class VirusTotalProvider:
    """VirusTotal v3 domain reports — one host per request.

    The free tier is 4 requests/minute and 500/day, so this cannot be the filter
    that sees every connection. The scanner uses it to backfill, and the pacing
    and daily counter live in core/reputation (they must survive a restart, which
    a provider instance does not)."""

    name = "virustotal"

    def available(self, cfg) -> bool:
        return bool((cfg.get("rep_vt_key") or "").strip())

    def lookup_one(self, host, cfg):
        """Return (status, detail) for one host, or None if VT knows nothing.
        Raises RateLimited on 429 so the caller requeues instead of dropping."""
        key = (cfg.get("rep_vt_key") or "").strip()
        if not key or not host:
            return None
        opener = _opener(cfg)
        url = _VT_ENDPOINT + urllib.parse.quote(host, safe="")
        try:
            data = _api_get(opener, url, headers={"x-apikey": key})
        except urllib.error.HTTPError as e:
            if e.code == 429:
                raise RateLimited("virustotal quota exceeded")
            if e.code == 404:
                return ("unknown", "not in the VirusTotal dataset")
            raise
        stats = (((data.get("data") or {}).get("attributes") or {})
                 .get("last_analysis_stats") or {})
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        total = sum(int(v or 0) for v in stats.values())
        hits = malicious + suspicious
        if hits >= _VT_MIN_DETECTIONS:
            return ("malicious", f"{hits}/{total} engines flagged it")
        if total:
            return ("clean", f"{hits}/{total} engines flagged it")
        return ("unknown", "no VirusTotal analysis available")
