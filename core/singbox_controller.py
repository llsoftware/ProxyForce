"""
ProxyForce - sing-box Controller (engine)

Re-platforms ProxyForce off the hand-rolled WinDivert loopback engine and onto
sing-box running in TUN -> HTTP-CONNECT mode. This module is a DROP-IN
replacement for the old core.redirector.Redirector: it exposes the same
constructor signature, the same on_state_change / on_stats_update / on_log
callbacks, the same ProxyConfig / ConnectionStats shapes, and start()/stop().
main.py's engine_loop therefore needs only a one-line import change.

WHY TUN + FAKEIP (validated against sing-box 1.13.12 on 2026-05-31):
  * TUN is a real L3 interface, so there is no 127.0.0.1 "loopback martian"
    drop and no re-capture loop (the two failures that sank the WinDivert build).
  * Many inspecting corporate proxies do SNI-based HTTPS inspection and BLOCK
    CONNECT-by-raw-IP. So the proxy CONNECT request MUST carry a hostname.
  * In sing-box 1.13 a bare `{"action":"sniff"}` does NOT override the
    destination (the OverrideDestination field is no longer settable from JSON),
    so sniff alone yields CONNECT-by-IP -> blocked. The mechanism that DOES make
    sing-box CONNECT by hostname is FAKEIP: sing-box answers DNS with a synthetic
    IP, the app connects to it, sing-box maps the fake IP back to the domain, and
    the http outbound issues `CONNECT <hostname>:port`. This was proven
    end-to-end (fake proxy received "CONNECT example.com:443").

Stats come from sing-box's Clash API (/connections, /traffic) on a loopback port.
"""

import os
import re
import sys
import json
import time
import base64
import socket
import ctypes
import winreg
import threading
import subprocess
import ipaddress
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Callable, List

import logging

from core._version import __version__ as APP_VERSION

logger = logging.getLogger("proxyforce.singbox")

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# A urllib opener that NEVER routes through a system/corporate proxy. The Clash
# API lives on 127.0.0.1, but urllib.request.urlopen() honors the WinINET system
# proxy by default — and a corporate proxy often has no localhost bypass. When
# ProxyForce is pointed at such a proxy, every probe to 127.0.0.1:<clash port>
# gets sent THROUGH the proxy, which answers 403 → the probe returns None.
# That false "not ready" is what silently killed a perfectly healthy sing-box
# ~30s after launch (readiness timeout) and pinned the stats dashboard at zero
# (stats reads failed the same way). Force a direct loopback connection.
_LOOPBACK_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# ── Windows Job Object (kill sing-box when the GUI process dies) ──────────────
# If the GUI crashes without calling stop(), the OS kills sing-box automatically
# because its process handle is assigned to this kill-on-close job object.

_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_JOB_OBJECT_EXTENDED_LIMIT_INFO     = 9   # JobObjectExtendedLimitInformation


class _JOBasicLimit(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit",     ctypes.c_longlong),
        ("LimitFlags",              ctypes.c_ulong),
        ("MinimumWorkingSetSize",   ctypes.c_size_t),
        ("MaximumWorkingSetSize",   ctypes.c_size_t),
        ("ActiveProcessLimit",      ctypes.c_ulong),
        ("Affinity",                ctypes.c_void_p),
        ("PriorityClass",           ctypes.c_ulong),
        ("SchedulingClass",         ctypes.c_ulong),
    ]


class _JOExtLimit(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBasicLimit),
        ("IoInfo",                ctypes.c_ulonglong * 6),   # IO_COUNTERS
        ("ProcessMemoryLimit",    ctypes.c_size_t),
        ("JobMemoryLimit",        ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed",     ctypes.c_size_t),
    ]


_job_handle = None


def _ensure_job():
    """Create (once) a Windows Job Object that kills all children on close."""
    global _job_handle
    if _job_handle is not None:
        return _job_handle
    try:
        k32  = ctypes.windll.kernel32
        job  = k32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = _JOExtLimit()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if k32.SetInformationJobObject(job, _JOB_OBJECT_EXTENDED_LIMIT_INFO,
                                        ctypes.byref(info), ctypes.sizeof(info)):
            _job_handle = job
            return job
        k32.CloseHandle(job)
    except Exception:
        pass
    return None

# sing-box fakeip range (RFC-reserved benchmarking block; never real traffic).
# IPv6 TUN is intentionally omitted: on Windows 10 the OS performs IPv6
# neighbour-discovery on the TUN adapter which crashes sing-box (exit code 1).
FAKEIP_V4 = "198.18.0.0/15"

# TUN interface — IPv4 only for maximum Win 10 compatibility.
TUN_NAME = "ProxyForce"
TUN_V4   = "172.19.0.1/30"

# ── Windows-10 wintun launch tuning ──────────────────────────────────────────
# On Windows 10 (works on 11) sing-box's wintun adapter creation hits a well-known
# timing bug — "configure tun interface: Cannot create a file when that file
# already exists" — when a previous adapter has not finished being torn down, or
# when an orphaned sing-box still owns it. The documented community workaround is
# simply to retry: once the stale adapter is released, the next attempt succeeds.
# ProxyForce automates that here (preflight cleanup + bounded auto-retry).
_LAUNCH_ATTEMPTS = 3       # total sing-box launch attempts before giving up
_READY_TIMEOUT   = 30      # seconds to wait for the Clash API per attempt
_ADAPTER_WAIT    = 15      # seconds to wait for a stale TUN adapter to disappear
_ADAPTER_SETTLE  = 3.0     # extra settle so CreateAdapter doesn't race teardown

# sing-box log levels we allow the config's log_level to select. Kept deliberately
# small: "debug" is the verbose capture trace (large logs on long runs — see
# _render_config), "info" the sane default, "warn" the quietest useful level.
_SINGBOX_LOG_LEVELS = {"debug", "info", "warn"}
_DEFAULT_LOG_LEVEL  = "info"

_NCSI_SETTLE_SECONDS = 10
_NCSI_REFRESH_SECONDS = 8


class SingBoxState(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class ProxyConfig:
    host: str
    port: int
    auth_type: str = "none"        # none | basic
    username: str = ""
    password: str = ""
    exclude_private: bool = True    # send RFC1918 / ULA / link-local direct
    exclude_loopback: bool = True
    bypass_list: list = None        # extra hosts/CIDRs to send DIRECT
    log_level: str = "info"         # sing-box log verbosity (see _SINGBOX_LOG_LEVELS)
    auto_bypass: bool = True        # auto-add + reconnect when the proxy explicitly
                                     # refuses a CONNECT, instead of requiring a manual
                                     # Bypass List edit (core.auto_bypass)

    def __post_init__(self):
        if self.bypass_list is None:
            self.bypass_list = []


@dataclass
class ConnectionStats:
    active_connections: int = 0
    total_connections: int = 0
    bytes_forwarded: int = 0
    start_time: float = 0.0

    def uptime_str(self) -> str:
        if self.start_time == 0:
            return "00:00:00"
        elapsed = int(time.time() - self.start_time)
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def bytes_str(self) -> str:
        b = float(self.bytes_forwarded)
        for unit in ["B", "KB", "MB", "GB"]:
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"


def _data_dir() -> str:
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "ProxyForce")


def _singbox_dir() -> str:
    return os.path.join(_data_dir(), "singbox")


def _find_singbox_exe() -> Optional[str]:
    """Locate the bundled sing-box.exe across frozen-onedir and source layouts."""
    candidates: List[str] = []
    mei = getattr(sys, "_MEIPASS", None)
    if mei:
        candidates.append(os.path.join(mei, "singbox", "sing-box.exe"))
    if getattr(sys, "frozen", False):
        exedir = os.path.dirname(sys.executable)
    else:
        exedir = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(exedir, "_internal", "singbox", "sing-box.exe"))
    candidates.append(os.path.join(exedir, "singbox", "sing-box.exe"))
    # source / dev tree: <repo>/vendor/singbox/sing-box.exe
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.normpath(os.path.join(here, "..", "vendor", "singbox", "sing-box.exe")))
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def _free_loopback_ports(n: int = 1) -> List[int]:
    """Grab `n` DISTINCT free 127.0.0.1 TCP ports.

    All sockets are held open until every port has been chosen, then closed
    together — otherwise allocating them one-at-a-time (bind→read→close, repeat)
    lets the OS hand the just-freed port back on the next call, so two "free"
    ports could collide (e.g. clash_port == local_proxy_port → one sing-box bind
    fails). Holding them open guarantees distinct ports.
    """
    socks = []
    try:
        for _ in range(n):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            socks.append(s)
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


def _free_loopback_port() -> int:
    """Grab a single free 127.0.0.1 TCP port for the Clash API."""
    return _free_loopback_ports(1)[0]


# Fixed defaults for (clash_port, local_proxy_port, http_proxy_port) — v2.2.2.
# 18080/18081 are the pre-existing hardcoded fallback constants already baked
# into _render_config (used when it's called without going through start(), e.g.
# tests) for local_proxy_port/http_proxy_port respectively; 18089 is a new pick
# for clash_port, distinct from both.
_DEFAULT_PORTS = (18089, 18080, 18081)


def _bind_ports_preferring(preferred, log=None) -> List[int]:
    """Bind each port in `preferred` if free; for any already taken by something
    else, fall back to an OS-ephemeral port for JUST that one slot. Returns the
    assigned ports in the same order as `preferred`.

    WHY FIXED PORTS AT ALL (diagnosed 2026-08-08): _free_loopback_ports always
    picked a fresh OS-ephemeral port, so every ProxyForce restart changed the
    HTTP_PROXY/HTTPS_PROXY env vars and the WinINET/WinHTTP proxy string to new
    port numbers. Windows never propagates an env-var change to an
    already-running process — a process's environment block is fixed at its own
    creation time — so an already-open shell (Claude Code, PowerShell, anything
    else reading those vars) silently broke on every ProxyForce restart and
    needed to be closed and reopened to pick up the new value. Keeping the SAME
    port numbers across an ordinary restart (the common case — nothing else is
    squatting on 18080/18081/18089) means the env vars/system-proxy string don't
    change, so nothing downstream needs to be restarted either.

    Genuine conflicts (rare) still degrade gracefully to an ephemeral port for
    just that slot, logged clearly — no regression for that case, just no longer
    the default path.

    All sockets are held open until every slot is resolved, then closed together
    — same anti-collision technique as _free_loopback_ports (guards against an
    ephemeral fallback landing on a not-yet-closed slot; in practice Windows'
    ephemeral range starts well above these fixed numbers, so this is defense in
    depth rather than an observed real collision)."""
    socks = []
    try:
        for port in preferred:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                if log:
                    log(f"Port {port} is in use by another process — using an "
                        f"ephemeral port for this run instead (env vars/system "
                        f"proxy will change this time).", "info")
                s.bind(("127.0.0.1", 0))
            socks.append(s)
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


# NCSI (Network Connectivity Status Indicator) is the service that decides whether
# Windows believes it has internet access (Get-NetConnectionProfile's
# IPv4Connectivity). Its DNS probe resolves ActiveDnsProbeHost and requires the
# answer to be EXACTLY ActiveDnsProbeContent. Under fakeip the answer is a
# 198.18.x.x address instead, so NCSI reports "no internet" — which silently
# starves every component gating on connectivity level (Windows Spotlight,
# Store, Widgets, Teams presence). Diagnosed 2026-08-07.
_NCSI_KEY = r"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
_NCSI_DNS_HOST_DEFAULT = "dns.msftncsi.com"
_NCSI_DNS_CONTENT_DEFAULT = "131.107.255.255"


def _ncsi_dns_probe():
    """Return (probe_host, probe_content) NCSI's DNS probe checks. Read from the
    registry rather than hardcoded — a corporate image can retarget NCSI's probe —
    falling back to the stock Windows defaults if the key is missing/unreadable."""
    host, content = _NCSI_DNS_HOST_DEFAULT, _NCSI_DNS_CONTENT_DEFAULT
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NCSI_KEY) as k:
            try:
                host = winreg.QueryValueEx(k, "ActiveDnsProbeHost")[0] or host
            except FileNotFoundError:
                pass
            try:
                content = winreg.QueryValueEx(k, "ActiveDnsProbeContent")[0] or content
            except FileNotFoundError:
                pass
    except OSError:
        pass
    return host, content


def _ncsi_event_reason(text: str) -> str:
    """Extract NCSI's machine-readable ChangeReason from an event message."""
    m = re.search(r"\bChangeReason:\s*([A-Za-z0-9]+)", text or "")
    return m.group(1) if m else ""


def _looks_like_cidr_or_ip(entry: str) -> Optional[str]:
    """Return a CIDR string if entry is an IP or CIDR, else None (treat as domain)."""
    e = entry.strip()
    try:
        if "/" in e:
            ipaddress.ip_network(e, strict=False)
            return e
        ipaddress.ip_address(e)
        return e + ("/32" if ":" not in e else "/128")
    except ValueError:
        return None


# Bare hostname (or one hostname label with a leading "." stripped) — no scheme,
# no port, no path, no leading/trailing dot. Validated empirically against
# sing-box 1.13.12's `domain_suffix` matcher (see tests/test_config_render.py):
# label/dot-boundary aware, so "scientology.net" never over-matches
# "notscientology.net".
_BYPASS_HOST_RE = re.compile(
    r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")


def normalize_bypass_entry(entry: str):
    """Normalize one Bypass List line into (base, apex_included, error).

    `base` is either a CIDR/IP string (unchanged) or a bare lowercase hostname
    with scheme/port/path/wildcard stripped — the one form every consumer
    (sing-box `domain_suffix`, WinINET `ProxyOverride`, `NO_PROXY`) renders
    from, so the three can never drift on syntax.

    `apex_included` is False only for an explicit leading-dot entry
    (".example.com"), meaning "subdomains only". Every other form — a bare
    host, or "*.example.com" — is treated as "this domain AND its subdomains":
    that's what a user adding an exception almost always means, and a strict
    subdomains-only default would leave the bare apex silently still proxied.

    `error` is a user-facing string for anything that isn't a parseable
    IP/CIDR/hostname (returned with base=None) so the caller can drop the
    entry and warn instead of silently emitting a rule that can never match —
    e.g. "imaps.example.com:993" as a literal `domain_suffix` string, which
    `sing-box check` accepts but which matches nothing.
    """
    raw = (entry or "").strip()
    if not raw:
        return None, True, None                      # blank line: silently ignore
    cidr = _looks_like_cidr_or_ip(raw)                # test the ORIGINAL first,
    if cidr:                                          # so "10.0.0.0/8" survives untouched
        return cidr, True, None
    e = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", raw, flags=re.I)   # scheme, e.g. "https://"
    e = e.split("/", 1)[0]                                       # path
    e = e.rsplit("@", 1)[-1]                                     # userinfo
    e = e.strip().lower()
    e = re.sub(r":\d+$", "", e)                                  # :993 / :465 / :587
    apex_included = True
    if e.startswith("."):
        apex_included = False
        e = e[1:]
    elif e.startswith("*."):
        e = e[2:]
    e = e.strip(".")
    if not e:
        return None, True, f"bypass entry ignored (empty after normalization): {raw!r}"
    cidr = _looks_like_cidr_or_ip(e)                  # e.g. "https://10.1.2.3/"
    if cidr:
        return cidr, True, None
    if not _BYPASS_HOST_RE.match(e):
        return None, True, f"bypass entry ignored (not a hostname/IP/CIDR): {raw!r}"
    return e, apex_included, None


# Ports worth probing by default: :443 (should always work, the sanity check),
# :80 (the documented Edge-updater CONNECT-refusal case), and the three mail
# ports a corporate proxy commonly refuses CONNECT to (diagnosed 2026-08-07:
# Outlook IMAPS/SMTPS through a proxy that only permits CONNECT on :443).
_CONNECT_PROBE_PORTS = (443, 80, 993, 465, 587)


def probe_connect(proxy_host, proxy_port, target_host, target_port,
                   username="", password="", timeout=6.0):
    """Send one real HTTP CONNECT to the upstream proxy for target_host:port and
    return (code, reason) parsed from its status line — (0, "<error text>") if
    the TCP connection to the proxy itself never comes up. Sends nothing beyond
    the CONNECT request/headers and closes immediately either way; never
    relays any actual traffic.

    This is the test a bare TCP connect to the proxy (the old "Test Proxy"
    behaviour) cannot do: a proxy that 403s every CONNECT still passes a plain
    TCP handshake. Many corporate proxies permit CONNECT only to :443 and
    refuse everything else by policy — the only fix for a host that needs a
    refused port is to route it DIRECT via the Bypass List, not to keep
    retrying the proxy."""
    try:
        with socket.create_connection((proxy_host, int(proxy_port)), timeout=timeout) as s:
            s.settimeout(timeout)
            req = (f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                   f"Host: {target_host}:{target_port}\r\n")
            if username:
                token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
                req += f"Proxy-Authorization: Basic {token}\r\n"
            req += "Proxy-Connection: keep-alive\r\n\r\n"
            s.sendall(req.encode("ascii", "replace"))
            buf = b""
            while b"\r\n" not in buf and len(buf) < 1024:
                chunk = s.recv(512)
                if not chunk:
                    break
                buf += chunk
        status_line = buf.split(b"\r\n", 1)[0].decode("latin1", "replace").strip()
        parts = status_line.split(" ", 2)
        if len(parts) >= 3 and parts[1].isdigit():
            return int(parts[1]), parts[2]
        return 0, status_line or "<no response>"
    except Exception as e:
        return 0, str(e)


def make_proxy_config(cfg: dict) -> "ProxyConfig":
    """Build a ProxyConfig from a config_store dict. Used by the GUI."""
    return ProxyConfig(
        host=cfg.get("host", ""),
        port=int(cfg.get("port", 8080)),
        auth_type=cfg.get("auth_type", "none"),
        username=cfg.get("username", ""),
        password=cfg.get("password", ""),
        exclude_private=cfg.get("exclude_private", True),
        exclude_loopback=cfg.get("exclude_loopback", True),
        bypass_list=cfg.get("bypass_list", []),
        log_level=cfg.get("log_level", _DEFAULT_LOG_LEVEL),
        auto_bypass=cfg.get("auto_bypass", True),
    )


class SingBoxController:
    """Runs and supervises sing-box; presents the Redirector interface."""

    def __init__(self, config: ProxyConfig, on_state_change: Callable = None,
                 on_stats_update: Callable = None, on_log: Callable = None,
                 on_auto_bypass: Callable = None):
        self.config = config
        self.on_state_change = on_state_change
        self.on_stats_update = on_stats_update
        self.on_log = on_log
        # Called with a list of newly-discovered hostnames the moment
        # _check_auto_bypass finds an explicit proxy CONNECT refusal for them —
        # never with dial timeouts/unreachable, only real "the proxy answered and
        # said no" cases. The controller can't safely restart itself from inside
        # its own steady-state thread; the caller (the GUI) owns swapping in a
        # fresh SingBoxController, same as it already does for a Settings-save
        # restart. See _check_auto_bypass and core/auto_bypass for the full
        # rationale.
        self.on_auto_bypass = on_auto_bypass
        self.state = SingBoxState.STOPPED
        self.stats = ConnectionStats()

        self._proc: Optional[subprocess.Popen] = None
        self._log_fh = None
        self._clash_port = 0
        self._local_proxy_port = 0   # local mixed inbound the system proxy points at (HTTPS)
        self._http_proxy_port = 0    # local forward-proxy for plaintext HTTP (the port-80 fix)
        self._http_proxy = None
        self._proxy_connect_host = ""  # corp proxy IP resolved pre-DNS-hijack (forward proxy)
        self._exit_code = 0
        self._stop_event = threading.Event()
        self._monitor: Optional[threading.Thread] = None
        # _seen_conn_ids is pruned to the CURRENTLY-ACTIVE ids each poll so it stays
        # bounded on long runs; _total_connections is the monotonic lifetime count.
        self._seen_conn_ids = set()
        self._total_connections = 0
        # v2.1.10: stream each new connection to the GUI log as sing-box
        # establishes it, so the user can watch traffic being captured/routed.
        self._trace_conns = True
        self._uwp_thread: Optional[threading.Thread] = None
        self._uwp_sweep_ticks = 0
        # Hosts already reported/handed to on_auto_bypass this engine lifetime, so
        # a rejection that keeps reappearing in the log tail (it will, until enough
        # newer lines push it out) doesn't re-trigger the callback/restart request
        # every tick while a restart is still pending.
        self._auto_bypass_reported = set()
        self._auto_bypass_ticks = 0

    # ── helpers ───────────────────────────────────────────────────────────────

    def _set_state(self, state: SingBoxState):
        self.state = state
        if self.on_state_change:
            self.on_state_change(state)

    def _log(self, msg: str, level: str = "info"):
        logger.info(msg)
        if self.on_log:
            self.on_log(msg, level)

    def _normalized_bypass(self):
        """Normalize cfg.bypass_list ONCE, shared by _render_config,
        _build_proxy_bypass and _build_no_proxy so the three can't drift on
        syntax (sing-box `domain_suffix`, WinINET `ProxyOverride`, `NO_PROXY`
        each have different wildcard/suffix rules — see normalize_bypass_entry).

        Returns (cidrs, domain_suffixes, warnings). A domain that should match
        subdomains only (the user typed a leading dot) carries that leading dot
        into `domain_suffixes` — sing-box's domain_suffix honours it the same
        way; the two consumer builders strip or expand it as their own syntax
        requires.
        """
        cidrs: List[str] = []
        domains: List[str] = []
        warnings: List[str] = []
        for entry in (self.config.bypass_list or []):
            base, apex_included, err = normalize_bypass_entry(entry)
            if err:
                warnings.append(err)
                continue
            if base is None:
                continue
            if "/" in base:                       # _looks_like_cidr_or_ip always emits a CIDR
                cidrs.append(base)
            else:
                domains.append(base if apex_included else f".{base}")
        return cidrs, domains, warnings

    # ── config rendering ────────────────────────────────────────────────────────

    def _render_config(self, clash_port: int) -> dict:
        cfg = self.config
        sbdir = _singbox_dir()

        bypass_cidrs, bypass_domains, _bypass_warnings = self._normalized_bypass()

        # ── DNS: EVERYTHING goes to fakeip, bypass domains included ──
        # Bypass domains deliberately do NOT get real resolution here. Keeping
        # them on fakeip preserves the fakeip -> domain reverse map, so at
        # connect time sing-box knows the exact hostname for ANY TCP protocol on
        # ANY port — before sniffing and independent of it — and the
        # domain_suffix route rule below matches deterministically. Giving them
        # real IPs instead (the old behaviour) destroyed that map and left the
        # route rule dependent on sniffing a hostname off the wire: that works
        # for TLS-with-SNI and HTTP Host, but FAILS for server-speaks-first
        # protocols (SMTP/587 STARTTLS) and clients that omit SNI, so those fell
        # through to route.final = proxy-out and the corporate proxy 403'd
        # CONNECT on :993/:465/:587 (diagnosed 2026-08-07, Outlook/IMAPS/SMTPS).
        # The `direct` outbound resolves the real IP itself via
        # route.default_domain_resolver below.
        # Force IPv4 for everything: answer AAAA with NODATA (NOERROR + no
        # records) so dual-stack apps fall back to the A record, which gets a
        # fakeip and is routed through the proxy. WITHOUT this, browsers resolve a
        # REAL IPv6 (dns.final = local) and Happy Eyeballs connects over IPv6,
        # which bypasses the IPv4-only TUN entirely — the engine runs and captures
        # IPv4-only system traffic (counters move) while the browser leaks direct.
        ncsi_probe_host, ncsi_probe_content = _ncsi_dns_probe()
        dns_rules = [
            {"query_type": ["AAAA"], "action": "predefined", "rcode": "NOERROR"},
            # NCSI's DNS probe (see _ncsi_dns_probe) must get EXACTLY this literal
            # answer or Windows reports "no internet" — a `predefined` answer is
            # used rather than letting it fall through to fakeip/real resolution
            # because NCSI compares byte-for-byte against a fixed constant, not
            # whatever corporate DNS happens to return. Nothing ever connects to
            # this address, so — unlike the bypass domains below — it never needs
            # a fakeip reverse-map entry. Must precede the blanket A → fakeip rule.
            {"domain": [ncsi_probe_host], "query_type": ["A"], "action": "predefined",
             "answer": [f"{ncsi_probe_host}. IN A {ncsi_probe_content}"]},
            {"query_type": ["A"], "server": "fakeip"},
        ]

        # ── route rules ──
        route_rules = [
            {"action": "sniff"},                              # detect TLS/HTTP/DNS
            {"protocol": "dns", "action": "hijack-dns"},      # answer DNS ourselves (fakeip)
            # Port-based DNS hijack fallback: if the sniffer fails to tag a packet
            # as DNS, these still catch it by port 53 — and they sit BEFORE the
            # udp-reject rule below, so a DNS query can never be silently dropped
            # (a dropped query would leave apps resolving real IPs and bypassing
            # the fakeip / CONNECT-by-hostname path). Validated against 1.13.12.
            {"network": "udp", "port": 53, "action": "hijack-dns"},
            {"network": "tcp", "port": 53, "action": "hijack-dns"},
        ]
        # Never route traffic destined to the proxy server itself back through the
        # proxy — send it DIRECT (covers raw-IP proxy hosts; prevents any loop).
        # Also cover the pre-resolved real IP when cfg.host is a hostname (resolved
        # in start(), BEFORE fakeip hijacks DNS, into _proxy_connect_host) — without
        # this, a hostname-configured proxy's IP could be caught by the port-80
        # rule below and the local forward-proxy's own upstream socket would loop
        # back into itself.
        proxy_ips = []
        proxy_ip = _looks_like_cidr_or_ip(cfg.host)
        if proxy_ip:
            proxy_ips.append(proxy_ip)
        resolved_ip = _looks_like_cidr_or_ip(getattr(self, "_proxy_connect_host", "") or "")
        if resolved_ip and resolved_ip not in proxy_ips:
            proxy_ips.append(resolved_ip)
        if proxy_ips:
            route_rules.append({"ip_cidr": proxy_ips, "action": "route", "outbound": "direct"})
        if cfg.exclude_loopback:
            route_rules.append({"ip_cidr": ["127.0.0.0/8"],
                                "action": "route", "outbound": "direct"})
        if cfg.exclude_private:
            route_rules.append({"ip_is_private": True, "action": "route", "outbound": "direct"})
        if bypass_cidrs:
            route_rules.append({"ip_cidr": bypass_cidrs, "action": "route", "outbound": "direct"})
        if bypass_domains:
            route_rules.append({"domain_suffix": bypass_domains, "action": "route", "outbound": "direct"})
        # Route TUN-captured plaintext HTTP (port 80) into our OWN local forward-
        # proxy instead of sing-box's http outbound (CONNECT-only). The corporate
        # proxy 403s CONNECT on :80 (proven 2026-06-19) but serves the identical
        # URL as a normal forward-proxy GET — core/local_proxy.py already does
        # exactly that for proxy-aware apps sent to the http= system-proxy entry;
        # this extends the same fix to anything captured by the TUN instead, which
        # is what NCSI's own web probe hits (it ignores the WinINET/WinHTTP proxy
        # split entirely) and any app that ignores proxy settings (WPAD). Without
        # this, NCSI's probe 403s, Windows reports IPv4Connectivity=LocalNetwork
        # ("no internet"), and every component gating on connectivity level goes
        # dark — diagnosed 2026-08-07 via Windows Spotlight silently not
        # downloading. Must sit AFTER the direct rules above (loopback/private/
        # bypass/proxy-IP keep their own path) and BEFORE the UDP reject below.
        # `self._http_proxy_port` is reserved in start() before the config is ever
        # rendered (see _free_loopback_ports(3)); the `or 18081` fallback only
        # matters for a bare _render_config() call outside the normal start path
        # (e.g. tests), matching the same pattern used for local-in's listen_port.
        route_rules.append({
            "network": "tcp", "port": 80, "action": "route", "outbound": "direct",
            "override_address": "127.0.0.1",
            "override_port": self._http_proxy_port or 18081,
        })
        # HTTP CONNECT is TCP-only: reject ALL UDP (incl. QUIC/443) so apps fall
        # back to TCP and nothing leaks unproxied. DNS is already handled above.
        route_rules.append({"network": "udp", "action": "reject"})

        proxy_out = {
            "type": "http",
            "tag": "proxy-out",
            "server": cfg.host,
            "server_port": int(cfg.port),
        }
        if cfg.auth_type == "basic" and cfg.username:
            proxy_out["username"] = cfg.username
            proxy_out["password"] = cfg.password

        # Log level from config (validated). "debug" captures every sniff / route /
        # CONNECT decision — invaluable for diagnostics but large on long runs, so it
        # is opt-in via Settings; "info" is the default. The decisive diagnostics
        # (routes / DNS / reachability) come from PowerShell + the Clash API, not this
        # log, so a quieter level does not blind _run_diagnostics.
        level = (cfg.log_level or "").strip().lower()
        if level not in _SINGBOX_LOG_LEVELS:
            level = _DEFAULT_LOG_LEVEL

        return {
            "log": {
                "level": level,
                "timestamp": True,
            },
            "experimental": {
                "clash_api": {"external_controller": f"127.0.0.1:{clash_port}"},
                "cache_file": {
                    "enabled": True,
                    "path": os.path.join(sbdir, "cache.db"),
                    "store_fakeip": True,
                },
            },
            "dns": {
                "servers": [
                    {"type": "fakeip", "tag": "fakeip",
                     "inet4_range": FAKEIP_V4},
                    {"type": "local", "tag": "local"},
                ],
                "rules": dns_rules,
                "final": "local",
            },
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": TUN_NAME,
                    "address": [TUN_V4],
                    "mtu": 1500,
                    "auto_route": True,
                    # Install the SPLIT-default routes (0.0.0.0/1 + 128.0.0.0/1)
                    # instead of a single 0.0.0.0/0. This is the decisive Win 10 fix
                    # (v2.1.7, proven on the failing box 2026-06-18): auto_route's
                    # default 0.0.0.0/0 on the TUN only TIES the physical NIC's
                    # 0.0.0.0/0 on prefix length, then LOSES the interface-metric
                    # tiebreak (a 100 Mbps Realtek sits at metric 35) — so every
                    # packet took Ethernet and nothing entered the tunnel ("green
                    # but no capture"). The two /1 routes are MORE SPECIFIC than any
                    # /0, so Windows longest-prefix-match always picks the TUN,
                    # immune to the metric battle. `route_address` is the modern
                    # 1.13 field (legacy inet4_route_address is FATAL); validated
                    # with `sing-box check` against 1.13.12. A Windows-native
                    # backstop (_enforce_capture_routes) re-asserts these after green
                    # in case auto_route still under-installs them on some box.
                    "route_address": ["0.0.0.0/1", "128.0.0.0/1"],
                    # strict_route:true is required on Windows 10: without it,
                    # auto_route only modifies the routing table (which Win 10 may
                    # ignore for elevated processes), so regular app traffic bypasses
                    # the TUN entirely. strict_route uses Windows Filtering Platform
                    # callouts which work on Win 10. IPv6 TUN is omitted (already),
                    # so the Win 10 IPv6 neighbour-discovery crash cannot recur.
                    "strict_route": True,
                    "stack": "system",
                },
                # Local HTTP/SOCKS listener that the Windows system proxy points at for
                # HTTPS (the https= entry; see _takeover_system_proxy). Proxy-aware apps
                # — including the Microsoft Edge updater — send TCP CONNECT here and
                # sing-box forwards them to the corporate proxy (final = proxy-out),
                # authenticated centrally. Plaintext HTTP (port 80) does NOT come here:
                # the corporate proxy returns 403 to CONNECT on :80 (proven 2026-06-19),
                # which is all sing-box's outbound can do — so port-80 traffic is sent to
                # ProxyForce's local forward-proxy (core/local_proxy) instead, which
                # relays it as a normal forward-proxy GET. The TUN remains the catch-all
                # for apps that ignore proxy settings.
                {
                    "type": "mixed",
                    "tag": "local-in",
                    "listen": "127.0.0.1",
                    "listen_port": self._local_proxy_port or 18080,
                },
            ],
            "outbounds": [
                proxy_out,
                {"type": "direct", "tag": "direct"},
            ],
            "route": {
                "rules": route_rules,
                "final": "proxy-out",
                # strategy: prefer_ipv4 — dial-time resolution for the `direct`
                # outbound (bypass domains, now fakeip'd) skips dns.rules entirely,
                # so the AAAA-NODATA rule above does NOT apply to it; without this
                # it would return both A and AAAA and cost a Happy-Eyeballs stall
                # per connection on a box with no working IPv6. prefer_ipv4 (not
                # ipv4_only) so an IPv6-only bypassed host stays reachable.
                # Validated: `sing-box check` rejects "prefer_ipv9" by exact field
                # path (route.default_domain_resolver.strategy), proving this key
                # is genuinely parsed, not silently ignored.
                "default_domain_resolver": {"server": "local", "strategy": "prefer_ipv4"},
                "auto_detect_interface": True,
            },
        }

    def _write_config(self, clash_port: int) -> str:
        sbdir = _singbox_dir()
        os.makedirs(sbdir, exist_ok=True)
        cfg_path = os.path.join(sbdir, "config.json")
        data = self._render_config(clash_port)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return cfg_path

    # ── lifecycle ────────────────────────────────────────────────────────────────

    def start(self):
        if self.state not in (SingBoxState.STOPPED, SingBoxState.ERROR):
            return
        self._set_state(SingBoxState.STARTING)
        self._stop_event.clear()
        self._seen_conn_ids = set()
        self._total_connections = 0
        self.stats = ConnectionStats(start_time=time.time())

        if not self.config.host:
            self._set_state(SingBoxState.ERROR)
            self._log("No proxy host configured.", "error")
            return

        sb = _find_singbox_exe()
        if not sb:
            self._set_state(SingBoxState.ERROR)
            self._log("sing-box.exe not found in the install folder (vendor/singbox).", "error")
            return

        # Reserve the forward-proxy port here too (not just clash/local-proxy):
        # _render_config's port-80 route rule needs a concrete override_port at
        # WRITE time, which happens below, well before _start_http_proxy() would
        # otherwise have assigned one from an ephemeral bind. Prefer the FIXED
        # defaults (_DEFAULT_PORTS) so an ordinary restart keeps the same port
        # numbers — see _bind_ports_preferring for why that matters.
        self._clash_port, self._local_proxy_port, self._http_proxy_port = \
            _bind_ports_preferring(_DEFAULT_PORTS, log=self._log)
        # Resolve the corporate proxy's REAL IP now — BEFORE sing-box hijacks DNS to
        # fakeip — so the local forward-proxy (started after green) dials the real
        # upstream rather than a fakeip that would loop back into the TUN. For an
        # IP-literal proxy this is just the host; for a hostname we best-effort resolve
        # and reject a fakeip answer (a stale TUN from a crashed run).
        self._proxy_connect_host = self.config.host
        if not _looks_like_cidr_or_ip(self.config.host):
            try:
                ip = socket.gethostbyname(self.config.host)
                if not ip.startswith(("198.18.", "198.19.")):
                    self._proxy_connect_host = ip
            except Exception:
                pass
        cfg_path = self._write_config(self._clash_port)

        # Surface any Bypass List entries that couldn't be normalized into a
        # hostname/IP/CIDR — e.g. "imaps.example.com:993" — BEFORE the config is
        # validated below. sing-box check would pass either way (a dead
        # domain_suffix string is still valid JSON); without this the entry
        # just silently never matches anything.
        _cidrs, _domains, bypass_warnings = self._normalized_bypass()
        for w in bypass_warnings:
            self._log(w, "warning")

        # Validate the generated config before running — turns a malformed config
        # into a clear log line instead of a crash/restart loop.
        try:
            chk = subprocess.run([sb, "check", "-c", cfg_path],
                                 capture_output=True, text=True,
                                 creationflags=_NO_WINDOW, timeout=30)
            if chk.returncode != 0:
                self._set_state(SingBoxState.ERROR)
                self._log(f"sing-box config invalid: {(chk.stderr or chk.stdout).strip()}", "error")
                return
        except Exception as e:
            self._log(f"Could not run sing-box check ({e}); attempting to start anyway.", "warning")

        # Hand off to the supervisor thread: it does preflight TUN cleanup,
        # launches sing-box with bounded auto-retry (Win 10 wintun timing bug),
        # waits for Clash-API readiness, then runs the steady-state stats loop.
        # Keeping this off the caller's thread leaves the GUI responsive.
        self._monitor = threading.Thread(
            target=self._supervise, args=(sb, cfg_path), daemon=True)
        self._monitor.start()

    # ── supervisor: launch + Win 10 retry + readiness + steady state ──────────

    def _supervise(self, sb: str, cfg_path: str):
        # Preflight: a leftover "ProxyForce" TUN adapter from a crashed or
        # hard-killed previous run is the #1 cause of the Windows-10 wintun
        # "Cannot create a file when that file already exists" failure. Clear it
        # before the first launch so the first attempt has a clean slate.
        if self._tun_adapter_exists():
            self._log("Found a leftover TUN adapter from a previous run; cleaning up…")
            self._cleanup_stale_tun()

        # Flush the OS DNS cache so apps re-resolve through our fakeip DNS on start
        # rather than connecting to real IPs cached before ProxyForce ran (a real IP
        # → CONNECT-by-IP → an inspecting proxy blocks it). Cheap, non-destructive.
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                           creationflags=_NO_WINDOW, timeout=10)
        except Exception:
            pass

        # Truncate the sing-box log once per start(); launch attempts within this
        # start() APPEND (see _launch_proc) so a failed attempt's evidence survives.
        try:
            open(os.path.join(_singbox_dir(), "singbox.log"), "w").close()
        except Exception:
            pass

        for attempt in range(1, _LAUNCH_ATTEMPTS + 1):
            if self._stop_event.is_set():
                return
            if not self._launch_proc(sb, cfg_path):
                return  # spawn failed — ERROR already set + logged

            ready, exited, tail = self._await_ready()
            if ready:
                self._run_steady_state()
                return
            if self._stop_event.is_set():
                return

            # Not ready. Retry the known Win 10 wintun timing bug (or a process
            # that came up but never answered the Clash API) while attempts remain.
            self._terminate_proc()
            retryable = self._is_retryable_tun_error(tail)
            if attempt < _LAUNCH_ATTEMPTS and (retryable or not exited):
                self._log(f"TUN adapter busy — Windows 10 wintun timing bug; "
                          f"cleaning up and retrying (attempt {attempt + 1} of "
                          f"{_LAUNCH_ATTEMPTS})…", "warning")
                self._cleanup_stale_tun()
                continue

            # Out of retries, or a non-retryable failure.
            self._set_state(SingBoxState.ERROR)
            if exited:
                self._log(f"sing-box exited during startup (code {self._exit_code}). "
                          f"{tail}", "error")
            else:
                self._log(f"sing-box did not become ready in time. {tail}", "error")
            self._close_log()
            return

    def _launch_proc(self, sb: str, cfg_path: str) -> bool:
        """Spawn sing-box (fresh log per attempt). Returns False + sets ERROR on failure."""
        sbdir    = os.path.dirname(sb)
        log_path = os.path.join(_singbox_dir(), "singbox.log")
        try:
            # Append (the file is truncated once per start() in _supervise) so each
            # retry's output is preserved, with a separator, for the diagnostics report.
            self._log_fh = open(log_path, "a", encoding="utf-8", errors="replace")
            self._log_fh.write(f"\n--- launch attempt @ {time.strftime('%H:%M:%S')} ---\n")
            self._log_fh.flush()
        except Exception:
            self._log_fh = subprocess.DEVNULL
        try:
            self._proc = subprocess.Popen(
                # --disable-color: singbox.log otherwise carries raw ANSI escape
                # codes, which is why _tail_log/_tail_log_lines output looked like
                # junk in diagnostics.txt. Not a config-file field — CLI flag only.
                [sb, "run", "--disable-color", "-c", cfg_path],
                cwd=sbdir,
                stdout=self._log_fh,
                stderr=subprocess.STDOUT,
                creationflags=_NO_WINDOW,
            )
        except Exception as e:
            self._set_state(SingBoxState.ERROR)
            self._log(f"Failed to launch sing-box: {e}", "error")
            self._close_log()
            return False
        # Assign to the kill-on-close job so a GUI crash still cleans up.
        try:
            job = _ensure_job()
            if job and self._proc._handle:
                ctypes.windll.kernel32.AssignProcessToJobObject(job, self._proc._handle)
        except Exception:
            pass
        self._log(f"sing-box launched (pid {self._proc.pid}); bringing up TUN…")
        return True

    def _await_ready(self):
        """Wait for the Clash API to answer (=sing-box healthy) or the process to die.

        Readiness is gated ONLY on the Clash API responding — never on the mere
        presence of the TUN adapter, because a *stale* adapter left by a crashed
        run would otherwise be mistaken for a healthy engine (the engine reports
        "running" while traffic still goes direct and stats stay at zero).
        Returns (ready, exited, tail).
        """
        deadline = time.time() + _READY_TIMEOUT
        while time.time() < deadline and not self._stop_event.is_set():
            if self._proc.poll() is not None:
                self._exit_code = self._proc.returncode
                return (False, True, self._tail_log())
            if self._clash_get("/version") is not None:
                return (True, False, "")
            time.sleep(0.5)
        return (False, False, self._tail_log())

    def _run_steady_state(self):
        self._set_state(SingBoxState.RUNNING)
        self._log(f"ProxyForce active → {self.config.host}:{self.config.port} "
                  f"(sing-box TUN, fakeip, CONNECT-by-hostname).")
        # THE FIX (v2.1.7): force the split-default routes onto the TUN so it wins
        # by longest-prefix-match. Runs every start, immediately after green, before
        # any user traffic — do not rely on auto_route alone (it under-installed
        # these on Win 10, the root cause of "green but no capture").
        self._enforce_capture_routes()
        # Bring up the local plaintext-HTTP forward proxy BEFORE the system-proxy
        # takeover (the takeover points the http= entry at it). See _start_http_proxy.
        self._start_http_proxy()
        # v2.1.9: take over the Windows system proxy. While a system proxy is set,
        # cooperating apps (browsers) send traffic STRAIGHT to it and never produce
        # the "direct" traffic the TUN captures — they bypass ProxyForce entirely.
        # Disabling it (snapshot saved, restored on stop) makes EVERY app fall back
        # to direct → into the TUN → forwarded to the proxy by us. This is what
        # makes capture truly universal (incl. proxy-honoring apps).
        self._takeover_system_proxy()
        # ~2s after green, capture ground truth (routes / DNS / WFP / competing
        # agents) off the stats loop so the GUI stays responsive. Writes
        # %ProgramData%\ProxyForce\diagnostics.txt + a one-line GUI verdict; now
        # also VERIFIES the enforcement above took (expects 2/2 split routes).
        threading.Thread(target=self._run_diagnostics_after_ncsi_settle,
                         daemon=True).start()
        while not self._stop_event.is_set():
            if self._proc.poll() is not None:
                self._set_state(SingBoxState.ERROR)
                self._log(f"sing-box exited unexpectedly (code {self._proc.returncode}). "
                          f"{self._tail_log()}", "error")
                # The engine died — tear down the forward proxy and restore the system
                # proxy so the machine isn't left with no working proxy path.
                self._join_uwp_sweep()
                self._stop_http_proxy()
                self._restore_system_proxy()
                self._close_log()
                return
            self._poll_stats()
            # Re-sweep UWP loopback exemptions every ~5 minutes (this loop ticks
            # every 2s) so a package installed WHILE ProxyForce is running (e.g.
            # a Store app the user just downloaded) also gets exempted, not just
            # whatever was installed at start. Cheap and idempotent — already-
            # exempt packages are skipped by CheckNetIsolation — and skipped
            # entirely while the previous sweep is still running.
            self._uwp_sweep_ticks += 1
            if self._uwp_sweep_ticks >= 150:
                self._uwp_sweep_ticks = 0
                if self._uwp_thread is None or not self._uwp_thread.is_alive():
                    self._uwp_thread = threading.Thread(
                        target=self._exempt_uwp_loopback, daemon=True)
                    self._uwp_thread.start()
            # Check for new proxy CONNECT refusals every ~6s (3 ticks at 2s each) —
            # short enough to feel immediate, long enough to naturally batch several
            # refusals discovered close together into one restart instead of one per
            # host. See _check_auto_bypass / core/auto_bypass.
            self._auto_bypass_ticks += 1
            if self._auto_bypass_ticks >= 3:
                self._auto_bypass_ticks = 0
                self._check_auto_bypass()
            self._stop_event.wait(2)

    # ── TUN adapter lifecycle (Win 10 wintun cleanup) ─────────────────────────

    @staticmethod
    def _is_retryable_tun_error(tail: str) -> bool:
        """True if the failure looks like the Win 10 wintun adapter timing bug."""
        t = (tail or "").lower()
        return ("already exists" in t or "file exists" in t
                or "device is not ready" in t or "take too much time" in t
                or "configure tun interface" in t)

    def _tun_adapter_exists(self) -> bool:
        """True if a network interface named TUN_NAME currently exists."""
        try:
            r = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True, text=True,
                creationflags=_NO_WINDOW, timeout=5,
            )
            return TUN_NAME in (r.stdout or "")
        except Exception:
            return False

    def _cleanup_stale_tun(self):
        """Release a leftover sing-box TUN adapter so the next launch can recreate it.

        TerminateProcess gives sing-box no chance to remove its own adapter, so a
        crashed/killed instance can leave the wintun device behind. Kill any
        orphaned sing-box.exe (releases the device the wintun driver owns), make a
        best-effort attempt to remove the adapter outright, then wait for Windows
        to finish the teardown before the caller relaunches.
        """
        try:
            subprocess.run(["taskkill", "/F", "/IM", "sing-box.exe"],
                           capture_output=True, creationflags=_NO_WINDOW, timeout=10)
        except Exception:
            pass
        # Best-effort device removal in case the adapter lingers with no owning
        # process: try the NetAdapter API, then fall back to pnputil removing the
        # underlying PnP device by instance id — this covers wintun adapters that
        # Remove-NetAdapter can't drop in some Windows-10 states.
        ps = (
            "$ErrorActionPreference='SilentlyContinue';"
            f"$a = Get-NetAdapter -Name '{TUN_NAME}';"
            "if ($a) {"
            " Disable-NetAdapter -Name $a.Name -Confirm:$false;"
            " Remove-NetAdapter  -Name $a.Name -Confirm:$false;"
            f" $b = Get-NetAdapter -Name '{TUN_NAME}';"
            " if ($b -and $b.PnpDeviceID) { pnputil /remove-device \"$($b.PnpDeviceID)\" }"
            "}"
        )
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, creationflags=_NO_WINDOW, timeout=25)
        except Exception:
            pass
        # Wait for the adapter to actually disappear, then a short settle so a
        # fresh CreateAdapter does not race the in-progress teardown.
        end = time.time() + _ADAPTER_WAIT
        while time.time() < end and self._tun_adapter_exists():
            if self._stop_event.wait(0.5):
                return
        self._stop_event.wait(_ADAPTER_SETTLE)

    def _terminate_proc(self):
        """Hard-stop the current sing-box process and close its log handle."""
        proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=8)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self._proc = None
        self._close_log()

    # ── Clash API ────────────────────────────────────────────────────────────────

    def _clash_get(self, path: str):
        try:
            url = f"http://127.0.0.1:{self._clash_port}{path}"
            # _LOOPBACK_OPENER (not urlopen) so the request is never sent through
            # the system/corporate proxy — see the opener's definition above.
            with _LOOPBACK_OPENER.open(url, timeout=2) as r:
                return json.loads(r.read().decode("utf-8", errors="replace"))
        except Exception:
            return None

    _CONN_TRACE_CAP = 8   # max connection lines logged per 2s poll (anti-flood)

    def _poll_stats(self):
        data = self._clash_get("/connections")
        if data is None:
            return
        conns = data.get("connections") or []
        self.stats.active_connections = len(conns)
        # Detect NEW connections this tick so we can both count totals and trace
        # them live to the GUI (the "watch it connect" view the user asked for).
        new = []
        active_ids = set()
        for c in conns:
            cid = c.get("id")
            if not cid:
                continue
            active_ids.add(cid)
            if cid not in self._seen_conn_ids:
                new.append(c)
        if self._trace_conns and new:
            self._emit_conn_trace(new)
        # Bound _seen_conn_ids to the currently-active ids (Clash ids are unique per
        # connection and never reused, so dropping closed ones is safe and keeps the
        # set from growing without limit on long runs); track the lifetime total in a
        # monotonic counter rather than the set's size.
        self._total_connections += len(new)
        self._seen_conn_ids = active_ids
        self.stats.total_connections = self._total_connections
        down = data.get("downloadTotal", 0) or 0
        up = data.get("uploadTotal", 0) or 0
        self.stats.bytes_forwarded = down + up
        if self.on_stats_update:
            self.on_stats_update(self.stats)

    def _emit_conn_trace(self, new: list):
        """Log each newly-established connection to the GUI: host:port → outbound.

        The outbound chain tells the whole story at a glance: `proxy` means the
        connection was captured and forwarded through the corporate proxy (the
        goal); `direct` means it was sent unproxied (a private/loopback/bypass
        destination, or — if you see a public host here — a leak worth noting).
        Bounded per tick so a connection burst can't flood the log.
        """
        shown = 0
        for c in new:
            if shown >= self._CONN_TRACE_CAP:
                break
            md = c.get("metadata") or {}
            host = md.get("host") or md.get("destinationIP") or "?"
            port = md.get("destinationPort") or ""
            net = (md.get("network") or "tcp").lower()
            chains = c.get("chains") or []
            if "proxy-out" in chains:
                tag = "proxy"
            elif "direct" in chains:
                tag = "direct (bypass)"
            else:
                tag = (chains[0] if chains else (c.get("rule") or "?"))
            dest = f"{host}:{port}" if port else str(host)
            self._log(f"  conn  {dest}  [{net}]  ->  {tag}")
            shown += 1
        extra = len(new) - shown
        if extra > 0:
            self._log(f"  conn  … +{extra} more new connection(s) this tick")

    # ── capture-route enforcement (THE Win 10 fix) ────────────────────────────────

    def _enforce_capture_routes(self):
        """Guarantee the TUN wins the default route on Windows.

        Root cause of the Win 10 "green but no capture" failure (diagnosed from a
        hardware diagnostics.txt, 2026-06-18): sing-box's auto_route installed only
        a 0.0.0.0/0 default route on the TUN. That route TIES the physical NIC's
        own 0.0.0.0/0 on prefix length and then LOSES the interface-metric tiebreak
        (a 100 Mbps Realtek NIC sits at metric 35), so Windows sent every packet out
        Ethernet and nothing ever entered the tunnel — even though the engine was
        fully healthy.

        The standard remedy is the split-route trick: 0.0.0.0/1 + 128.0.0.0/1 are
        MORE SPECIFIC than any 0.0.0.0/0, so Windows longest-prefix-match always
        picks the TUN for them, regardless of metric. We also pin the TUN interface
        metric to 1. Both are non-persistent (ActiveStore + tied to the adapter), so
        sing-box's teardown on stop() removes them — nothing leaks past shutdown.

        Belt-and-suspenders with the config's `route_address` (which asks auto_route
        to install the same /1 routes): if either path lands them, capture works.
        Idempotent — only adds a /1 route that is missing; always re-pins the metric.
        Proven on the failing box: adding these flipped capture ON (example.com:443
        then flowed through proxy-out with real bytes).
        """
        idx = self._ps("$a=Get-NetAdapter -Name '" + TUN_NAME + "' "
                       "-ErrorAction SilentlyContinue; if($a){$a.ifIndex}else{''}").strip()
        if not idx.isdigit():
            self._log("Capture-route enforcement skipped: TUN adapter not found yet.",
                      "warning")
            return

        # SERVER-EXCLUDE (the v2.1.8 loop fix). With the split-default routes
        # capturing the WHOLE address space, sing-box's OWN connection out to the
        # upstream proxy would also match 128.0.0.0/1 and get routed back into the
        # TUN — an infinite loop that surfaces as "dial tcp <proxy>:<port>: i/o
        # timeout" (observed on Win 11 v2.1.7; requesting the split routes via
        # route_address suppressed sing-box's automatic server-exclude). Pin a /32
        # host route for the proxy via the REAL default gateway: a /32 is more
        # specific than /1, so that single connection escapes the tunnel while
        # everything else stays captured. IPv4-literal proxies only; for a hostname
        # we leave the exclude to sing-box (can't pre-resolve it — DNS is hijacked).
        proxy_v4 = None
        try:
            _ip = ipaddress.ip_address(self.config.host.strip())
            if _ip.version == 4:
                proxy_v4 = str(_ip)
        except ValueError:
            proxy_v4 = None

        excl = ""
        if proxy_v4:
            excl = (
                "$gw = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |"
                " Where-Object {$_.InterfaceAlias -ne '" + TUN_NAME + "' -and $_.NextHop -and "
                "$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric,InterfaceMetric |"
                " Select-Object -First 1;"
                "if($gw){Remove-NetRoute -DestinationPrefix '" + proxy_v4 + "/32' -Confirm:$false "
                "-ErrorAction SilentlyContinue;"
                "New-NetRoute -DestinationPrefix '" + proxy_v4 + "/32' -InterfaceIndex $gw.ifIndex "
                "-NextHop $gw.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null};"
            )

        ps = (
            "$ErrorActionPreference='SilentlyContinue';"
            + excl +
            "Set-NetIPInterface -InterfaceIndex " + idx + " -InterfaceMetric 1;"
            "foreach($p in '0.0.0.0/1','128.0.0.0/1'){"
            " if(-not (Get-NetRoute -InterfaceIndex " + idx + " -DestinationPrefix $p "
            "-ErrorAction SilentlyContinue)){"
            "  New-NetRoute -DestinationPrefix $p -InterfaceIndex " + idx +
            " -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null}};"
            "(Get-NetRoute -InterfaceIndex " + idx + " -ErrorAction SilentlyContinue | "
            "Where-Object {$_.DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1'} | "
            "Measure-Object).Count"
        )
        out = self._ps(ps, timeout=25)
        count = out.strip().splitlines()[-1].strip() if out.strip() else "?"
        excl_note = (f"; proxy {proxy_v4} pinned to physical gateway (loop-break)"
                     if proxy_v4 else "")
        if count == "2":
            self._log("Capture routes enforced on TUN (0.0.0.0/1 + 128.0.0.0/1, metric 1"
                      + excl_note + ") — all traffic now flows through the proxy.")
        else:
            self._log(f"Capture-route enforcement incomplete ({count}/2 split routes). "
                      "A VPN/endpoint agent may own the route table — see diagnostics.txt.",
                      "warning")

    # ── system-proxy takeover (make capture universal) ────────────────────────────

    def _build_proxy_bypass(self) -> str:
        """WinINET/WinHTTP ProxyOverride for the local-listener takeover: keep
        loopback/intranet (and the engine's bypass set) DIRECT so only real
        outbound goes through ProxyForce."""
        cfg = self.config
        parts = ["<local>", "localhost", "127.*"]
        if getattr(cfg, "exclude_private", True):
            parts += ["10.*", "192.168.*"] + [f"172.{n}.*" for n in range(16, 32)]
        _cidrs, domains, _warnings = self._normalized_bypass()
        for d in domains:
            # ProxyOverride has NO implicit suffix matching — unlike sing-box's
            # domain_suffix, a bare host here is an EXACT match only, so
            # subdomains would silently stay proxied unless the "*.host"
            # wildcard form is added alongside it. A ".host" (subdomains-only)
            # entry only needs the wildcard form, not the bare one.
            if d.startswith("."):
                parts.append(f"*.{d[1:]}")
            else:
                parts.append(d)
                parts.append(f"*.{d}")
        return ";".join(parts)

    def _build_no_proxy(self) -> str:
        """NO_PROXY/no_proxy for the env-var takeover: the same exclusion set as
        _build_proxy_bypass, rendered in NO_PROXY's syntax — comma-separated,
        glob-free hosts/domains (unlike WinINET's ';'/'*' ProxyOverride). NO_PROXY
        is dot-boundary aware on its own (curl/requests/urllib already treat a
        bare host as covering its subdomains) and has no glob support, so a
        "*.host" bypass entry needs its wildcard stripped, and it can't express
        "subdomains only" — a ".host" (leading-dot) entry widens to include the
        apex here too. Documented fail-open toward MORE direct, never less."""
        cfg = self.config
        parts = ["localhost", "127.0.0.1", "::1"]
        if getattr(cfg, "exclude_private", True):
            parts += ["10.", "192.168."] + [f"172.{n}." for n in range(16, 32)]
        _cidrs, domains, _warnings = self._normalized_bypass()
        for d in domains:
            parts.append(d.lstrip("."))
        return ",".join(parts)

    # ── local forward-proxy (plaintext-HTTP / port-80 fix) ─────────────────────────

    def _start_http_proxy(self) -> bool:
        """Start the loopback forward-proxy that relays plaintext HTTP (port 80) to the
        corporate proxy as a forward-proxy GET. This is the fix for the Edge updater and
        any port-80 download: the corporate proxy returns 403 to CONNECT on :80 (which
        is all sing-box's outbound can do), but happily serves the same URL as a normal
        forward-proxy GET. See core/local_proxy for the full rationale. Best-effort: on
        failure HTTPS still works via sing-box and only plaintext HTTP stays broken —
        but the rendered sing-box config's port-80 route rule (override_port) already
        points at self._http_proxy_port, reserved in start() BEFORE the config was
        written, so binding that exact port here (not an ephemeral one) is required or
        TUN-captured port-80 traffic (NCSI, WPAD) gets connection-refused instead."""
        try:
            from core import local_proxy
            basic = self.config.auth_type == "basic"
            prx = local_proxy.LocalForwardProxy(
                self._proxy_connect_host or self.config.host, int(self.config.port),
                username=(self.config.username if basic else ""),
                password=(self.config.password if basic else ""),
                on_log=self.on_log)
            self._http_proxy_port = prx.start(port=self._http_proxy_port)
            self._http_proxy = prx
            self._log(f"Local HTTP forward-proxy up on 127.0.0.1:{self._http_proxy_port} "
                      f"→ relays plaintext HTTP to the corporate proxy as a forward GET "
                      f"(fixes port-80 downloads such as the Edge updater, and — via the "
                      f"sing-box port-80 route rule — NCSI/WPAD traffic captured by the TUN).")
            return True
        except Exception as e:
            self._http_proxy = None
            self._http_proxy_port = 0
            self._log(f"Could not start the local HTTP forward-proxy ({e}); plaintext-HTTP "
                      f"(port 80) may fail behind a CONNECT-only proxy.", "warning")
            return False

    def _stop_http_proxy(self):
        prx = self._http_proxy
        self._http_proxy = None
        self._http_proxy_port = 0
        if prx is not None:
            try:
                prx.stop()
            except Exception:
                pass

    def _takeover_system_proxy(self):
        """Point the Windows system proxy (WinINET + WinHTTP) at ProxyForce while it
        runs, using a PROTOCOL-SPLIT proxy so each scheme takes its working path:

          https=127.0.0.1:<sing-box mixed>  — TLS via CONNECT (sing-box, native/fast)
          http =127.0.0.1:<local forward>   — plaintext HTTP relayed as a forward-proxy
                                              GET (core/local_proxy)

        The split is the fix for the Edge updater: the corporate proxy 403s CONNECT to
        :80, so plaintext-HTTP downloads (Delivery Optimization) must leave as a
        forward-proxy GET, which sing-box's CONNECT-only outbound cannot produce. If the
        forward proxy did not start, fall back to the single sing-box listener (HTTPS
        keeps working; port-80 stays broken). Proxy-aware apps then route through us; the
        TUN still captures apps that ignore proxy settings. The previous config is
        snapshotted and restored on stop (crash-recovered from proxy_backup.json)."""
        try:
            from core import system_proxy
            if self._http_proxy_port:
                server = (f"http=127.0.0.1:{self._http_proxy_port};"
                          f"https=127.0.0.1:{self._local_proxy_port}")
            else:
                server = f"127.0.0.1:{self._local_proxy_port}"
            prev = system_proxy.point_at(server, self._build_proxy_bypass())
            was = f" (was: {prev})" if prev else ""
            self._log(f"Windows system proxy pointed at ProxyForce ({server}){was} — "
                      f"HTTPS via sing-box, plaintext HTTP via the local forward-proxy; "
                      f"original restored on stop.")
        except Exception as e:
            self._log(f"Could not take over the Windows system proxy: {e}", "warning")
        # Also export HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY (both cases, user +
        # machine environment) — the fix for CLI/dev tools (yt-dlp, curl, git, pip,
        # node, …) that read the environment instead of WinINET/WinHTTP and can be
        # thrown off proxy entirely by a single stray *_proxy var elsewhere on the
        # box (see core/env_proxy for how that happens). Best-effort: HTTPS/registry
        # capture still works if this fails.
        try:
            from core import env_proxy
            http_url = (f"http://127.0.0.1:{self._http_proxy_port}" if self._http_proxy_port
                        else f"http://127.0.0.1:{self._local_proxy_port}")
            https_url = f"http://127.0.0.1:{self._local_proxy_port}"
            prev = env_proxy.point_at(http_url, https_url, self._build_no_proxy())
            was = f" (was: {prev})" if prev else ""
            self._log(f"Proxy environment variables set (HTTP_PROXY={http_url}, "
                      f"HTTPS_PROXY={https_url}){was} — fixes CLI tools (yt-dlp, curl, "
                      f"pip, git, …) that read the environment instead of the Windows "
                      f"proxy setting. A shell opened BEFORE this value ever existed "
                      f"still needs reopening once to pick it up; after that, restarts "
                      f"normally keep the same port (_bind_ports_preferring) so an "
                      f"already-open shell keeps working without needing to be reopened "
                      f"again.")
        except Exception as e:
            self._log(f"Could not set proxy environment variables: {e}", "warning")
        # Recover a crash-safe backup left by the short-lived v2.2.2 passive-only
        # workaround. New sessions never disable active probing: NCSI needs its
        # active HTTP/DNS result to classify the ProxyForce interface as Internet.
        try:
            from core import ncsi
            if ncsi.restore():
                self._log("Legacy NCSI active-probing setting restored; active "
                          "probing remains enabled while ProxyForce runs.")
        except Exception as e:
            self._log(f"Could not restore the legacy NCSI setting: {e}", "warning")
        # v2.1.27: Store/UWP apps run in an AppContainer, which Windows blocks from
        # reaching loopback by default — so pointing the system proxy at 127.0.0.1
        # above makes the Microsoft Store (and every other UWP app) fail outright
        # instead of falling back to direct: it obeys the proxy setting, tries to
        # reach it, and the OS kills the connection before it leaves the app. The
        # TUN catch-all can't rescue it either, since the app never goes direct.
        # Grant a loopback exemption to every installed package so they can reach
        # us like everything else; see core/appcontainer for the snapshot/restore
        # contract. Runs on a background thread — ~113 packages takes a few
        # seconds and must not delay the GUI going green. stop() joins this
        # thread (briefly) before restoring, so a fast start->stop can't race
        # the sweep and leave an exemption it added un-restored.
        self._uwp_thread = threading.Thread(target=self._exempt_uwp_loopback, daemon=True)
        self._uwp_thread.start()

    def _exempt_uwp_loopback(self):
        try:
            from core import appcontainer
            added, total = appcontainer.exempt_installed()
            if total:
                self._log(f"Loopback exemptions granted to {added} of {total} "
                          f"Store/UWP app packages — required because the system "
                          f"proxy is on 127.0.0.1, which AppContainer apps "
                          f"(Microsoft Store, Mail, Xbox, …) are blocked from "
                          f"reaching by default. Removed on stop.")
                # Immediately re-read the exempt count via a FRESH `LoopbackExempt -s`
                # call, rather than trusting the exit-code-derived `added` count above.
                # This is the exact discrepancy that made the v2.1.27 fix impossible to
                # root-cause from the log alone: it reported "122 of 122" granted (every
                # -a call genuinely exited 0) while a readback ~1 minute later (in
                # diagnostics) found only "1" exempt — a parser bug in _list_exempt, not
                # a real add failure, but there was no way to tell from this log line by
                # itself. Logging the immediate readback next to the grant count means
                # any future mismatch (parser bug OR something external reverting the
                # list between checks) is visible right here, side by side, with no
                # guessing required.
                self._log(f"Verified immediately after: {appcontainer.current_state()}")
        except Exception as e:
            self._log(f"Could not exempt Store/UWP apps from loopback isolation: {e}",
                      "warning")

    def _join_uwp_sweep(self, timeout: float = 10):
        """Wait (briefly) for the UWP-exemption sweep before restore() runs — a
        fast start->stop, or an engine crash right after start, could otherwise
        race it: restore()'s snapshot would be taken mid-add, and any exemption
        the sweep adds AFTER that snapshot never gets cleaned up. Best-effort like
        every other lane here: if the sweep is still running past the timeout,
        teardown proceeds anyway rather than blocking shutdown indefinitely."""
        uwp = self._uwp_thread
        if uwp is not None and uwp.is_alive() and uwp is not threading.current_thread():
            uwp.join(timeout=timeout)

    def _restore_system_proxy(self):
        """Restore the system proxy snapshotted at start. Idempotent (no-op if
        already restored / nothing was taken over)."""
        try:
            from core import system_proxy
            if system_proxy.restore():
                self._log("Windows system proxy restored to its previous setting.")
        except Exception as e:
            self._log(f"Could not restore the Windows system proxy: {e}", "warning")
        try:
            from core import env_proxy
            if env_proxy.restore():
                self._log("Proxy environment variables restored to their previous "
                          "setting.")
        except Exception as e:
            self._log(f"Could not restore proxy environment variables: {e}", "warning")
        try:
            from core import appcontainer
            if appcontainer.restore():
                self._log("Store/UWP loopback exemptions removed.")
        except Exception as e:
            self._log(f"Could not remove Store/UWP loopback exemptions: {e}", "warning")
        try:
            from core import ncsi
            if ncsi.restore():
                self._log("Legacy NCSI active-probing setting restored.")
        except Exception as e:
            self._log(f"Could not restore the NCSI active-probing setting: {e}", "warning")

    # ── diagnostics (ground-truth capture for the "green but no capture" bug) ──────

    def _ps(self, command: str, timeout: int = 20) -> str:
        """Run a PowerShell one-liner; return combined stdout+stderr (best-effort)."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True, text=True, creationflags=_NO_WINDOW, timeout=timeout)
            return ((r.stdout or "") + (r.stderr or "")).strip()
        except Exception as e:
            return f"<command failed: {e}>"

    def _proxyforce_connectivity(self) -> str:
        """Return NCSI's IPv4 capability for the ProxyForce interface only."""
        return self._ps(
            "(Get-NetConnectionProfile -InterfaceAlias 'ProxyForce' "
            "-ErrorAction SilentlyContinue).IPv4Connectivity").strip()

    def _run_diagnostics_after_ncsi_settle(self):
        """Keep startup quiet until NCSI's active probe has had a fair run.

        The old diagnostics burst began one second before the diagnosed HTTP
        probe and the interface fell back to LocalNetwork. If the first quiet
        window still has not produced Internet capability, announce the already-
        configured proxy once more (an NCSI refresh trigger) and allow one final
        quiet window before collecting the full report.
        """
        if self._stop_event.wait(_NCSI_SETTLE_SECONDS):
            return
        if self._proxyforce_connectivity() != "Internet":
            try:
                from core import system_proxy
                system_proxy.refresh()
                self._log("ProxyForce network profile is not Internet yet; "
                          "re-announced the proxy configuration and allowing NCSI "
                          "one final quiet probe window.", "warning")
            except Exception as e:
                self._log(f"Could not refresh NCSI after startup: {e}", "warning")
            if self._stop_event.wait(_NCSI_REFRESH_SECONDS):
                return
        self._run_diagnostics()

    def _run_diagnostics(self):
        """Capture the GROUND TRUTH of why traffic is/ isn't being redirected.

        The Clash API is pure loopback, so a green dashboard says NOTHING about
        whether the OS is actually routing packets into the TUN or whether
        strict_route's WFP filters win against a corporate agent. This writes a full
        report to %ProgramData%\\ProxyForce\\diagnostics.txt and echoes a one-line
        verdict to the GUI log. Everything here is READ-ONLY except one safe,
        non-persistent route/metric repair attempted ONLY when auto_route's
        split-default routes are missing (i.e. nothing was capturing anyway); those
        routes live on the TUN adapter and vanish when it is torn down on stop().
        """
        # Pre-init so the final GUI echo is safe even if something throws.
        verdict = "diagnostics did not complete"
        adapter_present = routes_ok = fakeip_ok = unspec_ok = competing = ep_ok = False
        uwp_ok = False
        ncsi_ok = False
        proxy_reachable = True
        problems = []

        if self._stop_event.wait(2.0):   # let auto_route settle on a loaded box
            return
        path = os.path.join(_data_dir(), "diagnostics.txt")
        self._log("Running live diagnostics — verifying the capture path "
                  "(adapter -> routes -> DNS -> proxy); full report will be written "
                  r"to %ProgramData%\ProxyForce\diagnostics.txt.")

        def section(fh, title, body, v=None):
            fh.write(f"\n===== {title} =====\n")
            fh.write((body if (body and body.strip()) else "(no output)") + "\n")
            if v:
                fh.write(f">>> {v}\n")
                if v.startswith(("FAIL", "WARN")):
                    problems.append(v)

        def step(ok, msg):
            """Echo a single live checkpoint to the GUI as each check completes."""
            self._log(("  [ok] " if ok else "  [!]  ") + msg,
                      "info" if ok else "warning")

        try:
            fh = open(path, "w", encoding="utf-8", errors="replace")
        except Exception:
            return
        try:
            fh.write(f"ProxyForce diagnostics — v{APP_VERSION}\n")
            fh.write(time.strftime("Generated: %Y-%m-%d %H:%M:%S\n"))
            fh.write(f"Proxy target : {self.config.host}:{self.config.port} "
                     f"(auth={self.config.auth_type})\n")
            fh.write(f"Clash API    : 127.0.0.1:{self._clash_port}\n")
            section(fh, "OS", self._ps(
                "(Get-CimInstance Win32_OperatingSystem).Caption + ' build ' + "
                "(Get-CimInstance Win32_OperatingSystem).BuildNumber"))

            # ── TUN adapter ──
            idx_raw = self._ps("$a=Get-NetAdapter -Name 'ProxyForce' "
                               "-ErrorAction SilentlyContinue; if($a){$a.ifIndex}else{'NONE'}")
            adapter_present = idx_raw.strip().isdigit()
            tun_idx = idx_raw.strip() if adapter_present else ""
            section(fh, "TUN adapter", self._ps(
                "Get-NetAdapter -Name 'ProxyForce' -ErrorAction SilentlyContinue | "
                "Select-Object Name,ifIndex,Status,InterfaceDescription | "
                "Format-List | Out-String"),
                (f"PASS — adapter present (ifIndex={tun_idx})" if adapter_present
                 else "FAIL — ProxyForce wintun adapter not found / not Up "
                      "(driver-signature / HVCI policy block on this box?)"))
            step(adapter_present,
                 f"TUN adapter up (ifIndex={tun_idx})" if adapter_present
                 else "TUN adapter not found / not Up")

            section(fh, "TUN IP address", self._ps(
                "Get-NetIPAddress -InterfaceAlias 'ProxyForce' -ErrorAction SilentlyContinue | "
                "Select-Object IPAddress,PrefixLength,AddressFamily | Format-Table -Auto | Out-String"))

            # ── DECISIVE: did auto_route install the split-default routes? ──
            if adapter_present:
                count_cmd = ("(Get-NetRoute -InterfaceIndex " + tun_idx +
                             " -ErrorAction SilentlyContinue | Where-Object "
                             "{$_.DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1'} | "
                             "Measure-Object).Count")
                before = self._ps(count_cmd).strip()
                if before == "2":
                    routes_ok = True
                    section(fh, "Split-default routes (DECISIVE)",
                            f"Found {before}/2 split-default routes on the TUN.",
                            "PASS — 0.0.0.0/1 + 128.0.0.0/1 present on ProxyForce "
                            "(route_address + startup enforcement) → TUN wins by "
                            "longest-prefix-match; all traffic captured.")
                else:
                    # Safe, non-persistent repair: lower the TUN metric and add the
                    # split routes on-link. Only when MISSING. Removed with the adapter.
                    repair_cmd = (
                        "Set-NetIPInterface -InterfaceIndex " + tun_idx +
                        " -InterfaceMetric 1 -ErrorAction SilentlyContinue;"
                        "New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceIndex " + tun_idx +
                        " -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore "
                        "-ErrorAction SilentlyContinue | Out-Null;"
                        "New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceIndex " + tun_idx +
                        " -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore "
                        "-ErrorAction SilentlyContinue | Out-Null;" + count_cmd)
                    out = self._ps(repair_cmd, timeout=25)
                    after = out.strip().splitlines()[-1].strip() if out.strip() else "?"
                    routes_ok = after == "2"
                    section(fh, "Split-default routes (DECISIVE)",
                            f"Found {before}/2 BEFORE repair. Attempted metric=1 + on-link "
                            f"route-add. Now {after}/2.",
                            (f"WARN — routes were MISSING at diag time; re-added them (now {after}/2). "
                             "Capture should be live now — re-test your browser."
                             if routes_ok else
                             "FAIL — split-default routes missing AND repair failed; a VPN / "
                             "endpoint agent likely owns the route table. Disable it and retest."))
            else:
                section(fh, "Split-default routes (DECISIVE)", "Skipped — no TUN adapter.")
            step(routes_ok,
                 "capture routes present (0.0.0.0/1 + 128.0.0.0/1) — TUN wins the route table"
                 if routes_ok else "capture routes MISSING — traffic may bypass the TUN")

            section(fh, "Full IPv4 route table", self._ps(
                "Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric | Select-Object "
                "DestinationPrefix,InterfaceAlias,NextHop,RouteMetric,InterfaceMetric | "
                "Format-Table -Auto | Out-String", timeout=25))
            section(fh, "Interface metrics", self._ps(
                "Get-NetIPInterface -AddressFamily IPv4 | Sort-Object InterfaceMetric | "
                "Select-Object InterfaceAlias,InterfaceMetric,ConnectionState | "
                "Format-Table -Auto | Out-String"))

            # ── DNS: is it hijacked to fakeip? (proves DNS traverses the TUN) ──
            a_ip = self._ps(
                "ipconfig /flushdns | Out-Null; (Resolve-DnsName -Name example.com -Type A "
                "-ErrorAction SilentlyContinue | Where-Object {$_.IPAddress}).IPAddress -join ','")
            fakeip_ok = "198.18." in a_ip or "198.19." in a_ip
            section(fh, "DNS A → fakeip", f"example.com A = {a_ip or '(none)'}",
                    ("PASS — DNS hijacked to fakeip (CONNECT-by-hostname path active)" if fakeip_ok
                     else "FAIL — DNS not returning a fakeip; either routes are missing (DNS "
                          "not traversing the TUN) or DoH is bypassing us. CONNECT-by-IP → "
                          "an inspecting proxy blocks it."))
            step(fakeip_ok,
                 f"DNS hijacked to fakeip (example.com -> {a_ip})" if fakeip_ok
                 else "DNS NOT hijacked to fakeip (DoH or routing gap)")
            aaaa = self._ps(
                "(Resolve-DnsName -Name example.com -Type AAAA -ErrorAction SilentlyContinue | "
                "Where-Object {$_.IPAddress}).IPAddress -join ','")
            section(fh, "DNS AAAA suppression", f"example.com AAAA = {aaaa or '(none — good)'}",
                    ("PASS — AAAA suppressed (no IPv6 leak)" if not aaaa.strip()
                     else "WARN — AAAA returned real IPv6; Happy Eyeballs may bypass the "
                          "IPv4-only TUN."))

            # ── DNS: getaddrinfo(AF_UNSPEC) — what apps ACTUALLY call, not just A-only.
            # The A-only probe above can PASS while this fails (observed on a box
            # reporting yt-dlp "getaddrinfo failed" while browsers worked fine): most
            # CLI tools (yt-dlp/curl/git/pip/…) call getaddrinfo() with no family hint,
            # which is AF_UNSPEC on Windows. If that path doesn't return a fakeip, such
            # a tool gets a REAL IP (or an outright resolution failure if the real
            # resolver blocks the domain) and bypasses capture entirely — invisible to
            # every proxy-aware app tested, since none of them call getaddrinfo() ──
            unspec_ip = self._ps(
                "([System.Net.Dns]::GetHostAddresses('example.com') | "
                "Where-Object {$_.AddressFamily -eq 'InterNetwork'}).IPAddressToString -join ','")
            unspec_ok = "198.18." in unspec_ip or "198.19." in unspec_ip
            section(fh, "DNS getaddrinfo(AF_UNSPEC) — the path apps actually call",
                    f"example.com getaddrinfo = {unspec_ip or '(none)'}",
                    ("PASS — AF_UNSPEC also resolves to a fakeip (matches the A-only probe)"
                     if unspec_ok else
                     "FAIL — AF_UNSPEC does NOT resolve to a fakeip even though the A-only "
                     "probe did; a tool calling getaddrinfo() (yt-dlp, curl, git, pip, …) "
                     "gets a REAL IP and bypasses capture. This is the 'getaddrinfo failed' "
                     "failure mode."))
            step(unspec_ok,
                 f"getaddrinfo(AF_UNSPEC) hijacked to fakeip (example.com -> {unspec_ip})"
                 if unspec_ok else
                 "getaddrinfo(AF_UNSPEC) NOT hijacked to fakeip — CLI tools may bypass capture")

            # ── NCSI: does WINDOWS ITSELF believe it has internet? Diagnosed
            # 2026-08-07: NlaSvc's probes ignore the WinINET/WinHTTP proxy split
            # entirely (it is a SYSTEM-account service making raw, proxy-less
            # requests — exactly what the checks below reproduce with .Proxy=$null
            # so they test the real TUN path, not our own proxy takeover). Every
            # check above can PASS while this still fails, and the failure is
            # completely silent: Get-NetConnectionProfile just reports
            # IPv4Connectivity=LocalNetwork and every component that gates on
            # connectivity level (Windows Spotlight/ContentDeliveryManager, Store,
            # Widgets, Teams presence) quietly does nothing — no error, no log,
            # just content that never refreshes.
            #
            # v2.2.2 postmortem: the DNS/web probe fixes below are real and were
            # PROVEN correct via the Microsoft-Windows-NCSI/Operational event log
            # (ActiveDnsProbeSucceeded -> Capability:Internet, immediately after
            # start) — but active probing needs a tight ~3.5s round trip
            # (registry WebTimeout) through our interception layer, and that one
            # observed run's OWN _run_diagnostics() subprocess burst (this exact
            # method!) starved it a second later, flipping the verdict back to
            # LocalNetwork with nothing left to notice or correct it. That is why
            # _takeover_system_proxy() now suppresses active probing
            # UNCONDITIONALLY, before this diagnostics pass ever runs, rather than
            # this method deciding reactively whether to apply it — see that
            # method's comment for the full reasoning. This check now reads the
            # result rather than deciding whether to act on it, and keys off the
            # ProxyForce interface specifically — Ethernet's own NCSI reading was
            # the one observed flapping in the event log and isn't the profile the
            # fixes target.
            conn_profile = self._ps(
                "Get-NetConnectionProfile | Select-Object InterfaceAlias,IPv4Connectivity | "
                "Format-Table -Auto | Out-String")
            pf_connectivity = self._proxyforce_connectivity()
            ncsi_ok = pf_connectivity == "Internet"
            ncsi_event = self._ps(
                "$g=(Get-NetAdapter -Name 'ProxyForce' -ErrorAction SilentlyContinue)."
                "InterfaceGuid.ToString();"
                "if($g){Get-WinEvent -FilterHashtable "
                "@{LogName='Microsoft-Windows-NCSI/Operational'} -ErrorAction "
                "SilentlyContinue | Where-Object {$_.Message -match "
                "[regex]::Escape($g)} | Select-Object -First 1 -ExpandProperty Message}",
                timeout=10)
            ncsi_reason = _ncsi_event_reason(ncsi_event)
            ncsi_conf = self._ps(
                "$k='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NlaSvc\\Parameters\\Internet';"
                "$p=Get-ItemProperty $k -ErrorAction SilentlyContinue;"
                "$dh=$p.ActiveDnsProbeHost; $dw=$p.ActiveDnsProbeContent;"
                "$wh=$p.ActiveWebProbeHost; $wp=$p.ActiveWebProbePath; $ww=$p.ActiveWebProbeContent;"
                "$dg=(Resolve-DnsName -Name $dh -Type A -ErrorAction SilentlyContinue | "
                "Select-Object -First 1).IPAddress;"
                "try {"
                "  $req=[System.Net.HttpWebRequest]::Create(\"http://$wh/$wp\");"
                "  $req.Proxy=$null; $req.Timeout=8000;"
                "  $resp=$req.GetResponse();"
                "  $sr=New-Object System.IO.StreamReader($resp.GetResponseStream());"
                "  $wg=$sr.ReadToEnd().Trim(); $resp.Close()"
                "} catch { $wg=\"<error: $($_.Exception.Message)>\" }"
                "\"DNSHOST=$dh|DNSWANT=$dw|DNSGOT=$dg|WEBHOST=$wh|WEBWANT=$ww|WEBGOT=$wg\"",
                timeout=20)

            def _kv(s, key):
                m = re.search(re.escape(key) + r"=(.*?)(?:\||$)", s)
                return (m.group(1) if m else "").strip()

            dns_host, dns_want, dns_got = (_kv(ncsi_conf, "DNSHOST"),
                                            _kv(ncsi_conf, "DNSWANT"), _kv(ncsi_conf, "DNSGOT"))
            web_host, web_want, web_got = (_kv(ncsi_conf, "WEBHOST"),
                                            _kv(ncsi_conf, "WEBWANT"), _kv(ncsi_conf, "WEBGOT"))
            dns_probe_ok = bool(dns_want) and dns_want == dns_got
            web_probe_ok = bool(web_want) and web_want in web_got
            section(fh, "NCSI connectivity (Get-NetConnectionProfile)", conn_profile,
                    ("PASS — Windows reports Internet connectivity"
                     if ncsi_ok else
                     "FAIL — Windows does NOT report Internet connectivity "
                     "(IPv4Connectivity is LocalNetwork/NoTraffic/Subnet). Every component "
                     "gating on connectivity level — Windows Spotlight, Store, Widgets, Teams "
                     "presence — will silently stop refreshing. See the two probe checks below."))
            step(ncsi_ok,
                 "Windows reports Internet connectivity (NCSI)" if ncsi_ok else
                 "Windows does NOT report Internet connectivity (NCSI) — Spotlight/Store/"
                 "Widgets will silently stop refreshing")
            section(fh, "Latest NCSI event for ProxyForce",
                    ncsi_event or "(no matching event found)",
                    (f"Latest change reason: {ncsi_reason}" if ncsi_reason else
                     "No ChangeReason was available; use the DNS/web checks below."))
            section(fh, "NCSI DNS probe",
                    f"{dns_host}: want '{dns_want}', got '{dns_got or '(none)'}'",
                    ("PASS — matches exactly" if dns_probe_ok else
                     "FAIL — fakeip answers this instead of the literal constant NCSI expects "
                     "(see _ncsi_dns_probe's predefined DNS rule in _render_config)."))
            section(fh, "NCSI web probe",
                    f"http://{web_host}: want body '{web_want}', got '{web_got or '(none)'}'",
                    ("PASS — matches" if web_probe_ok else
                     "FAIL — request bypasses any proxy setting (.Proxy=$null, matching how "
                     "NlaSvc itself probes) and is captured by the TUN; without the port-80 "
                     "route rule sending it to the local forward-proxy, sing-box's CONNECT-only "
                     "outbound gets 403'd by the corporate proxy on :80."))

            # Active probing must remain enabled. Passive polling alone cannot
            # establish every connectivity state and previously left Spotlight idle.
            try:
                from core import ncsi
                ncsi_state = ncsi.current_state()
            except Exception as e:
                ncsi_state = f"<unavailable: {e}>"
            probing_suppressed = "EnableActiveProbing=0" in ncsi_state
            section(fh, "NCSI active probing", ncsi_state,
                    ("FAIL — active probing is disabled; ProxyForce no longer makes "
                     "this change. Check Group Policy or a legacy ncsi_backup.json."
                     if probing_suppressed else
                     "PASS — active probing remains enabled."))

            # ── End-to-end capture probe ──
            section(fh, "Capture probe (TCP 443 → example.com)", self._ps(
                "$r=Test-NetConnection -ComputerName example.com -Port 443 "
                "-WarningAction SilentlyContinue; "
                "\"TcpTestSucceeded=$($r.TcpTestSucceeded) RemoteAddress=$($r.RemoteAddress)\"",
                timeout=30))

            # ── Proxy reachability: can sing-box's OWN connection escape the TUN? ──
            # If the split routes also capture the proxy IP, sing-box loops trying to
            # reach its upstream → "dial …: i/o timeout" and NOTHING is forwarded even
            # though capture/DNS look perfect. The /32 server-exclude (enforced before
            # this runs) must let this one connection out the physical NIC.
            reach = self._ps(
                "$r=Test-NetConnection -ComputerName '" + str(self.config.host) + "' -Port "
                + str(self.config.port) + " -WarningAction SilentlyContinue;"
                "\"TcpTestSucceeded=$($r.TcpTestSucceeded) via=$($r.InterfaceAlias) "
                "remote=$($r.RemoteAddress)\"", timeout=30)
            # Decide reachability from AUTHORITATIVE signals, not log noise:
            #   1) the live TCP test to the proxy succeeded (reachable right now), OR
            #   2) real traffic has already been forwarded through the engine.
            # The OLD heuristic flagged a failure whenever "proxy-out" AND any timeout
            # keyword BOTH appeared ANYWHERE in the last 80 log lines — so a single
            # ordinary per-site timeout, or a stale startup dial from before the /32
            # exclude took hold, produced a FALSE "PROXY UNREACHABLE" even though the
            # TCP test passed and traffic was flowing. Now a log line counts as a real
            # UPSTREAM-proxy dial failure (the v2.1.7 loop) only when it BOTH reports a
            # connection failure AND names the proxy server itself (its host or :port
            # on a "dial …" line). An ordinary per-site timeout names the destination
            # (:443/:80), not the proxy, so it no longer trips the alarm.
            host = str(self.config.host).strip()
            port = str(self.config.port).strip()
            loop_lines = self._scan_upstream_dial_failures(
                self._tail_log_lines(120), host, port)
            tcp_ok = "TcpTestSucceeded=True" in reach
            traffic_flowing = (self.stats.bytes_forwarded > 0
                               or self.stats.active_connections > 0)
            # Reachable if the TCP test passes OR traffic is already flowing. A loop is
            # only a genuine failure when NOTHING has been forwarded — if bytes are
            # moving, the proxy is plainly reachable and any old loop line is stale.
            proxy_reachable = tcp_ok or traffic_flowing
            if loop_lines and not traffic_flowing:
                proxy_reachable = False
            reach_detail = (
                reach
                + f"\nForwarded so far: {self.stats.bytes_forwarded} bytes across "
                  f"{self.stats.active_connections} active connection(s)."
                + ("\nUPSTREAM-proxy dial failures found in the sing-box log "
                   "(connection looping back into the TUN):\n  "
                   + "\n  ".join(loop_lines[-3:]) if loop_lines else ""))
            section(fh, "Proxy reachability (must escape the TUN via /32 exclude)",
                    reach_detail,
                    ("PASS — upstream proxy reachable; sing-box's own connection escapes "
                     "the TUN" + (" (traffic already forwarded)" if traffic_flowing else "")
                     if proxy_reachable else
                     "FAIL — sing-box cannot reach the proxy (dial timeout/refused) and no "
                     "traffic has been forwarded. Its connection is looping back into the TUN, "
                     "OR the proxy host:port is blocked from this machine. The /32 server-exclude "
                     "route should break the loop; if this persists, confirm the proxy is "
                     "reachable from this box."))
            step(proxy_reachable,
                 (f"upstream proxy reachable ({host}:{port})"
                  + (" — traffic flowing" if traffic_flowing else ""))
                 if proxy_reachable else
                 f"upstream proxy NOT reachable ({host}:{port})")

            # ── Proxy CONNECT policy: the proxy answered and REFUSED a port, as
            # opposed to being unreachable. Diagnosed 2026-08-07: a corporate proxy
            # that refuses CONNECT on some destination/port — the connection is
            # fine, the policy says no, and no amount of retrying fixes it. Every
            # corporate network has its own idea of what gets refused (diagnosed
            # 2026-08-08: an internal DNS-suffixed hostname refused on an
            # arbitrary internal port, nothing to do with any one documented
            # case), so this is intentionally generic rather than naming a
            # specific scenario. Sourced from sing-box's own log, since this
            # happens entirely inside sing-box's proxy-out outbound.
            #
            # Port 80 USED to be excluded here as "expected" — core/local_proxy.py
            # handled it, but only for proxy-aware apps reading the http= system-
            # proxy entry. Since the port-80 sing-box route rule (v2.2.1) now sends
            # ALL TUN-captured :80 traffic direct to that same local forward-proxy
            # BEFORE it ever reaches this CONNECT-only outbound, a :80 refusal here
            # can no longer be routine — it means something upstream of proxy-out
            # (a bypassed host, a manual routing override) is still hitting CONNECT
            # on :80, which is worth surfacing rather than silently swallowing.
            #
            # As of v2.2.2 this is no longer purely a "go fix it yourself" WARN:
            # _check_auto_bypass (running periodically in the steady-state loop)
            # already handles this automatically when cfg.auto_bypass is enabled,
            # so by the time a user reads this report the destination has often
            # already been bypassed and reconnected past. This section reports
            # what was SEEN, not what the user needs to go do about it.
            from core import auto_bypass as _auto_bypass_mod
            reject_lines = self._scan_upstream_rejections(self._tail_log_lines(200))
            rejections = _auto_bypass_mod.extract_rejections(reject_lines)
            connect_denied = bool(rejections)
            denied_desc = ", ".join(f"{h}:{p}" for h, p, _c in rejections)
            auto_bypass_on = getattr(self.config, "auto_bypass", True)
            already_bypassed = {normalize_bypass_entry(e)[0]
                                for e in (self.config.bypass_list or [])}
            all_handled = connect_denied and all(
                normalize_bypass_entry(h)[0] in already_bypassed for h, _p, _c in rejections)
            section(fh, "Proxy CONNECT policy (upstream refusals, distinct from unreachable)",
                    (f"Refused in the recent sing-box log: {denied_desc}" if connect_denied
                     else "No CONNECT refusals seen in the recent log."),
                    ("PASS — refusal(s) seen but already routed DIRECT via the Bypass List "
                     f"({denied_desc})" if all_handled else
                     f"INFO — the proxy refused CONNECT for {denied_desc}; auto-bypass is "
                     "enabled and will route it DIRECT automatically (a brief reconnect "
                     "follows if it hasn't already happened by the time you read this)."
                     if connect_denied and auto_bypass_on else
                     f"WARN — the proxy refuses CONNECT for {denied_desc} and auto-bypass is "
                     "disabled; add the destination(s) to the Bypass List manually so they "
                     "route DIRECT."
                     if connect_denied else
                     "PASS — no CONNECT refusals seen in the recent log."))
            step(not connect_denied or all_handled,
                 "no proxy CONNECT refusals seen" if not connect_denied else
                 (f"refusal(s) already auto-bypassed ({denied_desc})" if all_handled else
                  f"proxy refuses CONNECT for {denied_desc} — "
                  + ("auto-bypass will apply shortly" if auto_bypass_on else
                     "route those hosts DIRECT via the Bypass List")))
            # connect_denied now only drives the VERDICT when auto-bypass hasn't
            # (yet, or can't) resolve it — see the verdict block below.
            connect_denied = connect_denied and not all_handled and not auto_bypass_on

            # ── System proxy: must point at OUR local listener (so proxy-aware apps,
            # incl. the Edge updater, route through sing-box over TCP — not QUIC/direct
            # and not some other proxy that would bypass us) ──
            try:
                from core import system_proxy
                sp_state = system_proxy.current_state()
            except Exception as e:
                sp_state = f"<unavailable: {e}>"
            mixed = f"127.0.0.1:{self._local_proxy_port}"
            fwd = f"127.0.0.1:{self._http_proxy_port}" if self._http_proxy_port else ""
            ours = (f"http={fwd};https={mixed}" if fwd else mixed)
            sp_ok = (mixed in sp_state) and (not fwd or fwd in sp_state)
            section(fh, "System proxy (should point at ProxyForce's local listeners)", sp_state,
                    (f"PASS — system proxy points at ProxyForce ({ours}); proxy-aware apps "
                     "route HTTPS through sing-box (CONNECT) and plaintext HTTP through the "
                     "local forward-proxy (forward GET)"
                     if sp_ok else
                     "WARN — system proxy does not fully point at ProxyForce. Takeover may have "
                     "been blocked (GPO?) or overridden by a per-app/group-policy proxy; "
                     "proxy-aware apps may bypass capture."))
            step(sp_ok,
                 f"Windows system proxy points at ProxyForce ({ours})" if sp_ok
                 else "Windows system proxy does NOT fully point at ProxyForce (proxy-aware apps may bypass)")

            # ── Proxy environment variables: HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY.
            # CLI/dev tools (yt-dlp, curl, git, pip, node, …) read these INSTEAD of
            # WinINET/WinHTTP above — a box can show sp_ok=PASS and still send such a
            # tool nowhere near the proxy if this is missing or a stray *_proxy var
            # elsewhere on the box is shadowing it (see core/env_proxy) ──
            try:
                from core import env_proxy
                ep_state = env_proxy.current_state()
            except Exception as e:
                ep_state = f"<unavailable: {e}>"
            expect_http = (f"http://127.0.0.1:{self._http_proxy_port}" if self._http_proxy_port
                           else f"http://127.0.0.1:{self._local_proxy_port}")
            expect_https = f"http://127.0.0.1:{self._local_proxy_port}"
            ep_ok = (expect_http in ep_state) and (expect_https in ep_state)
            section(fh, "Proxy environment variables (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY)",
                    ep_state,
                    (f"PASS — env vars point at ProxyForce ({expect_http} / {expect_https}); "
                     "CLI/dev tools that read the environment instead of the Windows proxy "
                     "setting will use the proxy instead of falling back to direct DNS"
                     if ep_ok else
                     "WARN — proxy environment variables do not point at ProxyForce. A shell "
                     "opened BEFORE Start won't see this until reopened — that alone explains "
                     "a stale failure; if a NEWLY opened shell also misses it, the env "
                     "takeover itself failed."))
            step(ep_ok,
                 f"Proxy environment variables point at ProxyForce ({expect_http} / {expect_https})"
                 if ep_ok else
                 "Proxy environment variables do NOT point at ProxyForce (env-reading CLI tools may bypass)")

            # ── Store/UWP loopback exemption: the system proxy above points at
            # 127.0.0.1, and every UWP app runs in an AppContainer, which Windows
            # blocks from reaching loopback unless exempted. An app that honours
            # the proxy setting but ISN'T exempt fails outright — it never falls
            # back to direct, so the TUN can't rescue it either. Probe the
            # Microsoft Store specifically since it's the package the user will
            # notice first (see core/appcontainer) ──
            try:
                from core import appcontainer
                uwp_ok = appcontainer.is_exempt("Microsoft.WindowsStore_8wekyb3d8bbwe")
                uwp_state = appcontainer.current_state()
            except Exception as e:
                uwp_state = f"<unavailable: {e}>"
            # Raw `-s` text, not just the parsed summary above — the v2.1.27 fix's
            # failure to root-cause came from having ONLY a summarized count to go on
            # (a parser bug in core/appcontainer undercounted "122 exempt" as "1" with
            # no way to see why from the log alone). Whatever CheckNetIsolation actually
            # printed on THIS box is right here so a future mismatch is visible by eye.
            raw_list = self._ps("CheckNetIsolation LoopbackExempt -s", timeout=20)
            uwp_body = f"{uwp_state}\n\nRaw `CheckNetIsolation LoopbackExempt -s`:\n{raw_list}"
            section(fh, "Store/UWP loopback exemption (Microsoft Store probe)", uwp_body,
                    ("PASS — Microsoft Store is loopback-exempt; it can reach the local proxy"
                     if uwp_ok else
                     "FAIL — Microsoft Store is NOT loopback-exempt. Windows blocks AppContainer "
                     "apps from reaching 127.0.0.1 by default, so the Store (and other UWP apps) "
                     "cannot reach the local proxy the system-proxy takeover points them at, and "
                     "will fail to load. See core/appcontainer.exempt_installed()."))
            step(uwp_ok,
                 "Store/UWP apps exempted from loopback isolation"
                 if uwp_ok else
                 "Store/UWP apps CANNOT reach the local proxy — Microsoft Store and other "
                 "Store apps will fail to load")

            # ── What sing-box itself saw ──
            conns = self._clash_get("/connections") or {}
            clist = conns.get("connections") or []
            lines = []
            for c in clist[:15]:
                md = c.get("metadata") or {}
                dst = md.get("host") or md.get("destinationIP") or "?"
                lines.append(f"  {md.get('network','?')} -> {dst}:{md.get('destinationPort','')}"
                             f"  chains={c.get('chains') or c.get('rule')}")
            section(fh, "sing-box Clash /connections",
                    f"active={len(clist)} downloadTotal={conns.get('downloadTotal')} "
                    f"uploadTotal={conns.get('uploadTotal')}\n" + "\n".join(lines))
            section(fh, "sing-box log (last 40 lines, debug)", self._tail_log(40))

            # ── Competing agents / WFP arbitration ──
            procs = self._ps(
                "Get-Process | Where-Object {$_.Name -match "
                "'ZSATunnel|zscaler|nstunnel|netskope|vpnagent|csc_vpnagent|acvpnagent|"
                "falcon|SentinelAgent|MpNetworkProtection|pangp|acosd|openvpn|wireguard|"
                "forcefield|fdrsvc|umbrella'} | Select-Object Name,Id | Format-Table -Auto | Out-String")
            competing = bool(procs.strip())
            section(fh, "Competing VPN/endpoint agents", procs or "(none detected)",
                    ("WARN — competing agent(s) detected; may outbid strict_route's WFP callout"
                     if competing else "PASS — no known competing agent process"))
            section(fh, "All network adapters (incl. hidden)", self._ps(
                "Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,Status | "
                "Format-Table -Auto | Out-String", timeout=25))
            wfp_xml = os.path.join(_data_dir(), "wfp_state.xml")
            section(fh, "WFP state dump", self._ps(
                "netsh wfp show state file=\"" + wfp_xml + "\" | Out-Null;"
                " if(Test-Path '" + wfp_xml + "'){'written: " + wfp_xml + "'}else{'FAILED to write'}",
                timeout=45))

            # ── VERDICT ──
            if not adapter_present:
                verdict = ("ADAPTER FAILURE — the ProxyForce wintun adapter is not Up, so "
                           "sing-box cannot capture. Suspect a driver-signature / HVCI policy on "
                           "this box.")
            elif not routes_ok:
                verdict = ("ROUTING FAILURE — auto_route's split-default routes are missing and "
                           "the on-the-fly repair failed; a VPN or endpoint agent likely owns the "
                           "route table. Disable it and retest.")
            elif not fakeip_ok:
                verdict = ("DNS HIJACK FAILURE — DNS is not returning a fakeip, so connections go "
                           "CONNECT-by-IP and an inspecting proxy blocks them. Suspect browser/system DoH.")
            elif not unspec_ok:
                verdict = ("DNS AF_UNSPEC MISMATCH — the A-only probe resolves to a fakeip but "
                           "getaddrinfo(AF_UNSPEC) — the call apps actually make — does not; CLI "
                           "tools (yt-dlp, curl, git, pip, …) get a REAL IP and bypass capture. "
                           "This is the 'getaddrinfo failed' failure mode; see the DNS "
                           "getaddrinfo(AF_UNSPEC) section.")
            elif not proxy_reachable:
                verdict = ("PROXY UNREACHABLE — capture + DNS work, but sing-box cannot reach the "
                           "upstream proxy (dial timeout/refused). Its own connection is looping "
                           "into the TUN, or the proxy host:port is blocked from this machine. See "
                           "the Proxy reachability section.")
            elif connect_denied:
                verdict = ("PROXY CONNECT POLICY — the upstream proxy is reachable but refuses "
                           f"CONNECT for {denied_desc}. Auto-bypass is disabled (Settings), so this "
                           "won't resolve on its own — add the destination(s) to the Bypass List "
                           "manually so they route DIRECT instead of retrying the proxy, or "
                           "re-enable auto-bypass. See the Proxy CONNECT policy section.")
            elif competing:
                verdict = ("WFP CONTENTION LIKELY — routes/DNS look OK but a competing agent is "
                           "present and may outbid capture. Disable it to confirm.")
            elif not ep_ok:
                verdict = ("ENV PROXY MISSING — capture works but the HTTP_PROXY/HTTPS_PROXY "
                           "environment variables are not set; CLI/dev tools that read the "
                           "environment instead of the Windows proxy setting (yt-dlp, curl, "
                           "pip, git, …) may bypass capture. See the Proxy environment "
                           "variables section.")
            elif not uwp_ok:
                verdict = ("UWP LOOPBACK BLOCKED — capture, DNS, and the proxy takeover all work, "
                           "but Store/UWP apps (Microsoft Store, Mail, Xbox, …) are not loopback-"
                           "exempt, so they cannot reach the local proxy and will fail to load. "
                           "See the Store/UWP loopback exemption section; core/appcontainer "
                           "should have granted this automatically — check for an Access Denied "
                           "error in the log (requires elevation, which ProxyForce should already "
                           "have).")
            elif not ncsi_ok:
                verdict = ("NO INTERNET (NCSI) — Windows' ProxyForce network profile does not yet "
                           "report 'Internet' connectivity, even though capture/DNS/the proxy "
                           "takeover all work. Every component that gates on connectivity level — "
                           "Windows Spotlight/lock-screen images, Microsoft Store, Widgets, Teams "
                           "presence — silently stops refreshing with no visible error. See the "
                           "latest NCSI event plus the DNS/web probe sections for the exact "
                           "active-probe failure reason.")
            elif problems:
                verdict = "PARTIAL — engine mostly healthy; see the WARN lines in diagnostics.txt."
            else:
                verdict = ("ENGINE HEALTHY per diagnostics — routes + fakeip OK, no competing "
                           "agent. If the browser is still direct, disable its Secure DNS (DoH) "
                           "and retest.")
            fh.write(f"\n========== VERDICT ==========\n{verdict}\n")
        finally:
            try:
                fh.close()
            except Exception:
                pass

        bad = (not adapter_present) or (not routes_ok) or (not fakeip_ok) or \
              (not unspec_ok) or (not proxy_reachable) or connect_denied or \
              (not ep_ok) or (not uwp_ok) or (not ncsi_ok) or competing or bool(problems)
        self._log(f"DIAG: {verdict}  (full report: "
                  r"%ProgramData%\ProxyForce\diagnostics.txt)",
                  "warning" if bad else "info")

    # ── logs ──────────────────────────────────────────────────────────────────────

    def _tail_log(self, n: int = 20) -> str:
        try:
            with open(os.path.join(_singbox_dir(), "singbox.log"),
                      "r", encoding="utf-8", errors="replace") as f:
                lines = [l.strip() for l in f.readlines() if l.strip()]
            return "Last log: " + " | ".join(lines[-n:]) if lines else ""
        except Exception:
            return ""

    def _tail_log_lines(self, n: int = 40) -> List[str]:
        """Last n non-blank sing-box log lines as a list (for per-line scanning)."""
        try:
            with open(os.path.join(_singbox_dir(), "singbox.log"),
                      "r", encoding="utf-8", errors="replace") as f:
                lines = [l.rstrip("\n") for l in f if l.strip()]
            return lines[-n:]
        except Exception:
            return []

    _DIAL_FAIL_KEYWORDS = (
        "i/o timeout", "connection refused", "no route to host",
        "network is unreachable", "context deadline exceeded")

    @classmethod
    def _scan_upstream_dial_failures(cls, lines, host, port) -> List[str]:
        """Return only the log lines that show sing-box failing to dial the UPSTREAM
        proxy (the v2.1.7 routing-loop symptom) — NOT ordinary per-site timeouts.

        A line qualifies only if it BOTH reports a connection failure AND names the
        proxy server itself: its host literal, or `:<proxy_port>:` inside a "dial …"
        line (e.g. `dial tcp 203.0.113.10:800: i/o timeout`). An ordinary per-site
        timeout names the *destination* (:443/:80), not the proxy, so it is excluded.
        This precision is what kills the false "PROXY UNREACHABLE" verdict: the old
        check fired if "proxy-out" and any timeout word appeared ANYWHERE in the tail.
        """
        host = (host or "")
        if not isinstance(host, str):
            host = str(host)
        host = host.strip()
        port = str(port or "").strip()
        hits = []
        for ln in (lines or []):
            low = ln.lower()
            if not any(k in low for k in cls._DIAL_FAIL_KEYWORDS):
                continue
            if "dial" in low and ((host and host in ln) or (port and f":{port}:" in ln)):
                hits.append(ln)
        return hits

    # Distinct from a dial failure (above): the upstream proxy ANSWERED and
    # refused the CONNECT — a policy failure, not a reachability one. sing-box
    # logs this as `unexpected status: 403 Forbidden` (or 407/502/503).
    _UPSTREAM_REJECT_MARKER = "unexpected status:"

    @classmethod
    def _scan_upstream_rejections(cls, lines) -> List[str]:
        """Return log lines where sing-box's proxy-out outbound got a real HTTP
        response to CONNECT that wasn't 200 — e.g. a corporate proxy that only
        permits CONNECT to :443 refusing :993/:465/:587/:80 with 403. Kept as a
        sibling of _scan_upstream_dial_failures rather than folded into
        _DIAL_FAIL_KEYWORDS (guarded by tests/test_proxy_reachability.py) since
        the two failure modes need different verdicts and different fixes: a
        dial failure means the proxy is unreachable; a rejection means it IS
        reachable and is refusing this port by policy — see _check_auto_bypass,
        which now handles this automatically rather than requiring a manual
        Bypass List edit."""
        return [ln for ln in (lines or []) if cls._UPSTREAM_REJECT_MARKER in ln.lower()]

    def _check_auto_bypass(self):
        """Detect NEW proxy CONNECT refusals and, if cfg.auto_bypass allows it, ask
        to route them DIRECT going forward — no manual Bypass List edit required.

        ProxyForce is used against many different corporate proxy policies, each
        with its own idea of what gets refused (diagnosed 2026-08-08: an internal
        DNS-suffixed hostname refused on an arbitrary internal port, nothing to do
        with any documented case like Outlook's mail ports). The general answer is
        to try the proxy first and notice when it explicitly says no, rather than
        hardcode assumptions about any particular network.

        Deliberately narrow: only an EXPLICIT refusal counts (the proxy answered
        with a real non-2xx status — see core.auto_bypass.extract_rejections,
        fed from _scan_upstream_rejections). A dial timeout/unreachable condition
        is a different failure mode (_scan_upstream_dial_failures) and must NOT
        trigger this — that's evidence of a network problem, not a policy
        decision, and auto-bypassing on it would silently leak traffic around the
        proxy for the wrong reason.

        Can't safely restart the engine from inside its own steady-state thread,
        so this only detects + persists + asks (via on_auto_bypass); the actual
        restart is the GUI's job, reusing the exact same path a Settings-save
        restart already uses.
        """
        if not getattr(self.config, "auto_bypass", True):
            return
        try:
            from core import auto_bypass
            reject_lines = self._scan_upstream_rejections(self._tail_log_lines(200))
            rejections = auto_bypass.extract_rejections(reject_lines)
        except Exception:
            return
        if not rejections:
            return
        existing = {normalize_bypass_entry(e)[0] for e in (self.config.bypass_list or [])}
        new_entries = []
        for host, port, code in rejections:
            base, _apex, err = normalize_bypass_entry(host)
            if err or base is None or base in existing or base in self._auto_bypass_reported:
                continue
            self._auto_bypass_reported.add(base)
            new_entries.append((base, port, code))
        if not new_entries:
            return
        for base, port, code in new_entries:
            self._log(f"{base} now routes DIRECT — the proxy refused CONNECT on "
                      f"port {port} (status {code}). Reconnecting to apply…")
        if self.on_auto_bypass:
            try:
                self.on_auto_bypass([base for base, _port, _code in new_entries])
            except Exception as e:
                self._log(f"Auto-bypass callback failed: {e}", "warning")

    def _close_log(self):
        try:
            if self._log_fh not in (None, subprocess.DEVNULL):
                self._log_fh.close()
        except Exception:
            pass
        self._log_fh = None

    # ── stop ───────────────────────────────────────────────────────────────────────

    def stop(self):
        if self.state == SingBoxState.STOPPED:
            return
        self._set_state(SingBoxState.STOPPING)
        self._stop_event.set()

        # TerminateProcess. sing-box's WFP rules live in a DYNAMIC session that is
        # torn down when the process handle closes, so a hard stop still cleans
        # those up. The wintun adapter, however, can linger briefly on Windows 10
        # — so wait for it to disappear before declaring STOPPED, otherwise a
        # quick Start again would hit the "already exists" timing bug.
        self._terminate_proc()
        # Join the supervisor so a quick Stop→Start can't leave two _supervise
        # threads racing (the second would orphan the first's sing-box, which keeps
        # holding its WFP filters and contends with the new instance).
        mon = self._monitor
        if mon is not None and mon.is_alive() and mon is not threading.current_thread():
            mon.join(timeout=10)
        end = time.time() + 6
        while time.time() < end and self._tun_adapter_exists():
            time.sleep(0.3)

        # Stop the local forward-proxy and put the Windows system proxy back exactly
        # as we found it.
        self._join_uwp_sweep()
        self._stop_http_proxy()
        self._restore_system_proxy()

        self.stats.active_connections = 0
        self._set_state(SingBoxState.STOPPED)
        self._log("ProxyForce stopped.")

    def update_config(self, config: ProxyConfig):
        self.config = config
        self._log(f"Config updated → {config.host}:{config.port}")
