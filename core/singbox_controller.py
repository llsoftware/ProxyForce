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
import sys
import json
import time
import socket
import ctypes
import threading
import subprocess
import ipaddress
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Callable, List

import logging

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

    def __post_init__(self):
        if self.bypass_list is None:
            self.bypass_list = []


@dataclass
class ConnectionStats:
    active_connections: int = 0
    total_connections: int = 0
    bytes_forwarded: int = 0
    errors: int = 0
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


def _free_loopback_port() -> int:
    """Grab a free 127.0.0.1 TCP port for the Clash API (avoids reserved ranges)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


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
    )


class SingBoxController:
    """Runs and supervises sing-box; presents the Redirector interface."""

    def __init__(self, config: ProxyConfig, on_state_change: Callable = None,
                 on_stats_update: Callable = None, on_log: Callable = None):
        self.config = config
        self.on_state_change = on_state_change
        self.on_stats_update = on_stats_update
        self.on_log = on_log
        self.state = SingBoxState.STOPPED
        self.stats = ConnectionStats()
        self._debug = False

        self._proc: Optional[subprocess.Popen] = None
        self._log_fh = None
        self._clash_port = 0
        self._local_proxy_port = 0   # local mixed inbound the system proxy points at
        self._exit_code = 0
        self._stop_event = threading.Event()
        self._monitor: Optional[threading.Thread] = None
        self._seen_conn_ids = set()
        # v2.1.10: stream each new connection to the GUI log as sing-box
        # establishes it, so the user can watch traffic being captured/routed.
        self._trace_conns = True

    # ── helpers ───────────────────────────────────────────────────────────────

    def _set_state(self, state: SingBoxState):
        self.state = state
        if self.on_state_change:
            self.on_state_change(state)

    def _log(self, msg: str, level: str = "info"):
        logger.info(msg)
        if self.on_log:
            self.on_log(msg, level)

    # ── config rendering ────────────────────────────────────────────────────────

    def _render_config(self, clash_port: int) -> dict:
        cfg = self.config
        sbdir = _singbox_dir()

        # Split the bypass list into IP/CIDR entries and domain entries.
        bypass_cidrs: List[str] = []
        bypass_domains: List[str] = []
        for entry in (cfg.bypass_list or []):
            cidr = _looks_like_cidr_or_ip(entry)
            if cidr:
                bypass_cidrs.append(cidr)
            elif entry.strip():
                bypass_domains.append(entry.strip().lower())

        # ── DNS: fakeip for everything proxied; bypass domains resolved for real ──
        dns_rules = []
        if bypass_domains:
            # Internal/bypass domains resolve to their REAL IP (so the route rules
            # below can send them DIRECT) instead of getting a fake IP. This rule
            # has no query_type filter, so bypass domains keep BOTH A and AAAA —
            # they go direct anyway, so real IPv6 for them is fine.
            dns_rules.append({"domain_suffix": bypass_domains, "server": "local"})
        # Force IPv4 for everything else: answer AAAA with NODATA (NOERROR + no
        # records) so dual-stack apps fall back to the A record, which gets a
        # fakeip and is routed through the proxy. WITHOUT this, browsers resolve a
        # REAL IPv6 (dns.final = local) and Happy Eyeballs connects over IPv6,
        # which bypasses the IPv4-only TUN entirely — the engine runs and captures
        # IPv4-only system traffic (counters move) while the browser leaks direct.
        dns_rules.append({"query_type": ["AAAA"], "action": "predefined", "rcode": "NOERROR"})
        dns_rules.append({"query_type": ["A"], "server": "fakeip"})

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
        proxy_ip = _looks_like_cidr_or_ip(cfg.host)
        if proxy_ip:
            route_rules.append({"ip_cidr": [proxy_ip], "action": "route", "outbound": "direct"})
        if cfg.exclude_loopback:
            route_rules.append({"ip_cidr": ["127.0.0.0/8"],
                                "action": "route", "outbound": "direct"})
        if cfg.exclude_private:
            route_rules.append({"ip_is_private": True, "action": "route", "outbound": "direct"})
        if bypass_cidrs:
            route_rules.append({"ip_cidr": bypass_cidrs, "action": "route", "outbound": "direct"})
        if bypass_domains:
            route_rules.append({"domain_suffix": bypass_domains, "action": "route", "outbound": "direct"})
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

        return {
            "log": {
                # Diagnostic build: full detail unconditionally, so singbox.log
                # captures every sniff / route / CONNECT decision for the report.
                "level": "debug",
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
                # Local HTTP/SOCKS listener that the Windows system proxy points at
                # (see _takeover_system_proxy). Proxy-aware apps — including the
                # Microsoft Edge updater — send TCP CONNECT here instead of believing
                # they're on direct internet and attempting HTTP-3/QUIC (which the
                # all-UDP reject below kills, the root cause of Edge update error
                # 0x80072EFE). sing-box forwards these to the corporate proxy via the
                # same route rules (final = proxy-out), authenticated centrally. The
                # TUN remains the catch-all for apps that ignore proxy settings.
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
                "default_domain_resolver": {"server": "local"},
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

        self._clash_port = _free_loopback_port()
        self._local_proxy_port = _free_loopback_port()
        cfg_path = self._write_config(self._clash_port)

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
                [sb, "run", "-c", cfg_path],
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
        threading.Thread(target=self._run_diagnostics, daemon=True).start()
        while not self._stop_event.is_set():
            if self._proc.poll() is not None:
                self._set_state(SingBoxState.ERROR)
                self._log(f"sing-box exited unexpectedly (code {self._proc.returncode}). "
                          f"{self._tail_log()}", "error")
                # The engine died with the system proxy disabled — restore it so the
                # machine isn't left with no working proxy path.
                self._restore_system_proxy()
                self._close_log()
                return
            self._poll_stats()
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
        for c in conns:
            cid = c.get("id")
            if not cid:
                continue
            if cid not in self._seen_conn_ids:
                self._seen_conn_ids.add(cid)
                new.append(c)
        if self._trace_conns and new:
            self._emit_conn_trace(new)
        self.stats.total_connections = len(self._seen_conn_ids)
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
        for entry in (cfg.bypass_list or []):
            e = entry.strip()
            if e and not _looks_like_cidr_or_ip(e):   # ProxyOverride uses host wildcards, not CIDR
                parts.append(e)
        return ";".join(parts)

    def _takeover_system_proxy(self):
        """Point the Windows system proxy (WinINET + WinHTTP) at ProxyForce's local
        sing-box listener (127.0.0.1:<port>) while it runs. Proxy-aware apps — incl.
        the Microsoft Edge updater — then use TCP CONNECT through sing-box and never
        attempt the QUIC/direct path that fails behind the corporate proxy. The TUN
        still captures apps that ignore proxy settings. The previous config is
        snapshotted and restored on stop (crash-recovered from proxy_backup.json)."""
        try:
            from core import system_proxy
            server = f"127.0.0.1:{self._local_proxy_port}"
            prev = system_proxy.point_at(server, self._build_proxy_bypass())
            was = f" (was: {prev})" if prev else ""
            self._log(f"Windows system proxy pointed at ProxyForce ({server}){was} — "
                      f"proxy-aware apps now route through sing-box; original restored on stop.")
        except Exception as e:
            self._log(f"Could not take over the Windows system proxy: {e}", "warning")

    def _restore_system_proxy(self):
        """Restore the system proxy snapshotted at start. Idempotent (no-op if
        already restored / nothing was taken over)."""
        try:
            from core import system_proxy
            if system_proxy.restore():
                self._log("Windows system proxy restored to its previous setting.")
        except Exception as e:
            self._log(f"Could not restore the Windows system proxy: {e}", "warning")

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
        adapter_present = routes_ok = fakeip_ok = competing = False
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
            fh.write("ProxyForce diagnostics — v2.1.10\n")
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

            # ── System proxy: must point at OUR local listener (so proxy-aware apps,
            # incl. the Edge updater, route through sing-box over TCP — not QUIC/direct
            # and not some other proxy that would bypass us) ──
            try:
                from core import system_proxy
                sp_state = system_proxy.current_state()
            except Exception as e:
                sp_state = f"<unavailable: {e}>"
            ours = f"127.0.0.1:{self._local_proxy_port}"
            sp_ok = ours in sp_state
            section(fh, "System proxy (should point at ProxyForce's local listener)", sp_state,
                    (f"PASS — system proxy points at ProxyForce ({ours}); proxy-aware apps "
                     "route through sing-box over TCP CONNECT"
                     if sp_ok else
                     "WARN — system proxy does not point at ProxyForce. Takeover may have been "
                     "blocked (GPO?) or overridden by a per-app/group-policy proxy; proxy-aware "
                     "apps may bypass capture or attempt QUIC."))
            step(sp_ok,
                 f"Windows system proxy points at ProxyForce ({ours})" if sp_ok
                 else "Windows system proxy does NOT point at ProxyForce (proxy-aware apps may bypass)")

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
            elif not proxy_reachable:
                verdict = ("PROXY UNREACHABLE — capture + DNS work, but sing-box cannot reach the "
                           "upstream proxy (dial timeout/refused). Its own connection is looping "
                           "into the TUN, or the proxy host:port is blocked from this machine. See "
                           "the Proxy reachability section.")
            elif competing:
                verdict = ("WFP CONTENTION LIKELY — routes/DNS look OK but a competing agent is "
                           "present and may outbid capture. Disable it to confirm.")
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
              (not proxy_reachable) or competing or bool(problems)
        self._log(f"DIAG: {verdict}  (full report: "
                  r"%ProgramData%\ProxyForce\diagnostics.txt — please paste it back)",
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

        # Put the Windows system proxy back exactly as we found it.
        self._restore_system_proxy()

        self.stats.active_connections = 0
        self._set_state(SingBoxState.STOPPED)
        self._log("ProxyForce stopped.")

    def update_config(self, config: ProxyConfig):
        self.config = config
        self._log(f"Config updated → {config.host}:{config.port}")
