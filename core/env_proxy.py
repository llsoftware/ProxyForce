"""
ProxyForce — process-environment proxy variables (the env-var-CLI-tool fix).

WHY THIS EXISTS (yt-dlp report, 2026-08-04):
  ProxyForce's system-proxy takeover (core/system_proxy) writes WinINET (HKCU) and
  WinHTTP (HKLM) — the two mechanisms browsers, Office, and most Windows components
  read. A large class of CLI/dev tools (yt-dlp, curl, git, pip, node, ffmpeg, aws-cli,
  …) ignores both and instead calls `getenv("HTTP_PROXY"/"HTTPS_PROXY"/…)`. ProxyForce
  never set those, so those tools fell back to resolving DNS and connecting directly —
  invisible on a healthy box (fakeip DNS still routes them through the TUN), but a
  single stray `*_proxy` variable anywhere in the user's or machine's environment
  breaks it in a way that is easy to miss, because it looks identical to "everything
  works" for every proxy-aware app tested (browsers never read the environment).

  The trigger, confirmed empirically: Python's `urllib.request.getproxies()` (which
  yt-dlp/requests/urllib3 all end up calling) is
  `getproxies_environment() or getproxies_registry()` — ANY `*_proxy` env var,
  including a bare `no_proxy`, makes the environment lookup truthy and the Windows
  registry proxy is never consulted:

      $env:no_proxy = 'localhost'
      getproxies_environment()  ->  {'no': 'localhost'}      # truthy!
      getproxies()               ->  {'no': 'localhost'}      # registry never read

  So the fix is to make ProxyForce's environment-variable proxy the SAME source of
  truth as its registry proxy, rather than leaving that lane empty for whatever the
  user's login script / dev tooling / WSL happened to set.

ON LINUX THIS LANE IS THE PRIMARY ONE, NOT A SUPPLEMENT:
  There is no WinINET/WinHTTP equivalent — no single registry value every app obeys.
  `http_proxy`/`https_proxy`/`no_proxy` ARE the Linux convention, honoured by curl,
  git, apt, dnf, pip, npm, docker's client, wget and essentially every CLI tool, plus
  GNOME and KDE when their proxy mode is "manual". So what is a supplement to the
  registry on Windows is the main explicit-proxy mechanism here, and core/system_proxy
  is the thin one (it only nudges the desktop's own setting). The TUN remains the
  catch-all on both platforms for apps that ignore all of it.

HOW IT IS WIRED (see singbox_controller._takeover_system_proxy /
_restore_system_proxy):
  Written in BOTH cases, uppercase and lowercase (tools disagree on which they read):
  HTTP_PROXY/http_proxy, HTTPS_PROXY/https_proxy, ALL_PROXY/all_proxy,
  NO_PROXY/no_proxy — in BOTH the machine scope and the user scope, because a
  per-user value overrides a machine one in a process's merged environment, so
  machine alone is not enough. core/env_store owns where each scope is persisted
  (registry hives on Windows; /etc/environment + /etc/profile.d + the user's
  environment.d drop-in on Linux).

  Values reuse the SAME protocol split as the registry takeover: HTTPS goes to
  sing-box's mixed inbound (native CONNECT); plaintext HTTP goes to the local
  forward-proxy (core/local_proxy), which also relays CONNECT as a safety net — so it
  is a superset and is what ALL_PROXY points at too.

  Written and restored as ONE atomic group: NO_PROXY is never set without HTTP_PROXY/
  HTTPS_PROXY alongside it, because a lone NO_PROXY would itself trip the
  getproxies_environment() truthiness trap and break a box that had no proxy env vars
  at all. Any variables already present (including a stray no_proxy — the exact cause
  of the report above) are snapshotted and OVERWRITTEN, then restored verbatim on stop.

NOTES:
  * Environment variables are read by a process at CreateProcess/exec time —
    already-open shells must be reopened to see the change (or the change to be
    undone). The caller logs this caveat. True on both platforms.
  * A variable exported from a user's own dotfile (~/.bashrc, ~/.zshrc) is outside
    what any tool should rewrite, so it is reported by env_store.foreign_vars()
    rather than overwritten — see current_state().
  * Crash-safe like core/system_proxy: the snapshot is written to disk before the
    first overwrite, so a crashed run's original values are restored on next start.
"""

import os
import json

from core import hostos, env_store

# Every case variant we write. Grouped so callers can iterate scheme -> (UPPER, lower).
_SCHEME_VARS = {
    "http": ("HTTP_PROXY", "http_proxy"),
    "https": ("HTTPS_PROXY", "https_proxy"),
    "all": ("ALL_PROXY", "all_proxy"),
    "no": ("NO_PROXY", "no_proxy"),
}
_ALL_VAR_NAMES = tuple(n for pair in _SCHEME_VARS.values() for n in pair)


def _data_dir() -> str:
    return hostos.data_dir()


def _backup_path() -> str:
    return os.path.join(_data_dir(), "env_proxy_backup.json")


# ── snapshot / serialize ──────────────────────────────────────────────────────

def _snapshot() -> dict:
    """Read the current *_proxy variables (both cases) from both scopes."""
    return env_store.snapshot(_ALL_VAR_NAMES)


def _describe(snap: dict) -> str:
    """One-line summary of any *_proxy vars found before takeover (for the log)."""
    return env_store.describe(snap, _ALL_VAR_NAMES)


# ── set / restore ─────────────────────────────────────────────────────────────

def _set(http_url: str, https_url: str, no_proxy: str):
    """Write HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY (both cases) into both the
    machine and the user scope, as one group — ALL_PROXY points at the forward-proxy
    (http_url): it is a superset that also relays CONNECT, so it is the safe single-
    address choice for tools that don't split by scheme."""
    env_store.write({
        "HTTP_PROXY": http_url, "http_proxy": http_url,
        "HTTPS_PROXY": https_url, "https_proxy": https_url,
        "ALL_PROXY": http_url, "all_proxy": http_url,
        "NO_PROXY": no_proxy, "no_proxy": no_proxy,
    })


def _restore(snap: dict):
    """Write the snapshotted *_proxy variables back verbatim (including 'was not
    set', which deletes the value we added)."""
    env_store.restore(snap, _ALL_VAR_NAMES)


# ── backup file ───────────────────────────────────────────────────────────────

def _write_backup(snap: dict):
    try:
        os.makedirs(_data_dir(), exist_ok=True)
        with open(_backup_path(), "w", encoding="utf-8") as f:
            json.dump(snap, f)
    except Exception:
        pass


def _read_backup():
    try:
        with open(_backup_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _clear_backup():
    try:
        os.remove(_backup_path())
    except OSError:
        pass


# ── public API ────────────────────────────────────────────────────────────────

def point_at(http_url: str, https_url: str, no_proxy: str = "") -> str:
    """Snapshot (crash-safe) then set the *_proxy environment variables to point at
    ProxyForce's local listeners. Returns a description of what was previously set
    (for the log), or '' if nothing was. Idempotent/crash-safe like
    system_proxy.point_at: if a backup already exists (a prior run set these and
    never restored), the existing backup is kept as the true original."""
    if _read_backup() is None:
        snap = _snapshot()
        _write_backup(snap)
        prev = _describe(snap)
    else:
        prev = ""   # mid-takeover from a previous run; original already saved
    _set(http_url, https_url, no_proxy)
    return prev


def restore() -> bool:
    """Restore the snapshotted *_proxy variables. Idempotent: no backup -> no-op.
    Returns True if a restore was performed."""
    snap = _read_backup()
    if snap is None:
        return False
    _restore(snap)
    _clear_backup()
    return True


def current_state() -> str:
    """One-line human-readable current *_proxy environment state (for diagnostics).
    Includes any value coming from a shell dotfile that ProxyForce does not manage —
    on Linux that is the most likely cause of a tool ignoring the takeover."""
    return env_store.current_state(_ALL_VAR_NAMES)


def storage_description() -> str:
    """Where these variables live on this platform (for diagnostics)."""
    return env_store.storage_description()
