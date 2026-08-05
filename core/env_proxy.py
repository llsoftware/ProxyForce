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

HOW IT IS WIRED (see singbox_controller._takeover_system_proxy /
_restore_system_proxy):
  Written in BOTH cases, uppercase and lowercase (tools disagree on which they read):
  HTTP_PROXY/http_proxy, HTTPS_PROXY/https_proxy, ALL_PROXY/all_proxy,
  NO_PROXY/no_proxy — in BOTH the machine environment
  (HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment; per-user
  overrides per-machine in a process's merged environment, so machine alone is not
  enough) and the process's own HKCU\\Environment.

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
  * Environment variables are read by a process at CreateProcess time — already-open
    shells must be reopened to see the change (or the change to be undone). The
    caller logs this caveat.
  * Crash-safe like core/system_proxy: the snapshot is written to disk before the
    first overwrite, so a crashed run's original values are restored on next start.
"""

import os
import json
import ctypes
import winreg

_USER_KEY = r"Environment"
_MACHINE_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"

# Every case variant we write. Grouped so callers can iterate scheme -> (UPPER, lower).
_SCHEME_VARS = {
    "http": ("HTTP_PROXY", "http_proxy"),
    "https": ("HTTPS_PROXY", "https_proxy"),
    "all": ("ALL_PROXY", "all_proxy"),
    "no": ("NO_PROXY", "no_proxy"),
}
_ALL_VAR_NAMES = tuple(n for pair in _SCHEME_VARS.values() for n in pair)

_HIVES = {"user": winreg.HKEY_CURRENT_USER, "machine": winreg.HKEY_LOCAL_MACHINE}
_SUBKEYS = {"user": _USER_KEY, "machine": _MACHINE_KEY}


def _data_dir() -> str:
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "ProxyForce")


def _backup_path() -> str:
    return os.path.join(_data_dir(), "env_proxy_backup.json")


# ── snapshot / serialize ──────────────────────────────────────────────────────

def _snapshot() -> dict:
    """Read the current *_proxy variables (both cases) from both hives."""
    snap = {}
    for scope, hive in _HIVES.items():
        entry = {}
        try:
            with winreg.OpenKey(hive, _SUBKEYS[scope]) as k:
                for name in _ALL_VAR_NAMES:
                    try:
                        val, typ = winreg.QueryValueEx(k, name)
                        entry[name] = [val, typ]
                    except FileNotFoundError:
                        entry[name] = None
        except OSError:
            entry = {name: None for name in _ALL_VAR_NAMES}
        snap[scope] = entry
    return snap


def _describe(snap: dict) -> str:
    """One-line summary of any *_proxy vars found before takeover (for the log)."""
    parts = []
    for scope in ("user", "machine"):
        for name in _ALL_VAR_NAMES:
            entry = (snap.get(scope) or {}).get(name)
            if entry is not None and entry[0]:
                parts.append(f"{scope}:{name}={entry[0]}")
    return ", ".join(parts)


# ── set / restore ─────────────────────────────────────────────────────────────

def _set(http_url: str, https_url: str, no_proxy: str):
    """Write HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY (both cases) into both the
    machine environment and the current user's environment, as one group — ALL_PROXY
    points at the forward-proxy (http_url): it is a superset that also relays CONNECT,
    so it is the safe single-address choice for tools that don't split by scheme."""
    values = {
        "HTTP_PROXY": http_url, "http_proxy": http_url,
        "HTTPS_PROXY": https_url, "https_proxy": https_url,
        "ALL_PROXY": http_url, "all_proxy": http_url,
        "NO_PROXY": no_proxy, "no_proxy": no_proxy,
    }
    for scope, hive in _HIVES.items():
        try:
            with winreg.OpenKey(hive, _SUBKEYS[scope], 0, winreg.KEY_SET_VALUE) as k:
                for name, val in values.items():
                    if val:
                        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, val)
                    else:
                        try:
                            winreg.DeleteValue(k, name)
                        except FileNotFoundError:
                            pass
        except OSError:
            pass
    _broadcast()


def _restore(snap: dict):
    """Write the snapshotted *_proxy variables back verbatim (including 'was not
    set', which deletes the value we added)."""
    for scope, hive in _HIVES.items():
        entry = snap.get(scope) or {}
        try:
            with winreg.OpenKey(hive, _SUBKEYS[scope], 0, winreg.KEY_SET_VALUE) as k:
                for name in _ALL_VAR_NAMES:
                    stored = entry.get(name)
                    if stored is None:
                        try:
                            winreg.DeleteValue(k, name)
                        except FileNotFoundError:
                            pass
                    else:
                        val, typ = stored
                        winreg.SetValueEx(k, name, 0, typ, val)
        except OSError:
            pass
    _broadcast()


def _broadcast():
    """Tell running apps the environment changed (WM_SETTINGCHANGE). Best-effort:
    only processes that re-read the environment on this signal see it live — most
    CLI tools read it once at process start anyway, so a shell must be reopened."""
    try:
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        SMTO_ABORTIFHUNG = 0x0002
        result = ctypes.c_ulong()
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment",
            SMTO_ABORTIFHUNG, 1000, ctypes.byref(result))
    except Exception:
        pass


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
    """One-line human-readable current *_proxy environment state (for diagnostics)."""
    snap = _snapshot()
    parts = []
    for scope in ("user", "machine"):
        entry = snap.get(scope) or {}
        set_vars = [f"{n}={entry[n][0]}" for n in _ALL_VAR_NAMES
                    if entry.get(n) is not None and entry[n][0]]
        parts.append(f"{scope}: " + (", ".join(set_vars) if set_vars else "(none set)"))
    return "  ||  ".join(parts)
