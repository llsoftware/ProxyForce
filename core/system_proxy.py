"""
ProxyForce — Windows system-proxy takeover.

ProxyForce is a TRANSPARENT interceptor: it captures traffic at the network layer
(the TUN) and forwards it to the corporate proxy itself. Windows also has an
EXPLICIT proxy mechanism, in two independent places:

  * WinINET — the per-user proxy in Settings ▸ Network ▸ Proxy
    (HKCU\\…\\Internet Settings: ProxyEnable / ProxyServer / AutoConfigURL).
    Honored by browsers, Office, most desktop apps.
  * WinHTTP — the per-machine proxy set via `netsh winhttp set proxy`
    (HKLM\\…\\Connections\\WinHttpSettings, a binary blob). Honored by services
    and system components.

Any app that honors either of those sends its traffic STRAIGHT to the configured
proxy, bypassing the TUN entirely — the two mechanisms cannot coexist for the
same app. So to capture EVERYTHING regardless of whether an app cooperates,
ProxyForce must OWN the system proxy while it runs: snapshot the current config,
disable it (every app then falls back to "direct" → into the TUN → forwarded to
the corporate proxy by us), and restore the exact original on stop.

The snapshot is also written to disk (proxy_backup.json) so a crashed run can be
rolled back on the next start — the original is never lost.
"""

import os
import json
import ctypes
import winreg
import subprocess

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# WinINET per-user proxy.
_INET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_INET_VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")

# WinHTTP per-machine proxy (binary blob).
_WINHTTP_CONN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
_WINHTTP_VALUE = "WinHttpSettings"


def _data_dir() -> str:
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "ProxyForce")


def _backup_path() -> str:
    return os.path.join(_data_dir(), "proxy_backup.json")


# ── snapshot / serialize ──────────────────────────────────────────────────────

def _snapshot() -> dict:
    """Read the current WinINET + WinHTTP proxy config into a JSON-safe dict."""
    snap = {"wininet": {}, "winhttp": None}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_SETTINGS) as k:
            for name in _INET_VALUES:
                try:
                    val, typ = winreg.QueryValueEx(k, name)
                    snap["wininet"][name] = [val, typ]
                except FileNotFoundError:
                    snap["wininet"][name] = None
    except OSError:
        pass
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _WINHTTP_CONN) as k:
            try:
                val, typ = winreg.QueryValueEx(k, _WINHTTP_VALUE)
                # REG_BINARY → hex string for JSON.
                snap["winhttp"] = [bytes(val).hex(), typ]
            except FileNotFoundError:
                snap["winhttp"] = None
    except OSError:
        pass
    return snap


def _wininet_proxy_on(snap: dict) -> str:
    """Return the proxy server string if WinINET proxy was enabled, else ''."""
    wi = snap.get("wininet") or {}
    en = wi.get("ProxyEnable")
    srv = wi.get("ProxyServer")
    if en and en[0] and srv and srv[0]:
        return str(srv[0])
    pac = wi.get("AutoConfigURL")
    if pac and pac[0]:
        return f"PAC {pac[0]}"
    return ""


# ── disable / restore ─────────────────────────────────────────────────────────

def _disable():
    """Turn off WinINET (per-user) and WinHTTP (per-machine) proxies."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_SETTINGS, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            # AutoConfigURL (PAC) is NOT gated by ProxyEnable — must be removed
            # explicitly or PAC-driven apps keep using the old proxy.
            for name in ("ProxyServer", "AutoConfigURL"):
                try:
                    winreg.DeleteValue(k, name)
                except FileNotFoundError:
                    pass
    except OSError:
        pass
    # WinHTTP → direct.
    try:
        subprocess.run(["netsh", "winhttp", "reset", "proxy"],
                       capture_output=True, creationflags=_NO_WINDOW, timeout=15)
    except Exception:
        pass
    _broadcast()


def _restore(snap: dict):
    """Write the snapshotted WinINET + WinHTTP config back verbatim."""
    wi = snap.get("wininet") or {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_SETTINGS, 0,
                            winreg.KEY_SET_VALUE) as k:
            for name in _INET_VALUES:
                entry = wi.get(name)
                if entry is None:
                    if name == "ProxyEnable":
                        winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, 0)
                    else:
                        try:
                            winreg.DeleteValue(k, name)
                        except FileNotFoundError:
                            pass
                else:
                    val, typ = entry
                    winreg.SetValueEx(k, name, 0, typ, val)
    except OSError:
        pass
    wh = snap.get("winhttp")
    if wh is not None:
        try:
            blob_hex, typ = wh
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _WINHTTP_CONN, 0,
                                winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, _WINHTTP_VALUE, 0, typ, bytes.fromhex(blob_hex))
        except OSError:
            pass
    else:
        try:
            subprocess.run(["netsh", "winhttp", "reset", "proxy"],
                           capture_output=True, creationflags=_NO_WINDOW, timeout=15)
        except Exception:
            pass
    _broadcast()


def _broadcast():
    """Tell running WinINET apps the proxy config changed (so they re-read it)."""
    try:
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
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

def take_over() -> str:
    """Snapshot + disable the system proxy. Returns the previous proxy (for the
    log), or '' if none was set. Crash-safe: if a backup already exists (a prior
    run disabled it and never restored), the existing backup is kept as the true
    original and the proxy is merely re-asserted disabled."""
    if _read_backup() is None:
        snap = _snapshot()
        _write_backup(snap)
        prev = _wininet_proxy_on(snap)
    else:
        prev = ""   # mid-takeover from a previous run; original already saved
    _disable()
    return prev


def _set(server: str, bypass: str):
    """Point WinINET (per-user) + WinHTTP (per-machine) at `server`."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_SETTINGS, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, server)
            if bypass:
                winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, bypass)
            # A leftover PAC (AutoConfigURL) is NOT gated by ProxyEnable and would
            # override our fixed proxy — remove it.
            try:
                winreg.DeleteValue(k, "AutoConfigURL")
            except FileNotFoundError:
                pass
    except OSError:
        pass
    try:
        args = ["netsh", "winhttp", "set", "proxy", f"proxy-server={server}"]
        if bypass:
            args.append(f"bypass-list={bypass}")
        subprocess.run(args, capture_output=True, creationflags=_NO_WINDOW, timeout=15)
    except Exception:
        pass
    _broadcast()


def point_at(server: str, bypass: str = "") -> str:
    """Snapshot (crash-safe) then POINT the WinINET + WinHTTP proxy at `server`
    (ProxyForce's local sing-box listener, e.g. 127.0.0.1:18080) instead of
    disabling it. Proxy-aware apps then use it over TCP CONNECT and never attempt
    the direct/QUIC path — which is what was breaking the Edge updater. Non-proxy
    apps are still caught by the TUN. Returns the previous proxy string."""
    if _read_backup() is None:
        snap = _snapshot()
        _write_backup(snap)
        prev = _wininet_proxy_on(snap)
    else:
        prev = ""   # mid-takeover from a previous run; original already saved
    _set(server, bypass)
    return prev


def restore() -> bool:
    """Restore the snapshotted system proxy. Idempotent: no backup → no-op.
    Returns True if a restore was performed."""
    snap = _read_backup()
    if snap is None:
        return False
    _restore(snap)
    _clear_backup()
    return True


def current_state() -> str:
    """One-line human-readable current system-proxy state (for diagnostics)."""
    snap = _snapshot()
    wi = snap.get("wininet") or {}
    en = (wi.get("ProxyEnable") or [0])[0]
    srv = (wi.get("ProxyServer") or [""])[0]
    pac = (wi.get("AutoConfigURL") or [""])[0]
    try:
        r = subprocess.run(["netsh", "winhttp", "show", "proxy"],
                           capture_output=True, text=True,
                           creationflags=_NO_WINDOW, timeout=15)
        wh = (r.stdout or "").strip().replace("\r\n", " ").replace("\n", " ")
    except Exception:
        wh = "<unavailable>"
    return (f"WinINET ProxyEnable={en} ProxyServer='{srv}' AutoConfigURL='{pac}'"
            f"  ||  WinHTTP: {wh}")
