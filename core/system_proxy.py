"""
ProxyForce — desktop/system proxy takeover.

ProxyForce is a TRANSPARENT interceptor: it captures traffic at the network layer
(the TUN) and forwards it to the corporate proxy itself. Operating systems also
have an EXPLICIT proxy mechanism, and any app that honors one sends its traffic
STRAIGHT to the configured proxy, bypassing the TUN entirely — the two mechanisms
cannot coexist for the same app. So to capture EVERYTHING regardless of whether an
app cooperates, ProxyForce must OWN that setting while it runs: snapshot it, point
it at ProxyForce's own local listeners, and restore the exact original on stop.

WINDOWS — two independent places, and owning both is what makes capture universal:

  * WinINET — the per-user proxy in Settings ▸ Network ▸ Proxy
    (HKCU\\…\\Internet Settings: ProxyEnable / ProxyServer / AutoConfigURL).
    Honored by browsers, Office, most desktop apps.
  * WinHTTP — the per-machine proxy set via `netsh winhttp set proxy`
    (HKLM\\…\\Connections\\WinHttpSettings, a binary blob). Honored by services
    and system components.

LINUX — this module is deliberately the THIN one. There is no WinINET/WinHTTP:
  no single setting that most apps obey. The Linux convention is the `http_proxy`
  / `https_proxy` / `no_proxy` environment variables, and that lane is owned by
  core/env_proxy, which on Linux is the PRIMARY explicit-proxy mechanism rather
  than a supplement. What remains here is the desktop environment's own setting,
  which a browser reads when its proxy mode is "use system settings":

  * GNOME (and Cinnamon, Budgie, Unity, anything on GSettings) —
    org.gnome.system.proxy. Set through `gsettings`, run as the logged-in user in
    their own D-Bus session, because it is per-user configuration and ProxyForce
    runs as root.
  * KDE Plasma — ~/.config/kioslaverc, an INI file KIO reads.

  Both are best-effort and neither is load-bearing: if a desktop is not present,
  or gsettings is missing, capture still works through the TUN and the environment
  variables. That is why a failure here is logged and stepped over rather than
  surfaced as an error, on a platform where — unlike Windows — no single setting
  can claim to cover "most apps".

The snapshot is written to disk (proxy_backup.json) on both platforms so a crashed
run can be rolled back on the next start — the original is never lost. The file's
contents are platform-specific and only ever read back by the same platform's
restore path; the crash-safety contract around it is identical.
"""

import os
import json
import subprocess

from core import hostos

# WinINET per-user proxy.
_INET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_INET_VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")

# WinHTTP per-machine proxy (binary blob).
_WINHTTP_CONN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
_WINHTTP_VALUE = "WinHttpSettings"

# GSettings keys that together describe a GNOME proxy configuration.
_GS_SCHEMA = "org.gnome.system.proxy"
_GS_KEYS = (
    (_GS_SCHEMA, "mode"),
    (_GS_SCHEMA, "ignore-hosts"),
    (_GS_SCHEMA + ".http", "host"),
    (_GS_SCHEMA + ".http", "port"),
    (_GS_SCHEMA + ".https", "host"),
    (_GS_SCHEMA + ".https", "port"),
    (_GS_SCHEMA + ".ftp", "host"),
    (_GS_SCHEMA + ".ftp", "port"),
    (_GS_SCHEMA + ".socks", "host"),
    (_GS_SCHEMA + ".socks", "port"),
)

_KDE_RC_REL = os.path.join(".config", "kioslaverc")


def _data_dir() -> str:
    return hostos.data_dir()


def _backup_path() -> str:
    return os.path.join(_data_dir(), "proxy_backup.json")


# ══════════════════════════════════════════════════════════════════════════════
# Windows backend
# ══════════════════════════════════════════════════════════════════════════════

def _win_snapshot() -> dict:
    """Read the current WinINET + WinHTTP proxy config into a JSON-safe dict."""
    import winreg
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
                snap["winhttp"] = [bytes(val).hex(), typ]
            except FileNotFoundError:
                snap["winhttp"] = None
    except OSError:
        pass
    return snap


def _win_previous(snap: dict) -> str:
    """Human-readable description of the proxy that was configured before we
    touched anything ('' when none was)."""
    wi = snap.get("wininet") or {}
    enabled = (wi.get("ProxyEnable") or [0])[0]
    server = (wi.get("ProxyServer") or [""])[0]
    pac = (wi.get("AutoConfigURL") or [""])[0]
    parts = []
    if enabled and server:
        parts.append(str(server))
    if pac:
        parts.append(f"PAC {pac}")
    return ", ".join(parts)


def _win_disable():
    import winreg
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
    try:
        subprocess.run(["netsh", "winhttp", "reset", "proxy"],
                       capture_output=True, timeout=15, **hostos.popen_kwargs())
    except Exception:
        pass
    _win_broadcast()


def _win_set(server: str, bypass: str):
    """Point WinINET (per-user) + WinHTTP (per-machine) at `server`."""
    import winreg
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
        subprocess.run(args, capture_output=True, timeout=15, **hostos.popen_kwargs())
    except Exception:
        pass
    _win_broadcast()


def _win_restore(snap: dict):
    """Write the snapshotted WinINET + WinHTTP config back verbatim."""
    import winreg
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
                           capture_output=True, timeout=15, **hostos.popen_kwargs())
        except Exception:
            pass
    _win_broadcast()


def _win_broadcast():
    """Tell running WinINET apps the proxy config changed (so they re-read it)."""
    import ctypes
    try:
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:
        pass


def _win_current_state() -> str:
    snap = _win_snapshot()
    wi = snap.get("wininet") or {}
    en = (wi.get("ProxyEnable") or [0])[0]
    srv = (wi.get("ProxyServer") or [""])[0]
    pac = (wi.get("AutoConfigURL") or [""])[0]
    try:
        r = subprocess.run(["netsh", "winhttp", "show", "proxy"],
                           capture_output=True, text=True, timeout=15,
                           **hostos.popen_kwargs())
        wh = (r.stdout or "").strip().replace("\r\n", " ").replace("\n", " ")
    except Exception:
        wh = "<unavailable>"
    return (f"WinINET ProxyEnable={en} ProxyServer='{srv}' AutoConfigURL='{pac}'"
            f"  ||  WinHTTP: {wh}")


# ══════════════════════════════════════════════════════════════════════════════
# Linux backend
# ══════════════════════════════════════════════════════════════════════════════

def _desktop_user() -> str:
    from core import env_store
    return env_store.target_user()


def _user_uid(user: str):
    try:
        import pwd
        return pwd.getpwnam(user).pw_uid
    except Exception:
        return None


def _as_user(args, timeout=10):
    """Run a command as the logged-in desktop user, inside their D-Bus session.

    gsettings writes per-user dconf, so running it as root would write root's
    database — the setting would appear nowhere in the user's own desktop. The
    session bus address has to be supplied explicitly because the root process
    ProxyForce runs as has no DBUS_SESSION_BUS_ADDRESS of its own.
    """
    user = _desktop_user()
    if not user:
        return None
    uid = _user_uid(user)
    if uid is None:
        return None
    env_args = [f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                f"XDG_RUNTIME_DIR=/run/user/{uid}"]
    try:
        return hostos.run(["sudo", "-n", "-u", user, "env", *env_args, *args],
                          timeout=timeout)
    except Exception:
        return None


def _gsettings_available() -> bool:
    if not hostos.which("gsettings") or not hostos.which("sudo"):
        return False
    r = _as_user(["gsettings", "get", _GS_SCHEMA, "mode"])
    return bool(r and r.returncode == 0)


def _gs_get(schema: str, key: str):
    r = _as_user(["gsettings", "get", schema, key])
    if not r or r.returncode != 0:
        return None
    return (r.stdout or "").strip()


def _gs_set(schema: str, key: str, value: str) -> bool:
    r = _as_user(["gsettings", "set", schema, key, value])
    return bool(r and r.returncode == 0)


def _kde_rc_path() -> str:
    user = _desktop_user()
    if not user:
        return ""
    try:
        import pwd
        return os.path.join(pwd.getpwnam(user).pw_dir, _KDE_RC_REL)
    except Exception:
        return ""


def _kde_read() -> dict:
    """The [Proxy Settings] group of kioslaverc, or {} when there is no KDE here."""
    path = _kde_rc_path()
    if not path or not os.path.isfile(path):
        return {}
    out, in_group = {}, False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("["):
                    in_group = stripped.lower() == "[proxy settings]"
                    continue
                if in_group and "=" in stripped:
                    k, v = stripped.split("=", 1)
                    out[k.strip()] = v.strip()
    except OSError:
        return {}
    return out


def _kde_write(values: dict) -> bool:
    """Apply {key: value-or-None} to kioslaverc's [Proxy Settings] group, leaving
    every other group and key untouched. Returns True if the file was written."""
    path = _kde_rc_path()
    if not path:
        return False
    if not os.path.isfile(path) and not values:
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []

    out, seen, in_group, group_found = [], set(), False, False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            if in_group:            # leaving our group: flush anything not seen
                for k, v in values.items():
                    if k not in seen and v is not None:
                        out.append(f"{k}={v}")
            in_group = stripped.lower() == "[proxy settings]"
            group_found = group_found or in_group
            out.append(line)
            continue
        if in_group and "=" in stripped:
            k = stripped.split("=", 1)[0].strip()
            if k in values:
                seen.add(k)
                if values[k] is not None:
                    out.append(f"{k}={values[k]}")
                continue
        out.append(line)

    if in_group:
        for k, v in values.items():
            if k not in seen and v is not None:
                out.append(f"{k}={v}")
    elif not group_found and any(v is not None for v in values.values()):
        out.append("")
        out.append("[Proxy Settings]")
        for k, v in values.items():
            if v is not None:
                out.append(f"{k}={v}")

    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".proxyforce.tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(out).rstrip("\n") + "\n")
        os.replace(tmp, path)
    except OSError:
        return False
    user = _desktop_user()
    if user:
        try:
            import pwd
            pw = pwd.getpwnam(user)
            os.chown(path, pw.pw_uid, pw.pw_gid)
        except Exception:
            pass
    return True


def _linux_snapshot() -> dict:
    """Capture both desktop proxy configurations. Keys absent from a desktop that
    is not installed simply come back empty, and restore() then writes nothing."""
    gnome = {}
    if _gsettings_available():
        for schema, key in _GS_KEYS:
            val = _gs_get(schema, key)
            if val is not None:
                gnome[f"{schema}/{key}"] = val
    return {"gnome": gnome, "kde": _kde_read()}


def _linux_previous(snap: dict) -> str:
    parts = []
    gnome = snap.get("gnome") or {}
    mode = (gnome.get(f"{_GS_SCHEMA}/mode") or "").strip("'\"")
    if mode and mode != "none":
        host = (gnome.get(f"{_GS_SCHEMA}.http/host") or "").strip("'\"")
        port = (gnome.get(f"{_GS_SCHEMA}.http/port") or "").strip()
        parts.append(f"GNOME mode={mode}" + (f" {host}:{port}" if host else ""))
    kde = snap.get("kde") or {}
    if kde.get("ProxyType") not in (None, "", "0"):
        parts.append(f"KDE ProxyType={kde.get('ProxyType')}")
    return ", ".join(parts)


def _split_hostport(server: str):
    """'127.0.0.1:18080' -> ('127.0.0.1', 18080). ProxyForce always builds this
    string itself, so a malformed value means a bug here, not bad user input."""
    if ":" in server:
        host, _, port = server.rpartition(":")
        try:
            return host, int(port)
        except ValueError:
            return host, 0
    return server, 0


def _linux_set(http_server: str, https_server: str, bypass: str):
    host_h, port_h = _split_hostport(http_server)
    host_s, port_s = _split_hostport(https_server)
    ignore = [x.strip() for x in (bypass or "").split(",") if x.strip()]
    if _gsettings_available():
        _gs_set(_GS_SCHEMA + ".http", "host", host_h)
        _gs_set(_GS_SCHEMA + ".http", "port", str(port_h))
        _gs_set(_GS_SCHEMA + ".https", "host", host_s)
        _gs_set(_GS_SCHEMA + ".https", "port", str(port_s))
        if ignore:
            gv = "[" + ", ".join("'%s'" % h for h in ignore) + "]"
            _gs_set(_GS_SCHEMA, "ignore-hosts", gv)
        # Set the mode LAST: it is the switch that makes the rest take effect, and
        # flipping it before the host/port are in place would briefly point every
        # GNOME app at an empty proxy.
        _gs_set(_GS_SCHEMA, "mode", "manual")
    _kde_write({
        "ProxyType": "1",                       # 1 = manually specified
        "httpProxy": f"http://{host_h} {port_h}",
        "httpsProxy": f"http://{host_s} {port_s}",
        "NoProxyFor": ",".join(ignore),
    })


def _linux_disable():
    if _gsettings_available():
        _gs_set(_GS_SCHEMA, "mode", "none")
    _kde_write({"ProxyType": "0"})


def _linux_restore(snap: dict):
    gnome = snap.get("gnome") or {}
    if gnome and _gsettings_available():
        # mode first here, the mirror image of _linux_set: dropping out of manual
        # before the old host/port go back avoids a window where apps see our
        # loopback address under the user's original mode.
        mode_key = f"{_GS_SCHEMA}/mode"
        if mode_key in gnome:
            _gs_set(_GS_SCHEMA, "mode", gnome[mode_key].strip("'\""))
        for schema, key in _GS_KEYS:
            full = f"{schema}/{key}"
            if full == mode_key or full not in gnome:
                continue
            _gs_set(schema, key, gnome[full])
    kde = snap.get("kde")
    if kde is not None:
        # Keys we set that were not in the original are removed (None), not left
        # behind pointing at a loopback port nothing is listening on any more.
        restore_map = {k: kde.get(k) for k in
                       ("ProxyType", "httpProxy", "httpsProxy", "NoProxyFor")}
        if any(v is not None for v in restore_map.values()) or kde:
            _kde_write(restore_map)


def _linux_current_state() -> str:
    parts = []
    if _gsettings_available():
        mode = _gs_get(_GS_SCHEMA, "mode") or "?"
        hh = _gs_get(_GS_SCHEMA + ".http", "host") or "?"
        hp = _gs_get(_GS_SCHEMA + ".http", "port") or "?"
        sh = _gs_get(_GS_SCHEMA + ".https", "host") or "?"
        sp = _gs_get(_GS_SCHEMA + ".https", "port") or "?"
        parts.append(f"GNOME mode={mode} http={hh}:{hp} https={sh}:{sp}")
    else:
        parts.append("GNOME gsettings: not available")
    kde = _kde_read()
    parts.append(f"KDE kioslaverc: {kde}" if kde else "KDE kioslaverc: not present")
    return "  ||  ".join(parts)


def desktop_available() -> bool:
    """True when at least one desktop proxy setting can actually be written. The
    controller logs a different message when nothing here is reachable, so a
    headless server is not told its 'system proxy takeover failed'."""
    if hostos.IS_WINDOWS:
        return True
    return _gsettings_available() or bool(_kde_rc_path())


# ══════════════════════════════════════════════════════════════════════════════
# backup file
# ══════════════════════════════════════════════════════════════════════════════

def _snapshot() -> dict:
    return _win_snapshot() if hostos.IS_WINDOWS else _linux_snapshot()


def _previous(snap: dict) -> str:
    return _win_previous(snap) if hostos.IS_WINDOWS else _linux_previous(snap)


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


# ══════════════════════════════════════════════════════════════════════════════
# public API
# ══════════════════════════════════════════════════════════════════════════════

def take_over() -> str:
    """Snapshot + disable the system proxy. Returns the previous proxy (for the
    log), or '' if none was set. Crash-safe: if a backup already exists (a prior
    run disabled it and never restored), the existing backup is kept as the true
    original and the proxy is merely re-asserted disabled."""
    if _read_backup() is None:
        snap = _snapshot()
        _write_backup(snap)
        prev = _previous(snap)
    else:
        prev = ""   # mid-takeover from a previous run; original already saved
    if hostos.IS_WINDOWS:
        _win_disable()
    else:
        _linux_disable()
    return prev


def point_at(server: str, bypass: str = "", https_server: str = "") -> str:
    """Snapshot (crash-safe) then POINT the desktop/system proxy at ProxyForce's
    own local listeners instead of disabling it. Proxy-aware apps then use it over
    TCP CONNECT and never attempt the direct/QUIC path — which is what was breaking
    the Edge updater. Apps that ignore the setting are still caught by the TUN.
    Returns the previous proxy string.

    `server` is the Windows protocol-split string
    ("http=127.0.0.1:A;https=127.0.0.1:B", or a bare "host:port"). Linux has no
    such combined syntax, so the split is passed explicitly: `server` is the HTTP
    address and `https_server` the HTTPS one, defaulting to the same.
    """
    if _read_backup() is None:
        snap = _snapshot()
        _write_backup(snap)
        prev = _previous(snap)
    else:
        prev = ""   # mid-takeover from a previous run; original already saved
    if hostos.IS_WINDOWS:
        _win_set(server, bypass)
    else:
        _linux_set(server, https_server or server, bypass)
    return prev


def restore() -> bool:
    """Restore the snapshotted system proxy. Idempotent: no backup → no-op.
    Returns True if a restore was performed."""
    snap = _read_backup()
    if snap is None:
        return False
    if hostos.IS_WINDOWS:
        _win_restore(snap)
    else:
        _linux_restore(snap)
    _clear_backup()
    return True


def current_state() -> str:
    """One-line human-readable current system-proxy state (for diagnostics)."""
    return _win_current_state() if hostos.IS_WINDOWS else _linux_current_state()


def refresh():
    """Re-announce the current proxy configuration without changing it. Windows
    only: GSettings and KIO push their own change notifications over D-Bus, so
    there is nothing to re-announce on Linux."""
    if hostos.IS_WINDOWS:
        _win_broadcast()
