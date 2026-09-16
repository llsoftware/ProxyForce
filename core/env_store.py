"""
ProxyForce — persistent environment variables (the Windows/Linux storage seam).

WHY THIS EXISTS (v3.0.0):
  core/env_proxy and core/env_certs do the same thing to different variable sets:
  snapshot what is currently persisted, overwrite it as one atomic group, and put
  the original back on stop. Both were written directly against the Windows
  registry. This module is that storage, abstracted, so both keep their policy and
  their on-disk backup format unchanged across platforms.

THE SHAPE:
  Everything is keyed by SCOPE — "machine" (every account on the box) and "user"
  (the interactive user ProxyForce is running for). A process's effective
  environment is the machine set overlaid by the user set, on both platforms, so
  writing machine alone is not enough: a pre-existing user-scope value would win
  and silently defeat the takeover.

  Values are carried as [value, type] pairs so a Windows REG_EXPAND_SZ is restored
  as REG_EXPAND_SZ rather than flattened to REG_SZ. Linux has no such distinction
  and always reports TYPE_STRING; the backup JSON is therefore byte-identical in
  shape on both platforms, which is what lets a backup written by either be read
  by the same restore code.

WINDOWS STORAGE:
  machine -> HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment
  user    -> HKCU\\Environment
  Followed by a WM_SETTINGCHANGE broadcast.

LINUX STORAGE:
  machine -> /etc/environment  (the canonical machine-wide env file, read by PAM)
             plus a fully ProxyForce-owned /etc/profile.d/proxyforce.sh, because
             /etc/environment is NOT read by non-login shells, and the CLI tools
             this whole mechanism exists for (curl, git, pip, docker) are usually
             invoked from exactly those.
  user    -> ~/.config/environment.d/99-proxyforce.conf, read by the systemd user
             session and therefore by anything the desktop launches.

  Only /etc/environment is snapshotted and restored value-by-value: it is a file
  that pre-exists and belongs to the system. The other two are created by
  ProxyForce and deleted wholesale on restore, so there is nothing of anyone
  else's in them to preserve.

  A value exported from a user's own dotfile (~/.bashrc, ~/.zshrc) cannot be
  captured or overridden from here — rewriting a user's shell config is not
  something a proxy tool should do. Such variables are REPORTED by foreign_vars()
  so the diagnostics can name them, which is the same job _describe() does on
  Windows for a stray registry value.

NOTE ON VISIBILITY (both platforms):
  A process reads its environment once, at exec time. An already-open shell must
  be reopened to see any of this — the caller logs that caveat.
"""

import os
import re

from core import hostos

SCOPES = ("machine", "user")

# Value-type markers. The Windows numbers are winreg's REG_SZ / REG_EXPAND_SZ,
# kept as literals so this module imports on Linux without touching winreg.
TYPE_STRING = 1         # REG_SZ
TYPE_EXPAND = 2         # REG_EXPAND_SZ

_WIN_SUBKEYS = {
    "user": r"Environment",
    "machine": r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
}

_LINUX_ETC_ENVIRONMENT = "/etc/environment"
_LINUX_PROFILE_D = "/etc/profile.d/proxyforce.sh"
_LINUX_USER_ENV_REL = os.path.join(".config", "environment.d", "99-proxyforce.conf")


# ══════════════════════════════════════════════════════════════════════════════
# Windows backend
# ══════════════════════════════════════════════════════════════════════════════

def _win_hive(scope: str):
    import winreg
    return (winreg.HKEY_CURRENT_USER if scope == "user"
            else winreg.HKEY_LOCAL_MACHINE)


def _win_read(scope: str, names) -> dict:
    import winreg
    entry = {}
    try:
        with winreg.OpenKey(_win_hive(scope), _WIN_SUBKEYS[scope]) as k:
            for name in names:
                try:
                    val, typ = winreg.QueryValueEx(k, name)
                    entry[name] = [val, typ]
                except FileNotFoundError:
                    entry[name] = None
    except OSError:
        entry = {name: None for name in names}
    return entry


def _win_write(scope: str, values: dict):
    import winreg
    try:
        with winreg.OpenKey(_win_hive(scope), _WIN_SUBKEYS[scope], 0,
                            winreg.KEY_SET_VALUE) as k:
            for name, val in values.items():
                if val is None or val == "":
                    try:
                        winreg.DeleteValue(k, name)
                    except FileNotFoundError:
                        pass
                elif isinstance(val, (list, tuple)):
                    winreg.SetValueEx(k, name, 0, int(val[1]), val[0])
                else:
                    winreg.SetValueEx(k, name, 0, winreg.REG_SZ, val)
    except OSError:
        pass


def _win_broadcast():
    """Tell running apps the environment changed (WM_SETTINGCHANGE). Best-effort:
    most CLI tools read the environment once at process start anyway."""
    import ctypes
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


# ══════════════════════════════════════════════════════════════════════════════
# Linux backend
# ══════════════════════════════════════════════════════════════════════════════

def target_user() -> str:
    """The interactive user ProxyForce is acting for, even though it runs as root.

    sudo and pkexec both record who invoked them; without this the "user" scope
    would land in /root and be invisible to the person actually using the machine.
    """
    for var in ("SUDO_USER", "PKEXEC_UID", "LOGNAME", "USER"):
        val = os.environ.get(var, "").strip()
        if not val or val == "root":
            continue
        if var == "PKEXEC_UID":
            try:
                import pwd
                return pwd.getpwuid(int(val)).pw_name
            except Exception:
                continue
        return val
    return ""


def _target_home() -> str:
    user = target_user()
    if not user:
        return ""
    try:
        import pwd
        return pwd.getpwnam(user).pw_dir
    except Exception:
        return ""


def _linux_user_file() -> str:
    home = _target_home()
    return os.path.join(home, _LINUX_USER_ENV_REL) if home else ""


def _chown_to_target(path: str):
    """Keep a file written under the user's home owned by that user — ProxyForce
    runs as root, and a root-owned file in ~/.config is a papercut the user cannot
    clear without sudo."""
    user = target_user()
    if not user:
        return
    try:
        import pwd
        pw = pwd.getpwnam(user)
        os.chown(path, pw.pw_uid, pw.pw_gid)
    except Exception:
        pass


_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def _parse_env_file(path: str) -> dict:
    """{NAME: value} from a KEY=value file, tolerating `export `, comments, blank
    lines, and surrounding quotes."""
    out = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return out
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _ENV_LINE_RE.match(line)
        if not m:
            continue
        val = m.group(2)
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        out[m.group(1)] = val
    return out


def _rewrite_env_file(path: str, updates: dict, export: bool = False,
                      header: str = ""):
    """Apply {NAME: value-or-None} to a KEY=value file IN PLACE, preserving every
    line that is not one of ours — comments, ordering, and unrelated variables all
    survive, which matters because /etc/environment belongs to the system and a
    rewritten-from-scratch version would silently drop anything we did not model.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []
        if header:
            lines = header.splitlines()

    prefix = "export " if export else ""
    seen = set()
    out = []
    for line in lines:
        m = _ENV_LINE_RE.match(line) if line.strip() and not line.lstrip().startswith("#") else None
        if m and m.group(1) in updates:
            name = m.group(1)
            seen.add(name)
            val = updates[name]
            if val is not None and val != "":
                out.append('%s%s="%s"' % (prefix, name, val))
            # val None/"" -> drop the line entirely (that is the delete case)
            continue
        out.append(line)

    for name, val in updates.items():
        if name in seen or val is None or val == "":
            continue
        out.append('%s%s="%s"' % (prefix, name, val))

    text = "\n".join(out).rstrip("\n") + "\n"
    tmp = path + ".proxyforce.tmp"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _linux_read(scope: str, names) -> dict:
    """Read only from the file this module OWNS for that scope — the snapshot must
    describe what restore() can actually put back."""
    path = _LINUX_ETC_ENVIRONMENT if scope == "machine" else _linux_user_file()
    values = _parse_env_file(path) if path else {}
    return {name: ([values[name], TYPE_STRING] if name in values else None)
            for name in names}


def _linux_write(scope: str, values: dict):
    flat = {}
    for name, val in values.items():
        flat[name] = (val[0] if isinstance(val, (list, tuple)) else val)

    if scope == "machine":
        _rewrite_env_file(_LINUX_ETC_ENVIRONMENT, flat, export=False)
        # /etc/environment is read by PAM only. Non-login shells — where curl, git
        # and pip actually get run — read /etc/profile.d/*.sh, so the same values
        # are mirrored into a file we own outright.
        live = {k: v for k, v in flat.items() if v}
        if live:
            body = ["#!/bin/sh",
                    "# ProxyForce - generated, do not edit. Removed when ProxyForce stops.",
                    ""]
            body += ['export %s="%s"' % (k, v) for k, v in sorted(live.items())]
            try:
                os.makedirs(os.path.dirname(_LINUX_PROFILE_D), exist_ok=True)
                tmp = _LINUX_PROFILE_D + ".tmp"
                with open(tmp, "w", encoding="utf-8", newline="\n") as f:
                    f.write("\n".join(body) + "\n")
                os.chmod(tmp, 0o644)
                os.replace(tmp, _LINUX_PROFILE_D)
            except OSError:
                pass
        else:
            _remove_profile_d()
        return

    path = _linux_user_file()
    if not path:
        return
    header = ("# ProxyForce - generated. Read by the systemd user session.\n")
    _rewrite_env_file(path, flat, export=False, header=header)
    _chown_to_target(path)


def _remove_profile_d():
    try:
        os.remove(_LINUX_PROFILE_D)
    except OSError:
        pass


def foreign_vars(names) -> dict:
    """{NAME: value} for variables that are live in THIS process's environment but
    are not in a file we manage — i.e. exported from a user dotfile or a systemd
    drop-in we deliberately do not rewrite. Reported by diagnostics so a value that
    overrides the takeover is named rather than mysterious."""
    if hostos.IS_WINDOWS:
        return {}
    managed = {}
    managed.update(_parse_env_file(_LINUX_ETC_ENVIRONMENT))
    user_file = _linux_user_file()
    if user_file:
        managed.update(_parse_env_file(user_file))
    out = {}
    for name in names:
        live = os.environ.get(name)
        if live and managed.get(name) != live:
            out[name] = live
    return out


# ══════════════════════════════════════════════════════════════════════════════
# Public API (platform-agnostic)
# ══════════════════════════════════════════════════════════════════════════════

def snapshot(names) -> dict:
    """{scope: {name: [value, type] | None}} for every scope. `None` means "was
    not set", which restore() honours by deleting rather than writing an empty."""
    reader = _win_read if hostos.IS_WINDOWS else _linux_read
    return {scope: reader(scope, names) for scope in SCOPES}


def write(values: dict):
    """Set (or delete, on a falsy value) `values` in BOTH scopes, then broadcast."""
    writer = _win_write if hostos.IS_WINDOWS else _linux_write
    for scope in SCOPES:
        writer(scope, values)
    broadcast()


def restore(snap: dict, names):
    """Put a snapshot() back verbatim, including "was not set" -> delete."""
    writer = _win_write if hostos.IS_WINDOWS else _linux_write
    for scope in SCOPES:
        entry = (snap or {}).get(scope) or {}
        writer(scope, {name: entry.get(name) for name in names})
    if not hostos.IS_WINDOWS:
        # The profile.d mirror is ours alone; once the values are restored there is
        # nothing left for it to export.
        _remove_profile_d()
    broadcast()


def broadcast():
    if hostos.IS_WINDOWS:
        _win_broadcast()
    # Linux has no equivalent signal: a process reads its environment at exec time
    # and there is no supported way to change an already-running one. The caller
    # logs "reopen your shell", which is the honest answer on both platforms.


def describe(snap: dict, names) -> str:
    """One-line summary of the non-empty values in a snapshot (for the log)."""
    parts = []
    for scope in ("user", "machine"):
        for name in names:
            entry = (snap.get(scope) or {}).get(name)
            if entry is not None and entry[0]:
                parts.append("%s:%s=%s" % (scope, name, entry[0]))
    return ", ".join(parts)


def current_state(names) -> str:
    """Human-readable current state of `names` across both scopes (diagnostics)."""
    snap = snapshot(names)
    parts = []
    for scope in ("user", "machine"):
        entry = snap.get(scope) or {}
        set_vars = ["%s=%s" % (n, entry[n][0]) for n in names
                    if entry.get(n) is not None and entry[n][0]]
        parts.append("%s: %s" % (scope, ", ".join(set_vars) if set_vars else "(none set)"))
    foreign = foreign_vars(names)
    if foreign:
        parts.append("shell/dotfile (not managed by ProxyForce): "
                     + ", ".join("%s=%s" % (k, v) for k, v in sorted(foreign.items())))
    return "  ||  ".join(parts)


def storage_description() -> str:
    """Where these variables are persisted on this platform (for diagnostics)."""
    if hostos.IS_WINDOWS:
        return (r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
                r" + HKCU\Environment")
    user_file = _linux_user_file() or "(no target user resolved)"
    return "%s + %s + %s" % (_LINUX_ETC_ENVIRONMENT, _LINUX_PROFILE_D, user_file)
