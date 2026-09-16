"""
ProxyForce — legacy NCSI active-probing recovery (Windows only).

v2.2.2 briefly disabled EnableActiveProbing and saved its previous registry value
here. Current versions keep active probing enabled, as required for Windows to mark
the ProxyForce interface as Internet. This module remains only to restore a backup
left by an interrupted older run and to report the current value in diagnostics.

LINUX: there is no NCSI. The nearest equivalent is NetworkManager's connectivity
check, which ProxyForce does not touch — NM probes a plain HTTP URL that the
port-80 route rule already sends through the local forward-proxy, so the failure
mode this module was written for (Windows concluding "no internet" and silently
switching off Spotlight/Store/Widgets) has no counterpart. Both public functions
are no-ops there rather than absent, so callers need no platform branch.
"""

import os
import json

from core import hostos

_NCSI_KEY = r"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
_VALUE = "EnableActiveProbing"


def _data_dir() -> str:
    return hostos.data_dir()


def _backup_path() -> str:
    return os.path.join(_data_dir(), "ncsi_backup.json")


# ── snapshot / serialize ────────────────────────────────────────────────────────

def _snapshot() -> dict:
    """Read the current EnableActiveProbing value. {"value": None} means the value
    doesn't exist (Windows treats absence as enabled=1) — restore() must delete it
    again rather than writing a value that was never really there."""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NCSI_KEY) as k:
            try:
                val, typ = winreg.QueryValueEx(k, _VALUE)
                return {"value": [val, typ]}
            except FileNotFoundError:
                return {"value": None}
    except OSError:
        return {"value": None}


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


def _write_entry(entry):
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NCSI_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            if entry is None:
                try:
                    winreg.DeleteValue(k, _VALUE)
                except FileNotFoundError:
                    pass
            else:
                val, typ = entry
                winreg.SetValueEx(k, _VALUE, 0, typ, val)
    except OSError:
        pass


# ── public API ──────────────────────────────────────────────────────────────────

def restore() -> bool:
    """Restore a backup left by the v2.2.2 passive-probing workaround. Idempotent:
    no backup -> no-op. Returns True if a restore was performed."""
    if not hostos.IS_WINDOWS:
        return False
    snap = _read_backup()
    if snap is None:
        return False
    _write_entry(snap.get("value"))
    _clear_backup()
    return True


def current_state() -> str:
    """One-line human-readable current state (for diagnostics)."""
    if not hostos.IS_WINDOWS:
        return "n/a on Linux (no NCSI; NetworkManager connectivity check untouched)"
    snap = _snapshot()
    entry = snap.get("value")
    if entry is None:
        return "EnableActiveProbing not set (Windows default: active probing ON)"
    return "EnableActiveProbing=%s" % entry[0]
