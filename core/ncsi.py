"""
ProxyForce — legacy NCSI active-probing recovery.

v2.2.2 briefly disabled EnableActiveProbing and saved its previous registry value
here. Current versions keep active probing enabled, as required for Windows to mark
the ProxyForce interface as Internet. This module remains only to restore a backup
left by an interrupted older run and to report the current value in diagnostics.
"""

import os
import json
import winreg

_NCSI_KEY = r"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
_VALUE = "EnableActiveProbing"


def _data_dir() -> str:
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "ProxyForce")


def _backup_path() -> str:
    return os.path.join(_data_dir(), "ncsi_backup.json")


# ── snapshot / serialize ────────────────────────────────────────────────────────

def _snapshot() -> dict:
    """Read the current EnableActiveProbing value. {"value": None} means the value
    doesn't exist (Windows treats absence as enabled=1) — restore() must delete it
    again rather than writing a value that was never really there."""
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


# ── public API ───────────────────────────────────────────────────────────────────

def _write_entry(entry):
    """Restore None (delete) or a saved [value, registry_type] pair."""
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


def restore() -> bool:
    """Restore the snapshotted EnableActiveProbing value (or delete it if it never
    existed). Idempotent: no backup -> no-op. Returns True if a restore ran."""
    snap = _read_backup()
    if snap is None:
        return False
    try:
        _write_entry(snap.get("value"))
    except OSError:
        pass
    _clear_backup()
    return True


def current_state() -> str:
    """One-line human-readable current NCSI active-probing state (for diagnostics)."""
    snap = _snapshot()
    entry = snap.get("value")
    if entry is None:
        return f"{_VALUE}=<not set> (default: active probing enabled)"
    return f"{_VALUE}={entry[0]}"
