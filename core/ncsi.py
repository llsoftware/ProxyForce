"""
ProxyForce — NCSI active-probing fallback (last resort for the Spotlight/NCSI fix).

WHY THIS EXISTS: the port-80 route rule (singbox_controller._render_config) and the
NCSI DNS `predefined` rule (_ncsi_dns_probe) are the REAL fix — they make NlaSvc's
own probes genuinely succeed, so Windows correctly reports Internet connectivity
while ProxyForce runs. This module is the fallback for anything that fix doesn't
anticipate (a probe host/path retargeted by policy in a way the two rules above
don't cover, an NlaSvc quirk on a specific Windows build, …): it tells NlaSvc to
stop ACTIVELY probing and fall back to passive connectivity detection, which reports
Internet as long as traffic is actually flowing — sidestepping the probe entirely
rather than trying to make it succeed.

Because it is a fallback, singbox_controller only calls suppress_active_probing()
if diagnostics still finds IPv4Connectivity != Internet after the real fix has had
a chance to take effect — never unconditionally. See core.config_store's
"ncsi_fallback" key to disable this lane entirely.

Snapshot/backup/restore follows the exact same crash-safe contract as
core.system_proxy: the backup is written to disk BEFORE the first mutation, so a
crashed run can be rolled back on the next start, and an existing backup found at
start is kept as the true original (a previous run is still mid-takeover).
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

def _set_disabled():
    """The actual registry mutation for suppress_active_probing(), split out so
    tests can stub just this primitive (see tests/test_ncsi.py) rather than
    touching the real machine's NlaSvc setting."""
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NCSI_KEY, 0,
                        winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, _VALUE, 0, winreg.REG_DWORD, 0)


def _write_entry(entry):
    """The actual registry mutation for restore(), split out for the same reason
    as _set_disabled(). `entry` is None (value never existed — delete it again) or
    [value, type] (write it back verbatim)."""
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


def suppress_active_probing() -> bool:
    """Snapshot (crash-safe) then set EnableActiveProbing=0, so NlaSvc stops
    actively probing dns.msftncsi.com / www.msftconnecttest.com and falls back to
    passive detection instead. Returns True if the value was set."""
    if _read_backup() is None:
        _write_backup(_snapshot())
    try:
        _set_disabled()
        return True
    except OSError:
        return False


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
