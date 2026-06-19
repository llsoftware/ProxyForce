"""
ProxyForce - Configuration Manager

Config is stored MACHINE-WIDE so the elevated GUI and any other processes on
the same machine share one source of truth:

  * Primary store:  HKEY_LOCAL_MACHINE\\SOFTWARE\\ProxyForce   (registry)
  * Fallback store: C:\\ProgramData\\ProxyForce\\config.json     (JSON file)

Writing HKLM requires administrator rights. The GUI ships with a
requireAdministrator manifest so it can always write HKLM. If an HKLM write
fails we fall back to ProgramData JSON (same machine-wide visibility).
"""

import json
import os
import base64
import winreg

REG_ROOT = winreg.HKEY_LOCAL_MACHINE
REG_KEY = r"SOFTWARE\ProxyForce"

# Machine-wide JSON fallback (NOT %APPDATA% — that is per-user and invisible to
# the SYSTEM engine). ProgramData is the same for every account on the box.
_PROGRAMDATA = os.environ.get("ProgramData", r"C:\ProgramData")
CONFIG_FILE_FALLBACK = os.path.join(_PROGRAMDATA, "ProxyForce", "config.json")

# Value names we persist. Anything else under the key (InstalledVersion,
# InstallPath, ...) is ignored by load_config.
_DEFAULTS = {
    "host": "",
    "port": 8080,
    "auth_type": "none",
    "username": "",
    "password": "",
    "exclude_private": True,
    "exclude_loopback": True,
    "bypass_list": [],
    "autostart": False,
    "start_minimized": False,
    "log_level": "info",
    "appearance": "system",   # "light" | "dark" | "system" (follow OS)
}


def _simple_obfuscate(s: str) -> str:
    """Basic obfuscation for credential storage (not true encryption — use a
    machine-scoped DPAPI blob for production)."""
    return base64.b64encode(s.encode("utf-8")).decode()


def _simple_deobfuscate(s: str) -> str:
    try:
        return base64.b64decode(s.encode("utf-8")).decode("utf-8")
    except Exception:
        return s


def _save_to_registry(config_dict: dict):
    """Write every value under HKLM\\SOFTWARE\\ProxyForce. Raises on failure
    (e.g. not elevated) so the caller can fall back to the JSON file."""
    key = winreg.CreateKey(REG_ROOT, REG_KEY)
    try:
        for k, v in config_dict.items():
            if k == "password" and v:
                v = _simple_obfuscate(v)
            if isinstance(v, bool):
                winreg.SetValueEx(key, k, 0, winreg.REG_DWORD, int(v))
            elif isinstance(v, int):
                winreg.SetValueEx(key, k, 0, winreg.REG_DWORD, v)
            elif isinstance(v, list):
                winreg.SetValueEx(key, k, 0, winreg.REG_SZ, json.dumps(v))
            else:
                winreg.SetValueEx(key, k, 0, winreg.REG_SZ, str(v))
    finally:
        winreg.CloseKey(key)


def _save_to_file(config_dict: dict):
    os.makedirs(os.path.dirname(CONFIG_FILE_FALLBACK), exist_ok=True)
    data = dict(config_dict)
    if data.get("password"):
        data["password"] = _simple_obfuscate(data["password"])
    with open(CONFIG_FILE_FALLBACK, "w") as f:
        json.dump(data, f, indent=2)


def save_config(config_dict: dict) -> bool:
    """Persist config machine-wide. Tries HKLM first, then ProgramData JSON.

    Writes BOTH stores when possible is overkill; we prefer HKLM and only fall
    back to the file if the registry write fails, so there is a single source of
    truth that load_config() reads in the same priority order.
    """
    try:
        _save_to_registry(config_dict)
        return True
    except Exception:
        # Most likely: not elevated, so HKLM is read-only for us.
        try:
            _save_to_file(config_dict)
            return True
        except Exception:
            return False   # both stores failed — caller should surface an error


def load_config() -> dict:
    """Load config from HKLM, falling back to the ProgramData JSON file.
    Always returns a complete dict (defaults filled in)."""
    result = dict(_DEFAULTS)

    # 1) Registry (HKLM) — authoritative whenever the key EXISTS, even if host is
    # still empty (fresh install: the service then waits for the GUI to set it).
    # Falling through to JSON only when host is empty would let a stale JSON value
    # silently override a deliberately-cleared registry config.
    try:
        key = winreg.OpenKey(REG_ROOT, REG_KEY)
        try:
            for k in _DEFAULTS:
                try:
                    val, vtype = winreg.QueryValueEx(key, k)
                except FileNotFoundError:
                    continue
                if k == "password" and val:
                    val = _simple_deobfuscate(val)
                if k == "bypass_list" and isinstance(val, str):
                    try:
                        val = json.loads(val)
                    except Exception:
                        val = []
                if vtype == winreg.REG_DWORD:
                    val = bool(val) if isinstance(_DEFAULTS[k], bool) else int(val)
                result[k] = val
        finally:
            winreg.CloseKey(key)
        return result   # HKLM wins whenever the key exists
    except FileNotFoundError:
        pass            # key absent -> fall through to the JSON fallback
    except Exception:
        pass

    # 2) ProgramData JSON fallback
    if os.path.exists(CONFIG_FILE_FALLBACK):
        try:
            with open(CONFIG_FILE_FALLBACK) as f:
                data = json.load(f)
            if data.get("password"):
                data["password"] = _simple_deobfuscate(data["password"])
            result.update({k: data[k] for k in _DEFAULTS if k in data})
        except Exception:
            pass

    return result


def save_autostart(enabled: bool, exe_path: str):
    """Add/remove a per-user logon entry that launches the GUI.
    Note: because the exe is requireAdministrator, logon autostart will trigger
    a UAC prompt at each sign-in."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                             0, winreg.KEY_SET_VALUE)
        try:
            if enabled:
                winreg.SetValueEx(key, "ProxyForce", 0, winreg.REG_SZ,
                                  f'"{exe_path}" --minimized')
            else:
                try:
                    winreg.DeleteValue(key, "ProxyForce")
                except FileNotFoundError:
                    pass
        finally:
            winreg.CloseKey(key)
    except Exception:
        pass
