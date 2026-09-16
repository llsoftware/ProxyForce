"""
ProxyForce - Configuration Manager

Config is stored MACHINE-WIDE so the elevated GUI and any other processes on
the same machine share one source of truth:

  WINDOWS
  * Primary store:  HKEY_LOCAL_MACHINE\\SOFTWARE\\ProxyForce   (registry)
  * Fallback store: C:\\ProgramData\\ProxyForce\\config.json     (JSON file)

    Writing HKLM requires administrator rights. The GUI ships with an asInvoker
    manifest and self-elevates at startup via ShellExecuteW("runas") (see
    main.py:relaunch_as_admin), so the running process is always elevated and can
    write HKLM. If an HKLM write still fails we fall back to ProgramData JSON
    (same machine-wide visibility).

  LINUX
  * Single store:   /var/lib/proxyforce/config.json

    There is no registry, and a second store is not wanted: the JSON path already
    satisfies what the registry was chosen for (machine-wide, readable by the
    elevated engine regardless of which account is logged in). The file is written
    0600 root-owned because it holds the proxy password — HKLM's ACL is what
    protects the registry equivalent, and the obfuscation below is NOT encryption
    on either platform.

The JSON format is identical on both platforms, so a config file copied between
them is read without migration.
"""

import json
import os
import base64
import subprocess

from core import hostos

REG_KEY = r"SOFTWARE\ProxyForce"

# Machine-wide JSON store. On Windows it is the registry's fallback (NOT %APPDATA%
# — that is per-user and invisible to the elevated engine); on Linux it is the only
# store. See core/hostos.data_dir().
CONFIG_FILE_FALLBACK = os.path.join(hostos.data_dir(), "config.json")

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
    # ── TLS inspection (see core/env_certs) ──
    # OPT-IN. Points the CA-bundle environment variables (SSL_CERT_FILE,
    # REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS, …) at a merged bundle that trusts
    # the corporate inspection CA, fixing docker/pip/npm/git/curl on a network
    # that MITMs TLS. Off by default: repointing a machine's trust configuration
    # is not something a proxy tool should do uninvited.
    "ca_inject": False,
    # Empty = use the corporate CA ProxyForce ships with (assets/ca/corporate-ca.pem).
    # Set to a .pem/.crt path to trust a different one — the shipped cert expires,
    # and other sites run a different appliance.
    "ca_cert_path": "",
    # ── Auto-update ──
    "auto_update_check": True,      # nightly background check while running
    "update_hour": 3,               # local hour (0-23) for the nightly check / "install tonight"
    "update_channel": "stable",     # "stable" (releases) | "dev" (incl. pre-releases)
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
    (e.g. not elevated, or not Windows) so the caller falls back to the JSON file."""
    import winreg
    key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_KEY)
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
    if not hostos.IS_WINDOWS:
        # The file holds the proxy password, obfuscated but not encrypted. On
        # Windows HKLM's ACL keeps it away from unprivileged accounts; /var/lib is
        # world-readable by default, so the mode has to say so explicitly.
        try:
            os.chmod(CONFIG_FILE_FALLBACK, 0o600)
        except OSError:
            pass


def save_config(config_dict: dict) -> bool:
    """Persist config machine-wide.

    Windows: HKLM first, then the ProgramData JSON file. Writing both is overkill;
    HKLM is preferred and the file is only used if the registry write fails, so
    there is a single source of truth that load_config() reads in the same priority
    order. Linux: the JSON file is the only store, so _save_to_registry raises
    immediately (no winreg) and the fallback path is the normal path.
    """
    if hostos.IS_WINDOWS:
        try:
            _save_to_registry(config_dict)
            return True
        except Exception:
            pass    # most likely: not elevated, so HKLM is read-only for us
    try:
        _save_to_file(config_dict)
        return True
    except Exception:
        return False   # both stores failed — caller should surface an error


def load_config() -> dict:
    """Load config from HKLM, falling back to the ProgramData JSON file.
    Always returns a complete dict (defaults filled in)."""
    result = dict(_DEFAULTS)

    # 1) Registry (HKLM) — Windows only, and authoritative whenever the key EXISTS,
    # even if host is still empty (fresh install: the engine then waits for the GUI
    # to set it). Falling through to JSON only when host is empty would let a stale
    # JSON value silently override a deliberately-cleared registry config.
    try:
        if not hostos.IS_WINDOWS:
            raise FileNotFoundError
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_KEY)
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


def auth_config_warnings(cfg: dict) -> list:
    """Warn when Auth Type and the credential fields disagree, i.e. the config
    looks authenticated but no credentials will actually reach the proxy (the
    engine only sends them when auth_type == "basic" — see
    SingBoxController._render_config). Returns [] when consistent.

    Diagnosed 2026-08-08: auto-bypass silently flipped a saved config's
    auth_type to "none" while leaving username/password populated, so the
    proxy got no credentials and answered 407 with nothing telling the user
    why — hours were lost to that. This has no dependency on auto-bypass
    (removed) since the same silent mismatch could arise from any other
    partial config write, a hand-edited registry value, or a stale JSON
    fallback file."""
    auth = str(cfg.get("auth_type", "none")).lower()
    username = cfg.get("username") or ""
    password = cfg.get("password") or ""
    warnings = []
    if auth == "none" and (username or password):
        warnings.append(
            'Auth Type is "None" but a username/password is configured — the '
            "credentials will NOT be sent to the proxy. Set Auth Type to Basic "
            "if the proxy requires authentication.")
    elif auth == "basic" and not username:
        warnings.append(
            'Auth Type is "Basic" but the username is empty — the proxy will '
            "answer 407 Proxy Authentication Required.")
    elif auth == "basic" and not password:
        warnings.append(
            'Auth Type is "Basic" but the password is empty — the proxy will '
            "answer 407 if it requires one.")
    elif auth == "ntlm" and (username or password):
        warnings.append(
            'Auth Type is "NTLM", which ProxyForce does not implement — the '
            "credentials will NOT be sent (NTLM behaves exactly like None). "
            "Use Basic if the proxy accepts it.")
    return warnings


# ── Legacy migration ────────────────────────────────────────────────────────
# The v2.2.2 "auto_bypass" registry/JSON value is gone from _DEFAULTS (the
# feature it drove — auto-discovering and adding hosts to the Bypass List —
# was removed: it picked up bad entries and, via a partial-config-write bug,
# reset Auth Type to "none" on every reconnect). A machine that still carries
# the leftover value may also carry Bypass List entries that feature added on
# its own, worth a one-time nudge to review.
_LEGACY_AUTO_BYPASS_KEY = "auto_bypass"


def consume_legacy_auto_bypass_flag() -> bool:
    """True (once) if this machine still carries the v2.2.2 `auto_bypass`
    value, meaning entries may have been auto-added to bypass_list. Deletes it
    from both stores so the notice never repeats. Best-effort, never raises."""
    found = False
    if hostos.IS_WINDOWS:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_KEY, 0,
                                winreg.KEY_ALL_ACCESS) as key:
                try:
                    winreg.QueryValueEx(key, _LEGACY_AUTO_BYPASS_KEY)
                    found = True
                    winreg.DeleteValue(key, _LEGACY_AUTO_BYPASS_KEY)
                except FileNotFoundError:
                    pass
        except OSError:
            pass
    if os.path.exists(CONFIG_FILE_FALLBACK):
        try:
            with open(CONFIG_FILE_FALLBACK) as f:
                data = json.load(f)
            if _LEGACY_AUTO_BYPASS_KEY in data:
                found = True
                del data[_LEGACY_AUTO_BYPASS_KEY]
                with open(CONFIG_FILE_FALLBACK, "w") as f:
                    json.dump(data, f, indent=2)
        except Exception:
            pass
    return found


# ── Autostart ─────────────────────────────────────────────────────────────────
# WINDOWS: a Scheduled Task, NOT an HKCU\...\Run entry. WHY:
# The GUI ships asInvoker and self-elevates via ShellExecuteW("runas")
# (main.py:relaunch_as_admin), so a Run-key launch popped a UAC prompt at EVERY
# sign-in — fatal on an unattended box where nobody clicks it. A task registered
# with /RL HIGHEST launches the process ALREADY elevated, so is_admin() is true in
# main.py, the self-elevation (and its UAC prompt) is skipped, and the app comes up
# silently at logon. /SC ONLOGON runs it in the interactive desktop session (the
# tray needs one). No /RU is passed on purpose: it would make schtasks demand a
# password, which this non-interactive call cannot answer — ONLOGON then binds to
# the logon that creates it, running as the current (elevated) user.
#
# LINUX: a systemd SYSTEM unit running `--headless`, not a desktop autostart entry.
# Same reasoning, different mechanism. A .desktop entry in ~/.config/autostart runs
# unprivileged, so it would have to call pkexec and pop an authentication dialog at
# every single login — the exact failure the Scheduled Task exists to avoid on
# Windows, and worse here because polkit cannot be satisfied non-interactively.
# A system unit starts as root at boot with nothing to click. It runs headless
# because a system service has no session to draw a window in; the GUI is then a
# separate, optional launch that attaches to the already-running engine's config.
# Boxes with no systemd (or a container) get a clear failure rather than a silent
# no-op — enable_autostart_error() reports it to the GUI.
_TASK_NAME     = "ProxyForce"
_LEGACY_RUN_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
_NO_WINDOW     = hostos.NO_WINDOW

_SYSTEMD_UNIT_PATH = "/etc/systemd/system/proxyforce.service"
_SYSTEMD_UNIT = """\
[Unit]
Description=ProxyForce transparent corporate-proxy redirector
Documentation=https://github.com/llsoftware/ProxyForce
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} --headless
Restart=on-failure
RestartSec=5
# The engine creates a TUN, rewrites the routing table and edits /etc files, so it
# genuinely needs root; it is not sandboxed here for that reason.
User=root

[Install]
WantedBy=multi-user.target
"""


def _remove_legacy_run_entry():
    """Delete the old HKCU\\...\\Run\\ProxyForce value so upgraded installs don't
    double-launch (Run key + Scheduled Task). Best-effort."""
    if not hostos.IS_WINDOWS:
        return
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _LEGACY_RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as key:
            try:
                winreg.DeleteValue(key, _TASK_NAME)
            except FileNotFoundError:
                pass
    except OSError:
        pass


def _delete_autostart_task():
    try:
        subprocess.run(["schtasks", "/Delete", "/F", "/TN", _TASK_NAME],
                       capture_output=True, timeout=15, **hostos.popen_kwargs())
    except Exception:
        pass


def _systemctl(*args, timeout=20) -> bool:
    """Run systemctl; True on success. False (not an exception) when systemd is
    absent, so a container or a non-systemd distro degrades to "autostart
    unavailable" rather than crashing Save."""
    try:
        r = hostos.run(["systemctl", *args], timeout=timeout)
        return r.returncode == 0
    except Exception:
        return False


def _save_autostart_linux(enabled: bool, exe_path: str):
    if enabled:
        try:
            with open(_SYSTEMD_UNIT_PATH, "w", encoding="utf-8", newline="\n") as f:
                f.write(_SYSTEMD_UNIT.format(exe=exe_path))
            os.chmod(_SYSTEMD_UNIT_PATH, 0o644)
        except OSError:
            return
        _systemctl("daemon-reload")
        _systemctl("enable", "proxyforce.service")
    else:
        _systemctl("disable", "proxyforce.service")
        try:
            os.remove(_SYSTEMD_UNIT_PATH)
        except OSError:
            pass
        _systemctl("daemon-reload")


def save_autostart(enabled: bool, exe_path: str):
    """Register/unregister start-at-boot for the engine.

    Windows: a logon Scheduled Task with /RL HIGHEST, so ProxyForce starts already
    elevated and the UAC prompt is skipped (see the note above). Always removes the
    legacy Run-key entry first.
    Linux: a systemd system unit running --headless (see the note above).

    All best-effort on both: a failure here never crashes Save."""
    _remove_legacy_run_entry()
    if not hostos.IS_WINDOWS:
        _save_autostart_linux(enabled, exe_path)
        return
    if enabled:
        try:
            subprocess.run(
                ["schtasks", "/Create", "/F", "/TN", _TASK_NAME,
                 "/SC", "ONLOGON", "/RL", "HIGHEST",
                 "/TR", f'"{exe_path}" --minimized'],
                capture_output=True, timeout=15, **hostos.popen_kwargs())
        except Exception:
            pass
    else:
        _delete_autostart_task()


def autostart_available() -> "tuple[bool, str]":
    """(available, reason). The GUI disables the Autostart checkbox and shows the
    reason when the platform cannot honour it — better than a checkbox that saves
    happily and then does nothing at boot."""
    if hostos.IS_WINDOWS:
        return (True, "")
    if not hostos.which("systemctl"):
        return (False, "systemd not found — start ProxyForce from your session "
                       "manager, or run it with sudo when you need it.")
    return (True, "")
