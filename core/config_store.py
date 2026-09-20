"""
ProxyForce - Configuration Manager

Config is stored MACHINE-WIDE so the elevated GUI and any other processes on
the same machine share one source of truth:

  * Primary store:  HKEY_LOCAL_MACHINE\\SOFTWARE\\ProxyForce   (registry)
  * Fallback store: C:\\ProgramData\\ProxyForce\\config.json     (JSON file)

Writing HKLM requires administrator rights. The GUI ships with an asInvoker
manifest and self-elevates at startup via ShellExecuteW("runas") (see
main.py:relaunch_as_admin), so the running process is always elevated and can
write HKLM. If an HKLM write still fails we fall back to ProgramData JSON (same
machine-wide visibility).
"""

import json
import os
import base64
import subprocess
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
    # ── Site reputation scanning (see core/reputation) ──
    # OPT-IN. Checks the hostname of every NEW connection against reputation
    # sources, once per host, and remembers the verdict. Off by default: it sends
    # the names of the sites you visit to a third party, which is not something a
    # proxy tool should start doing uninvited.
    "rep_scan": False,
    # Free malware/phishing feeds (URLhaus + OpenPhish), downloaded and matched
    # locally. No API key, no per-host quota — so this tier stays on by default
    # and is the only one that works out of the box.
    "rep_feeds": True,
    # Google Safe Browsing key. Batched (up to 500 hosts per request), ~10k
    # requests/day — effectively unlimited for one machine. The primary filter.
    "rep_gsb_key": "",
    # VirusTotal key. 4 lookups/minute and 500/day on the free tier, so it is a
    # queued second opinion for hosts the tiers above said nothing about, never a
    # primary filter.
    "rep_vt_key": "",
    "rep_block": True,          # add flagged hosts to rep_blocklist
    "rep_blocklist": [],        # hosts flagged malicious -> sing-box reject rules
    # False-positive overrides: hosts the user chose to allow after a flag. These
    # are still SCANNED (there are no scan exemptions — every host is looked up
    # exactly once and then served from cache); they are simply never blocked.
    "rep_allowlist": [],
}

# Values obfuscated at rest in both stores. Base64 is obfuscation, NOT encryption
# — see _simple_obfuscate. An API key is no more protected here than the proxy
# password is; HKLM\SOFTWARE\ProxyForce is readable by any local user.
_SECRET_KEYS = frozenset({"password", "rep_gsb_key", "rep_vt_key"})

# Values persisted as JSON strings because the registry has no list type.
_LIST_KEYS = frozenset(k for k, v in _DEFAULTS.items() if isinstance(v, list))


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
            if k in _SECRET_KEYS and v:
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
    for k in _SECRET_KEYS:
        if data.get(k):
            data[k] = _simple_obfuscate(data[k])
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
                if k in _SECRET_KEYS and val:
                    val = _simple_deobfuscate(val)
                if k in _LIST_KEYS and isinstance(val, str):
                    try:
                        val = json.loads(val)
                    except Exception:
                        val = []
                    if not isinstance(val, list):
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
            for k in _SECRET_KEYS:
                if data.get(k):
                    data[k] = _simple_deobfuscate(data[k])
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


def rep_config_warnings(cfg: dict) -> list:
    """Warn when reputation scanning is enabled but cannot actually do anything,
    or is configured in a way that silently degrades. Returns [] when sane.

    Mirrors auth_config_warnings: the failure mode being guarded against is a
    setting that LOOKS on but produces no verdicts, which is worse than off
    because the user believes they are covered."""
    if not cfg.get("rep_scan"):
        return []
    feeds = bool(cfg.get("rep_feeds"))
    gsb = bool((cfg.get("rep_gsb_key") or "").strip())
    vt = bool((cfg.get("rep_vt_key") or "").strip())
    warnings = []
    if not (feeds or gsb or vt):
        warnings.append(
            "Site scanning is ON but every source is disabled — no site will "
            "ever be checked. Enable the free feeds, or add a Google Safe "
            "Browsing or VirusTotal API key.")
        return warnings
    if not gsb:
        if vt and not feeds:
            # The worst realistic combination: VT alone is 4 lookups/minute and
            # 500/day, so a normal browsing session queues faster than it drains
            # and most hosts stay unknown for days.
            warnings.append(
                "VirusTotal is the only source configured. Its free tier allows "
                "4 lookups/minute (500/day), so new sites will be checked slowly "
                "and a backlog will build. Add a Google Safe Browsing key — it "
                "batches and covers everything — or enable the free feeds.")
        else:
            warnings.append(
                "No Google Safe Browsing key — only the offline feeds are "
                "active, which catch known malware and phishing hosts but "
                "nothing newer than the last feed download.")
    if not cfg.get("rep_block"):
        warnings.append(
            "Blocking is off — flagged sites will be reported but still "
            "reachable.")
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
    try:
        with winreg.OpenKey(REG_ROOT, REG_KEY, 0, winreg.KEY_ALL_ACCESS) as key:
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


# ── Autostart (Scheduled Task) ─────────────────────────────────────────────────
# Autostart is a Scheduled Task, NOT an HKCU\...\Run entry. WHY:
# The GUI ships asInvoker and self-elevates via ShellExecuteW("runas")
# (main.py:relaunch_as_admin), so a Run-key launch popped a UAC prompt at EVERY
# sign-in — fatal on an unattended box where nobody clicks it. A task registered
# with /RL HIGHEST launches the process ALREADY elevated, so is_admin() is true in
# main.py, the self-elevation (and its UAC prompt) is skipped, and the app comes up
# silently at logon. /SC ONLOGON runs it in the interactive desktop session (the
# tray needs one). No /RU is passed on purpose: it would make schtasks demand a
# password, which this non-interactive call cannot answer — ONLOGON then binds to
# the logon that creates it, running as the current (elevated) user.
_TASK_NAME     = "ProxyForce"
_LEGACY_RUN_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
_NO_WINDOW     = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _remove_legacy_run_entry():
    """Delete the old HKCU\\...\\Run\\ProxyForce value so upgraded installs don't
    double-launch (Run key + Scheduled Task). Best-effort."""
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
                       capture_output=True, creationflags=_NO_WINDOW, timeout=15)
    except Exception:
        pass


def save_autostart(enabled: bool, exe_path: str):
    """Register/unregister the logon-autostart Scheduled Task that launches the GUI.

    The task runs at logon with highest privileges, so ProxyForce starts elevated
    with no UAC prompt (see the note above). Always removes the legacy Run-key entry
    first. All best-effort: a failure here never crashes Save."""
    _remove_legacy_run_entry()
    if enabled:
        try:
            subprocess.run(
                ["schtasks", "/Create", "/F", "/TN", _TASK_NAME,
                 "/SC", "ONLOGON", "/RL", "HIGHEST",
                 "/TR", f'"{exe_path}" --minimized'],
                capture_output=True, creationflags=_NO_WINDOW, timeout=15)
        except Exception:
            pass
    else:
        _delete_autostart_task()
