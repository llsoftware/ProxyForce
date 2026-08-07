"""
ProxyForce — Store/UWP loopback exemptions (the "Microsoft Store won't load" fix).

WHY THIS EXISTS (2026-08-06):
  ProxyForce's system-proxy takeover (core/system_proxy) points WinINET/WinHTTP at
  127.0.0.1 — ProxyForce's own local listeners. Every Windows Store / UWP app runs
  inside an AppContainer, and Windows blocks an AppContainer's connections to
  loopback by default, regardless of what the system proxy says. The app isn't
  ignoring the proxy — it's obeying an unreachable one, and the OS kills the
  connection before it ever reaches the network, so the TUN catch-all never sees it
  either. Confirmed empirically: with `CheckNetIsolation LoopbackExempt -s` showing
  no exemptions, the Microsoft Store loads nothing and its API hosts
  (storeedgefd.dsx.mp.microsoft.com, displaycatalog.mp.microsoft.com) never appear
  in the sing-box log for the entire session — while every other app works fine.

  Before the switch to a loopback-pointed system proxy (core/system_proxy.point_at),
  this had no symptom: the old take_over() mode disabled the system proxy entirely,
  so UWP apps fell through to direct → captured by the TUN like everything else.
  Pointing at loopback fixed CONNECT-honouring apps but broke AppContainer apps as
  a side effect.

  The fix: grant a loopback exemption to every installed UWP package for the
  lifetime of the ProxyForce session (`CheckNetIsolation LoopbackExempt -a`), and
  revoke exactly what we added when ProxyForce stops.

HOW IT IS WIRED (see singbox_controller._takeover_system_proxy /
_restore_system_proxy):
  Same snapshot → crash-safe backup → set → restore pattern as core/env_proxy:
    1. Snapshot the CURRENT exemption list (parsed from `LoopbackExempt -s`).
    2. Persist it to disk BEFORE the first mutation. If a backup already exists,
       keep it — a prior run crashed mid-takeover and that file holds the true
       original.
    3. Enumerate installed packages (`Get-AppxPackage`, current user — ProxyForce
       runs elevated as the interactive user, and exemptions are per-user) and add
       an exemption for each — ONE SEPARATE `CheckNetIsolation.exe` PROCESS PER
       PACKAGE (see _checknetisolation's docstring for why: a single batched
       PowerShell script with an internal loop over all packages was tried first
       and reproducibly corrupted the exemption list instead of populating it —
       confirmed live on two different machines/Windows versions).
    4. On stop, remove only the exemptions THIS run added (packages present now but
       absent from the snapshot), then delete the backup.

  This matters more than the env-var case: loopback exemptions persist across
  reboots. A crash that skips restore() must not permanently loosen the machine —
  hence the crash-safe backup file, and a diff-based restore rather than a blanket
  clear (`-c` would also wipe exemptions the user granted themselves, unrelated to
  ProxyForce).

NOTES:
  * Best-effort throughout: every public function catches its own exceptions and
    degrades to "nothing changed" rather than raising into the caller. A machine
    where this fails should still run ProxyForce for every non-UWP app.
  * `CheckNetIsolation` is a legacy console tool but remains the only supported way
    to manage this list on Windows 10/11; there is no WinRT/PowerShell cmdlet
    equivalent as of this writing.
  * Deliberately one process per package, not one batched script — see
    _checknetisolation's docstring. Do not "optimize" this back to a loop inside a
    single PowerShell invocation; that is the exact pattern that silently corrupted
    the exemption list (verified: every call reported success, but the real list
    ended up with a single unresolvable entry sharing an IDENTICAL SID across two
    unrelated machines — proof the corruption wasn't coming from the input at all).
"""

import os
import re
import json
import subprocess

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Matches a Package Family Name's stable shape: <name>_<13-char publisher id>, e.g.
# "microsoft.windowsstore_8wekyb3d8bbwe". The 13-character base32-style suffix is a
# fixed Windows convention for EVERY package (first- and third-party alike) — unlike
# the surrounding label text in `CheckNetIsolation LoopbackExempt -s` output, which
# varies across Windows builds/locales (see _list_exempt below for why this matters).
_PFN_RE = re.compile(r"\b[A-Za-z0-9][\w.-]*_[A-Za-z0-9]{13}\b")


def _data_dir() -> str:
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "ProxyForce")


def _backup_path() -> str:
    return os.path.join(_data_dir(), "appcontainer_backup.json")


def _ps(command: str, timeout: int = 30) -> str:
    """Run a PowerShell one-liner; return combined stdout+stderr (best-effort)."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, creationflags=_NO_WINDOW, timeout=timeout)
        return ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:
        return f"<command failed: {e}>"


def _checknetisolation(*args: str, timeout: int = 15) -> "tuple[int, str]":
    """Run CheckNetIsolation.exe DIRECTLY (no PowerShell in between) with the given
    arguments; return its real exit code and combined output.

    WHY NOT A POWERSHELL SCRIPT WITH A LOOP (the pattern this replaces): a single,
    standalone `CheckNetIsolation LoopbackExempt -a -n=<PFN>` call works perfectly —
    resolved name, correct SID, persists. But `exempt_installed()` used to build ONE
    PowerShell script with a `foreach` loop calling this ~113 times back-to-back in
    the SAME process, capturing each call's output with `2>&1`. That pattern is what
    actually broke: every call still reported exit 0 (a genuine reading — a real
    failure, e.g. non-elevation, DOES surface as a non-zero exit, confirmed directly),
    yet the real exempt list ended up containing exactly one unresolvable entry —
    with the SAME fixed SID reproduced on two different machines (different Windows
    versions, different hardware, different installed packages). A value that
    doesn't vary with the real input isn't derived from it — it's an artifact of the
    rapid-fire loop + merged-stderr-redirection pattern itself. Calling the
    executable directly, once per invocation, with no PowerShell native-command
    interop in between, avoids that pattern entirely.

    Passed as an argv list (no shell involved), so package family names never need
    escaping — dots and underscores are ordinary argument characters."""
    try:
        r = subprocess.run(
            ["CheckNetIsolation.exe", *args],
            capture_output=True, text=True, creationflags=_NO_WINDOW, timeout=timeout)
        return (r.returncode, ((r.stdout or "") + (r.stderr or "")).strip())
    except Exception as e:
        return (-1, f"<command failed: {e}>")


# ── snapshot / list parsing ────────────────────────────────────────────────────

def _list_exempt() -> set:
    """Current loopback-exempt AppContainers, as a set of package family names.

    `CheckNetIsolation LoopbackExempt -s` output is a numbered block per entry, e.g.:
        [1] -----------------------------------------------------------------
        Name: microsoft.windowsstore_8wekyb3d8bbwe
        SID: S-1-15-2-...
    followed by a trailing "OK." — but an EARLIER version of this function anchored on
    that literal "Name:" label, and that turned out to be exactly the wrong thing to
    depend on: on a real dev machine (Windows 11 build 26200) it caused a silent, severe
    undercount — `exempt_installed()` reported "122 of 122" granted (every `-a` call
    genuinely exited 0) while a readback moments later via this function found only "1"
    exempt, because the label text this function was matching against didn't match what
    that build's `CheckNetIsolation` actually prints. Never re-anchor on label text again.

    Instead, scan the ENTIRE raw output for the package-family-name SHAPE itself
    (`_PFN_RE`: `<name>_<13-char publisher id>`) — that suffix format is a fixed Windows
    convention independent of whatever label/casing/table layout a given build's
    `CheckNetIsolation` chooses to print, and SID lines can't accidentally match it (they
    use hyphens, never an underscore)."""
    out = _ps("CheckNetIsolation LoopbackExempt -s")
    return set(_PFN_RE.findall(out))


def _installed_package_family_names() -> list:
    """Every installed package's PackageFamilyName, for the current user."""
    out = _ps(
        "Get-AppxPackage | Select-Object -ExpandProperty PackageFamilyName",
        timeout=30)
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


# ── backup file ────────────────────────────────────────────────────────────────

def _write_backup(snap: list):
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


# ── public API ──────────────────────────────────────────────────────────────────

def exempt_installed() -> "tuple[int, int]":
    """Grant a loopback exemption to every installed UWP package, so AppContainer
    apps (Microsoft Store, Mail, Xbox, …) can still reach the local proxy that the
    system-proxy takeover points them at. Snapshot-then-add, crash-safe like
    env_proxy.point_at: if a backup already exists (a prior run's takeover never
    restored), it is kept as the true original rather than overwritten.

    Safe to call repeatedly (e.g. a periodic re-sweep for apps installed mid-
    session) — already-exempt packages are simply skipped by CheckNetIsolation.

    Returns (added, total) — packages newly exempted this call, and the total
    number of installed packages considered. (0, 0) on failure.
    """
    try:
        pfns = _installed_package_family_names()
        if not pfns:
            return (0, 0)
        if _read_backup() is None:
            _write_backup(sorted(_list_exempt()))
        # ONE PROCESS PER PACKAGE, deliberately — see _checknetisolation's docstring
        # for why a single batched PowerShell script with an internal loop corrupts
        # the exemption list instead of populating it. Slower (~113 process spawns
        # instead of one script), but this is the pattern confirmed to actually work.
        added = 0
        for p in pfns:
            code, _ = _checknetisolation("LoopbackExempt", "-a", f"-n={p}")
            if code == 0:
                added += 1
        return (added, len(pfns))
    except Exception:
        return (0, 0)


def restore() -> bool:
    """Revoke exactly the loopback exemptions exempt_installed() added — packages
    exempt now but absent from the pre-takeover snapshot — then delete the backup.
    Never touches an exemption the user granted themselves outside ProxyForce.
    Idempotent: no backup -> no-op, returns False."""
    snap = _read_backup()
    if snap is None:
        return False
    try:
        original = set(snap)
        current = _list_exempt()
        added_by_us = current - original
        # Same one-process-per-package fix as exempt_installed() — a batched script
        # with an internal -d loop is the same suspect pattern, just in reverse.
        for p in sorted(added_by_us):
            _checknetisolation("LoopbackExempt", "-d", f"-n={p}")
    except Exception:
        pass
    _clear_backup()
    return True


def is_exempt(package_family_name: str) -> bool:
    """True if the given package family name currently holds a loopback exemption."""
    try:
        return package_family_name.strip().lower() in {n.lower() for n in _list_exempt()}
    except Exception:
        return False


def current_state() -> str:
    """One-line human-readable summary for diagnostics."""
    try:
        n = len(_list_exempt())
        return f"{n} package(s) loopback-exempt"
    except Exception as e:
        return f"<unavailable: {e}>"
