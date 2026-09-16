"""
ProxyForce — host-OS abstraction (the Windows/Linux seam).

WHY THIS EXISTS (v3.0.0):
  Every takeover in this codebase follows the same contract — snapshot the current
  state, write a crash-safe backup to the data directory BEFORE the first mutation,
  mutate, and restore exactly what was found on stop. That *policy* is identical on
  Windows and Linux; only the *mechanism* differs (registry vs files, UAC vs euid,
  Job Objects vs PDEATHSIG). This module owns the mechanism so every other module
  can keep its policy platform-free.

  Nothing here makes a decision. It answers "where does state live", "am I
  privileged", "how do I spawn a child quietly" — and lets the caller branch on
  IS_WINDOWS / IS_LINUX only where a genuine behavioural difference exists.

PLATFORM SUPPORT:
  Windows 10 22H2+ / Windows 11, and Linux with a kernel that has /dev/net/tun.
  Anything else imports fine (so the test suite collects everywhere) but
  is_supported() returns False and main.py refuses to start the engine.

DATA DIRECTORY:
  Windows: %ProgramData%\\ProxyForce   — machine-wide, admin-writable.
  Linux:   /var/lib/proxyforce         — machine-wide, root-writable (FHS state).
  Both are deliberately machine-scoped, not per-user: the engine runs elevated and
  a per-user directory would be invisible to it (see core/config_store).
"""

import os
import sys
import subprocess

IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")

# Suffix for executables we ship / look for (sing-box, keytool).
EXE_SUFFIX = ".exe" if IS_WINDOWS else ""

# CREATE_NO_WINDOW keeps helper processes from flashing a console on Windows.
# It does not exist on POSIX, and passing creationflags= there raises — so every
# subprocess call in this codebase goes through run()/popen_kwargs() instead of
# naming the flag directly.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0


def is_supported() -> bool:
    """True on a platform where the engine can actually run."""
    return IS_WINDOWS or IS_LINUX


def platform_name() -> str:
    return "windows" if IS_WINDOWS else ("linux" if IS_LINUX else sys.platform)


# ── paths ─────────────────────────────────────────────────────────────────────

def data_dir() -> str:
    """The machine-wide ProxyForce state directory (see the module docstring)."""
    if IS_WINDOWS:
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(base, "ProxyForce")
    return "/var/lib/proxyforce"


def runtime_dir() -> str:
    """Directory for the pid/lock file. Cleared on reboot on both platforms."""
    if IS_WINDOWS:
        return data_dir()
    return "/run" if os.path.isdir("/run") else "/tmp"


# ── subprocess ────────────────────────────────────────────────────────────────

def popen_kwargs(**extra) -> dict:
    """Keyword arguments for subprocess.Popen/run that hide the console on Windows
    and are a no-op elsewhere. Callers add their own stdout/stderr/timeout."""
    kw = dict(extra)
    if NO_WINDOW:
        kw["creationflags"] = NO_WINDOW
    return kw


def run(args, timeout=15, text=True, check=False):
    """subprocess.run with output captured and the console hidden. Never raises for
    an ordinary non-zero exit; a missing binary or a timeout surfaces as the
    exception the caller already handles."""
    return subprocess.run(args, capture_output=True, text=text, timeout=timeout,
                          check=check, **popen_kwargs())


def run_text(args, timeout=15) -> str:
    """Combined stdout+stderr of a helper command, or a '<...>' marker on failure.
    Best-effort by contract — diagnostics must never crash on a missing tool."""
    try:
        r = run(args, timeout=timeout)
        return ((r.stdout or "") + (r.stderr or "")).strip()
    except FileNotFoundError:
        return "<not installed: %s>" % args[0]
    except Exception as e:
        return "<command failed: %s>" % e


def which(name: str) -> str:
    """Absolute path of a helper binary on PATH, or '' — used to degrade
    gracefully on a distro that does not ship `ip`, `keytool`, `gsettings`, …"""
    import shutil
    return shutil.which(name) or ""


# ── privilege ─────────────────────────────────────────────────────────────────

def is_admin() -> bool:
    """True when this process can write machine-wide state and create a TUN."""
    if IS_WINDOWS:
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def can_self_elevate() -> bool:
    """Windows always can (UAC). Linux only when a graphical polkit agent is
    reachable — a headless box must be told to use sudo instead, which is strictly
    better than spawning a prompt nobody can answer."""
    if IS_WINDOWS:
        return True
    return bool(which("pkexec")) and bool(os.environ.get("DISPLAY")
                                          or os.environ.get("WAYLAND_DISPLAY"))


def relaunch_elevated(exe_path: str, args: list) -> bool:
    """Re-launch this program with privileges. Returns True if a relaunch was
    started (the caller then exits); False if elevation is not possible here.

    Windows: ShellExecuteW("runas") — the UAC prompt. Linux: pkexec, which shows
    the desktop's own polkit dialog. pkexec scrubs the environment by design, so
    DISPLAY/WAYLAND_DISPLAY/XAUTHORITY are passed through explicitly or the Tk
    window has no display to open on.
    """
    if IS_WINDOWS:
        import ctypes
        params = " ".join('"%s"' % a for a in args)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", exe_path, params, None, 1)
        return True
    if not can_self_elevate():
        return False
    passthrough = []
    for var in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR"):
        val = os.environ.get(var)
        if val:
            passthrough.append("%s=%s" % (var, val))
    try:
        subprocess.Popen(["pkexec", "env"] + passthrough + [exe_path] + list(args))
        return True
    except Exception:
        return False


def elevation_hint(exe_path: str) -> str:
    """What to tell the user when self-elevation is unavailable."""
    if IS_WINDOWS:
        return "Right-click ProxyForce.exe and choose 'Run as administrator'."
    return ("ProxyForce needs root to create the TUN interface and change "
            "system-wide settings. Run:\n\n    sudo %s\n\n"
            "(or enable the bundled systemd unit — see the README)." % exe_path)


# ── single instance ───────────────────────────────────────────────────────────

_INSTANCE_HANDLE = None     # kept alive for the process lifetime


def acquire_single_instance() -> bool:
    """True if this is the first instance. The handle/lock is intentionally kept in
    a module global: releasing it early would let a second instance start while
    this one is still running."""
    global _INSTANCE_HANDLE
    if IS_WINDOWS:
        import ctypes
        try:
            m = ctypes.windll.kernel32.CreateMutexW(
                None, True, "Global\\\\ProxyForce_SingleInst_v2")
            err = ctypes.windll.kernel32.GetLastError()
            if err == 183:          # ERROR_ALREADY_EXISTS
                ctypes.windll.kernel32.CloseHandle(m)
                return False
            _INSTANCE_HANDLE = m
            return True
        except Exception:
            return True             # assume first instance on any error
    # POSIX: an exclusive flock on a pid file. The kernel releases the lock when
    # the process dies however it dies, so a crash cannot wedge the app out of
    # starting again — which a bare "does the pid file exist" check would.
    import fcntl
    path = os.path.join(runtime_dir(), "proxyforce.pid")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fh = open(path, "a+")
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fh.seek(0)
        fh.truncate()
        fh.write(str(os.getpid()))
        fh.flush()
        _INSTANCE_HANDLE = fh
        return True
    except BlockingIOError:
        return False
    except Exception:
        return True


# ── user-visible message outside the GUI ──────────────────────────────────────

def message_box(title: str, text: str, error: bool = False):
    """Show a message before (or instead of) the GUI existing. Falls back to
    stderr wherever no display is available — a headless Linux run must still say
    why it refused to start."""
    if IS_WINDOWS:
        import ctypes
        try:
            ctypes.windll.user32.MessageBoxW(0, text, title, 0x10 if error else 0x40)
            return
        except Exception:
            pass
    else:
        try:
            import tkinter
            from tkinter import messagebox
            root = tkinter.Tk()
            root.withdraw()
            (messagebox.showerror if error else messagebox.showinfo)(title, text)
            root.destroy()
            return
        except Exception:
            pass
    print("%s: %s" % (title, text), file=sys.stderr)


# ── child-process lifetime ────────────────────────────────────────────────────

def kill_on_parent_death_preexec():
    """`preexec_fn` for Popen that makes the child die with us (Linux), or None on
    Windows where the Job Object in core/singbox_controller does the same job.

    This is the POSIX half of the crash-safety guarantee: if the GUI dies without
    calling stop(), sing-box must not be left holding a TUN up with the routing
    table hijacked and nothing running to restore it.
    """
    if IS_WINDOWS:
        return None

    def _preexec():
        import ctypes as _c
        import signal as _s
        try:
            _c.CDLL("libc.so.6", use_errno=True).prctl(1, _s.SIGKILL)  # PR_SET_PDEATHSIG
        except Exception:
            pass
        try:
            os.setpgrp()    # own process group, so a stray Ctrl-C can't race us
        except Exception:
            pass

    return _preexec
