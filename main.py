"""
ProxyForce v2.0 — Portable Single-Exe Launcher

No Windows service, no install step. Double-click ProxyForce.exe (approve UAC),
configure your proxy in Settings, and click Start. Close the window to minimize
to the system tray — enforcement runs until you Quit from the tray menu.

The elevated GUI owns and runs sing-box directly as a child subprocess.
A Windows Job Object ensures sing-box is killed if the GUI crashes.

Build:  pyinstaller proxyforce_onefile.spec  ->  dist\\ProxyForce.exe  (single file)
"""

import sys
import os
import ctypes
import json
import subprocess
import logging

APP_VERSION = "2.1.10"

# Global mutex handle — kept alive for the process lifetime to maintain the lock.
_SINGLE_INST_MUTEX = None


# ─── Paths ───────────────────────────────────────────────────────────────────

def get_data_dir() -> str:
    appdata = os.environ.get("ProgramData", "C:\\ProgramData")
    return os.path.join(appdata, "ProxyForce")


def get_exe_path() -> str:
    """Path of the current executable (works both frozen and from source)."""
    if getattr(sys, "frozen", False):
        return sys.executable
    return os.path.abspath(__file__)


# ─── Logging ─────────────────────────────────────────────────────────────────

def setup_logging():
    data_dir = get_data_dir()
    os.makedirs(data_dir, exist_ok=True)
    log_file = os.path.join(data_dir, "proxyforce.log")
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    return logging.getLogger("proxyforce.main")


# ─── Admin / UAC ─────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(extra_args: list = None):
    """Re-launch the current EXE elevated via the UAC prompt, then exit."""
    args   = sys.argv[1:] + (extra_args or [])
    params = " ".join(f'"{a}"' for a in args)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", get_exe_path(), params, None, 1)
    sys.exit(0)


# ─── Single-instance guard ────────────────────────────────────────────────────

def _acquire_single_instance() -> bool:
    """Return True if this is the first instance; False if one is already running."""
    global _SINGLE_INST_MUTEX
    try:
        m   = ctypes.windll.kernel32.CreateMutexW(
                  None, True, "Global\\\\ProxyForce_SingleInst_v2")
        err = ctypes.windll.kernel32.GetLastError()
        if err == 183:          # ERROR_ALREADY_EXISTS
            ctypes.windll.kernel32.CloseHandle(m)
            return False
        _SINGLE_INST_MUTEX = m  # keep the handle alive
        return True
    except Exception:
        return True             # assume first instance on any error


# ─── Build-machine smoke test ─────────────────────────────────────────────────

def run_selftest(logger):
    """Verify imports and the bundled sing-box. Exit 0 on pass, non-zero on fail."""
    print(f"ProxyForce v{APP_VERSION} selftest…")
    try:
        from core.singbox_controller import (
            SingBoxController, ProxyConfig, _find_singbox_exe, make_proxy_config)
        from core.config_store import load_config     # noqa: F401
        import urllib.request                         # noqa: F401
        print("[ok] imports (controller, config_store, urllib.request)")
    except Exception as e:
        print("[FAIL] import error:", e)
        sys.exit(2)

    sb = _find_singbox_exe()
    print("[..] sing-box.exe:", sb)
    if not sb or not os.path.isfile(sb):
        print("[FAIL] bundled sing-box.exe not found")
        sys.exit(3)

    try:
        ver = subprocess.run([sb, "version"], capture_output=True, text=True,
                             creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
        lines = (ver.stdout or "").splitlines()
        print("[ok] sing-box:", lines[0] if lines else "?")
    except Exception as e:
        print("[FAIL] could not run sing-box:", e)
        sys.exit(3)

    cfg      = ProxyConfig(host="203.0.113.10", port=800, auth_type="basic",
                           username="u", password="p",
                           bypass_list=["10.0.0.0/8", "intranet.local"])
    data     = SingBoxController(cfg)._render_config(12345)
    cfg_path = os.path.join(get_data_dir(), "selftest_config.json")
    os.makedirs(get_data_dir(), exist_ok=True)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    chk = subprocess.run([sb, "check", "-c", cfg_path],
                         capture_output=True, text=True,
                         creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
    msg = (chk.stderr or chk.stdout or "").strip()
    ok  = chk.returncode == 0
    print(f"[{'ok' if ok else 'FAIL'}] sing-box check rc={chk.returncode} "
          f"{msg[:300]}")
    print("SELFTEST RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 4)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    logger = setup_logging()

    # ── Build-machine smoke test (CI / offline build validation) ──
    if "--selftest" in sys.argv:
        run_selftest(logger)
        return

    # ── Elevation check first — non-admin launch just relaunches and exits.
    # The single-instance guard runs only in the elevated instance so it
    # doesn't race with the brief non-admin → admin handoff window.
    if not is_admin():
        relaunch_as_admin()
        return  # never reached (sys.exit inside relaunch_as_admin)

    # ── Single-instance guard (elevated instance only) ─────────────
    if not _acquire_single_instance():
        ctypes.windll.user32.MessageBoxW(
            0,
            "ProxyForce is already running.\n\nCheck the system tray icon.",
            "ProxyForce",
            0x40,   # MB_ICONINFORMATION
        )
        sys.exit(0)

    logger.info(f"ProxyForce v{APP_VERSION} starting (portable mode).")

    # ── Launch GUI (which owns and runs the sing-box engine directly) ──
    from gui.app import main as gui_main
    gui_main(start_minimized="--minimized" in sys.argv)


if __name__ == "__main__":
    main()
