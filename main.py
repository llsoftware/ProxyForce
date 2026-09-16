"""
ProxyForce v3 — portable launcher for Windows and Linux.

No install step required. Run the executable with privileges (approve UAC on
Windows, or use sudo / the polkit prompt on Linux), configure your proxy in
Settings, and click Start. Close the window to minimize to the system tray —
enforcement runs until you Quit from the tray menu.

The elevated GUI owns and runs sing-box directly as a child subprocess, and the
OS kills that child if the GUI dies without cleaning up (a Job Object on Windows,
PR_SET_PDEATHSIG on Linux — see core/hostos).

MODES
  (no flags)        the GUI.
  --minimized       the GUI, started in the tray. Used by Windows autostart.
  --headless        the engine with no GUI, until SIGTERM/SIGINT. This is what the
                    Linux systemd unit runs: a system service has no desktop
                    session to draw a window in, and needing one would have meant
                    a polkit prompt at every login. Works on Windows too, for a
                    box administered over SSH/WinRM.
  --selftest        build-machine smoke test.
  --apply-update    internal: the update worker (see core/updater).

Build:  pyinstaller proxyforce_onefile.spec         -> dist/ProxyForce/
        (onedir: the executable alongside its _internal/ folder — zip or tar the
        whole dist/ProxyForce/ folder to distribute)
"""

import sys
import os
import json
import signal
import subprocess
import logging
import threading
from logging.handlers import RotatingFileHandler

from core._version import __version__ as APP_VERSION
from core import hostos


# ─── Paths ───────────────────────────────────────────────────────────────────

def get_data_dir() -> str:
    return hostos.data_dir()


def get_exe_path() -> str:
    """Path of the current executable (works both frozen and from source)."""
    if getattr(sys, "frozen", False):
        return sys.executable
    return os.path.abspath(__file__)


# ─── Logging ─────────────────────────────────────────────────────────────────

def setup_logging(console: bool = False):
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # File logging is best-effort: never let a log-file problem (an unwritable
    # data directory, a locked file, a permissions issue) crash the launcher. The
    # app still runs and logs to nowhere if the handler can't be created.
    try:
        data_dir = get_data_dir()
        os.makedirs(data_dir, exist_ok=True)
        log_file = os.path.join(data_dir, "proxyforce.log")
        # Rotate so the app log can't grow without bound across long-running sessions.
        handler = RotatingFileHandler(
            log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        # Avoid stacking duplicate handlers if setup_logging() runs more than once.
        if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
            root.addHandler(handler)
    except Exception:
        pass
    if console and not any(isinstance(h, logging.StreamHandler)
                           and not isinstance(h, RotatingFileHandler)
                           for h in root.handlers):
        # Headless runs go to a terminal or the journal, where stdout is the log.
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        root.addHandler(sh)
    return logging.getLogger("proxyforce.main")


# ─── Privilege ───────────────────────────────────────────────────────────────

def is_admin() -> bool:
    return hostos.is_admin()


def relaunch_as_admin(extra_args: list = None):
    """Re-launch elevated, then exit. If the platform cannot raise its own
    privileges (a Linux box with no polkit agent, e.g. over SSH), say what to run
    instead rather than exiting silently — the old Windows-only path could always
    assume a UAC prompt was available."""
    args = sys.argv[1:] + (extra_args or [])
    if hostos.relaunch_elevated(get_exe_path(), args):
        sys.exit(0)
    hostos.message_box("ProxyForce", hostos.elevation_hint(get_exe_path()), error=True)
    sys.exit(1)


# ─── Build-machine smoke test ─────────────────────────────────────────────────

def run_selftest(logger):
    """Verify imports and the bundled sing-box. Exit 0 on pass, non-zero on fail."""
    print(f"ProxyForce v{APP_VERSION} selftest on {hostos.platform_name()}...")
    try:
        from core.singbox_controller import (
            SingBoxController, ProxyConfig, _find_singbox_exe, SINGBOX_EXE)
        from core.config_store import load_config     # noqa: F401
        import urllib.request                         # noqa: F401
        print("[ok] imports (controller, config_store, urllib.request)")
    except Exception as e:
        print("[FAIL] import error:", e)
        sys.exit(2)

    sb = _find_singbox_exe()
    print(f"[..] {SINGBOX_EXE}:", sb)
    if not sb or not os.path.isfile(sb):
        print(f"[FAIL] bundled {SINGBOX_EXE} not found")
        sys.exit(3)
    if not hostos.IS_WINDOWS and not os.access(sb, os.X_OK):
        print(f"[FAIL] {sb} is not executable (chmod +x it before packaging)")
        sys.exit(3)

    try:
        ver = hostos.run([sb, "version"], timeout=30)
        lines = (ver.stdout or "").splitlines()
        print("[ok] sing-box:", lines[0] if lines else "?")
    except Exception as e:
        print("[FAIL] could not run sing-box:", e)
        sys.exit(3)

    cfg      = ProxyConfig(host="203.0.113.10", port=800, auth_type="basic",
                           username="u", password="p",
                           bypass_list=["10.0.0.0/8", "intranet.local"])
    data     = SingBoxController(cfg)._render_config(12345)
    # Written into the data dir when we can, otherwise a temp dir — the selftest
    # runs on a build agent that may not be privileged, and refusing to validate
    # the config over a directory permission would defeat the point of the check.
    try:
        os.makedirs(get_data_dir(), exist_ok=True)
        cfg_path = os.path.join(get_data_dir(), "selftest_config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError:
        import tempfile
        cfg_path = os.path.join(tempfile.mkdtemp(), "selftest_config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    chk = hostos.run([sb, "check", "-c", cfg_path], timeout=30)
    msg = (chk.stderr or chk.stdout or "").strip()
    ok  = chk.returncode == 0
    print(f"[{'ok' if ok else 'FAIL'}] sing-box check rc={chk.returncode} "
          f"{msg[:300]}")
    print("SELFTEST RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 4)


# ─── Headless engine ─────────────────────────────────────────────────────────

def run_headless(logger):
    """Run the engine with no GUI until a termination signal arrives.

    This is the mode the Linux systemd unit uses. Shutdown is the important part:
    the engine holds the routing table, the desktop proxy setting, the environment
    variables and (with TLS inspection on) Java truststores, all of which must be
    handed back. SIGTERM — what `systemctl stop` sends — is therefore wired to the
    same stop() the GUI's Quit calls, and the process only exits once it returns.
    """
    from core.config_store import load_config, auth_config_warnings
    from core.singbox_controller import SingBoxController, make_proxy_config

    cfg = load_config()
    if not cfg.get("host"):
        logger.error("No proxy configured. Run ProxyForce's GUI once to set the "
                     "proxy host and port, or write %s.",
                     os.path.join(get_data_dir(), "config.json"))
        return 78    # EX_CONFIG
    for warning in auth_config_warnings(cfg):
        logger.warning(warning)

    stopped = threading.Event()
    controller = SingBoxController(
        make_proxy_config(cfg),
        on_state_change=lambda st: logger.info("state: %s", getattr(st, "value", st)),
        on_log=lambda msg, level="info": getattr(logger, level, logger.info)(msg),
    )

    def _shutdown(signum, _frame):
        logger.info("Signal %s received — stopping the engine and restoring the "
                    "system configuration.", signum)
        stopped.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _shutdown)
        except (ValueError, OSError):
            pass    # not available on this platform/thread; Ctrl-C still works

    logger.info("ProxyForce v%s starting headless (%s) -> %s:%s",
                APP_VERSION, hostos.platform_name(), cfg.get("host"), cfg.get("port"))
    controller.start()
    try:
        # A plain wait() ignores Ctrl-C on Windows, so tick instead.
        while not stopped.wait(1.0):
            pass
    finally:
        controller.stop()
        logger.info("ProxyForce stopped; system configuration restored.")
    return 0


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    headless = "--headless" in sys.argv
    logger = setup_logging(console=headless or "--selftest" in sys.argv)

    # ── Build-machine smoke test (CI / offline build validation) ──
    if "--selftest" in sys.argv:
        run_selftest(logger)
        return

    if not hostos.is_supported():
        hostos.message_box(
            "ProxyForce",
            f"ProxyForce supports Windows and Linux; this is {sys.platform}.",
            error=True)
        sys.exit(1)

    # ── Update apply-worker (spawned by the elevated GUI from the staged copy).
    # Must run elevated and must BYPASS the single-instance guard (the outgoing
    # instance still holds the lock until it exits, which this worker waits for).
    if "--apply-update" in sys.argv:
        if not is_admin():
            relaunch_as_admin()
            return
        from core import updater
        logger.info(f"ProxyForce v{APP_VERSION} apply-update worker starting.")
        updater.apply_worker(sys.argv[1:])
        return

    # ── Elevation check first — an unprivileged launch relaunches and exits.
    # The single-instance guard runs only in the elevated instance so it doesn't
    # race with the brief unprivileged -> elevated handoff window.
    if not is_admin():
        if headless:
            # A service that cannot elevate must fail loudly with a non-zero exit,
            # not spawn a prompt into a session that isn't there.
            logger.error("ProxyForce must run as root/Administrator. %s",
                         hostos.elevation_hint(get_exe_path()))
            sys.exit(1)
        relaunch_as_admin()
        return  # never reached (sys.exit inside relaunch_as_admin)

    # ── Single-instance guard (elevated instance only) ─────────────
    if not hostos.acquire_single_instance():
        msg = ("ProxyForce is already running.\n\nCheck the system tray icon."
               if not headless else "ProxyForce is already running.")
        if headless:
            logger.error(msg)
            sys.exit(1)
        hostos.message_box("ProxyForce", msg)
        sys.exit(0)

    logger.info(f"ProxyForce v{APP_VERSION} starting on {hostos.platform_name()} "
                f"(portable mode).")

    if headless:
        sys.exit(run_headless(logger))

    # ── If this launch is the relaunch after a self-update swap, prove as early as
    # possible that the new build reached here and holds the single-instance lock.
    # A waiting apply-update worker uses this "started" marker to tell "slow to boot"
    # apart from "dead" and extend its health-check budget accordingly — before the
    # GUI/CustomTkinter construction and update bookkeeping even begin.
    try:
        from core import updater
        txid = updater.load_state().get("transaction_id")
        if txid:
            updater.mark_update_started(txid)
    except Exception:
        pass

    # ── Launch GUI (which owns and runs the sing-box engine directly) ──
    from gui.app import main as gui_main
    gui_main(start_minimized="--minimized" in sys.argv)


if __name__ == "__main__":
    main()
