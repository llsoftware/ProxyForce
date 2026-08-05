"""
ProxyForce - Main GUI Application
Sidebar-navigation UI with light/dark theme support (CustomTkinter v2.0).
"""

import sys
import os
import math
import threading
import queue
import re
import time
from datetime import datetime
import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, ".."))

from core.config_store import load_config, save_config, save_autostart
from core.singbox_controller import SingBoxController, SingBoxState, make_proxy_config
from core import updater
from core._version import __version__ as _PF_VERSION

try:
    from PIL import Image
    from gui.icon_renderer import (
        LOGO_ACCENT, LOGO_BG, LOGO_R_CIRCLE, LOGO_R_HEX,
        STATE_COLORS, frame_count, render_logo,
    )
    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False
    LOGO_BG = (13, 15, 26)
    LOGO_ACCENT = (59, 130, 246)
    LOGO_R_CIRCLE = 0.42
    LOGO_R_HEX = 0.34
    STATE_COLORS = {
        "running": (52, 211, 153),
        "starting": (251, 191, 36),
        "stopping": (251, 191, 36),
        "error": (248, 113, 113),
        "stopped": (100, 116, 139),
        "waiting": (100, 116, 139),
    }

try:
    # ImageTk needs Pillow's Tk binding (_imagingtk); used for the canvas + window
    # icons. A separate guard so a missing binding can't also disable the tray.
    from PIL import ImageTk
    _HAS_IMAGETK = True
except Exception:
    _HAS_IMAGETK = False

try:
    import pystray
    _HAS_TRAY = _HAS_PIL          # the tray needs Pillow to render its icon
except ImportError:
    _HAS_TRAY = False

_APP_VERSION = _PF_VERSION
DATA_DIR    = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "ProxyForce")
SINGBOX_LOG = os.path.join(DATA_DIR, "singbox", "singbox.log")
_ANSI_RE    = re.compile(r"\x1b\[[0-9;]*m")
ANIM_INTERVAL_MS = 250  # sidebar pulse cadence while a state is animating (~4 fps)


# ── Palette ───────────────────────────────────────────────────────────────────
# Every value is a (light_hex, dark_hex) tuple accepted by CTk widgets.
# Raw-tk widgets use cc(key) to get the current-mode hex.
THEME = {
    "bg":         ("#F0F4FF", "#0F1117"),
    "surface":    ("#FFFFFF", "#1A1D27"),
    "sidebar":    ("#E2E8F5", "#0B0D14"),
    "card":       ("#FFFFFF", "#1E2130"),
    "card2":      ("#F4F7FF", "#252840"),
    "border":     ("#DDE3F0", "#2A2F45"),
    "nav_hover":  ("#D4DCF0", "#161924"),
    "nav_act":    ("#C8D2EC", "#1B1E2E"),
    "accent":     ("#2563EB", "#3B82F6"),
    "accent_dk":  ("#1D4ED8", "#2563EB"),
    "stop_bg":    ("#DC2626", "#7F1D1D"),
    "stop_hov":   ("#EF4444", "#F87171"),
    "green":      ("#059669", "#34D399"),
    "red":        ("#DC2626", "#F87171"),
    "yellow":     ("#B45309", "#FBBF24"),
    "text":       ("#1E293B", "#E2E8F0"),
    "muted":      ("#94A3B8", "#64748B"),
    "input_bg":   ("#F8FAFF", "#13151E"),
    # Hero card tints driven by proxy state
    "hero_run":   ("#EDFAF4", "#071C12"),
    "hero_err":   ("#FEF2F2", "#1C0707"),
    "hero_warn":  ("#FFFBEB", "#1C1307"),
}


def cc(key: str) -> str:
    """Return the current-mode hex for a theme key (for raw-tk widgets)."""
    mode = ctk.get_appearance_mode().lower()
    return THEME[key][0 if mode == "light" else 1]


# ── State → UI mapping ────────────────────────────────────────────────────────
# (label, color-key, hero-bg-key)
STATE_UI = {
    "running":  ("ACTIVE",    "green",  "hero_run"),
    "starting": ("STARTING…", "yellow", "hero_warn"),
    "stopping": ("STOPPING…", "yellow", "hero_warn"),
    "error":    ("ERROR",     "red",    "hero_err"),
    "stopped":  ("STOPPED",   "muted",  "card"),
    "waiting":  ("NO HOST",   "muted",  "card"),
}

LOG_COLOR_KEYS = {
    "info":    "text",
    "debug":   "muted",
    "error":   "red",
    "warning": "yellow",
    "success": "green",
}

_AUTH_DISPLAY  = {"none": "None", "basic": "Basic", "ntlm": "NTLM"}
_AUTH_INTERNAL = {v: k for k, v in _AUTH_DISPLAY.items()}

_APPEARANCE_MAP  = {"☀ Light": "light", "🖥 Auto": "system", "🌙 Dark": "dark"}
_APPEARANCE_RMAP = {v: k for k, v in _APPEARANCE_MAP.items()}

# sing-box log verbosity (must match core.singbox_controller._SINGBOX_LOG_LEVELS).
_LOGLEVEL_DISPLAY  = {"info": "Info", "debug": "Debug (verbose)", "warn": "Warnings only"}
_LOGLEVEL_INTERNAL = {v: k for k, v in _LOGLEVEL_DISPLAY.items()}


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar navigation button
# ─────────────────────────────────────────────────────────────────────────────
class _NavBtn:
    """Icon + label sidebar nav item with left accent bar and hover state."""

    def __init__(self, parent, icon: str, label: str, on_click):
        self._active   = False
        self._on_click = on_click

        self.f = ctk.CTkFrame(parent, fg_color="transparent",
                               corner_radius=6, cursor="hand2")
        # 3-px left accent bar (raw tk.Frame so we can color it exactly)
        self._bar = tk.Frame(self.f, width=3, bg=cc("sidebar"))
        self._bar.pack(side="left", fill="y")

        mid = ctk.CTkFrame(self.f, fg_color="transparent")
        mid.pack(side="left", fill="both", expand=True, padx=(10, 8), pady=9)

        self._ico = ctk.CTkLabel(mid, text=icon,
                                  font=ctk.CTkFont("Segoe UI", 15),
                                  text_color=THEME["muted"])
        self._ico.pack(side="left")

        self._lbl = ctk.CTkLabel(mid, text=label,
                                  font=ctk.CTkFont("Segoe UI", 11),
                                  text_color=THEME["muted"])
        self._lbl.pack(side="left", padx=10)

        for w in (self.f, mid, self._ico, self._lbl, self._bar):
            w.bind("<Button-1>", lambda e: self._on_click())
            w.bind("<Enter>",    lambda e: self._hover(True))
            w.bind("<Leave>",    lambda e: self._hover(False))

    def pack(self, **kw):
        self.f.pack(**kw)

    def _hover(self, on: bool):
        if not self._active:
            self.f.configure(fg_color=THEME["nav_hover"] if on else "transparent")

    def set_active(self, v: bool):
        self._active = v
        self.f.configure(fg_color=THEME["nav_act"] if v else "transparent")
        self._bar.configure(bg=cc("accent") if v else cc("sidebar"))
        col    = THEME["text"] if v else THEME["muted"]
        weight = "bold" if v else "normal"
        self._ico.configure(text_color=col)
        self._lbl.configure(text_color=col,
                             font=ctk.CTkFont("Segoe UI", 11, weight=weight))

    def repaint(self):
        self.set_active(self._active)


# ─────────────────────────────────────────────────────────────────────────────
# Stat card
# ─────────────────────────────────────────────────────────────────────────────
class StatCard(ctk.CTkFrame):
    def __init__(self, parent, label: str, initial: str = "0", **kwargs):
        super().__init__(parent, fg_color=THEME["card"],
                         corner_radius=10, border_width=1,
                         border_color=THEME["border"], **kwargs)
        self._accent_bar = tk.Frame(self, bg=cc("accent"), height=3)
        self._accent_bar.pack(fill="x")

        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=14, pady=12)

        self._val = ctk.CTkLabel(inner, text=initial,
                                  font=ctk.CTkFont("Segoe UI", 22, weight="bold"),
                                  text_color=THEME["accent"])
        self._val.pack(anchor="w")
        ctk.CTkLabel(inner, text=label.upper(),
                     font=ctk.CTkFont("Segoe UI", 9, weight="bold"),
                     text_color=THEME["muted"]).pack(anchor="w")

    def update_value(self, val: str):
        self._val.configure(text=val)

    def repaint_theme(self):
        self._accent_bar.configure(bg=cc("accent"))


# ─────────────────────────────────────────────────────────────────────────────
# Log panel
# ─────────────────────────────────────────────────────────────────────────────
class LogPanel(ctk.CTkFrame):
    _MAX_LINES = 2000  # keep long sessions from growing the Text widget unbounded

    def __init__(self, parent, title: str = "EVENT LOG", **kwargs):
        super().__init__(parent, fg_color=THEME["card"],
                         corner_radius=10, border_width=1,
                         border_color=THEME["border"], **kwargs)
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=14, pady=(10, 4))

        ctk.CTkLabel(hdr, text=title,
                     font=ctk.CTkFont("Consolas", 10, weight="bold"),
                     text_color=THEME["muted"]).pack(side="left")

        clr = ctk.CTkLabel(hdr, text="CLEAR",
                           font=ctk.CTkFont("Consolas", 10, weight="bold"),
                           text_color=THEME["muted"], cursor="hand2")
        clr.pack(side="right")
        clr.bind("<Button-1>", lambda e: self.clear())
        clr.bind("<Enter>",    lambda e: clr.configure(text_color=THEME["accent"]))
        clr.bind("<Leave>",    lambda e: clr.configure(text_color=THEME["muted"]))

        self._wrap = tk.Frame(self, bg=cc("input_bg"))
        self._wrap.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        self._text = tk.Text(
            self._wrap, bg=cc("input_bg"), fg=cc("text"),
            font=("Consolas", 9), relief="flat",
            padx=10, pady=8, state="disabled", wrap="word",
            insertbackground=cc("accent"),
            selectbackground=cc("border"))
        self._sb = tk.Scrollbar(
            self._wrap, command=self._text.yview,
            bg=cc("border"), troughcolor=cc("input_bg"),
            activebackground=cc("muted"))
        self._text.configure(yscrollcommand=self._sb.set)
        self._sb.pack(side="right", fill="y")
        self._text.pack(fill="both", expand=True)
        self._apply_tags()

    def _apply_tags(self):
        for level, key in LOG_COLOR_KEYS.items():
            self._text.tag_config(level, foreground=cc(key))
        self._text.tag_config("ts", foreground=cc("muted"))

    def log(self, msg: str, level: str = "info"):
        ts = time.strftime("%H:%M:%S")
        self._text.configure(state="normal")
        self._text.insert("end", f"[{ts}] ", "ts")
        self._text.insert("end", msg + "\n", level)
        overflow = int(self._text.index("end-1c").split(".")[0]) - self._MAX_LINES
        if overflow > 0:
            self._text.delete("1.0", f"{overflow + 1}.0")
        self._text.see("end")
        self._text.configure(state="disabled")

    def clear(self):
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.configure(state="disabled")

    def repaint_theme(self):
        ib = cc("input_bg")
        self._wrap.configure(bg=ib)
        self._text.configure(bg=ib, fg=cc("text"),
                             insertbackground=cc("accent"),
                             selectbackground=cc("border"))
        self._sb.configure(bg=cc("border"), troughcolor=ib,
                           activebackground=cc("muted"))
        self._apply_tags()


# ─────────────────────────────────────────────────────────────────────────────
# Settings panel
# ─────────────────────────────────────────────────────────────────────────────
class SettingsPanel(ctk.CTkScrollableFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color="transparent",
                         scrollbar_button_color=THEME["border"],
                         scrollbar_button_hover_color=THEME["muted"],
                         **kwargs)
        self._vars         = {}
        self._bypass_frame = None
        self._bypass_text  = None
        self._build()

    def _section(self, title: str) -> ctk.CTkFrame:
        wrap = ctk.CTkFrame(self, fg_color=THEME["card"], corner_radius=10,
                            border_width=1, border_color=THEME["border"])
        wrap.pack(fill="x", padx=4, pady=(0, 12))
        hdr = ctk.CTkFrame(wrap, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(14, 6))
        ctk.CTkLabel(hdr, text=title,
                     font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                     text_color=THEME["accent"]).pack(anchor="w")
        ctk.CTkFrame(wrap, fg_color=THEME["border"],
                     height=1, corner_radius=0).pack(fill="x", padx=16)
        body = ctk.CTkFrame(wrap, fg_color="transparent")
        body.pack(fill="x", padx=16, pady=(8, 16))
        return body

    def _lbl(self, parent, text: str):
        ctk.CTkLabel(parent, text=text.upper(),
                     font=ctk.CTkFont("Segoe UI", 9, weight="bold"),
                     text_color=THEME["muted"]).pack(anchor="w", pady=(10, 3))

    def _entry(self, parent, key: str, show: str = "", placeholder: str = ""):
        var = tk.StringVar()
        self._vars[key] = var
        ctk.CTkEntry(parent, textvariable=var,
                     placeholder_text=placeholder,
                     fg_color=THEME["input_bg"], border_color=THEME["border"],
                     border_width=1, text_color=THEME["text"],
                     placeholder_text_color=THEME["muted"],
                     show=show, corner_radius=6,
                     font=ctk.CTkFont("Segoe UI", 11)).pack(fill="x", ipady=4)
        return var

    def _check(self, parent, key: str, label: str):
        var = tk.BooleanVar()
        self._vars[key] = var
        ctk.CTkCheckBox(parent, text=label, variable=var,
                        fg_color=THEME["accent_dk"], hover_color=THEME["accent"],
                        checkmark_color=THEME["text"], text_color=THEME["text"],
                        font=ctk.CTkFont("Segoe UI", 10),
                        corner_radius=4).pack(anchor="w", pady=4)

    def _build(self):
        ctk.CTkFrame(self, fg_color="transparent", height=4).pack()

        s1 = self._section("PROXY SERVER")
        self._lbl(s1, "Hostname / IP")
        self._entry(s1, "host", placeholder="proxy.company.com")
        self._lbl(s1, "Port")
        self._entry(s1, "port", placeholder="8080")

        s2 = self._section("AUTHENTICATION")
        self._lbl(s2, "Auth Type")
        auth_var = tk.StringVar(value="None")
        self._vars["_auth_display"] = auth_var
        ctk.CTkSegmentedButton(
            s2, values=["None", "Basic", "NTLM"], variable=auth_var,
            fg_color=THEME["card2"], selected_color=THEME["accent_dk"],
            selected_hover_color=THEME["accent"], unselected_color=THEME["card2"],
            unselected_hover_color=THEME["border"], text_color=THEME["text"],
            font=ctk.CTkFont("Segoe UI", 10, weight="bold"),
            corner_radius=6,
        ).pack(anchor="w", pady=6)
        self._lbl(s2, "Username")
        self._entry(s2, "username", placeholder="domain\\user")
        self._lbl(s2, "Password")
        self._entry(s2, "password", show="●", placeholder="●●●●●●●●")

        s3 = self._section("TRAFFIC RULES")
        self._check(s3, "exclude_private",
                    "Bypass private IP ranges (RFC1918 / ULA / link-local)")
        self._check(s3, "exclude_loopback", "Bypass loopback (127.x / ::1)")
        self._lbl(s3, "Bypass List  —  one entry per line, CIDR or hostname")
        self._bypass_frame = tk.Frame(s3, bg=cc("input_bg"))
        self._bypass_frame.pack(fill="x", pady=(0, 4))
        self._bypass_text = tk.Text(
            self._bypass_frame, bg=cc("input_bg"), fg=cc("text"),
            insertbackground=cc("accent"), selectbackground=cc("border"),
            relief="flat", font=("Consolas", 10), height=4, padx=10, pady=8)
        self._bypass_text.pack(fill="x")

        s4 = self._section("APP OPTIONS")
        self._check(s4, "autostart",       "Launch & connect at logon  (runs elevated, no prompt)")
        self._check(s4, "start_minimized", "Start minimized to system tray")
        self._lbl(s4, "Engine log level  —  Debug is verbose (larger logs)")
        loglvl_var = tk.StringVar(value=_LOGLEVEL_DISPLAY["info"])
        self._vars["_loglevel_display"] = loglvl_var
        ctk.CTkOptionMenu(
            s4, values=list(_LOGLEVEL_DISPLAY.values()), variable=loglvl_var, width=180,
            fg_color=THEME["input_bg"], button_color=THEME["accent_dk"],
            button_hover_color=THEME["accent"], text_color=THEME["text"],
            font=ctk.CTkFont("Segoe UI", 11), corner_radius=6,
        ).pack(anchor="w", pady=4)

        s5 = self._section("UPDATES")
        self._lbl(s5, "Update Channel")
        chan_var = tk.StringVar(value="Stable")
        self._vars["_channel_display"] = chan_var
        ctk.CTkSegmentedButton(
            s5, values=["Stable", "Development"], variable=chan_var,
            fg_color=THEME["card2"], selected_color=THEME["accent_dk"],
            selected_hover_color=THEME["accent"], unselected_color=THEME["card2"],
            unselected_hover_color=THEME["border"], text_color=THEME["text"],
            font=ctk.CTkFont("Segoe UI", 10, weight="bold"), corner_radius=6,
        ).pack(anchor="w", pady=6)
        self._check(s5, "auto_update_check", "Check for updates nightly (in the background)")
        self._lbl(s5, "Nightly check / install hour (local, 0–23)")
        hour_var = tk.StringVar(value="3")
        self._vars["update_hour"] = hour_var
        ctk.CTkOptionMenu(
            s5, values=[str(h) for h in range(24)], variable=hour_var, width=80,
            fg_color=THEME["input_bg"], button_color=THEME["accent_dk"],
            button_hover_color=THEME["accent"], text_color=THEME["text"],
            font=ctk.CTkFont("Segoe UI", 11), corner_radius=6,
        ).pack(anchor="w", pady=4)
        self._upd_status = ctk.CTkLabel(
            s5, text=f"ProxyForce v{_APP_VERSION}",
            font=ctk.CTkFont("Segoe UI", 10), text_color=THEME["muted"])
        self._upd_status.pack(anchor="w", pady=(12, 2))
        self._upd_progress = ctk.CTkProgressBar(s5, height=8, corner_radius=4,
                                                progress_color=THEME["accent"])
        self._upd_progress.set(0)
        # packed on demand by set_update_progress()

        ctk.CTkFrame(self, fg_color="transparent", height=8).pack()

    def get_values(self) -> dict:
        d = {}
        for k, v in self._vars.items():
            if k == "_auth_display":
                d["auth_type"] = _AUTH_INTERNAL.get(v.get(), "none")
            elif k == "_channel_display":
                d["update_channel"] = "dev" if v.get() == "Development" else "stable"
            elif k == "_loglevel_display":
                d["log_level"] = _LOGLEVEL_INTERNAL.get(v.get(), "info")
            else:
                d[k] = v.get()
        try:
            d["port"] = int(d.get("port", 8080))
        except (ValueError, TypeError):
            d["port"] = 8080
        try:
            d["update_hour"] = max(0, min(23, int(d.get("update_hour", 3))))
        except (ValueError, TypeError):
            d["update_hour"] = 3
        raw = self._bypass_text.get("1.0", "end").strip() if self._bypass_text else ""
        d["bypass_list"] = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        return d

    def set_values(self, d: dict):
        for k, var in self._vars.items():
            if k == "_auth_display":
                var.set(_AUTH_DISPLAY.get(str(d.get("auth_type", "none")).lower(), "None"))
            elif k == "_channel_display":
                var.set("Development" if str(d.get("update_channel", "stable")).lower() == "dev"
                        else "Stable")
            elif k == "_loglevel_display":
                var.set(_LOGLEVEL_DISPLAY.get(str(d.get("log_level", "info")).lower(),
                                              _LOGLEVEL_DISPLAY["info"]))
            elif k in d:
                var.set(d[k])
        if "bypass_list" in d and self._bypass_text:
            self._bypass_text.delete("1.0", "end")
            self._bypass_text.insert("1.0", "\n".join(d["bypass_list"]))

    def set_update_status(self, text: str, color: str = None):
        lbl = getattr(self, "_upd_status", None)
        if lbl:
            lbl.configure(text=text, text_color=color or THEME["muted"])

    def set_update_progress(self, frac):
        """frac in [0,1] shows/updates the bar; None hides it."""
        bar = getattr(self, "_upd_progress", None)
        if not bar:
            return
        if frac is None or frac < 0:
            bar.pack_forget()
        else:
            if not bar.winfo_manager():
                bar.pack(fill="x", pady=(2, 6))
            bar.set(max(0.0, min(1.0, float(frac))))

    def repaint_theme(self):
        ib = cc("input_bg")
        if self._bypass_frame:
            self._bypass_frame.configure(bg=ib)
        if self._bypass_text:
            self._bypass_text.configure(bg=ib, fg=cc("text"),
                                        insertbackground=cc("accent"),
                                        selectbackground=cc("border"))


# ─────────────────────────────────────────────────────────────────────────────
# Main application window
# ─────────────────────────────────────────────────────────────────────────────
class ProxyForceApp(ctk.CTk):

    def __init__(self, start_minimized: bool = False):
        # Give Windows an explicit app identity so the taskbar shows OUR icon and
        # groups under "ProxyForce" rather than the generic Python host.
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "ProxyForce.App")
        except Exception:
            pass

        super().__init__()
        self.title("ProxyForce")
        self.geometry("960x660")
        self.minsize(780, 520)
        self.configure(fg_color=THEME["bg"])
        self._set_window_icon()
        # Re-apply shortly after startup — CustomTkinter can reset the icon while
        # it finishes building the window. (A blanket <Map> rebind was tried here
        # previously to also cover tray-restore/un-minimize, but it backfires
        # badly: _set_window_icon()'s wm_iconbitmap() reset perturbs window state
        # enough that the next nested update_idletasks() call — CTk widgets like
        # CTkOptionMenu/CTkScrollbar issue plenty of those while building —
        # re-delivers <Map> and re-enters _set_window_icon(), cascading into
        # ~140 synchronous re-entries during __init__ alone (measured), plus
        # another burst on every later map event. See _tray_show() for the
        # one-shot alternative that actually covers restore-from-tray.)
        self.after(400, self._set_window_icon)

        self._queue      = queue.Queue()
        self._last_state = "stopped"
        self._updates_busy = False
        self._icon_frame = 0
        self._anim_active = False   # True only while the pulse loop is alive
        self._icon_photo_cache = {}
        self._icon_pil_cache = {}
        self._engine: SingBoxController | None = None
        self._running    = True
        self._cur_page   = "dashboard"

        try:
            self._sb_log_pos = (os.path.getsize(SINGBOX_LOG)
                                if os.path.exists(SINGBOX_LOG) else 0)
        except Exception:
            self._sb_log_pos = 0

        # Apply saved appearance before widgets are built
        cfg = load_config()
        ctk.set_appearance_mode(cfg.get("appearance", "system"))

        self._build_topbar()
        self._build_body()
        self._load_and_apply_config()
        self._nav("dashboard")

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_queue()
        self._poll_singbox_log()

        if _HAS_TRAY:
            self._setup_tray()
        self._start_status_animation()

        # Auto-update: nightly background check timer + reconnect after an update swap.
        threading.Thread(target=self._update_timer_loop, daemon=True).start()
        self.after(1200, self._maybe_resume_after_update)
        # Auto-connect on launch when a proxy host is configured (so an unattended
        # box comes up connected without a Start click). Scheduled AFTER the
        # update-resume check so it no-ops if that already started the engine.
        self.after(1500, self._auto_start_if_configured)

        if start_minimized:
            self.withdraw()

    # ── Icon helpers ──────────────────────────────────────────────────────────

    def _draw_icon(self, canvas: tk.Canvas, bg_key: str = "sidebar"):
        """Paint the current state frame into the sidebar."""
        canvas.delete("all")
        canvas.configure(bg=cc(bg_key))
        s  = int(canvas["width"])
        cx = cy = s / 2
        if _HAS_IMAGETK:
            frames = self._status_photo_frames(s, self._last_state, transparent=True)
            photo = frames[self._icon_frame % len(frames)]
            canvas.create_image(cx, cy, image=photo)
            return
        # Static vector fallback for an installation missing Pillow's Tk binding.
        # No dark backing disc here either — the canvas bg (set above) already
        # matches the sidebar theme color.
        hr   = s * LOGO_R_HEX
        points = [
            (cx + hr * math.cos(math.radians(60 * i - 90)),
             cy + hr * math.sin(math.radians(60 * i - 90)))
            for i in range(6)
        ]
        flat = [v for point in points for v in point]
        canvas.create_polygon(*flat, fill="#%02x%02x%02x" % LOGO_ACCENT,
                              outline="")
        inner = STATE_COLORS.get(self._last_state, STATE_COLORS["stopped"])
        ri = hr * 0.26
        canvas.create_oval(cx - ri, cy - ri, cx + ri, cy + ri,
                           fill="#%02x%02x%02x" % inner, outline="")

    def _make_tray_image(self):
        """Initial system-tray image; subsequent frames are state-aware."""
        return self._status_pil_frames(64, self._last_state)[0]

    def _status_pil_frames(self, size: int, state: str, transparent: bool = False):
        key = (size, state, transparent)
        frames = self._icon_pil_cache.get(key)
        if frames is None:
            count = frame_count(state)
            frames = [
                render_logo(size, state, i / count, animated=count > 1,
                            bg_circle=not transparent)
                for i in range(count)
            ]
            self._icon_pil_cache[key] = frames
        return frames

    def _status_photo_frames(self, size: int, state: str, transparent: bool = False):
        key = (size, state, transparent)
        frames = self._icon_photo_cache.get(key)
        if frames is None:
            frames = [ImageTk.PhotoImage(img)
                      for img in self._status_pil_frames(size, state, transparent)]
            self._icon_photo_cache[key] = frames
        return frames

    def _animate_status_icon(self):
        """Advance the sidebar mark at a low-cost ~4 fps, self-terminating the
        instant the state stops animating instead of looping forever. The tray
        icon is NOT touched here — pystray re-serializes the image to a temp
        .ico file and round-trips it through Win32 LoadImage on every
        assignment, so doing that repeatedly (even for a static single-frame
        state) was pegging the main thread and made the whole UI feel laggy.
        The tray only updates once per actual state change, via
        _update_tray_icon()."""
        if not (self._running and _HAS_IMAGETK
                and frame_count(self._last_state) > 1):
            self._anim_active = False  # nothing to animate — let the loop die
            return
        self._icon_frame += 1
        self._draw_icon(self._icon_canvas, "sidebar")
        self.after(ANIM_INTERVAL_MS, self._animate_status_icon)

    def _start_status_animation(self):
        """Arm the pulse loop, but only if it isn't already running and the
        current state actually has more than one frame. Idle/static states
        (stopped, waiting) never start a timer at all — previously the
        animation loop rescheduled itself forever even at rest, as a
        perpetual no-op."""
        if self._anim_active:
            return
        if self._running and _HAS_IMAGETK and frame_count(self._last_state) > 1:
            self._anim_active = True
            self._animate_status_icon()

    def _update_tray_icon(self):
        """Push a single static frame for the current state to the tray."""
        tray = getattr(self, "_tray", None)
        if tray is None:
            return
        try:
            tray.icon = self._status_pil_frames(64, self._last_state)[0]
        except Exception:
            pass

    def _set_window_icon(self):
        """Set the titlebar / taskbar icon to the canonical badge.

        Tkinter does NOT inherit the executable's embedded icon for the window —
        without this the window shows the default Tk feather, which is why the
        taskbar icon never matched the tray and Explorer icons. iconphoto with
        several sizes from the canonical renderer guarantees they match.

        CustomTkinter schedules its own titlebar-icon reset shortly after a
        window is created, which silently overwrites iconphoto with CTk's own
        default (blue) mark — the bare wm_iconbitmap() call resets the native
        icon slot so the following iconphoto() sticks. Called once at startup
        plus once more 400ms later (CTk's own reset can land in between), and
        once more on tray-restore via _tray_show(). Deliberately NOT bound to
        <Map> in general: wm_iconbitmap()'s own state change is enough to get
        re-delivered through CTk widgets' internal update_idletasks() calls
        (CTkOptionMenu/CTkScrollbar issue plenty while building), so a <Map>
        binding here cascades into itself — measured at ~140 synchronous
        re-entries during __init__ alone, before the window is even shown.
        The PhotoImage set itself is built once and cached — same six sizes
        every time.
        """
        if not _HAS_IMAGETK:
            return
        try:
            icons = getattr(self, "_win_icons", None)
            if icons is None:
                icons = self._win_icons = [ImageTk.PhotoImage(
                                   render_logo(s, state="neutral", animated=False))
                                   for s in (256, 64, 48, 32, 20, 16)]
            self.wm_iconbitmap()
            self.iconphoto(True, *self._win_icons)
        except Exception:
            pass

    # ── Top bar ───────────────────────────────────────────────────────────────

    def _build_topbar(self):
        bar = ctk.CTkFrame(self, fg_color=THEME["surface"],
                           corner_radius=0, height=52)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        # Left: current page title
        self._page_title = ctk.CTkLabel(
            bar, text="Dashboard",
            font=ctk.CTkFont("Segoe UI", 14, weight="bold"),
            text_color=THEME["text"])
        self._page_title.pack(side="left", padx=20)

        # Right: start/stop + theme toggle
        ctrl = ctk.CTkFrame(bar, fg_color="transparent")
        ctrl.pack(side="right", padx=16)

        self._toggle_btn = ctk.CTkButton(
            ctrl, text="▶  START",
            command=self._toggle,
            fg_color=THEME["accent_dk"], hover_color=THEME["accent"],
            text_color=("#FFFFFF", "#FFFFFF"),
            font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
            corner_radius=8, width=140, height=36)
        self._toggle_btn.pack(side="right", padx=(8, 0))

        cur_mode  = ctk.get_appearance_mode().lower()
        cur_label = _APPEARANCE_RMAP.get(cur_mode, "🖥 Auto")
        self._theme_var = tk.StringVar(value=cur_label)
        ctk.CTkSegmentedButton(
            ctrl,
            values=list(_APPEARANCE_MAP.keys()),
            variable=self._theme_var,
            command=self._on_theme_change,
            fg_color=THEME["card2"],
            selected_color=THEME["accent_dk"],
            selected_hover_color=THEME["accent"],
            unselected_color=THEME["card2"],
            unselected_hover_color=THEME["border"],
            text_color=THEME["text"],
            font=ctk.CTkFont("Segoe UI", 10),
            corner_radius=8, height=32,
        ).pack(side="right")

        # Center-right: textual status; the animated mark lives in the sidebar.
        status_f = ctk.CTkFrame(bar, fg_color="transparent")
        status_f.pack(side="right", padx=28)

        self._status_lbl = ctk.CTkLabel(
            status_f, text="STOPPED",
            font=ctk.CTkFont("Segoe UI", 10, weight="bold"),
            text_color=THEME["muted"])
        self._status_lbl.pack(side="left", padx=6)

    # ── Body = sidebar + content ──────────────────────────────────────────────

    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        body.pack(fill="both", expand=True)
        self._build_sidebar(body)
        self._build_content(body)

    def _build_sidebar(self, body):
        sb = ctk.CTkFrame(body, fg_color=THEME["sidebar"],
                          width=148, corner_radius=0)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)
        self._sidebar = sb

        # Logo
        logo_f = ctk.CTkFrame(sb, fg_color="transparent")
        logo_f.pack(fill="x", padx=14, pady=(18, 4))

        self._icon_canvas = tk.Canvas(logo_f, width=46, height=46,
                                      bg=cc("sidebar"), highlightthickness=0)
        self._icon_canvas.pack(side="left")
        self._draw_icon(self._icon_canvas, "sidebar")

        ctk.CTkLabel(logo_f, text="ProxyForce",
                     font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                     text_color=THEME["text"]).pack(side="left", padx=7)

        ctk.CTkLabel(sb, text=f"v{_APP_VERSION}",
                     font=ctk.CTkFont("Segoe UI", 8),
                     text_color=THEME["muted"]).pack(anchor="w", padx=14, pady=(0, 10))

        # Divider
        ctk.CTkFrame(sb, fg_color=THEME["border"],
                     height=1, corner_radius=0).pack(fill="x")
        ctk.CTkFrame(sb, fg_color="transparent", height=6).pack()

        # Nav buttons
        self._nav_btns = {}
        for key, icon, label in [
            ("dashboard", "⬡", "Dashboard"),
            ("settings",  "⚙", "Settings"),
            ("log",       "☰", "Log"),
        ]:
            btn = _NavBtn(sb, icon, label, lambda k=key: self._nav(k))
            btn.pack(fill="x", padx=8, pady=2)
            self._nav_btns[key] = btn

    def _build_content(self, body):
        self._content = ctk.CTkFrame(body, fg_color=THEME["bg"], corner_radius=0)
        self._content.pack(side="left", fill="both", expand=True)

        self._pg_dashboard = ctk.CTkFrame(self._content,
                                          fg_color=THEME["bg"], corner_radius=0)
        self._pg_settings  = ctk.CTkFrame(self._content,
                                          fg_color=THEME["bg"], corner_radius=0)
        self._pg_log       = ctk.CTkFrame(self._content,
                                          fg_color=THEME["bg"], corner_radius=0)

        self._build_dashboard(self._pg_dashboard)
        self._build_settings(self._pg_settings)
        self._build_log(self._pg_log)

    # ── Navigation ────────────────────────────────────────────────────────────

    def _nav(self, key: str):
        self._cur_page = key
        titles = {"dashboard": "Dashboard", "settings": "Settings", "log": "Log"}
        self._page_title.configure(text=titles.get(key, key.capitalize()))

        for k, btn in self._nav_btns.items():
            btn.set_active(k == key)

        for pg in (self._pg_dashboard, self._pg_settings, self._pg_log):
            pg.pack_forget()

        {"dashboard": self._pg_dashboard,
         "settings":  self._pg_settings,
         "log":       self._pg_log}[key].pack(fill="both", expand=True)

    # ── Dashboard ─────────────────────────────────────────────────────────────

    def _build_dashboard(self, parent):
        # Hero status card — bg tints green/red/yellow with proxy state
        self._hero_card = ctk.CTkFrame(parent, fg_color=THEME["card"],
                                       corner_radius=12, border_width=1,
                                       border_color=THEME["border"])
        self._hero_card.pack(fill="x", padx=20, pady=(14, 10))

        hero_inner = ctk.CTkFrame(self._hero_card, fg_color="transparent")
        hero_inner.pack(fill="x", padx=24, pady=20)

        info = ctk.CTkFrame(hero_inner, fg_color="transparent")
        info.pack(side="left")

        self._hero_lbl = ctk.CTkLabel(
            info, text="STOPPED",
            font=ctk.CTkFont("Segoe UI", 24, weight="bold"),
            text_color=THEME["muted"])
        self._hero_lbl.pack(anchor="w")

        self._proxy_info_var = tk.StringVar(value="No proxy configured")
        self._proxy_info_lbl = ctk.CTkLabel(
            info, textvariable=self._proxy_info_var,
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=THEME["muted"])
        self._proxy_info_lbl.pack(anchor="w", pady=(2, 0))

        self._uptime_var = tk.StringVar(value="")
        ctk.CTkLabel(info, textvariable=self._uptime_var,
                     font=ctk.CTkFont("Segoe UI", 10),
                     text_color=THEME["muted"]).pack(anchor="w")

        # Stats row
        stats = ctk.CTkFrame(parent, fg_color="transparent")
        stats.pack(fill="x", padx=20, pady=(0, 10))

        self._card_active = StatCard(stats, "Active",    "0")
        self._card_total  = StatCard(stats, "Total",     "0")
        self._card_bytes  = StatCard(stats, "Forwarded", "0 B")
        self._card_uptime = StatCard(stats, "Uptime",    "00:00:00")

        for c in (self._card_active, self._card_total, self._card_bytes,
                  self._card_uptime):
            c.pack(side="left", fill="both", expand=True, padx=4)

        # Event log
        self._dash_log = LogPanel(parent)
        self._dash_log.pack(fill="both", expand=True, padx=20, pady=(0, 14))

    # ── Settings ──────────────────────────────────────────────────────────────

    def _build_settings(self, parent):
        self._settings_panel = SettingsPanel(parent)
        self._settings_panel.pack(fill="both", expand=True, padx=16, pady=(8, 0))

        btn_row = ctk.CTkFrame(parent, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=12)

        self._btn_check_updates = ctk.CTkButton(
                      btn_row, text="CHECK FOR UPDATES",
                      command=lambda: self._check_for_updates(manual=True),
                      fg_color=THEME["card2"], hover_color=THEME["border"],
                      text_color=THEME["text"], border_width=1,
                      border_color=THEME["border"],
                      font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                      corner_radius=8, width=180, height=38)
        self._btn_check_updates.pack(side="left", padx=4)

        ctk.CTkButton(btn_row, text="TEST PROXY",
                      command=self._test_proxy,
                      fg_color=THEME["card2"], hover_color=THEME["border"],
                      text_color=THEME["text"], border_width=1,
                      border_color=THEME["border"],
                      font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                      corner_radius=8, width=140, height=38
                      ).pack(side="right", padx=4)

        ctk.CTkButton(btn_row, text="SAVE CONFIG",
                      command=self._save_config,
                      fg_color=THEME["accent_dk"], hover_color=THEME["accent"],
                      text_color=("#FFFFFF", "#FFFFFF"),
                      font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
                      corner_radius=8, width=150, height=38
                      ).pack(side="right", padx=4)

    # ── Log page ──────────────────────────────────────────────────────────────

    def _build_log(self, parent):
        self._full_log = LogPanel(parent, title="SING-BOX LOG")
        self._full_log.pack(fill="both", expand=True, padx=20, pady=16)

    # ── Config ────────────────────────────────────────────────────────────────

    def _load_and_apply_config(self):
        cfg = load_config()
        self._settings_panel.set_values(cfg)
        if cfg.get("host"):
            auth     = cfg.get("auth_type", "none")
            auth_str = f"  [{auth.upper()}]" if auth != "none" else ""
            self._proxy_info_var.set(f"→ {cfg['host']}:{cfg['port']}{auth_str}")
        mode_label = _APPEARANCE_RMAP.get(cfg.get("appearance", "system"), "🖥 Auto")
        self._theme_var.set(mode_label)

    def _save_config(self):
        vals = self._settings_panel.get_values()
        vals["appearance"] = _APPEARANCE_MAP.get(self._theme_var.get(), "system")
        if not save_config(vals):
            messagebox.showerror("ProxyForce",
                "Could not save configuration.\nRun ProxyForce as administrator.")
            self._log("Config save FAILED.", "error")
            return
        try:
            save_autostart(bool(vals.get("autostart")), sys.executable)
        except Exception:
            pass
        auth     = vals.get("auth_type", "none")
        auth_str = f"  [{auth.upper()}]" if auth != "none" else ""
        self._proxy_info_var.set(f"→ {vals['host']}:{vals['port']}{auth_str}")
        self._log("Configuration saved.", "success")

        # Apply changes live: if a proxy-affecting field changed while the engine is
        # running, restart it so sing-box re-renders config.json with the new rules
        # (e.g. a freshly added bypass entry). sing-box has no hot-reload, so a
        # restart is the reliable path — the same brief-disconnect model the updater
        # uses. Cosmetic-only saves (theme, minimized, update options) don't restart.
        if (self._last_state in ("running", "waiting", "starting")
                and self._proxy_settings_changed(vals)):
            self._log("Applying updated settings — reconnecting…", "info")
            self._start_engine()

    # Proxy-affecting fields; a change to any of these while connected warrants an
    # engine restart. Cosmetic/app fields (appearance, start_minimized, autostart,
    # update_*) are intentionally excluded so they never cause a disconnect.
    _PROXY_FIELDS = ("host", "port", "auth_type", "username", "password",
                     "exclude_private", "exclude_loopback", "bypass_list",
                     "log_level")

    def _proxy_settings_changed(self, vals: dict) -> bool:
        """True if any proxy-affecting field in `vals` differs from the config the
        currently-running engine was started with."""
        eng = self._engine
        if eng is None:
            return False
        new_cfg = make_proxy_config(vals)
        cur_cfg = eng.config
        return any(getattr(new_cfg, f) != getattr(cur_cfg, f)
                   for f in self._PROXY_FIELDS)

    # ── Engine control ────────────────────────────────────────────────────────

    def _toggle(self):
        if self._last_state in ("running", "waiting", "starting", "stopping"):
            self._stop_engine()
        else:
            self._start_engine()

    def _start_engine(self):
        vals = self._settings_panel.get_values()
        if not vals.get("host"):
            messagebox.showerror("ProxyForce",
                "Configure a proxy host in Settings first.")
            self._nav("settings")
            return
        if not save_config(vals):
            messagebox.showerror("ProxyForce",
                "Could not save configuration.\nRun ProxyForce as administrator.")
            self._log("Config save FAILED.", "error")
            return
        auth     = vals.get("auth_type", "none")
        auth_str = f"  [{auth.upper()}]" if auth != "none" else ""
        self._proxy_info_var.set(f"→ {vals['host']}:{vals['port']}{auth_str}")
        self._log("Starting ProxyForce engine…", "info")
        self._apply_state("starting")

        def work():
            try:
                if self._engine is not None:
                    old = self._engine
                    self._engine = None
                    old.stop()

                def on_state(s):
                    self._queue.put(("state", getattr(s, "value", str(s))))

                def on_stats(st):
                    self._queue.put(("stats", st))

                def on_log(m, l):
                    self._queue.put(("log", m, l))

                proxy_cfg    = make_proxy_config(vals)
                engine       = SingBoxController(proxy_cfg,
                                                  on_state_change=on_state,
                                                  on_stats_update=on_stats,
                                                  on_log=on_log)
                self._engine  = engine
                engine.start()
            except Exception as e:
                self._queue.put(("log", f"Failed to start engine: {e}", "error"))
                self._queue.put(("state", "error"))

        threading.Thread(target=work, daemon=True).start()

    def _stop_engine(self):
        self._log("Stopping ProxyForce engine…", "info")
        self._apply_state("stopping")

        def work():
            eng = self._engine
            if eng is not None:
                eng.stop()

        threading.Thread(target=work, daemon=True).start()

    # ── Proxy test ────────────────────────────────────────────────────────────

    def _test_proxy(self):
        import socket
        vals = self._settings_panel.get_values()
        if not vals.get("host"):
            messagebox.showwarning("ProxyForce",
                "Enter a proxy host in Settings first.")
            return
        self._log(f"Testing {vals['host']}:{vals['port']}…", "info")

        def do_test():
            try:
                s = socket.create_connection(
                    (vals["host"], int(vals["port"])), timeout=5)
                s.close()
                self._queue.put(("log",
                    f"✓ Proxy reachable at {vals['host']}:{vals['port']}",
                    "success"))
            except Exception as e:
                self._queue.put(("log", f"✗ Cannot reach proxy: {e}", "error"))

        threading.Thread(target=do_test, daemon=True).start()

    # ── Updates ───────────────────────────────────────────────────────────────

    def _pending_staged(self):
        """Return a pending protected transaction; never trust a persisted path."""
        st = updater.load_state()
        tag, txid = st.get("staged_tag"), st.get("transaction_id")
        # A build that has already failed and been rolled back 3 times is not
        # going to succeed on a 4th silent retry — stop offering it automatically
        # rather than looping forever on the same broken transaction.
        if tag and st.get("apply_attempts_tag") == tag and int(st.get("apply_attempts") or 0) >= 3:
            return None
        try:
            ddir = updater.transaction_dir(txid) if txid else None
        except Exception:
            ddir = None
        if tag and ddir and os.path.isdir(ddir) \
                and updater.version_gt(tag, updater.current_version()):
            return {"tag": tag, "version": st.get("staged_version") or tag.lstrip("vV"),
                    "transaction_id": txid}
        return None

    def _check_for_updates(self, manual: bool = False):
        """Check the selected channel, then download+verify+stage in a worker thread.
        If a verified build is already staged, go straight to the install prompt.

        Guarded by _updates_busy + a disabled button so mashing "CHECK FOR
        UPDATES" (or the tray menu item firing while a check is already in
        flight) can't start a second overlapping download/install."""
        if self._updates_busy:
            return
        pend = self._pending_staged()
        if pend:
            if manual:
                self._prompt_install(pend["tag"], pend["version"])
            return
        cfg = load_config()
        if not cfg.get("host"):
            if manual:
                messagebox.showwarning("ProxyForce", "Configure a proxy host in Settings first.")
            return
        self._updates_busy = True
        self._btn_check_updates.configure(state="disabled")
        self._settings_panel.set_update_status("Checking for updates…", THEME["text"])

        def work():
            try:
                try:
                    info = updater.check_latest(cfg)
                except Exception as e:
                    self._queue.put(("upd_error", f"Update check failed: {e}"))
                    return
                if not info:
                    chan = "Development" if cfg.get("update_channel") == "dev" else "Stable"
                    self._queue.put(("upd_status",
                        f"Up to date — v{updater.current_version()} ({chan})", THEME["muted"]))
                    if manual:
                        self._queue.put(("log", "No updates available.", "info"))
                    return
                self._queue.put(("log", f"Update {info.version} available — downloading…", "info"))
                self._queue.put(("upd_status", f"Downloading {info.version}…", THEME["text"]))
                try:
                    def prog(done, total):
                        if total:
                            self._queue.put(("upd_progress", done / total))
                    ddir = updater.download(info, cfg, prog)
                    self._queue.put(("upd_progress", None))
                    self._queue.put(("upd_status", f"Verifying {info.version}…", THEME["text"]))
                    if not updater.verify(info, ddir):
                        self._queue.put(("upd_error",
                            "Verification FAILED (signature/checksum) — update rejected."))
                        return
                    txid = updater.transaction_id(ddir)
                    st = updater.load_state()
                    st.update({"staged_tag": info.tag, "staged_version": info.version,
                               "transaction_id": txid})
                    st.pop("staged_dir", None)
                    st.pop("apply_at_hour", None)
                    updater.save_state(st)
                    self._queue.put(("upd_ready", info.tag, info.version, manual))
                except Exception as e:
                    self._queue.put(("upd_progress", None))
                    self._queue.put(("upd_error", f"Update download failed: {e}"))
            finally:
                self._queue.put(("upd_done",))

        threading.Thread(target=work, daemon=True).start()

    def _prompt_install(self, tag: str, version: str):
        hour = int(load_config().get("update_hour", 3))
        ans = messagebox.askyesnocancel(
            "ProxyForce Update",
            f"Update {version} is downloaded and verified.\n\n"
            f"•  Yes — install now (brief disconnect, then auto-reconnect)\n"
            f"•  No — install tonight at {hour:02d}:00\n"
            f"•  Cancel — remind me later")
        if ans is True:
            self._apply_staged()
        elif ans is False:
            st = updater.load_state()
            st["apply_at_hour"] = hour
            updater.save_state(st)
            self._settings_panel.set_update_status(
                f"v{version} will install at {hour:02d}:00", THEME["accent"])
            self._log(f"Update {version} scheduled to install at {hour:02d}:00.", "info")
        else:
            self._settings_panel.set_update_status(
                f"v{version} ready — install via Check for Updates", THEME["accent"])
            self._log(f"Update {version} staged; install later.", "info")

    def _apply_staged(self):
        pend = self._pending_staged()
        if not pend:
            self._log("No staged update to install.", "warning")
            return
        if not getattr(sys, "frozen", False):
            messagebox.showinfo("ProxyForce",
                "Self-update only runs in the packaged build, not from source.")
            return
        install_dir = os.path.dirname(sys.executable)
        txid = pend["transaction_id"]
        self._settings_panel.set_update_status("Validating staged build…", THEME["text"])
        self._log("Validating staged build (selftest)…", "info")

        def work():
            info = updater.UpdateInfo(pend["tag"], False, "", "", "")
            try:
                staged = updater.prepare_apply(info, txid, install_dir)
            except Exception as e:
                self._queue.put(("upd_error", f"Final update verification failed: {e}"))
                return
            if not updater.selftest_staged(staged):
                self._queue.put(("upd_error", "Staged build failed selftest — not installing."))
                return
            st = updater.load_state()
            st["resume_proxy"] = self._last_state in ("running", "waiting", "starting")
            updater.save_state(st)
            self._queue.put(("upd_do_apply", staged, install_dir))

        threading.Thread(target=work, daemon=True).start()

    def _notify_tray(self, title: str, msg: str):
        try:
            if getattr(self, "_tray", None):
                self._tray.notify(msg, title)
        except Exception:
            pass

    def _maybe_resume_after_update(self):
        """On startup after an update swap, reconnect if we were running, and clean
        up old staging folders."""
        # Write the readiness marker FIRST, in its own try/except, before anything
        # else in this method (icacls-heavy legacy migration included) gets a
        # chance to raise and silently skip it — a missed marker reads to the
        # waiting worker as "the new build never came up" and it rolls back to
        # the OLD build with no visible error, which is exactly the reliability
        # bug this ordering fixes.
        txid = updater.load_state().get("transaction_id")
        if txid:
            try:
                updater.mark_update_ready(txid)
            except FileExistsError:
                pass
            except Exception:
                pass
        try:
            updater.migrate_legacy_update_state()
            st = updater.load_state()
            if st.get("resume_proxy"):
                st["resume_proxy"] = False
                updater.save_state(st)
                self._log("Reconnecting after update…", "info")
                self._start_engine()
            staged_tag = st.get("staged_tag")
            if staged_tag and not updater.version_gt(staged_tag, updater.current_version()):
                for key in ("staged_tag", "staged_version", "transaction_id", "apply_at_hour"):
                    st.pop(key, None)
                updater.save_state(st)
            last_error = st.get("last_apply_error")
            if last_error:
                failed_tag = st.get("last_apply_tag") or "the update"
                gave_up = (st.get("apply_attempts_tag") == st.get("last_apply_tag")
                          and int(st.get("apply_attempts") or 0) >= 3)
                st.pop("last_apply_error", None)
                st.pop("last_apply_tag", None)
                st.pop("last_apply_time", None)
                updater.save_state(st)
                log_path = os.path.join(updater.update_dir(), "apply.log")
                suffix = " — no further automatic attempts will be made" if gave_up else ""
                self._log(f"Update to {failed_tag} failed and was rolled back{suffix} — "
                          f"see {log_path}", "error")
                self._settings_panel.set_update_status(
                    f"Update to {failed_tag} failed — rolled back", THEME["red"])
                messagebox.showwarning("ProxyForce Update Failed",
                    f"The update to {failed_tag} could not be installed and was "
                    f"rolled back to the previous version.{suffix}\n\n"
                    f"Details: {log_path}")
            updater.cleanup_staging(keep_txid=txid)
        except Exception:
            pass

    def _auto_start_if_configured(self):
        """Auto-connect on launch when a proxy host is configured. The 'stopped'
        guard means this no-ops when _maybe_resume_after_update already started the
        engine (post-update resume), so the two paths never double-start."""
        try:
            if self._last_state == "stopped" and load_config().get("host"):
                self._log("Auto-connecting on launch…", "info")
                self._start_engine()
        except Exception:
            pass

    def _update_timer_loop(self):
        """Once-a-day background check at the configured hour, and scheduled
        ('install tonight') applies. Hour-granularity, fired at most once/day."""
        while self._running:
            try:
                cfg = load_config()
                now = datetime.now()
                today = now.strftime("%Y-%m-%d")
                st = updater.load_state()
                if (cfg.get("auto_update_check") and cfg.get("host")
                        and int(cfg.get("update_hour", 3)) == now.hour
                        and st.get("last_check_date") != today):
                    st["last_check_date"] = today
                    updater.save_state(st)
                    self._queue.put(("upd_check", False))
                st = updater.load_state()
                ah = st.get("apply_at_hour")
                if ah is not None and int(ah) == now.hour and st.get("transaction_id"):
                    st.pop("apply_at_hour", None)
                    updater.save_state(st)
                    self._queue.put(("upd_apply",))
            except Exception:
                pass
            time.sleep(300)

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, msg: str, level: str = "info"):
        self._dash_log.log(msg, level)
        self._full_log.log(msg, level)

    # ── State display ─────────────────────────────────────────────────────────

    def _apply_state(self, state: str):
        label, color_key, hero_bg = STATE_UI.get(
            state, ("STOPPED", "muted", "card"))
        color = cc(color_key)
        state_changed = state != self._last_state
        if state_changed:
            self._icon_frame = 0

        self._status_lbl.configure(text=label, text_color=color)
        self._hero_lbl.configure(text=label, text_color=color)
        self._proxy_info_lbl.configure(
            text_color=THEME["text"] if state == "running" else THEME["muted"])

        # Tint the hero card with the state colour
        self._hero_card.configure(fg_color=THEME.get(hero_bg, THEME["card"]))

        if state in ("running", "waiting", "starting", "stopping"):
            self._toggle_btn.configure(
                text="■  STOP",
                fg_color=THEME["stop_bg"],
                hover_color=THEME["stop_hov"])
        else:
            self._toggle_btn.configure(
                text="▶  START",
                fg_color=THEME["accent_dk"],
                hover_color=THEME["accent"])

        if state == "stopped":
            self._card_active.update_value("0")

        self._last_state = state
        if state_changed:
            self._draw_icon(self._icon_canvas, "sidebar")
            self._update_tray_icon()
            self._start_status_animation()

    def _update_stats(self, st):
        self._card_active.update_value(str(st.active_connections))
        self._card_total.update_value(str(st.total_connections))
        self._card_bytes.update_value(st.bytes_str())
        uptime = st.uptime_str()
        self._card_uptime.update_value(uptime)
        self._uptime_var.set(f"Uptime: {uptime}" if uptime else "")

    # ── Theme ─────────────────────────────────────────────────────────────────

    def _on_theme_change(self, label: str):
        mode = _APPEARANCE_MAP.get(label, "system")
        ctk.set_appearance_mode(mode)
        self._repaint_theme()
        try:
            cfg = load_config()
            cfg["appearance"] = mode
            save_config(cfg)
        except Exception:
            pass

    def _repaint_theme(self):
        """Repaint all raw-tk widgets after an appearance mode change."""
        # Sidebar
        self._sidebar.configure(fg_color=THEME["sidebar"])
        self._draw_icon(self._icon_canvas, "sidebar")
        # Nav buttons
        for btn in self._nav_btns.values():
            btn.repaint()
        # Stat cards
        for card in (self._card_active, self._card_total, self._card_bytes,
                     self._card_uptime):
            card.repaint_theme()
        # Log panels
        self._dash_log.repaint_theme()
        self._full_log.repaint_theme()
        # Settings bypass text
        self._settings_panel.repaint_theme()
        # Re-apply state to refresh colours
        self._apply_state(self._last_state)

    # ── System tray ───────────────────────────────────────────────────────────

    def _setup_tray(self):
        try:
            img  = self._make_tray_image()
            menu = pystray.Menu(
                pystray.MenuItem("Show ProxyForce", self._tray_show, default=True),
                pystray.MenuItem("Start Proxy",     self._tray_start),
                pystray.MenuItem("Stop Proxy",      self._tray_stop),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Check for updates", self._tray_check),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Quit",            self._tray_quit),
            )
            self._tray = pystray.Icon("ProxyForce", img, "ProxyForce", menu)
            self._tray.run_detached()
        except Exception as e:
            self._tray = None
            self._log(f"System tray unavailable: {e}", "warning")

    def _tray_show(self, icon=None, item=None):
        self.deiconify()
        self.lift()
        self.focus_force()
        # One-shot icon reapply for the restore-from-tray case (CustomTkinter's
        # own build-time icon reset doesn't recur here, but this covers it if
        # ever needed) -- bounded to exactly one call per restore, unlike the
        # blanket <Map> bind this replaces.
        self.after(50, self._set_window_icon)

    def _tray_start(self, icon=None, item=None):
        self._queue.put(("tray_start",))

    def _tray_stop(self, icon=None, item=None):
        self._queue.put(("tray_stop",))

    def _tray_check(self, icon=None, item=None):
        self._queue.put(("upd_check", True))

    def _tray_quit(self, icon=None, item=None):
        self._queue.put(("quit",))

    def _on_close(self):
        self.withdraw()

    # ── Quit ──────────────────────────────────────────────────────────────────

    def _do_quit(self):
        self._running = False
        if _HAS_TRAY and hasattr(self, "_tray") and self._tray:
            try:
                self._tray.stop()
            except Exception:
                pass
        eng = self._engine
        if eng is not None:
            try:
                eng.stop()
            except Exception:
                pass
        try:
            self.destroy()
        except Exception:
            sys.exit(0)

    # ── Polling ───────────────────────────────────────────────────────────────

    def _poll_singbox_log(self):
        try:
            if os.path.exists(SINGBOX_LOG):
                size = os.path.getsize(SINGBOX_LOG)
                if size < self._sb_log_pos:
                    self._sb_log_pos = 0
                if size > self._sb_log_pos:
                    with open(SINGBOX_LOG, "rb") as f:
                        f.seek(self._sb_log_pos)
                        chunk = f.read(8192)  # 8 KB cap per poll
                        self._sb_log_pos = f.tell()
                    for line in chunk.decode("utf-8", errors="replace").splitlines()[-50:]:
                        line = _ANSI_RE.sub("", line).strip()
                        if not line:
                            continue
                        low = line.lower()
                        lvl = ("error"   if "fatal" in low or "error" in low else
                               "warning" if "warn"  in low else
                               "debug"   if "debug" in low else "info")
                        self._full_log.log("[sb] " + line, lvl)
        except Exception:
            pass
        if self._running:
            self.after(2000, self._poll_singbox_log)

    def _poll_queue(self):
        try:
            while True:
                item = self._queue.get_nowait()
                tag  = item[0]
                if tag == "log":
                    self._log(item[1], item[2] if len(item) > 2 else "info")
                elif tag == "state":
                    self._apply_state(item[1])
                elif tag == "stats":
                    self._update_stats(item[1])
                elif tag == "tray_start":
                    self._tray_show()
                    self._start_engine()
                elif tag == "tray_stop":
                    self._stop_engine()
                elif tag == "upd_status":
                    self._settings_panel.set_update_status(
                        item[1], item[2] if len(item) > 2 else None)
                elif tag == "upd_progress":
                    self._settings_panel.set_update_progress(item[1])
                elif tag == "upd_error":
                    self._settings_panel.set_update_progress(None)
                    self._settings_panel.set_update_status(item[1])
                    self._log(item[1], "error")
                elif tag == "upd_ready":
                    rtag, rver, rmanual = item[1], item[2], item[3]
                    self._settings_panel.set_update_progress(None)
                    self._settings_panel.set_update_status(
                        f"v{rver} ready to install", THEME["accent"])
                    self._log(f"Update {rver} downloaded and verified.", "success")
                    if rmanual:
                        self._prompt_install(rtag, rver)
                    else:
                        self._notify_tray("ProxyForce update ready",
                                          f"v{rver} is ready — open ProxyForce to install.")
                elif tag == "upd_done":
                    self._updates_busy = False
                    self._btn_check_updates.configure(state="normal")
                elif tag == "upd_check":
                    self._check_for_updates(manual=item[1])
                elif tag == "upd_apply":
                    self._apply_staged()
                elif tag == "upd_do_apply":
                    staged, install_dir = item[1], item[2]
                    self._log("Installing update — ProxyForce will restart…", "info")
                    try:
                        updater.begin_apply(staged, install_dir, os.getpid())
                    except Exception as e:
                        self._log(f"Could not launch the updater: {e}", "error")
                        self._settings_panel.set_update_status("Update failed to launch")
                    else:
                        self._do_quit()
                        return
                elif tag == "quit":
                    self._do_quit()
                    return
        except queue.Empty:
            pass
        if self._running:
            self.after(100, self._poll_queue)  # was 50ms


# ── Entry point ───────────────────────────────────────────────────────────────

def main(start_minimized: bool = False):
    ctk.set_default_color_theme("blue")
    app = ProxyForceApp(start_minimized=start_minimized)
    app.mainloop()


if __name__ == "__main__":
    main(start_minimized="--minimized" in sys.argv)
