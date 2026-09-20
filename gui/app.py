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
from tkinter import messagebox, filedialog, ttk

import customtkinter as ctk

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, ".."))

from core.config_store import (
    load_config, save_config, save_autostart, auth_config_warnings,
    rep_config_warnings, consume_legacy_auto_bypass_flag,
)
from core import reputation as rep
from core.singbox_controller import (
    SingBoxController, SingBoxState, make_proxy_config, normalize_bypass_entry,
    probe_connect, _CONNECT_PROBE_PORTS,
)
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
ANIM_INTERVAL_MS = 125  # sidebar pulse cadence while a state is animating (8 fps)


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
# Sites panel  —  what the dashboard shows instead of a scrolling log
# ─────────────────────────────────────────────────────────────────────────────
def _ago(ts: float) -> str:
    """Compact relative time: the Sites and Scanning views update every second,
    so absolute clock times would just be noise."""
    if not ts:
        return "never"
    d = max(0, int(time.time() - ts))
    if d < 5:
        return "just now"
    if d < 60:
        return f"{d}s ago"
    if d < 3600:
        return f"{d // 60}m ago"
    if d < 86400:
        return f"{d // 3600}h ago"
    return f"{d // 86400}d ago"


# Verdict -> (glyph, theme colour key, sort rank). Flagged sorts to the top so a
# detection is never buried under hundreds of clean rows.
_REP_UI = {
    rep.MALICIOUS: ("⚠ FLAGGED", "red",    0),
    rep.ERROR:     ("— error",   "yellow", 1),
    "pending":     ("… checking", "accent", 2),
    rep.UNKNOWN:   ("? unknown",      "muted",  3),
    rep.CLEAN:     ("✓ clean",   "green",  4),
    "":            ("—",         "muted",  5),
}


class SitesPanel(ctk.CTkFrame):
    """A live, deduplicated table of every host connected to.

    Replaces the dashboard's copy of the event log: the log answers "what is the
    engine doing", which belongs on the Log tab, while the dashboard should
    answer "what am I actually talking to". One row per host, updated in place,
    so repeat connections bump a counter instead of scrolling anything away."""

    _MAX_ROWS = 600     # bound the widget on long sessions; oldest rows evicted

    def __init__(self, parent, on_select=None, **kwargs):
        super().__init__(parent, fg_color=THEME["card"], corner_radius=10,
                         border_width=1, border_color=THEME["border"], **kwargs)
        self._on_select = on_select
        self._rows = {}         # host -> last rendered tuple, for change detection

        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=14, pady=(10, 4))
        ctk.CTkLabel(hdr, text="SITES",
                     font=ctk.CTkFont("Consolas", 10, weight="bold"),
                     text_color=THEME["muted"]).pack(side="left")

        self._count_var = tk.StringVar(value="")
        ctk.CTkLabel(hdr, textvariable=self._count_var,
                     font=ctk.CTkFont("Consolas", 10),
                     text_color=THEME["muted"]).pack(side="left", padx=(10, 0))

        self._filter_var = tk.StringVar(value="All")
        ctk.CTkSegmentedButton(
            hdr, values=["All", "Flagged", "Direct"], variable=self._filter_var,
            command=lambda _v: self.refilter(),
            font=ctk.CTkFont("Segoe UI", 10),
            fg_color=THEME["input_bg"], selected_color=THEME["accent_dk"],
            selected_hover_color=THEME["accent"],
            unselected_color=THEME["input_bg"],
            unselected_hover_color=THEME["nav_hover"],
            height=22).pack(side="right")

        self._wrap = tk.Frame(self, bg=cc("input_bg"))
        self._wrap.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        # A private style name so theming this tree cannot disturb any other ttk
        # widget CustomTkinter creates internally.
        self._style = ttk.Style()
        self._style_name = "ProxyForce.Sites.Treeview"
        cols = ("host", "conns", "route", "rep", "seen")
        self._tree = ttk.Treeview(self._wrap, columns=cols, show="headings",
                                  style=self._style_name, selectmode="browse")
        for key, text, width, anchor in (
                ("host",  "Host",       320, "w"),
                ("conns", "Conns",       60, "e"),
                ("route", "Route",       90, "w"),
                ("rep",   "Reputation", 130, "w"),
                ("seen",  "Last seen",  100, "w")):
            self._tree.heading(key, text=text,
                               command=lambda k=key: self._sort_by(k))
            self._tree.column(key, width=width, anchor=anchor,
                              stretch=(key == "host"))

        self._sb = tk.Scrollbar(self._wrap, command=self._tree.yview)
        self._tree.configure(yscrollcommand=self._sb.set)
        self._sb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)
        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        self._sort_key = "seen"
        self._records = {}      # host -> SiteRecord
        self.repaint_theme()

    # ── data ─────────────────────────────────────────────────────────────────
    def upsert(self, record):
        """Insert or update one host's row. Cheap enough to call per connection."""
        self._records[record.host] = record
        if not self._passes_filter(record):
            if self._tree.exists(record.host):
                self._tree.delete(record.host)
                self._rows.pop(record.host, None)
            return
        values = self._row_values(record)
        if self._rows.get(record.host) == values:
            return              # nothing visible changed; skip the widget write
        self._rows[record.host] = values
        tag = self._tag_for(record)
        if self._tree.exists(record.host):
            self._tree.item(record.host, values=values, tags=(tag,))
        else:
            self._tree.insert("", 0, iid=record.host, values=values, tags=(tag,))
            self._evict()
        self._count_var.set(self._summary())

    def _row_values(self, record):
        glyph = _REP_UI.get(record.status, _REP_UI[""])[0]
        return (record.host, str(record.conns), record.route or "—",
                glyph, _ago(record.last_seen))

    @staticmethod
    def _tag_for(record):
        return {rep.MALICIOUS: "bad", rep.CLEAN: "good",
                rep.ERROR: "warn"}.get(record.status, "plain")

    def _summary(self):
        total = len(self._records)
        bad = sum(1 for r in self._records.values() if r.status == rep.MALICIOUS)
        shown = len(self._tree.get_children(""))
        base = f"{total:,} host{'s' if total != 1 else ''}"
        if shown != total:
            base += f" · {shown:,} shown"
        if bad:
            base += f" · {bad} flagged"
        return base

    def _evict(self):
        children = self._tree.get_children("")
        if len(children) <= self._MAX_ROWS:
            return
        for iid in children[self._MAX_ROWS:]:
            self._tree.delete(iid)
            self._rows.pop(iid, None)

    # ── filtering / sorting ──────────────────────────────────────────────────
    def _passes_filter(self, record):
        mode = self._filter_var.get()
        if mode == "Flagged":
            return record.status == rep.MALICIOUS
        if mode == "Direct":
            return record.route == "direct"
        return True

    def refilter(self):
        self._tree.delete(*self._tree.get_children(""))
        self._rows.clear()
        for record in self._sorted_records():
            if not self._passes_filter(record):
                continue
            values = self._row_values(record)
            self._rows[record.host] = values
            self._tree.insert("", "end", iid=record.host, values=values,
                              tags=(self._tag_for(record),))
        self._evict()
        self._count_var.set(self._summary())

    def _sorted_records(self):
        key = self._sort_key

        def sort_key(r):
            if key == "host":
                return (r.host,)
            if key == "conns":
                return (-r.conns,)
            if key == "route":
                return (r.route or "",)
            if key == "rep":
                return (_REP_UI.get(r.status, _REP_UI[""])[2], r.host)
            return (-r.last_seen,)

        return sorted(self._records.values(), key=sort_key)

    def _sort_by(self, key):
        self._sort_key = key
        self.refilter()

    def _on_tree_select(self, _event=None):
        if not self._on_select:
            return
        sel = self._tree.selection()
        if sel:
            self._on_select(self._records.get(sel[0]))

    def selected_host(self):
        sel = self._tree.selection()
        return sel[0] if sel else None

    def tick(self):
        """Refresh the relative 'last seen' column without rebuilding rows."""
        for host in list(self._tree.get_children("")):
            record = self._records.get(host)
            if record is None:
                continue
            values = self._row_values(record)
            if self._rows.get(host) != values:
                self._rows[host] = values
                self._tree.item(host, values=values, tags=(self._tag_for(record),))

    def clear(self):
        self._tree.delete(*self._tree.get_children(""))
        self._rows.clear()
        self._records.clear()
        self._count_var.set("")

    # ── theming ──────────────────────────────────────────────────────────────
    def repaint_theme(self):
        ib, txt, border = cc("input_bg"), cc("text"), cc("border")
        self._wrap.configure(bg=ib)
        # "default" is the only built-in ttk theme that honours fieldbackground
        # on Windows; the native "vista" theme ignores it and would render a
        # white tree in dark mode.
        try:
            self._style.theme_use("default")
        except Exception:
            pass
        self._style.configure(self._style_name, background=ib, fieldbackground=ib,
                              foreground=txt, borderwidth=0, rowheight=22,
                              font=("Consolas", 9))
        self._style.configure(self._style_name + ".Heading",
                              background=cc("card2"), foreground=cc("muted"),
                              relief="flat", font=("Segoe UI", 9, "bold"))
        self._style.map(self._style_name + ".Heading",
                        background=[("active", cc("nav_hover"))])
        self._style.map(self._style_name,
                        background=[("selected", cc("nav_act"))],
                        foreground=[("selected", txt)])
        self._tree.tag_configure("bad", foreground=cc("red"))
        self._tree.tag_configure("good", foreground=cc("green"))
        self._tree.tag_configure("warn", foreground=cc("yellow"))
        self._tree.tag_configure("plain", foreground=txt)
        self._sb.configure(bg=border, troughcolor=ib, activebackground=cc("muted"))


# ─────────────────────────────────────────────────────────────────────────────
# Scanning panel  —  scanner + per-provider live status
# ─────────────────────────────────────────────────────────────────────────────
# Provider state -> (theme colour key, label)
_PSTATE_UI = {
    rep.P_OK:      ("green",  "OK"),
    rep.P_IDLE:    ("accent", "READY"),
    rep.P_LIMITED: ("yellow", "LIMITED"),
    rep.P_ERROR:   ("red",    "ERROR"),
    rep.P_OFF:     ("muted",  "OFF"),
}


class _ProviderRow(ctk.CTkFrame):
    """One provider's live status: a beacon, its role, and its own metrics.

    The beacon brightens for one refresh whenever the provider's call count has
    moved since the last tick, which is what makes the panel read as live rather
    than as a static summary."""

    _DOT = 12

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self._calls = 0
        self._flash = False

        self._canvas = tk.Canvas(self, width=self._DOT + 8, height=self._DOT + 8,
                                 highlightthickness=0, bd=0, bg=cc("card"))
        self._canvas.pack(side="left", padx=(0, 10))
        self._dot = self._canvas.create_oval(4, 4, 4 + self._DOT, 4 + self._DOT,
                                             fill=cc("muted"), outline="")

        text = ctk.CTkFrame(self, fg_color="transparent")
        text.pack(side="left", fill="x", expand=True)

        top = ctk.CTkFrame(text, fg_color="transparent")
        top.pack(fill="x")
        self._name_var = tk.StringVar(value="")
        ctk.CTkLabel(top, textvariable=self._name_var, anchor="w",
                     font=ctk.CTkFont("Segoe UI", 12, weight="bold"),
                     text_color=THEME["text"]).pack(side="left")
        self._role_var = tk.StringVar(value="")
        ctk.CTkLabel(top, textvariable=self._role_var, anchor="w",
                     font=ctk.CTkFont("Segoe UI", 10),
                     text_color=THEME["muted"]).pack(side="left", padx=(8, 0))

        self._state_var = tk.StringVar(value="")
        self._state_lbl = ctk.CTkLabel(top, textvariable=self._state_var,
                                       font=ctk.CTkFont("Consolas", 10, weight="bold"),
                                       text_color=THEME["muted"])
        self._state_lbl.pack(side="right")

        self._detail_var = tk.StringVar(value="")
        ctk.CTkLabel(text, textvariable=self._detail_var, anchor="w",
                     justify="left", font=ctk.CTkFont("Consolas", 10),
                     text_color=THEME["muted"]).pack(fill="x", pady=(1, 0))

    def update_status(self, st: dict, detail_line: str):
        colour_key, label = _PSTATE_UI.get(st["state"], _PSTATE_UI[rep.P_OFF])
        self._name_var.set(st["label"])
        self._role_var.set("· " + st["role"])
        self._state_var.set(label)
        self._state_lbl.configure(text_color=THEME[colour_key])
        self._detail_var.set(detail_line)
        # Flash on activity since the previous tick.
        self._flash = st["calls"] > self._calls
        self._calls = st["calls"]
        self._paint_dot(colour_key)

    def _paint_dot(self, colour_key):
        colour = cc(colour_key)
        self._canvas.itemconfig(self._dot, fill=colour,
                                outline=cc("text") if self._flash else "",
                                width=2 if self._flash else 0)

    def repaint_theme(self):
        self._canvas.configure(bg=cc("card"))


class ScanPanel(ctk.CTkFrame):
    """The Scanning tab: overall state, coverage counters, per-provider health
    and the most recent detections."""

    def __init__(self, parent, on_apply_blocks=None, **kwargs):
        super().__init__(parent, fg_color=THEME["bg"], corner_radius=0, **kwargs)
        self._on_apply_blocks = on_apply_blocks

        # Hero
        self._hero = ctk.CTkFrame(self, fg_color=THEME["card"], corner_radius=12,
                                  border_width=1, border_color=THEME["border"])
        self._hero.pack(fill="x", padx=20, pady=(14, 10))
        inner = ctk.CTkFrame(self._hero, fg_color="transparent")
        inner.pack(fill="x", padx=24, pady=18)

        self._hero_state = tk.StringVar(value="OFF")
        self._hero_lbl = ctk.CTkLabel(
            inner, textvariable=self._hero_state,
            font=ctk.CTkFont("Segoe UI", 22, weight="bold"),
            text_color=THEME["muted"])
        self._hero_lbl.pack(anchor="w")

        self._hero_detail = tk.StringVar(value="Site scanning is disabled.")
        ctk.CTkLabel(inner, textvariable=self._hero_detail, anchor="w",
                     font=ctk.CTkFont("Segoe UI", 11),
                     text_color=THEME["muted"]).pack(anchor="w", pady=(2, 0))

        self._apply_btn = ctk.CTkButton(
            inner, text="APPLY BLOCKS NOW", width=170, height=30,
            font=ctk.CTkFont("Segoe UI", 11, weight="bold"),
            fg_color=THEME["stop_bg"], hover_color=THEME["stop_hov"],
            command=self._apply_clicked)
        # Only shown when blocks are pending — see set_pending_blocks.

        # Coverage counters
        stats = ctk.CTkFrame(self, fg_color="transparent")
        stats.pack(fill="x", padx=20, pady=(0, 10))
        self._card_sites = StatCard(stats, "Sites seen", "0")
        self._card_good  = StatCard(stats, "Known good", "0")
        self._card_bad   = StatCard(stats, "Flagged",    "0")
        self._card_queue = StatCard(stats, "Queued",     "0")
        for c in (self._card_sites, self._card_good, self._card_bad,
                  self._card_queue):
            c.pack(side="left", fill="both", expand=True, padx=4)

        # Providers
        box = ctk.CTkFrame(self, fg_color=THEME["card"], corner_radius=10,
                           border_width=1, border_color=THEME["border"])
        box.pack(fill="x", padx=20, pady=(0, 10))
        ctk.CTkLabel(box, text="SOURCES", anchor="w",
                     font=ctk.CTkFont("Consolas", 10, weight="bold"),
                     text_color=THEME["muted"]).pack(fill="x", padx=16, pady=(10, 6))
        self._rows = []
        for i in range(3):
            if i:
                tk.Frame(box, bg=cc("border"), height=1).pack(fill="x", padx=16)
            row = _ProviderRow(box)
            row.pack(fill="x", padx=16, pady=8)
            self._rows.append(row)

        # Recent detections
        self._flags = LogPanel(self, title="RECENT DETECTIONS")
        self._flags.pack(fill="both", expand=True, padx=20, pady=(0, 14))
        self._flag_seen = set()

    def _apply_clicked(self):
        if self._on_apply_blocks:
            self._on_apply_blocks()

    def set_pending_blocks(self, count: int):
        if count > 0:
            self._apply_btn.configure(
                text=f"APPLY {count} BLOCK{'S' if count != 1 else ''} NOW")
            self._apply_btn.pack(anchor="w", pady=(12, 0))
        else:
            self._apply_btn.pack_forget()

    def update_view(self, overall, statuses, stats, flags):
        state, headline = overall
        colour_key, _label = _PSTATE_UI.get(state, _PSTATE_UI[rep.P_OFF])
        self._hero_state.set(
            {rep.P_OK: "SCANNING", rep.P_IDLE: "SCANNING",
             rep.P_LIMITED: "RATIONED", rep.P_ERROR: "PROBLEM",
             rep.P_OFF: "OFF"}.get(state, "OFF"))
        self._hero_lbl.configure(text_color=THEME[colour_key])
        self._hero_detail.set(headline)
        self._hero.configure(fg_color=THEME[
            {rep.P_OK: "hero_run", rep.P_ERROR: "hero_err",
             rep.P_LIMITED: "hero_warn"}.get(state, "card")])

        self._card_sites.update_value(f"{stats['sites']:,}")
        self._card_good.update_value(f"{stats['known_good']:,}")
        self._card_bad.update_value(f"{stats['flagged']:,}")
        self._card_queue.update_value(
            f"{stats['queued'] + stats['inflight']:,}")

        for row, st in zip(self._rows, statuses):
            row.update_status(st, self._detail_for(st, stats))

        for flag in reversed(flags):
            key = (flag["host"], flag["at"])
            if key in self._flag_seen:
                continue
            self._flag_seen.add(key)
            self._flags.log(
                f"{flag['host']}  —  {flag['source']}: {flag['detail']}",
                "error")

    @staticmethod
    def _detail_for(st, stats):
        """The one metrics line under each provider, phrased for that provider's
        actual constraint rather than a generic call counter."""
        extra = st.get("extra") or {}
        if st["state"] == rep.P_OFF:
            return st["detail"] or "not in use"
        if st["name"] == "feeds":
            entries = extra.get("entries") or 0
            refreshed = extra.get("refreshed") or 0
            if not refreshed:
                # Downloaded on the first scan cycle, not at startup — saying
                # "stale" here would read as a fault rather than "not yet".
                return "waiting for the first feed download"
            parts = [f"{entries:,} known-bad hosts",
                     f"refreshed {_ago(refreshed)}"]
            stale = [n for n, _t, is_stale in (extra.get("sources") or [])
                     if is_stale]
            if stale:
                parts.append("stale: " + ", ".join(stale))
            return " · ".join(parts)
        if st["name"] == "safebrowsing":
            parts = [f"{st['hosts']:,} hosts checked",
                     f"{st['calls']:,} batch{'es' if st['calls'] != 1 else ''}"]
            if extra.get("queued"):
                parts.append(f"{extra['queued']:,} waiting")
            parts.append(f"last reply {_ago(st['last_ok'])}")
            if st["state"] == rep.P_ERROR and st["last_error"]:
                parts.append(st["last_error"])
            return " · ".join(parts)
        used, cap = extra.get("used_today", 0), extra.get("cap", 0)
        parts = [f"{used}/{cap} today"]
        if extra.get("queued"):
            parts.append(f"{extra['queued']:,} queued")
        parts.append(f"1 every {extra.get('interval', 0):.0f}s")
        if st["state"] == rep.P_ERROR and st["last_error"]:
            parts.append(st["last_error"])
        elif st["state"] == rep.P_LIMITED:
            parts.append(st["detail"])
        return " · ".join(parts)

    def repaint_theme(self):
        for row in self._rows:
            row.repaint_theme()
        self._flags.repaint_theme()


# ─────────────────────────────────────────────────────────────────────────────
# Settings panel
# ─────────────────────────────────────────────────────────────────────────────
# Config keys the panel must carry through a load/save round trip even though
# no widget edits them — they are maintained by the scanner at runtime.
_PASSTHROUGH_KEYS = ("rep_blocklist", "rep_allowlist")


class SettingsPanel(ctk.CTkScrollableFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color="transparent",
                         scrollbar_button_color=THEME["border"],
                         scrollbar_button_hover_color=THEME["muted"],
                         **kwargs)
        self._vars         = {}
        self._bypass_frame = None
        self._bypass_text  = None
        self._passthrough  = {k: [] for k in _PASSTHROUGH_KEYS}
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
        self._auth_warn_lbl = ctk.CTkLabel(
            s2, text="", justify="left", wraplength=260, anchor="w",
            font=ctk.CTkFont("Segoe UI", 10), text_color=THEME["yellow"])
        self._auth_warn_lbl.pack(anchor="w", pady=(6, 0))
        for k in ("_auth_display", "username", "password"):
            self._vars[k].trace_add("write", lambda *_: self._refresh_auth_warning())
        self._refresh_auth_warning()

        s3 = self._section("TRAFFIC RULES")
        self._check(s3, "exclude_private",
                    "Bypass private IP ranges (RFC1918 / ULA / link-local)")
        self._check(s3, "exclude_loopback", "Bypass loopback (127.x / ::1)")
        self._lbl(s3, "Bypass List  —  one entry per line: hostname, *.hostname, "
                      "or CIDR. No scheme, port or path — routed DIRECT for any "
                      "protocol/port, e.g. mail hosts on 993/465/587.")
        self._bypass_frame = tk.Frame(s3, bg=cc("input_bg"))
        self._bypass_frame.pack(fill="x", pady=(0, 4))
        self._bypass_text = tk.Text(
            self._bypass_frame, bg=cc("input_bg"), fg=cc("text"),
            insertbackground=cc("accent"), selectbackground=cc("border"),
            relief="flat", font=("Consolas", 10), height=4, padx=10, pady=8)
        self._bypass_text.pack(fill="x")

        s3b = self._section("TLS INSPECTION")
        self._check(s3b, "ca_inject",
                    "Trust the corporate TLS-inspection CA (fixes docker / pip / "
                    "npm / git / curl SSL errors)")
        self._lbl(s3b, "Corporate CA certificate  —  leave blank to use the one "
                       "ProxyForce ships with. Base-64 (PEM) .cer/.crt/.pem only.")
        row = ctk.CTkFrame(s3b, fg_color="transparent")
        row.pack(fill="x")
        cert_var = tk.StringVar()
        self._vars["ca_cert_path"] = cert_var
        ctk.CTkEntry(row, textvariable=cert_var,
                     placeholder_text="(shipped certificate)",
                     fg_color=THEME["input_bg"], border_color=THEME["border"],
                     border_width=1, text_color=THEME["text"],
                     placeholder_text_color=THEME["muted"], corner_radius=6,
                     font=ctk.CTkFont("Segoe UI", 11)).pack(
                         side="left", fill="x", expand=True, ipady=4)
        ctk.CTkButton(row, text="Browse…", width=78, corner_radius=6,
                      fg_color=THEME["accent_dk"], hover_color=THEME["accent"],
                      font=ctk.CTkFont("Segoe UI", 10, weight="bold"),
                      command=self._pick_ca_cert).pack(side="left", padx=(6, 0))
        self._ca_status_lbl = ctk.CTkLabel(
            s3b, text="", justify="left", wraplength=260, anchor="w",
            font=ctk.CTkFont("Segoe UI", 10), text_color=THEME["muted"])
        self._ca_status_lbl.pack(anchor="w", pady=(6, 0))
        cert_var.trace_add("write", lambda *_: self._refresh_ca_status())
        self._refresh_ca_status()

        s3c = self._section("SITE SCANNING")
        self._check(s3c, "rep_scan",
                    "Check every site against reputation services (each host is "
                    "looked up once, then remembered)")
        self._check(s3c, "rep_block",
                    "Block sites that come back flagged")
        self._lbl(s3c, "Sources — the free feeds need no key and work offline "
                       "once downloaded.")
        self._check(s3c, "rep_feeds",
                    "Free malware & phishing feeds (URLhaus, OpenPhish)")
        self._lbl(s3c, "Google Safe Browsing API key  —  batched and effectively "
                       "unlimited; the main filter.")
        self._entry(s3c, "rep_gsb_key", show="●",
                    placeholder="(no key — Safe Browsing disabled)")
        self._lbl(s3c, "VirusTotal API key  —  optional second opinion. The free "
                       "tier allows 4 lookups/minute, so it backfills in the "
                       "background rather than checking sites as you visit them.")
        self._entry(s3c, "rep_vt_key", show="●",
                    placeholder="(no key — VirusTotal disabled)")
        self._rep_status_lbl = ctk.CTkLabel(
            s3c, text="", justify="left", wraplength=260, anchor="w",
            font=ctk.CTkFont("Segoe UI", 10), text_color=THEME["yellow"])
        self._rep_status_lbl.pack(anchor="w", pady=(6, 0))
        for k in ("rep_scan", "rep_feeds", "rep_gsb_key", "rep_vt_key",
                  "rep_block"):
            self._vars[k].trace_add("write",
                                    lambda *_: self._refresh_rep_status())
        self._refresh_rep_status()

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
        # Values with no widget of their own still have to survive a Save. The
        # block list is written by the scanner, not typed by the user, and
        # _save_to_file rewrites the whole JSON document — so omitting it here
        # would silently erase it whenever settings were saved on a machine
        # using the ProgramData fallback store.
        d = dict(self._passthrough)
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
        entries = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        # Normalize each line NOW (same rules the engine applies) so the box
        # visibly rewrites to what will actually be used, and junk that could
        # never match (a scheme, a stray :port, "*host" without the dot) is
        # caught at Save time instead of silently doing nothing at runtime.
        normalized = []
        self._bypass_warnings = []
        for entry in entries:
            base, apex_included, err = normalize_bypass_entry(entry)
            if err:
                self._bypass_warnings.append(err)
                continue
            if base is None:
                continue
            normalized.append(base if apex_included or "/" in base else f".{base}")
        if self._bypass_text and normalized != entries:
            self._bypass_text.delete("1.0", "end")
            self._bypass_text.insert("1.0", "\n".join(normalized))
        d["bypass_list"] = normalized
        return d

    def set_values(self, d: dict):
        """Apply values from `d` to the matching widgets. `d` may be PARTIAL (a
        caller updating just one field, e.g. the Bypass List) — a key/pseudo-key
        with nothing in `d` for it MUST be left exactly as the user has it. This
        used to be the bug behind a since-removed feature: the three pseudo-keys
        below read d.get(..., "none"/"stable"/"info") unconditionally, so a
        partial dict silently reset Auth Type/Update Channel/Log Level to their
        defaults on every call — including flipping Basic auth to None while the
        username/password stayed put, so the proxy quietly stopped
        authenticating. Each pseudo-key is now guarded exactly like a plain key."""
        for k, var in self._vars.items():
            if k == "_auth_display":
                if "auth_type" in d:
                    var.set(_AUTH_DISPLAY.get(str(d.get("auth_type", "none")).lower(), "None"))
            elif k == "_channel_display":
                if "update_channel" in d:
                    var.set("Development" if str(d.get("update_channel", "stable")).lower() == "dev"
                            else "Stable")
            elif k == "_loglevel_display":
                if "log_level" in d:
                    var.set(_LOGLEVEL_DISPLAY.get(str(d.get("log_level", "info")).lower(),
                                                  _LOGLEVEL_DISPLAY["info"]))
            elif k in d:
                var.set(d[k])
        if "bypass_list" in d and self._bypass_text:
            self._bypass_text.delete("1.0", "end")
            self._bypass_text.insert("1.0", "\n".join(d["bypass_list"]))
        for k in _PASSTHROUGH_KEYS:
            if k in d:
                self._passthrough[k] = d[k]
        self._refresh_auth_warning()
        self._refresh_rep_status()

    def _refresh_rep_status(self):
        """Live feedback on the scanning configuration, same model as
        _refresh_auth_warning: a setting that looks enabled but can produce no
        verdicts is worse than one that is plainly off, because the user
        believes they are covered."""
        lbl = getattr(self, "_rep_status_lbl", None)
        if lbl is None:
            return
        try:
            vals = {k: self._vars[k].get()
                    for k in ("rep_scan", "rep_feeds", "rep_gsb_key",
                              "rep_vt_key", "rep_block")}
        except Exception:
            return
        if not vals["rep_scan"]:
            lbl.configure(text="Scanning is off — no site is checked and nothing "
                               "leaves this machine.",
                          text_color=THEME["muted"])
            return
        warnings = rep_config_warnings(vals)
        if warnings:
            lbl.configure(text="⚠ " + warnings[0], text_color=THEME["yellow"])
            return
        sources = ["feeds"] if vals["rep_feeds"] else []
        if (vals["rep_gsb_key"] or "").strip():
            sources.append("Safe Browsing")
        if (vals["rep_vt_key"] or "").strip():
            sources.append("VirusTotal")
        lbl.configure(text="✓ Active: " + ", ".join(sources) +
                           ". Each host is checked once and remembered.",
                      text_color=THEME["green"])

    def _pick_ca_cert(self):
        path = filedialog.askopenfilename(
            title="Select the corporate CA certificate",
            filetypes=[("Certificates", "*.pem *.crt *.cer"), ("All files", "*.*")])
        if path:
            self._vars["ca_cert_path"].set(path)

    def _refresh_ca_status(self):
        """Live-validate the chosen CA file. Validation happens HERE, at pick time,
        not at connect time: a certificate that does not parse would otherwise fail
        silently in the engine log, long after the user stopped looking at it."""
        lbl = getattr(self, "_ca_status_lbl", None)
        if lbl is None:
            return
        try:
            from core import env_certs
            path = (self._vars["ca_cert_path"].get() or "").strip()
            shipped = not path
            ok, summary = env_certs.describe_cert_file(
                path or env_certs.shipped_corporate_ca())
        except Exception as e:
            lbl.configure(text=f"Could not read the certificate: {e}",
                          text_color=THEME["yellow"])
            return
        prefix = "Shipped certificate — " if shipped else ""
        lbl.configure(text=prefix + summary,
                      text_color=THEME["muted"] if ok else THEME["yellow"])

    def _refresh_auth_warning(self):
        """Live-updates the yellow note under the Auth Type control whenever it,
        the username, or the password changes — see auth_config_warnings for
        the cases covered. No Save needed to see it."""
        lbl = getattr(self, "_auth_warn_lbl", None)
        if lbl is None:
            return
        cfg = {
            "auth_type": _AUTH_INTERNAL.get(self._vars["_auth_display"].get(), "none"),
            "username": self._vars["username"].get(),
            "password": self._vars["password"].get(),
        }
        warnings = auth_config_warnings(cfg)
        lbl.configure(text=("⚠ " + warnings[0]) if warnings else "")

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

        # Site reputation. Created unconditionally: the Sites view is populated
        # from observe() whether or not scanning is switched on, and the scanner
        # itself does no network work until rep_scan is true. Both callbacks fire
        # on worker threads, so they only ever touch the queue — _poll_queue does
        # the widget writes on the Tk thread.
        self._scanner = rep.ReputationScanner(
            load_config,
            on_update=lambda record: self._queue.put(("site", record)),
            on_log=lambda m, l: self._queue.put(("log", m, l)))
        self._scanner.start()
        self._pending_blocks = 0
        self._flagged_seen = set()   # hosts already alerted on, this session
        self._rep_last_scan_on = bool(load_config().get("rep_scan"))

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
        self._refresh_scan_view()

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
            ("scan",      "◎", "Scanning"),
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
        self._pg_scan      = ctk.CTkFrame(self._content,
                                          fg_color=THEME["bg"], corner_radius=0)

        self._build_dashboard(self._pg_dashboard)
        self._build_scan(self._pg_scan)
        self._build_settings(self._pg_settings)
        self._build_log(self._pg_log)

    # ── Navigation ────────────────────────────────────────────────────────────

    _PAGES = ("dashboard", "scan", "settings", "log")

    def _nav(self, key: str):
        self._cur_page = key
        titles = {"dashboard": "Dashboard", "scan": "Scanning",
                  "settings": "Settings", "log": "Log"}
        self._page_title.configure(text=titles.get(key, key.capitalize()))

        for k, btn in self._nav_btns.items():
            btn.set_active(k == key)

        pages = {"dashboard": self._pg_dashboard, "scan": self._pg_scan,
                 "settings":  self._pg_settings,  "log": self._pg_log}
        for pg in pages.values():
            pg.pack_forget()
        pages[key].pack(fill="both", expand=True)

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

        # Sites — one row per host, replacing the dashboard's old copy of the
        # event log. The log answers "what is the engine doing" and lives on the
        # Log tab; the dashboard answers "what am I actually talking to", which
        # is what the diagnostic chatter used to bury.
        self._sites_panel = SitesPanel(parent, on_select=self._on_site_selected)
        self._sites_panel.pack(fill="both", expand=True, padx=20, pady=(0, 4))

        # One-line status strip: warnings and errors still need to reach the
        # dashboard, they just no longer get a scrolling log to do it in.
        self._dash_status_var = tk.StringVar(value="")
        self._dash_status_lbl = ctk.CTkLabel(
            parent, textvariable=self._dash_status_var, anchor="w",
            font=ctk.CTkFont("Consolas", 10), text_color=THEME["muted"])
        self._dash_status_lbl.pack(fill="x", padx=24, pady=(0, 12))

    # ── Scanning ──────────────────────────────────────────────────────────────

    def _build_scan(self, parent):
        self._scan_panel = ScanPanel(parent, on_apply_blocks=self._apply_blocks)
        self._scan_panel.pack(fill="both", expand=True)

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
        for w in auth_config_warnings(cfg):
            self._log(w, "warning")
        if consume_legacy_auto_bypass_flag() and cfg.get("bypass_list"):
            self._log("Automatic bypass discovery has been removed. Review "
                      "Settings ▸ Bypass List and delete any entries you did not "
                      "add yourself — earlier versions could add hosts there on "
                      "their own.", "warning")

    def _save_config(self):
        vals = self._settings_panel.get_values()
        for w in getattr(self._settings_panel, "_bypass_warnings", []):
            self._log(w, "warning")
        for w in auth_config_warnings(vals):
            self._log(w, "warning")
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

        for w in rep_config_warnings(vals):
            self._log(w, "warning")
        # Switching scanning on should check the hosts already seen while it was
        # off, rather than leaving them blank until they are visited again.
        scan_on = bool(vals.get("rep_scan"))
        if scan_on and not self._rep_last_scan_on:
            self._scanner.rescan_all()
            self._log("Site scanning enabled — checking the sites seen so far.",
                      "info")
        self._rep_last_scan_on = scan_on

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
                     "log_level", "ca_inject", "ca_cert_path")

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
        for w in auth_config_warnings(vals):
            self._log(w, "warning")
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
                                                  on_log=on_log,
                                                  on_host_seen=self._scanner.observe)
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

        # Probe target: the first Bypass List host if the user has one (so the
        # CONNECT matrix below tests the exact host they're trying to reach),
        # else a generic well-known name.
        probe_target = "example.com"
        for entry in (vals.get("bypass_list") or []):
            base, _apex, err = normalize_bypass_entry(entry)
            if base and "/" not in base:
                probe_target = base
                break

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
                return

            # A bare TCP connect above only proves the proxy answers on its own
            # port — it says nothing about which CONNECT ports its POLICY allows.
            # Many corporate proxies permit CONNECT only to :443 and 403 every
            # other port (diagnosed 2026-08-07: this is exactly why Outlook's
            # IMAPS/SMTPS couldn't connect while ProxyForce ran, and why the old
            # version of this test could never have caught it).
            self._queue.put(("log", f"Probing CONNECT policy via {probe_target}…", "info"))
            for port in _CONNECT_PROBE_PORTS:
                code, reason = probe_connect(
                    vals["host"], vals["port"], probe_target, port,
                    username=(vals.get("username") or "") if vals.get("auth_type") == "basic" else "",
                    password=vals.get("password") or "")
                if code == 200:
                    self._queue.put(("log",
                        f"✓ CONNECT :{port} → 200 {reason}".rstrip(), "success"))
                elif code:
                    self._queue.put(("log",
                        f"✗ CONNECT :{port} → {code} {reason} — this port cannot be "
                        f"tunnelled; put the destination host in the Bypass List",
                        "error"))
                else:
                    self._queue.put(("log", f"✗ CONNECT :{port} → {reason}", "error"))

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
        """Everything goes to the Log tab. The dashboard used to mirror it, which
        buried the connection lines under diagnostics — now only warnings and
        errors surface there, on a single status line."""
        self._full_log.log(msg, level)
        if level in ("warning", "error"):
            self._dash_status_var.set(msg)
            self._dash_status_lbl.configure(
                text_color=THEME["red" if level == "error" else "yellow"])
        elif level == "success" and not self._dash_status_var.get():
            self._dash_status_var.set(msg)
            self._dash_status_lbl.configure(text_color=THEME["muted"])

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
                     self._card_uptime, self._scan_panel._card_sites,
                     self._scan_panel._card_good, self._scan_panel._card_bad,
                     self._scan_panel._card_queue):
            card.repaint_theme()
        # Log panels, sites table and the scanning view
        self._full_log.repaint_theme()
        self._sites_panel.repaint_theme()
        self._scan_panel.repaint_theme()
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
        # Flushes the verdict cache, so the next launch starts with everything
        # already known-good rather than re-scanning it.
        try:
            self._scanner.stop()
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

    # ── Site reputation ───────────────────────────────────────────────────────

    def _on_site_update(self, record):
        """One host changed. Runs on the Tk thread via _poll_queue."""
        self._sites_panel.upsert(record)
        if record.status != rep.MALICIOUS:
            return
        if record.host in self._flagged_seen:
            return
        self._flagged_seen.add(record.host)
        self._raise_alert(record)

    def _raise_alert(self, record):
        """Alert, then act. Alerting always happens; blocking is opt-in."""
        verdict = record.verdict
        detail = verdict.detail if verdict else ""
        source = verdict.source if verdict else "scanner"
        self._log(f"⚠ {record.host} flagged by {source}: {detail}", "error")
        self._notify_tray("ProxyForce blocked a site"
                          if load_config().get("rep_block")
                          else "ProxyForce flagged a site",
                          f"{record.host} — {detail}")

        cfg = load_config()
        if not cfg.get("rep_block"):
            return
        if record.host in (cfg.get("rep_allowlist") or []):
            self._log(f"{record.host} is on your allow list — not blocked.",
                      "warning")
            return

        # 1. Close what is already open. The reject rule below only applies from
        #    the next engine start, so without this the flagged host stays
        #    connected until the user restarts.
        engine = self._engine
        if engine is not None:
            try:
                closed = engine.close_connections_to(record.host)
                if closed:
                    self._log(f"Closed {closed} live connection(s) to "
                              f"{record.host}.", "warning")
            except Exception:
                pass

        # 2. Persist it, so the reject rule is rendered from the next start.
        blocklist = list(cfg.get("rep_blocklist") or [])
        if record.host not in blocklist:
            blocklist.append(record.host)
            cfg["rep_blocklist"] = blocklist
            if save_config(cfg):
                self._settings_panel.set_values({"rep_blocklist": blocklist})
            else:
                self._log("Could not save the block list.", "error")
                return
        self._pending_blocks += 1
        self._scan_panel.set_pending_blocks(self._pending_blocks)

    def _apply_blocks(self):
        """Restart the engine so pending reject rules take effect.

        Deliberately a button rather than automatic: a restart tears down the TUN
        and kills every open TCP connection, which is a 10-40s outage. That is
        the user's call to make, not a side effect of a background scan."""
        if self._pending_blocks <= 0:
            return
        if self._last_state not in ("running", "waiting", "starting"):
            self._pending_blocks = 0
            self._scan_panel.set_pending_blocks(0)
            return
        if not messagebox.askyesno(
                "ProxyForce",
                f"Apply {self._pending_blocks} new block"
                f"{'s' if self._pending_blocks != 1 else ''}?\n\n"
                "The engine restarts to load the new rules. Every open "
                "connection drops and the network is unavailable for roughly "
                "10-40 seconds."):
            return
        self._pending_blocks = 0
        self._scan_panel.set_pending_blocks(0)
        self._log("Applying block list — reconnecting…", "info")
        self._start_engine()

    def _on_site_selected(self, record):
        if record is None:
            return
        verdict = record.verdict
        if verdict is not None and verdict.detail:
            self._dash_status_var.set(f"{record.host} — {verdict.detail}")
            self._dash_status_lbl.configure(
                text_color=THEME["red" if verdict.status == rep.MALICIOUS
                                 else "muted"])

    def _refresh_scan_view(self):
        """Repaint the Scanning tab and the Sites 'last seen' column.

        Only does the work when the relevant page is visible — this runs once a
        second for the whole life of the process."""
        try:
            if self._cur_page == "scan":
                self._scan_panel.update_view(
                    self._scanner.overall_state(),
                    self._scanner.provider_status(),
                    self._scanner.stats(),
                    self._scanner.recent_flags())
            elif self._cur_page == "dashboard":
                self._sites_panel.tick()
        except Exception:
            pass
        if self._running:
            self.after(1000, self._refresh_scan_view)

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
                elif tag == "site":
                    self._on_site_update(item[1])
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
