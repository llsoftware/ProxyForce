"""
tools/make_assets.py
Generates assets/proxyforce.ico using Pillow.

Run before building with PyInstaller:
    python tools/make_assets.py

Output: assets/proxyforce.ico  (multi-size: 256, 128, 64, 48, 32, 16 px)

The design MUST stay identical to the in-app / tray / window icon. The numbers
below are a verbatim copy of the LOGO_* constants in gui/app.py (they are kept
in sync by hand because importing gui.app here would pull in customtkinter):
  - Dark circle background (#0D0F1A)
  - Pointed-top hexagon filled accent blue (#3B82F6) — same 60·i−90° formula
  - White centre dot, 42 % of the hexagon radius
  - Sizes < 20 px: the dot is omitted (renders as noise that small)
"""

import os
import math
from PIL import Image, ImageDraw

# ─ Keep these in lock-step with gui/app.py::LOGO_* ─
LOGO_BG       = (13,  15,  26)    # #0D0F1A
LOGO_ACCENT   = (59, 130, 246)    # #3B82F6
LOGO_INNER    = (255, 255, 255)
LOGO_R_CIRCLE = 0.47
LOGO_R_HEX    = 0.32
LOGO_R_INNER  = 0.42
LOGO_DOT_MIN  = 20

SIZES = [256, 128, 64, 48, 32, 16]


def _hex_points(cx, cy, r):
    """Pointed-top hexagon — same formula as gui/app.py::_hex_points."""
    return [(cx + r * math.cos(math.radians(60 * i - 90)),
             cy + r * math.sin(math.radians(60 * i - 90)))
            for i in range(6)]


def _render(size: int) -> Image.Image:
    ss   = size * 4          # 4× supersampling for smooth edges
    img  = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    c    = ss / 2

    cr = ss * LOGO_R_CIRCLE
    draw.ellipse([c - cr, c - cr, c + cr, c + cr], fill=LOGO_BG + (255,))

    hr = ss * LOGO_R_HEX
    draw.polygon(_hex_points(c, c, hr), fill=LOGO_ACCENT + (255,))

    if size >= LOGO_DOT_MIN:
        ir = hr * LOGO_R_INNER
        draw.ellipse([c - ir, c - ir, c + ir, c + ir], fill=LOGO_INNER + (255,))

    return img.resize((size, size), Image.LANCZOS)


def main():
    here       = os.path.dirname(os.path.abspath(__file__))
    assets_dir = os.path.join(here, "..", "assets")
    os.makedirs(assets_dir, exist_ok=True)
    out = os.path.join(assets_dir, "proxyforce.ico")

    frames = [_render(s) for s in SIZES]
    frames[0].save(
        out,
        format="ICO",
        sizes=[(s, s) for s in SIZES],
        append_images=frames[1:],
    )
    print(f"[ok] {out}  ({', '.join(str(s) for s in SIZES)} px)")


if __name__ == "__main__":
    main()
