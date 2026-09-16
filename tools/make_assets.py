"""
tools/make_assets.py
Generates the application icons using the canonical GUI renderer.

Run before building with PyInstaller:
    python tools/make_assets.py

Output:
    assets/proxyforce.ico  (multi-size: 256, 128, 64, 48, 32, 16 px)
    assets/proxyforce.png  (256 px)

The static neutral mark is used for Explorer, title-bar, and taskbar identity.
Both formats are generated on both platforms so the build is reproducible either
way: PyInstaller embeds the .ico in the Windows PE, and the Linux .desktop entry
points at the .png, which is the only icon format a freedesktop launcher reads.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from gui.icon_renderer import render_logo

SIZES = [256, 128, 64, 48, 32, 16]


def main():
    here       = os.path.dirname(os.path.abspath(__file__))
    assets_dir = os.path.join(here, "..", "assets")
    os.makedirs(assets_dir, exist_ok=True)
    out = os.path.join(assets_dir, "proxyforce.ico")

    frames = [render_logo(s, state="neutral", animated=False) for s in SIZES]
    frames[0].save(
        out,
        format="ICO",
        sizes=[(s, s) for s in SIZES],
        append_images=frames[1:],
    )
    print(f"[ok] {out}  ({', '.join(str(s) for s in SIZES)} px)")

    png = os.path.join(assets_dir, "proxyforce.png")
    frames[0].save(png, format="PNG")
    print(f"[ok] {png}  (256 px)")


if __name__ == "__main__":
    main()
