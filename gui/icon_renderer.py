"""Canonical ProxyForce logo and state-energy renderer.

This module is deliberately independent of Tk so the GUI, system tray, build
asset generator, and tests all use exactly the same geometry.
"""

import math

from PIL import Image, ImageDraw, ImageFilter


LOGO_BG = (13, 15, 26)
LOGO_ACCENT = (59, 130, 246)
LOGO_R_CIRCLE = 0.47
LOGO_R_HEX = 0.34
LOGO_R_INNER_HEX = 0.72

STATE_COLORS = {
    "neutral": (236, 241, 250),
    "running": (93, 240, 180),
    "starting": (255, 202, 44),
    "stopping": (255, 202, 44),
    "error": (255, 86, 86),
    "stopped": (170, 184, 204),
    "waiting": (170, 184, 204),
}

ANIMATION_FRAMES = {
    "running": 16,
    "starting": 16,
    "stopping": 16,
    "error": 16,
}


def normalize_state(state: str) -> str:
    state = str(state or "stopped").lower()
    return state if state in STATE_COLORS else "stopped"


def frame_count(state: str) -> int:
    return ANIMATION_FRAMES.get(normalize_state(state), 1)


def _hex_points(cx: float, cy: float, radius: float):
    return [
        (
            cx + radius * math.cos(math.radians(60 * i - 90)),
            cy + radius * math.sin(math.radians(60 * i - 90)),
        )
        for i in range(6)
    ]


def _pulse_for(state: str, phase: float) -> float:
    angle = phase * math.tau
    if state == "running":
        return 0.76 + 0.18 * (0.5 + 0.5 * math.sin(angle))
    if state in ("starting", "stopping"):
        return 0.78 + 0.14 * (0.5 + 0.5 * math.sin(angle * 2))
    if state == "error":
        # Two quick beats followed by a calmer hold.
        position = phase % 1.0
        beat1 = math.exp(-((position - 0.13) / 0.065) ** 2)
        beat2 = math.exp(-((position - 0.31) / 0.075) ** 2)
        return 0.62 + 0.34 * max(beat1, beat2)
    return 0.62


def render_logo(
    size: int,
    state: str = "neutral",
    phase: float = 0.0,
    animated: bool = False,
) -> Image.Image:
    """Return a supersampled RGBA ProxyForce badge.

    Animated variants keep all energy inside the blue hexagonal shell. The
    static ``neutral`` variant is used for Explorer, title-bar, and taskbar
    identity so connection state never changes the Windows taskbar icon.
    """
    if size < 8:
        raise ValueError("icon size must be at least 8 pixels")

    state = normalize_state(state)
    if not animated:
        phase = 0.0
    phase %= 1.0

    scale = 4
    side = size * scale
    center = side / 2
    circle_r = side * LOGO_R_CIRCLE
    hex_r = side * LOGO_R_HEX
    inner_r = hex_r * LOGO_R_INNER_HEX

    image = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse(
        [center - circle_r, center - circle_r, center + circle_r, center + circle_r],
        fill=LOGO_BG + (255,),
    )
    draw.polygon(_hex_points(center, center, hex_r), fill=LOGO_ACCENT + (255,))
    draw.polygon(
        _hex_points(center, center, inner_r),
        fill=(7, 12, 24, 255),
    )

    color = STATE_COLORS[state]
    pulse = _pulse_for(state, phase)
    energy = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    energy_draw = ImageDraw.Draw(energy)

    glow_r = inner_r * (0.62 + 0.12 * pulse)
    energy_draw.ellipse(
        [center - glow_r, center - glow_r, center + glow_r, center + glow_r],
        fill=color + (int(215 * pulse),),
    )

    if animated and state == "running":
        for index in range(3):
            angle = math.tau * (phase + index / 3)
            orbit = inner_r * 0.42
            x = center + math.cos(angle) * orbit
            y = center + math.sin(angle * 1.3) * orbit
            radius = inner_r * (0.13 if index else 0.17)
            energy_draw.ellipse(
                [x - radius, y - radius, x + radius, y + radius],
                fill=(205, 255, 235, 210),
            )
    elif animated and state in ("starting", "stopping"):
        direction = -1 if state == "stopping" else 1
        for index in range(4):
            angle = direction * math.tau * phase + index * math.pi / 2
            orbit = inner_r * (0.25 + index * 0.07)
            x = center + math.cos(angle) * orbit
            y = center + math.sin(angle) * orbit
            radius = inner_r * (0.11 + index * 0.018)
            energy_draw.ellipse(
                [x - radius, y - radius, x + radius, y + radius],
                fill=(255, 240, 170, 225 - index * 25),
            )
    elif animated and state == "error":
        spark_r = inner_r * (0.13 + 0.08 * pulse)
        for dx, dy in ((-0.28, -0.18), (0.25, 0.22)):
            x = center + inner_r * dx
            y = center + inner_r * dy
            energy_draw.ellipse(
                [x - spark_r, y - spark_r, x + spark_r, y + spark_r],
                fill=(255, 220, 220, int(210 * pulse)),
            )

    energy = energy.filter(ImageFilter.GaussianBlur(max(1, side // 45)))
    mask = Image.new("L", (side, side), 0)
    ImageDraw.Draw(mask).polygon(
        _hex_points(center, center, inner_r * 0.94),
        fill=255,
    )
    energy.putalpha(Image.composite(energy.getchannel("A"), Image.new("L", (side, side), 0), mask))
    image.alpha_composite(energy)

    # A crisp core keeps the state readable after Windows scales the tray icon.
    core_r = max(scale, inner_r * (0.27 + 0.045 * pulse))
    draw = ImageDraw.Draw(image)
    draw.ellipse(
        [center - core_r, center - core_r, center + core_r, center + core_r],
        fill=color + (255,),
    )
    highlight_r = max(1, core_r * 0.42)
    draw.ellipse(
        [
            center - core_r * 0.45 - highlight_r,
            center - core_r * 0.45 - highlight_r,
            center - core_r * 0.45 + highlight_r,
            center - core_r * 0.45 + highlight_r,
        ],
        fill=(255, 255, 255, 145),
    )

    return image.resize((size, size), Image.Resampling.LANCZOS)

