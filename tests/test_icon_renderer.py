"""Tests for the shared static and state-aware ProxyForce icon renderer."""

import unittest

from gui.icon_renderer import STATE_COLORS, frame_count, render_logo


class IconRendererTests(unittest.TestCase):

    def test_all_state_icons_are_rgba_at_requested_size(self):
        for state in ("neutral", "running", "starting", "stopping",
                      "error", "stopped", "waiting"):
            image = render_logo(64, state, phase=0.25, animated=True)
            self.assertEqual(image.mode, "RGBA")
            self.assertEqual(image.size, (64, 64))

    def test_outer_badge_is_transparent_and_center_opaque(self):
        image = render_logo(64, "neutral")
        self.assertEqual(image.getpixel((0, 0))[3], 0)
        self.assertEqual(image.getpixel((32, 32))[3], 255)

    def test_center_uses_state_color(self):
        for state in ("running", "starting", "error", "stopped", "waiting"):
            image = render_logo(64, state)
            actual = image.getpixel((32, 32))[:3]
            expected = STATE_COLORS[state]
            self.assertTrue(all(abs(a - e) <= 3 for a, e in zip(actual, expected)),
                            (state, actual, expected))

    def test_animated_states_change_but_stopped_is_static(self):
        for state in ("running", "starting", "stopping", "error"):
            first = render_logo(64, state, phase=0.0, animated=True)
            later = render_logo(64, state, phase=0.31, animated=True)
            self.assertNotEqual(first.tobytes(), later.tobytes(), state)
            self.assertGreater(frame_count(state), 1)

        first = render_logo(64, "stopped", phase=0.0, animated=True)
        later = render_logo(64, "stopped", phase=0.75, animated=True)
        self.assertEqual(first.tobytes(), later.tobytes())
        self.assertEqual(frame_count("stopped"), 1)

    def test_static_taskbar_logo_is_phase_invariant(self):
        first = render_logo(48, "neutral", phase=0.0, animated=False)
        later = render_logo(48, "neutral", phase=0.75, animated=False)
        self.assertEqual(first.tobytes(), later.tobytes())

    def test_tiny_invalid_size_is_rejected(self):
        with self.assertRaises(ValueError):
            render_logo(7)


if __name__ == "__main__":
    unittest.main(verbosity=2)

