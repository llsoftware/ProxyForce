"""
Auto-bypass tests (v2.2.2).

Diagnosed 2026-08-08: a corporate proxy refused CONNECT to an internal host on an
arbitrary port unrelated to any documented case (not mail/Outlook) — ProxyForce is
used against many different corporate proxy policies, so it now notices an EXPLICIT
refusal (a real non-2xx status back from the proxy) and routes that destination
DIRECT automatically, rather than requiring the user to read a diagnostics message
and manually edit the Bypass List.

Two layers are tested:
  * core.auto_bypass.extract_rejections — the pure (host, port, code) parser.
  * SingBoxController._check_auto_bypass — the integration: dedup against the
    existing bypass list and across repeated ticks, batching multiple new hosts
    into a single on_auto_bypass call, and never firing on a dial-timeout line
    (a different failure mode with a different, correct diagnosis — see
    tests/test_proxy_reachability.py).

Run:  python tests/test_auto_bypass.py
"""

import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import auto_bypass
from core import singbox_controller
from core.singbox_controller import SingBoxController, ProxyConfig

REJECTION_LINE = (
    "-0700 2026-08-08 10:25:56 ERROR [1929908630 614ms] connection: open connection "
    "to docker.illo.secure:1688 using outbound/http[proxy-out]: unexpected status: "
    "403 Forbidden")

DIAL_TIMEOUT_LINE = (
    "-0700 2026-08-08 10:25:07 ERROR [3918389240 5.0s] connection: open connection "
    "to 192.168.48.76:7680 using outbound/direct[direct]: dial tcp "
    "192.168.48.76:7680: i/o timeout")


class ExtractRejectionsTests(unittest.TestCase):

    def test_extracts_host_port_code_from_a_real_rejection_line(self):
        self.assertEqual(auto_bypass.extract_rejections([REJECTION_LINE]),
                         [("docker.illo.secure", 1688, 403)])

    def test_dial_timeout_line_is_not_a_rejection(self):
        """A dial timeout is a DIFFERENT failure mode (unreachable, not refused) —
        must never be mistaken for an explicit policy refusal."""
        self.assertEqual(auto_bypass.extract_rejections([DIAL_TIMEOUT_LINE]), [])

    def test_multiple_lines_all_extracted(self):
        other = REJECTION_LINE.replace("docker.illo.secure:1688", "other.host:9999") \
                              .replace("403 Forbidden", "407 Proxy Authentication Required")
        result = auto_bypass.extract_rejections([REJECTION_LINE, other])
        self.assertEqual(result, [("docker.illo.secure", 1688, 403),
                                  ("other.host", 9999, 407)])

    def test_empty_and_none_inputs_are_safe(self):
        self.assertEqual(auto_bypass.extract_rejections([]), [])
        self.assertEqual(auto_bypass.extract_rejections(None), [])

    def test_unrelated_line_yields_nothing(self):
        self.assertEqual(auto_bypass.extract_rejections(["INFO: all fine here"]), [])


class CheckAutoBypassIntegrationTests(unittest.TestCase):
    """Exercises SingBoxController._check_auto_bypass with the real log file read
    (redirected to a temp dir) but no real engine/network/restart involved —
    on_auto_bypass is just a list-recording stub."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_singbox_dir = singbox_controller._singbox_dir
        singbox_controller._singbox_dir = lambda: self._tmp

    def tearDown(self):
        singbox_controller._singbox_dir = self._orig_singbox_dir
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_log(self, lines):
        with open(os.path.join(self._tmp, "singbox.log"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def _controller(self, auto_bypass_enabled=True, bypass_list=None):
        calls = []
        cfg = ProxyConfig(host="203.0.113.10", port=800,
                          bypass_list=bypass_list or [],
                          auto_bypass=auto_bypass_enabled)
        c = SingBoxController(cfg, on_auto_bypass=lambda hosts: calls.append(hosts))
        return c, calls

    def test_new_rejection_triggers_callback_with_the_host(self):
        self._write_log([REJECTION_LINE])
        c, calls = self._controller()
        c._check_auto_bypass()
        self.assertEqual(calls, [["docker.illo.secure"]])

    def test_dial_timeout_never_triggers_a_bypass(self):
        self._write_log([DIAL_TIMEOUT_LINE])
        c, calls = self._controller()
        c._check_auto_bypass()
        self.assertEqual(calls, [])

    def test_already_bypassed_host_does_not_retrigger(self):
        self._write_log([REJECTION_LINE])
        c, calls = self._controller(bypass_list=["docker.illo.secure"])
        c._check_auto_bypass()
        self.assertEqual(calls, [])

    def test_disabled_by_config_never_fires(self):
        self._write_log([REJECTION_LINE])
        c, calls = self._controller(auto_bypass_enabled=False)
        c._check_auto_bypass()
        self.assertEqual(calls, [])

    def test_repeated_ticks_for_the_same_host_fire_only_once(self):
        """A rejection line keeps reappearing in the log tail until enough newer
        lines push it out — must not re-trigger the callback/restart request on
        every subsequent tick while a restart is still pending."""
        self._write_log([REJECTION_LINE])
        c, calls = self._controller()
        c._check_auto_bypass()
        c._check_auto_bypass()
        c._check_auto_bypass()
        self.assertEqual(len(calls), 1)

    def test_multiple_new_hosts_in_one_tick_batch_into_a_single_call(self):
        other = REJECTION_LINE.replace("docker.illo.secure:1688", "other.host:9999")
        self._write_log([REJECTION_LINE, other])
        c, calls = self._controller()
        c._check_auto_bypass()
        self.assertEqual(len(calls), 1)
        self.assertEqual(sorted(calls[0]), ["docker.illo.secure", "other.host"])

    def test_normalization_reuses_normalize_bypass_entry(self):
        """A wildcard/mixed-case host from the log must normalize the same way
        Settings does (one source of truth) — not a separate reimplementation."""
        weird = REJECTION_LINE.replace("docker.illo.secure", "DOCKER.ILLO.SECURE")
        self._write_log([weird])
        c, calls = self._controller()
        c._check_auto_bypass()
        self.assertEqual(calls, [["docker.illo.secure"]])

    def test_no_rejections_means_no_callback(self):
        self._write_log(["INFO: everything is fine"])
        c, calls = self._controller()
        c._check_auto_bypass()
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
