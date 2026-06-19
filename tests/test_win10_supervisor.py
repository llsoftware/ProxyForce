"""
Deterministic tests for the Windows-10 sing-box launch supervisor.

These reproduce, with the OS boundaries mocked, the exact failure the user hit
on Windows 10 and assert the v2.1.2 fix behaves correctly:

  * The known wintun bug — sing-box exits during startup with
    "configure tun interface: Cannot create a file when that file already
    exists" — is auto-retried (with stale-adapter cleanup) instead of giving up.
  * Readiness is gated ONLY on the Clash API answering, so a *stale* TUN adapter
    left behind by a crashed attempt can no longer be mistaken for a healthy
    engine (the v2.1.1 false-ACTIVE regression).
  * A genuinely non-retryable failure still fails fast (no pointless retries).
  * A leftover adapter present at preflight is cleaned up before the first launch.

Run:  python tests/test_win10_supervisor.py
"""

import os
import sys
import json as _json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.singbox_controller as sbc
from core.singbox_controller import SingBoxController, ProxyConfig, SingBoxState

# The literal FATAL line from the user's Windows-10 log.
WIN10_FATAL = ("Last log: ... WARN inbound/tun[tun-in]: open interface take too "
               "much time to finish! | FATAL start service: start inbound/tun"
               "[tun-in]: configure tun interface: Cannot create a file when "
               "that file already exists.")


class FakeProc:
    """Minimal stand-in for subprocess.Popen. `code` None = alive, int = exited."""
    def __init__(self, code):
        self._code = code
        self.returncode = code
        self.pid = 4321
        self._handle = 0          # falsy → _launch_proc skips the job-object call

    def poll(self):
        return self._code

    def terminate(self):
        pass

    def kill(self):
        pass

    def wait(self, timeout=None):
        return self.returncode


def _make_ctrl(states):
    c = SingBoxController(ProxyConfig(host="1.2.3.4", port=8080),
                          on_state_change=states.append)
    return c


class Win10SupervisorTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._p = mock.patch.object(sbc, "_singbox_dir", return_value=self.tmp)
        self._p.start()

    def tearDown(self):
        self._p.stop()

    def test_retries_then_runs(self):
        """Attempt 1 hits the wintun bug → cleanup → attempt 2 succeeds → RUNNING."""
        states = []
        c = _make_ctrl(states)
        procs = iter([FakeProc(1), FakeProc(None)])  # crash, then healthy
        c._launch_proc = mock.MagicMock(
            side_effect=lambda sb, cfg: (setattr(c, "_proc", next(procs)) or True))
        c._tun_adapter_exists = mock.MagicMock(return_value=False)  # clean preflight
        c._tail_log = mock.MagicMock(return_value=WIN10_FATAL)
        c._clash_get = mock.MagicMock(return_value={"version": "1.13"})
        c._cleanup_stale_tun = mock.MagicMock()
        c._run_steady_state = mock.MagicMock(
            side_effect=lambda: c._set_state(SingBoxState.RUNNING))

        c._supervise("sing-box.exe", "config.json")

        self.assertEqual(c._launch_proc.call_count, 2, "should retry exactly once")
        self.assertEqual(c._cleanup_stale_tun.call_count, 1, "cleanup between attempts")
        self.assertEqual(c.state, SingBoxState.RUNNING)
        self.assertNotIn(SingBoxState.ERROR, states,
                         "must not flap to ERROR on the recoverable wintun bug")

    def test_dead_proc_with_stale_adapter_is_not_ready(self):
        """v2.1.1 regression guard: a lingering adapter must NOT look 'ready'."""
        states = []
        c = _make_ctrl(states)
        c._proc = FakeProc(1)                                  # sing-box has exited
        c._tun_adapter_exists = mock.MagicMock(return_value=True)  # adapter lingers
        c._clash_get = mock.MagicMock(return_value=None)       # API never answered
        c._tail_log = mock.MagicMock(return_value=WIN10_FATAL)

        ready, exited, _tail = c._await_ready()

        self.assertFalse(ready, "a stale adapter must never be treated as ready")
        self.assertTrue(exited)

    def test_ready_only_when_clash_api_answers(self):
        """Healthy path: process alive + Clash API answering → ready."""
        states = []
        c = _make_ctrl(states)
        c._proc = FakeProc(None)                               # alive
        c._clash_get = mock.MagicMock(return_value={"version": "1.13"})

        ready, exited, _tail = c._await_ready()

        self.assertTrue(ready)
        self.assertFalse(exited)

    def test_nonretryable_failure_fails_fast(self):
        """A non-wintun startup failure must NOT be retried."""
        states = []
        c = _make_ctrl(states)
        c._launch_proc = mock.MagicMock(
            side_effect=lambda sb, cfg: (setattr(c, "_proc", FakeProc(1)) or True))
        c._tun_adapter_exists = mock.MagicMock(return_value=False)
        c._tail_log = mock.MagicMock(return_value="FATAL bad outbound configuration")
        c._cleanup_stale_tun = mock.MagicMock()
        c._run_steady_state = mock.MagicMock()

        c._supervise("sing-box.exe", "config.json")

        self.assertEqual(c._launch_proc.call_count, 1, "no retry on a non-wintun error")
        self.assertEqual(c._cleanup_stale_tun.call_count, 0)
        self.assertEqual(c.state, SingBoxState.ERROR)

    def test_preflight_cleans_leftover_adapter(self):
        """A leftover adapter detected at preflight is cleaned before launch."""
        states = []
        c = _make_ctrl(states)
        c._launch_proc = mock.MagicMock(
            side_effect=lambda sb, cfg: (setattr(c, "_proc", FakeProc(None)) or True))
        c._tun_adapter_exists = mock.MagicMock(return_value=True)   # leftover present
        c._clash_get = mock.MagicMock(return_value={"version": "1.13"})
        c._cleanup_stale_tun = mock.MagicMock()
        c._run_steady_state = mock.MagicMock(
            side_effect=lambda: c._set_state(SingBoxState.RUNNING))

        c._supervise("sing-box.exe", "config.json")

        self.assertGreaterEqual(c._cleanup_stale_tun.call_count, 1,
                                "preflight must clean the leftover adapter")
        self.assertEqual(c._launch_proc.call_count, 1, "first attempt then succeeds")
        self.assertEqual(c.state, SingBoxState.RUNNING)

    def test_retryable_classifier(self):
        """The exact Win-10 FATAL string is classified retryable; noise is not."""
        self.assertTrue(SingBoxController._is_retryable_tun_error(WIN10_FATAL))
        self.assertTrue(SingBoxController._is_retryable_tun_error(
            "configure tun interface: The device is not ready for use."))
        self.assertFalse(SingBoxController._is_retryable_tun_error(
            "FATAL bad outbound configuration"))
        self.assertFalse(SingBoxController._is_retryable_tun_error(""))


class _VersionHandler(BaseHTTPRequestHandler):
    """Tiny stand-in for the sing-box Clash API: answers /version on loopback."""
    def do_GET(self):
        body = _json.dumps({"version": "1.13.12"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class ClashApiProxyBypassTest(unittest.TestCase):
    """Regression guard for the v2.1.4 fix: the readiness/stats probe must reach
    the loopback Clash API even when a (corporate) system proxy is configured.

    This reproduces the real Windows-10 failure: with a system proxy set and no
    localhost bypass, urllib.request.urlopen() routed the 127.0.0.1 probe THROUGH
    the proxy → it never answered → a healthy sing-box was killed ~30s after
    launch and the dashboard stayed at zero. _clash_get must bypass the proxy.
    """

    def setUp(self):
        self.srv = HTTPServer(("127.0.0.1", 0), _VersionHandler)
        self.port = self.srv.server_address[1]
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()
        # A proxy that points nowhere usable. If _clash_get honored it, the probe
        # would fail (the whole bug); bypassing it, the probe reaches the server.
        self._saved = {k: os.environ.get(k) for k in
                       ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")}
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:9"
        os.environ["http_proxy"] = "http://127.0.0.1:9"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_clash_get_bypasses_system_proxy(self):
        c = SingBoxController(ProxyConfig(host="1.2.3.4", port=8080))
        c._clash_port = self.port
        result = c._clash_get("/version")
        self.assertIsNotNone(
            result, "readiness probe must reach the loopback Clash API despite a "
                    "configured system proxy (the v2.1.4 fix)")
        self.assertEqual(result.get("version"), "1.13.12")


if __name__ == "__main__":
    unittest.main(verbosity=2)
