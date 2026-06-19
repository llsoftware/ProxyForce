"""
ProxyForce — local HTTP forward-proxy shim (the Edge-update / port-80 fix).

WHY THIS EXISTS (proven 2026-06-19 against the corporate proxy + sing-box debug log):
  The corporate proxy is hardened to allow `CONNECT` only to :443 and returns
  **403 Forbidden** to `CONNECT` on :80. sing-box's `http` outbound relays ALL
  traffic — including plaintext HTTP on port 80 — via `CONNECT`, so every port-80
  request 403s. That is exactly what breaks the Microsoft Edge updater: it fetches
  its payload via Delivery Optimization over plaintext HTTP
  (`http://dl.delivery.mp.microsoft.com/filestreamingservice/...`), which 403s →
  `0x80072EFE`.

  The same proxy happily serves that identical URL as a *normal forward-proxy GET*
  (`GET http://host/path HTTP/1.1` → 200 OK). So the fix is simply to talk to the
  corporate proxy the normal way for plaintext HTTP: this module is a minimal
  loopback proxy that relays forward-proxy requests upstream (injecting the
  corporate `Proxy-Authorization`) instead of tunnelling them with CONNECT.

HOW IT IS WIRED (see singbox_controller._takeover_system_proxy):
  The Windows system proxy is set protocol-split:
      http=127.0.0.1:<this proxy>   ;   https=127.0.0.1:<sing-box mixed inbound>
  so HTTPS keeps using sing-box's native CONNECT path (fast, no regression) and only
  plaintext HTTP — low volume — comes through here.

  CONNECT is ALSO handled here (relayed upstream as CONNECT) purely as a safety net,
  in case an app ignores the protocol split and sends everything to the http= entry.

NOTES:
  * Binds 127.0.0.1 only — never exposed off-box.
  * Its socket to the corporate proxy follows the /32 "direct" route the engine pins
    for the proxy IP, so it does not loop back through the TUN.
  * Connection model: one upstream request per client connection (we force
    `Connection: close` upstream, then stream the response back until EOF). Simple,
    correct, and fine for the plaintext-HTTP volume this carries.
"""

import base64
import socket
import threading
import logging

logger = logging.getLogger("proxyforce.localproxy")

_CONNECT_TIMEOUT = 15      # seconds to establish the upstream TCP connection
_IDLE_TIMEOUT = 180        # seconds of no data before a relayed stream is abandoned
_HEAD_CAP = 64 * 1024      # max bytes of request/response head we will buffer
_BUF = 64 * 1024


class LocalForwardProxy:
    """A tiny loopback HTTP proxy that chains to an upstream HTTP proxy, relaying
    plaintext HTTP as a forward-proxy GET (not CONNECT) and tunnelling CONNECT."""

    def __init__(self, upstream_host: str, upstream_port: int,
                 username: str = "", password: str = "", on_log=None):
        self.upstream_host = upstream_host
        self.upstream_port = int(upstream_port)
        self._auth = ""
        if username:
            raw = f"{username}:{password}".encode("utf-8", "replace")
            self._auth = "Basic " + base64.b64encode(raw).decode("ascii")
        self._on_log = on_log
        self._srv = None
        self._thread = None
        self._stop = threading.Event()
        self.port = 0

    # ── lifecycle ──────────────────────────────────────────────────────────────

    def start(self, port: int = 0) -> int:
        """Bind 127.0.0.1:<port> (0 = ephemeral) and serve. Returns the bound port."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", int(port)))
        srv.listen(128)
        self.port = srv.getsockname()[1]
        self._srv = srv
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="pf-localproxy",
                                        daemon=True)
        self._thread.start()
        return self.port

    def stop(self):
        self._stop.set()
        s = self._srv
        self._srv = None
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    def _log(self, msg: str, level: str = "info"):
        logger.log(getattr(logging, level.upper(), logging.INFO), msg)
        if self._on_log:
            try:
                self._on_log(msg, level)
            except Exception:
                pass

    # ── accept loop ──────────────────────────────────────────────────────────────

    def _serve(self):
        while not self._stop.is_set():
            try:
                client, _ = self._srv.accept()
            except OSError:
                break  # listen socket closed by stop()
            threading.Thread(target=self._handle, args=(client,),
                             daemon=True).start()

    # ── per-connection handling ──────────────────────────────────────────────────

    def _handle(self, client: socket.socket):
        try:
            client.settimeout(_IDLE_TIMEOUT)
            head, overflow = self._read_head(client)
            if not head:
                return
            line0 = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
            parts = line0.split(" ")
            if len(parts) < 3:
                return
            method = parts[0].upper()
            target = parts[1]
            if method == "CONNECT":
                self._do_connect(client, target, overflow)
            else:
                self._do_forward(client, head, overflow)
        except Exception as e:
            self._log(f"local proxy: connection error: {e}", "debug")
        finally:
            _close(client)

    @staticmethod
    def _read_head(sock: socket.socket):
        """Read until the end of the HTTP head (\\r\\n\\r\\n). Returns (head, overflow)
        where overflow is any bytes already read that belong to the body."""
        data = b""
        while b"\r\n\r\n" not in data:
            if len(data) > _HEAD_CAP:
                return b"", b""
            chunk = sock.recv(_BUF)
            if not chunk:
                return (b"", b"") if not data else (data, b"")
            data += chunk
        head, overflow = data.split(b"\r\n\r\n", 1)
        return head + b"\r\n\r\n", overflow

    def _connect_upstream(self) -> socket.socket:
        up = socket.create_connection((self.upstream_host, self.upstream_port),
                                      timeout=_CONNECT_TIMEOUT)
        up.settimeout(_IDLE_TIMEOUT)
        return up

    # ── plaintext HTTP: relay as a forward-proxy request ─────────────────────────

    def _do_forward(self, client: socket.socket, head: bytes, overflow: bytes):
        """Relay `GET http://host/path …` to the upstream proxy verbatim, but strip
        the client's hop-by-hop proxy headers and inject OUR Proxy-Authorization."""
        lines = head.split(b"\r\n")
        request_line = lines[0]
        rebuilt = [request_line]
        for h in lines[1:]:
            if not h:
                continue
            low = h.lower()
            if low.startswith((b"proxy-authorization:", b"proxy-connection:",
                               b"connection:")):
                continue  # hop-by-hop / will be re-set below
            rebuilt.append(h)
        if self._auth:
            rebuilt.append(b"Proxy-Authorization: " + self._auth.encode("ascii"))
        rebuilt.append(b"Connection: close")
        rebuilt.append(b"Proxy-Connection: close")
        new_head = b"\r\n".join(rebuilt) + b"\r\n\r\n"

        try:
            up = self._connect_upstream()
        except Exception as e:
            self._log(f"local proxy: cannot reach upstream for forward request: {e}",
                      "warning")
            return
        try:
            up.sendall(new_head)
            if overflow:
                up.sendall(overflow)          # any request body already buffered
            # Relay the rest of the client's request body (if any) upstream, and the
            # upstream response back to the client, until upstream closes (we forced
            # Connection: close, so the response ends at EOF).
            t = threading.Thread(target=_pipe, args=(client, up), daemon=True)
            t.start()
            _pipe(up, client)
        finally:
            _close(up)

    # ── CONNECT (safety net for HTTPS sent to the http= entry) ───────────────────

    def _do_connect(self, client: socket.socket, target: str, overflow: bytes):
        auth = (b"Proxy-Authorization: " + self._auth.encode("ascii") + b"\r\n"
                if self._auth else b"")
        req = (b"CONNECT " + target.encode("latin1") + b" HTTP/1.1\r\n"
               + b"Host: " + target.encode("latin1") + b"\r\n"
               + auth + b"\r\n")
        try:
            up = self._connect_upstream()
        except Exception as e:
            self._log(f"local proxy: cannot reach upstream for CONNECT: {e}", "warning")
            return
        try:
            up.sendall(req)
            resp, up_overflow = self._read_head(up)
            status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else ""
            if " 200" not in status:
                # Relay the upstream's refusal to the client and stop.
                client.sendall(resp or b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if up_overflow:
                client.sendall(up_overflow)
            if overflow:
                up.sendall(overflow)
            t = threading.Thread(target=_pipe, args=(client, up), daemon=True)
            t.start()
            _pipe(up, client)
        finally:
            _close(up)


def _pipe(src: socket.socket, dst: socket.socket):
    """Copy bytes src→dst until src EOF/error, then half-close dst for writing."""
    try:
        while True:
            data = src.recv(_BUF)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def _close(sock: socket.socket):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass
