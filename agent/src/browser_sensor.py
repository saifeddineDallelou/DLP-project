"""
Browser sensor -- the agent's local listener for the DLP browser extension.

WHY THIS EXISTS
Every other way this agent identifies an AI platform reads WINDOW titles, and
a browser puts every tab in one window. That mismatch is not a detail; it is
the source of three separate failures found by testing:

  * ChatGPT rewrites document.title to the conversation topic the moment you
    send a message, so a tab in active use -- the only state it is ever in
    when someone actually pastes customer data into it -- stops matching.
  * The address-bar fallback that was meant to cover that cannot run on every
    browser. Opera exposes seven accessibility nodes for its entire window
    and not one Edit control, so there is nothing to read.
  * Remembering a window that once identified itself patches the rename, but
    a window is not a tab: close the ChatGPT tab and the browser window is
    still open, so the memory keeps blocking pastes that are not going
    anywhere.

None of those are solvable from outside the browser, which is why commercial
DLP (Purview, Netskope) ships an extension rather than guessing from titles.

WHAT IT DOES
The extension reports the active tab -- and nothing else. It sends no page
content, no keystrokes, no browsing history: one platform name, or null.
Enforcement stays exactly where it was, in the agent. This turns
_detect_platform's best guess into a fact for browsers where the extension is
installed, and changes nothing else about how a block is decided.

WHY A LOCAL HTTP LISTENER
Native messaging would avoid the port but needs a registry entry and a host
manifest installed per browser and per user, which makes the extension far
harder to deploy than the thing it is fixing. A loopback listener needs
neither.

SECURITY
  * Bound to 127.0.0.1 -- never reachable off the machine.
  * Only accepts requests whose Origin is a browser extension, so an ordinary
    web page cannot drive the agent's detection by fetching localhost.
  * Read-only: the endpoint stores a platform name and a timestamp. There is
    nothing here to command.
"""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from loguru import logger

# The agent trusts a report for this long. The extension re-sends every few
# seconds, so a browser that is closed, crashes, or has the extension disabled
# stops being authoritative quickly rather than pinning detection to whatever
# it last said.
_REPORT_TTL = 15.0

# Below this, the sensor counts as absent and the agent falls back to its
# window-title tiers. Slightly longer than the TTL so a single missed
# heartbeat does not flap the whole detection strategy.
_SENSOR_TTL = 30.0

_DEFAULT_PORT = int(os.environ.get("BROWSER_SENSOR_PORT", "8765"))

# Only a browser extension may report. A page at evil.example fetching
# 127.0.0.1 carries its own http(s) origin and is refused -- otherwise any
# site could tell the agent an AI tab is open, or that none is.
_ALLOWED_ORIGIN_PREFIXES = ("chrome-extension://", "moz-extension://", "extension://")


class _SensorState:
    """Latest report from the extension, and when it arrived."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._platform: str | None = None
        self._detail: str = ""
        self._reported_at: float = 0.0
        self._last_contact: float = 0.0

    def record(self, platform: str | None, detail: str) -> None:
        with self._lock:
            self._platform = platform or None
            self._detail = detail or ""
            self._reported_at = time.monotonic()
            self._last_contact = self._reported_at

    def current(self) -> tuple[str | None, str]:
        """The active AI platform per the browser, or (None, "")."""
        with self._lock:
            if not self._platform:
                return None, ""
            if time.monotonic() - self._reported_at > _REPORT_TTL:
                return None, ""
            return self._platform, self._detail

    def is_live(self) -> bool:
        """Has the extension checked in recently?

        This is what decides whether the agent's guessing tiers are still
        needed. When the extension is present its answer is authoritative for
        browsers -- including when the answer is "no AI tab open", which is
        the case the window-title tiers get wrong.
        """
        with self._lock:
            return bool(self._last_contact) and (
                time.monotonic() - self._last_contact <= _SENSOR_TTL
            )


STATE = _SensorState()


class _Handler(BaseHTTPRequestHandler):
    # The extension keeps a connection warm across heartbeats; without
    # HTTP/1.1 every report pays a fresh TCP handshake.
    protocol_version = "HTTP/1.1"
    # BaseHTTPRequestHandler logs every request to stderr; the agent has its
    # own logger and does not want a line per heartbeat.
    def log_message(self, *_args) -> None:
        return

    def _json(self, code: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        origin = self.headers.get("Origin", "")
        if origin.startswith(_ALLOWED_ORIGIN_PREFIXES):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:      # noqa: N802 -- http.server naming
        self._json(204, {})

    def do_GET(self) -> None:          # noqa: N802
        if self.path != "/health":
            return self._json(404, {"error": "not found"})
        plat, detail = STATE.current()
        self._json(200, {"status": "ok", "platform": plat, "detail": detail})

    def _read_body(self) -> bytes:
        """Always consume the request body, whatever the answer will be.

        Replying to a POST without draining it resets the connection instead
        of returning the status -- so every rejection below would have reached
        the caller as a socket error rather than a 400 or a 403.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        return self.rfile.read(length) if length > 0 else b""

    def do_POST(self) -> None:         # noqa: N802
        raw = self._read_body()

        if self.path != "/tab":
            return self._json(404, {"error": "not found"})

        origin = self.headers.get("Origin", "")
        if not origin.startswith(_ALLOWED_ORIGIN_PREFIXES):
            # An ordinary web page must not be able to steer detection --
            # neither into blocking nor, more importantly, out of it.
            return self._json(403, {"error": "extension origin required"})

        try:
            body = json.loads(raw or b"{}")
        except Exception:
            return self._json(400, {"error": "invalid JSON"})
        if not isinstance(body, dict):
            return self._json(400, {"error": "body must be an object"})

        platform = body.get("platform")
        if platform is not None and not isinstance(platform, str):
            return self._json(400, {"error": "platform must be a string or null"})

        # `detail` is for the incident record: which site, not which page. The
        # extension sends a hostname, never a full URL -- a URL carries the
        # conversation in its path and query, and this agent does not collect
        # browsing history.
        detail = body.get("detail")
        detail = detail if isinstance(detail, str) else ""

        STATE.record(platform, detail[:120])
        self._json(200, {"ok": True})


def start_browser_sensor(stop: threading.Event, port: int = _DEFAULT_PORT):
    """Serve the extension endpoint on loopback until `stop` is set."""
    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    except OSError as exc:
        # Not fatal. Without the extension the agent falls back to its
        # window-title tiers, which is exactly how it behaved before.
        logger.error(
            f"[BROWSER-SENSOR] Could not bind 127.0.0.1:{port} ({exc}) -- "
            f"falling back to window-title detection"
        )
        return threading.Thread(target=lambda: None, daemon=True)

    server.daemon_threads = True

    def _serve():
        try:
            server.serve_forever(poll_interval=0.5)
        finally:
            server.server_close()

    def _wait_to_close():
        stop.wait()
        server.shutdown()

    t = threading.Thread(target=_serve, daemon=True, name="browser-sensor")
    t.start()
    threading.Thread(target=_wait_to_close, daemon=True, name="browser-sensor-stop").start()

    logger.info(
        f"[BROWSER-SENSOR] Listening on 127.0.0.1:{port} "
        f"(exact AI-tab detection once the extension is installed)"
    )
    return t
