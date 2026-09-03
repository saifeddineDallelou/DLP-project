import json
import threading
import time
import urllib.error
import urllib.request

import pytest

import browser_sensor
from browser_sensor import STATE, start_browser_sensor

# The sensor exists because every other detection tier reads WINDOW titles and
# a browser puts every tab in one window. Three failures came out of that
# mismatch during live testing -- a renamed tab going invisible, an
# accessibility tree Opera does not expose, and a remembered window that kept
# blocking after its AI tab was closed. This is the component that makes the
# answer a fact instead of a guess, so what is tested here is mostly that it
# cannot be lied to and cannot get stuck.

EXT_ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"


@pytest.fixture(scope="module")
def sensor():
    """One server for the module.

    Per-test start/stop on a fixed port is flaky: the socket is still in
    TIME_WAIT when the next test binds it, start_browser_sensor logs the
    clash and returns a dummy, and the requests then hit whichever server is
    actually still up. The state is reset per test instead.
    """
    stop = threading.Event()
    port = 8799
    start_browser_sensor(stop, port=port)
    time.sleep(0.3)
    yield f"http://127.0.0.1:{port}"
    stop.set()
    time.sleep(0.3)


@pytest.fixture(autouse=True)
def _clean_state():
    STATE.record(None, "")
    with STATE._lock:
        STATE._last_contact = 0.0      # "the extension has never checked in"
    yield


def post(base, payload, origin=EXT_ORIGIN):
    req = urllib.request.Request(
        f"{base}/tab",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **({"Origin": origin} if origin else {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


class TestReporting:
    def test_an_active_ai_tab_becomes_the_detected_platform(self, sensor):
        status, _ = post(sensor, {"platform": "OPENAI_CHATGPT", "detail": "chatgpt.com"})
        assert status == 200
        assert STATE.current() == ("OPENAI_CHATGPT", "chatgpt.com")

    def test_a_null_platform_clears_it(self, sensor):
        post(sensor, {"platform": "OPENAI_CHATGPT", "detail": "chatgpt.com"})
        post(sensor, {"platform": None, "detail": ""})
        # This is the case the window tiers get wrong: the tab was CLOSED and
        # the browser window is still open. The extension knows; a title does
        # not.
        assert STATE.current() == (None, "")

    def test_the_sensor_reads_as_live_once_it_has_reported(self, sensor):
        # Before any report the agent must NOT treat the extension as present,
        # or it would trust "no AI tab" from a browser that never spoke.
        assert STATE.is_live() is False
        post(sensor, {"platform": None, "detail": ""})
        assert STATE.is_live() is True

    def test_a_stale_report_stops_counting(self, sensor):
        post(sensor, {"platform": "OPENAI_CHATGPT", "detail": "chatgpt.com"})
        # Age the report past its TTL. A browser that closed, crashed or had
        # the extension disabled must stop pinning detection to whatever it
        # last said.
        with STATE._lock:
            STATE._reported_at -= (browser_sensor._REPORT_TTL + 1)
        assert STATE.current() == (None, "")

    def test_health_distinguishes_no_ai_tab_from_no_extension(self, sensor):
        # Both are `platform: null` on the wire. An operator checking whether
        # the extension actually installed needs to tell them apart, and so
        # does anyone debugging why nothing is being blocked.
        with urllib.request.urlopen(f"{sensor}/health", timeout=3) as r:
            before = json.loads(r.read())
        assert before["extensionConnected"] is False
        assert before["secondsSinceReport"] is None

        post(sensor, {"platform": None, "detail": ""})
        with urllib.request.urlopen(f"{sensor}/health", timeout=3) as r:
            after = json.loads(r.read())
        assert after["platform"] is None          # still no AI tab...
        assert after["extensionConnected"] is True  # ...but something is watching
        assert after["secondsSinceReport"] is not None

    def test_health_reports_what_it_currently_believes(self, sensor):
        post(sensor, {"platform": "ANTHROPIC_CLAUDE", "detail": "claude.ai"})
        with urllib.request.urlopen(f"{sensor}/health", timeout=3) as r:
            body = json.loads(r.read())
        assert body["platform"] == "ANTHROPIC_CLAUDE"


class TestItCannotBeLiedTo:
    def test_an_ordinary_web_page_cannot_report(self, sensor):
        # The important direction is NEGATIVE: a page that could POST
        # platform=null would switch the agent's blocking off for any site
        # that felt like it.
        status, _ = post(sensor, {"platform": None}, origin="https://evil.example")
        assert status == 403
        assert STATE.current() == (None, "")

    def test_a_page_cannot_fake_an_ai_tab_either(self, sensor):
        status, _ = post(sensor, {"platform": "OPENAI_CHATGPT", "detail": "x"},
                         origin="https://evil.example")
        assert status == 403
        assert STATE.current() == (None, "")

    def test_a_request_with_no_origin_is_refused(self, sensor):
        status, _ = post(sensor, {"platform": "OPENAI_CHATGPT"}, origin=None)
        assert status == 403

    def test_malformed_json_is_rejected_not_crashed_on(self, sensor):
        req = urllib.request.Request(
            f"{sensor}/tab", data=b"{not json",
            headers={"Content-Type": "application/json", "Origin": EXT_ORIGIN},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=3) as r:
                status = r.status
        except urllib.error.HTTPError as e:
            status = e.code
        assert status == 400

    def test_a_non_string_platform_is_rejected(self, sensor):
        status, _ = post(sensor, {"platform": {"nested": "object"}})
        assert status == 400

    def test_an_unknown_path_is_a_404(self, sensor):
        req = urllib.request.Request(f"{sensor}/anything", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=3) as r:
                status = r.status
        except urllib.error.HTTPError as e:
            status = e.code
        assert status == 404


class TestDeployment:
    def test_a_port_clash_does_not_take_the_agent_down(self):
        # Without the extension the agent falls back to window titles, which
        # is exactly how it behaved before this existed. A busy port must
        # degrade, not crash the process at startup.
        stop = threading.Event()
        port = 8798
        first = start_browser_sensor(stop, port=port)
        time.sleep(0.2)
        second = start_browser_sensor(threading.Event(), port=port)  # clashes
        assert second is not None
        stop.set()
        time.sleep(0.2)
        assert first is not None
