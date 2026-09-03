import sys

import pytest


@pytest.fixture(autouse=True)
def _reset_repeat_windows():
    """Give every test a clean repeat window.

    The windows are deliberately module-level: a real agent runs for days and
    has to remember what it already reported, across every drag and every
    capture. In a single test process that memory leaks between tests -- the
    second test to use the same content looks like a repeat of the first and
    files nothing, so it passes or fails for reasons that have nothing to do
    with what it is testing.

    Reset here rather than in each test, because a test that forgets is a test
    that silently stops checking anything.
    """
    import repeat_window

    for module_name in ("drag_drop_monitor", "file_dialog_monitor", "screenshot_monitor"):
        module = sys.modules.get(module_name)
        window = getattr(module, "_REPEATS", None) if module else None
        if isinstance(window, repeat_window.RepeatWindow):
            window.__init__(window._cooldown)
    yield


@pytest.fixture(autouse=True)
def _reset_browser_sensor_state():
    """Forget what the extension last reported.

    STATE is process-wide because a real agent has one browser sensor. In a
    test process it leaks: the sensor's own tests set a platform, and the
    file-dialog tests -- which now consult the sensor before falling back to
    the address bar -- then found a platform already reported and never
    reached the fallback they exist to test. They passed alone and failed
    together, which is the worst way for a test to be wrong.
    """
    import browser_sensor

    browser_sensor.STATE.record(None, "")
    with browser_sensor.STATE._lock:
        browser_sensor.STATE._last_contact = 0.0
    yield

