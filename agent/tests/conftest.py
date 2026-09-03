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
