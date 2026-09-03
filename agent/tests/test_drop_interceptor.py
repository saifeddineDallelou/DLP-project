import threading
from unittest.mock import MagicMock, patch

import pytest

import drop_interceptor as di


@pytest.fixture(autouse=True)
def _disarmed():
    """Never leave a test armed.

    Armed state is module-level because the callback runs on the hook thread
    for every mouse event in the system and cannot afford a lock. A test that
    leaves it set would arm the next one.
    """
    di.disarm()
    di._intercepted.clear()
    yield
    di.disarm()
    di._intercepted.clear()


class _Point:
    def __init__(self, x=10, y=20):
        self.x, self.y = x, y


class _HookData:
    def __init__(self, x=10, y=20):
        self.pt = _Point(x, y)


def _lparam(x=10, y=20):
    return [_HookData(x, y)]


class TestArming:
    def test_it_starts_disarmed(self):
        assert di._armed is False

    def test_arming_records_the_targets(self):
        di.arm({1234, 5678})
        assert di._armed is True
        assert di._targets == frozenset({1234, 5678})

    def test_arming_with_nothing_stays_disarmed(self):
        # No target means nothing to protect, and an armed hook with an empty
        # target set is pure risk for no benefit.
        di.arm(set())
        assert di._armed is False

    def test_arming_ignores_null_handles(self):
        di.arm({0, 4321, None})
        assert di._targets == frozenset({4321})

    def test_disarming_clears_everything(self):
        di.arm({1234})
        di.disarm()
        assert di._armed is False
        assert di._targets == frozenset()


class TestCallback:
    """
    The callback runs for every mouse event on the machine. A bug here breaks
    clicking system-wide, so what is pinned is mostly that it gets out of the
    way.
    """

    def test_an_ordinary_click_passes_straight_through_when_disarmed(self):
        with patch.object(di, "_user32") as u32:
            u32.CallNextHookEx.return_value = 0
            assert di._callback(di._HC_ACTION, di._WM_LBUTTONUP, _lparam()) == 0
            u32.CallNextHookEx.assert_called_once()
            u32.WindowFromPoint.assert_not_called()

    def test_a_non_button_up_event_is_never_inspected(self):
        # Mouse MOVE fires constantly. Doing any work on it is how a hook
        # exceeds LowLevelHooksTimeout and gets removed by Windows.
        di.arm({999})
        with patch.object(di, "_user32") as u32:
            u32.CallNextHookEx.return_value = 0
            di._callback(di._HC_ACTION, 0x0200, _lparam())
            u32.WindowFromPoint.assert_not_called()

    def test_a_release_somewhere_else_passes_through(self):
        di.arm({999})
        with patch.object(di, "_user32") as u32:
            u32.CallNextHookEx.return_value = 0
            u32.WindowFromPoint.return_value = 111
            u32.GetAncestor.return_value = 111        # not a target
            assert di._callback(di._HC_ACTION, di._WM_LBUTTONUP, _lparam()) == 0
            u32.keybd_event.assert_not_called()

    def test_a_release_over_the_target_is_swallowed(self):
        # The whole point: the browser never learns the button came up, so
        # there is no drop to be too late for.
        di.arm({999})
        with patch.object(di, "_user32") as u32:
            u32.WindowFromPoint.return_value = 42
            u32.GetAncestor.return_value = 999
            assert di._callback(di._HC_ACTION, di._WM_LBUTTONUP, _lparam()) == 1
            u32.CallNextHookEx.assert_not_called()

    def test_swallowing_also_cancels_the_drag(self):
        # The source is still in its drag loop with the button held as far as
        # it knows; ESC is what ends it cleanly.
        di.arm({999})
        with patch.object(di, "_user32") as u32:
            u32.WindowFromPoint.return_value = 42
            u32.GetAncestor.return_value = 999
            di._callback(di._HC_ACTION, di._WM_LBUTTONUP, _lparam())
            assert u32.keybd_event.call_count == 2     # down, up

    def test_a_drop_on_a_child_control_still_counts(self):
        # A file lands on some inner element; what we know are top-level
        # windows, which is why GA_ROOT is resolved first.
        di.arm({999})
        with patch.object(di, "_user32") as u32:
            u32.WindowFromPoint.return_value = 12345   # a child
            u32.GetAncestor.return_value = 999         # its top-level window
            assert di._callback(di._HC_ACTION, di._WM_LBUTTONUP, _lparam()) == 1

    def test_a_non_action_code_is_passed_on_untouched(self):
        # Windows requires codes below HC_ACTION to be forwarded unexamined.
        di.arm({999})
        with patch.object(di, "_user32") as u32:
            u32.CallNextHookEx.return_value = 0
            assert di._callback(-1, di._WM_LBUTTONUP, _lparam()) == 0
            u32.WindowFromPoint.assert_not_called()

    def test_a_crash_inside_never_eats_a_click(self):
        # The failure that matters. A bug here must not cost the machine its
        # mouse.
        di.arm({999})
        with patch.object(di, "_user32") as u32:
            u32.WindowFromPoint.side_effect = RuntimeError("boom")
            u32.CallNextHookEx.return_value = 0
            assert di._callback(di._HC_ACTION, di._WM_LBUTTONUP, _lparam()) == 0
            u32.CallNextHookEx.assert_called_once()

    def test_it_returns_zero_if_even_the_fallback_fails(self):
        di.arm({999})
        with patch.object(di, "_user32") as u32:
            u32.WindowFromPoint.side_effect = RuntimeError("boom")
            u32.CallNextHookEx.side_effect = RuntimeError("also boom")
            assert di._callback(di._HC_ACTION, di._WM_LBUTTONUP, _lparam()) == 0


class TestInterceptionReporting:
    """
    The drag monitor reports what happened. It has to be able to tell a drop
    that was PREVENTED from one it merely cancelled after the fact.
    """

    def test_nothing_intercepted_reads_false(self):
        assert di.take_interception() is False

    def test_an_interception_is_reported_once(self):
        di.arm({999})
        with patch.object(di, "_user32") as u32:
            u32.WindowFromPoint.return_value = 42
            u32.GetAncestor.return_value = 999
            di._callback(di._HC_ACTION, di._WM_LBUTTONUP, _lparam())

        assert di.take_interception() is True
        assert di.take_interception() is False     # not a second time
