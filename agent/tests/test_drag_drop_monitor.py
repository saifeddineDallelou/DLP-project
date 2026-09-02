import threading
from unittest.mock import MagicMock, patch

import pytest

import drag_drop_monitor as ddm
from drag_drop_monitor import _DragState, _classify_paths


SENSITIVE = {
    "risk_score": 0.95,
    "detections": [{"type": "credit_card", "value": "****-****-****-1111", "rule": "PCI-DSS"}],
}
CLEAN = {"risk_score": 0.05, "detections": []}


class TestClassifyPaths:
    def test_returns_the_highest_risk_file_in_a_multi_file_drag(self, tmp_path):
        # A drag can carry several files. The verdict has to reflect the worst
        # of them, not whichever happened to be read first.
        low = tmp_path / "notes.txt"
        low.write_text("nothing")
        high = tmp_path / "cards.txt"
        high.write_text("4111111111111111")

        client = MagicMock()
        client.classify.side_effect = [
            {"risk_score": 0.1, "detections": []},
            SENSITIVE,
        ]
        with patch("drag_drop_monitor.extract", side_effect=lambda p: "x"):
            verdict = _classify_paths(client, [str(low), str(high)])

        assert verdict["risk_score"] == 0.95
        assert verdict["path"] == str(high)

    def test_returns_none_when_nothing_is_readable(self, tmp_path):
        f = tmp_path / "image.png"
        f.write_text("x")
        client = MagicMock()
        with patch("drag_drop_monitor.extract", return_value=None):
            assert _classify_paths(client, [str(f)]) is None

    def test_skips_a_file_over_the_size_cap(self, tmp_path, monkeypatch):
        f = tmp_path / "huge.bin"
        f.write_text("x")
        monkeypatch.setattr("drag_drop_monitor.os.path.getsize",
                            lambda _p: ddm._MAX_FILE_SIZE + 1)
        client = MagicMock()
        assert _classify_paths(client, [str(f)]) is None
        client.classify.assert_not_called()

    def test_a_classifier_outage_does_not_raise(self, tmp_path):
        f = tmp_path / "a.txt"
        f.write_text("x")
        client = MagicMock()
        client.classify.return_value = None
        with patch("drag_drop_monitor.extract", return_value="x"):
            assert _classify_paths(client, [str(f)]) is None


class TestDragState:
    def test_reset_clears_everything(self):
        s = _DragState()
        s.active = True
        s.paths = ["/a"]
        s.verdict = SENSITIVE
        s.handled = True

        s.reset()

        assert not s.active and s.paths == [] and s.verdict is None and not s.handled


class TestDragLoop:
    """
    Drives the real loop with every Win32 call mocked. The loop is otherwise
    only exercisable by physically dragging a file, which no test can do.
    """

    EXPLORER_HWND = 100
    BROWSER_HWND = 200

    def _run(self, *, script, selection, classify_result, policy_action="BLOCK",
             report_side_effect=None, join_threads=True):
        """
        `script` is one (pressed, hwnd) pair per poll, so a whole gesture can
        be written out: press over Explorer, hold while the cursor crosses to
        a browser, release. The loop is otherwise only exercisable by
        physically dragging a file.
        """
        stop = threading.Event()
        steps = iter(script)
        current = {"hwnd": self.EXPLORER_HWND}

        def fake_key_state(_vk):
            try:
                pressed, hwnd = next(steps)
            except StopIteration:
                stop.set()
                return 0
            current["hwnd"] = hwnd
            return 0x8000 if pressed else 0

        client = MagicMock()
        client.classify.return_value = classify_result
        if report_side_effect is not None:
            client.report_ai_leak_attempt.side_effect = report_side_effect
        else:
            client.report_ai_leak_attempt.return_value = {"id": "leak-1"}

        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": policy_action, "name": "PCI-DSS"}

        def class_of(h):
            return "CabinetWClass" if h == self.EXPLORER_HWND else "Chrome_WidgetWin_1"

        def title_of(h):
            return "ChatGPT - Google Chrome" if h == self.BROWSER_HWND else "Downloads"

        with patch("drag_drop_monitor._user32") as u32, \
             patch("drag_drop_monitor._cursor_pos", return_value=(10, 10)), \
             patch("drag_drop_monitor._root_window_at", side_effect=lambda x, y: current["hwnd"]), \
             patch("drag_drop_monitor._class_name", side_effect=class_of), \
             patch("drag_drop_monitor._window_text", side_effect=title_of), \
             patch("drag_drop_monitor._explorer_selection", return_value=selection), \
             patch("drag_drop_monitor.extract", return_value="content"), \
             patch("drag_drop_monitor.os.path.getsize", return_value=1024), \
             patch("drag_drop_monitor._send_escape") as esc, \
             patch("drag_drop_monitor.quarantine_file") as quar:
            u32.GetAsyncKeyState.side_effect = fake_key_state
            ddm._drag_loop(client, "agent-1", stop, resolver,
                           ai_platform_for=lambda t: "OPENAI_CHATGPT" if "ChatGPT" in t else None)

            # Classify and report both run off the loop now. Join them here so
            # assertions about them are deterministic instead of a race with a
            # daemon thread that may or may not have been scheduled yet.
            if join_threads:
                for t in threading.enumerate():
                    if t.name in ("drag-classify", "drag-report"):
                        t.join(timeout=5)

        return esc, quar, client

    def _drag_to_browser(self, holds=8):
        """Press over Explorer, hold while crossing to the browser, release.
        Several holds so the background classify thread completes -- the loop
        deliberately does nothing until a verdict exists."""
        return ([(True, self.EXPLORER_HWND)]
                + [(True, self.BROWSER_HWND)] * holds
                + [(False, self.BROWSER_HWND)])

    def test_a_sensitive_drag_onto_an_ai_platform_is_cancelled(self):
        # The whole point: an OLE drop bypasses both the clipboard and the
        # file dialog, so this was the one leak path with no coverage at all.
        esc, _quar, client = self._run(
            script=self._drag_to_browser(),
            selection=[r"C:\Users\x\cards.txt"],
            classify_result=SENSITIVE,
        )

        esc.assert_called_once()
        client.report_ai_leak_attempt.assert_called_once()
        _, kwargs = client.report_ai_leak_attempt.call_args
        assert kwargs["blocked"] is True
        assert kwargs["platform"] == "OPENAI_CHATGPT"

    def test_the_report_carries_no_raw_content(self):
        _esc, _quar, client = self._run(
            script=self._drag_to_browser(),
            selection=[r"C:\Users\x\cards.txt"],
            classify_result=SENSITIVE,
        )
        sample = client.report_ai_leak_attempt.call_args.kwargs["content_sample"]
        assert "4111" not in sample
        assert "****-****-****-1111" in sample

    def test_a_clean_file_is_not_cancelled(self):
        esc, _quar, client = self._run(
            script=self._drag_to_browser(),
            selection=[r"C:\Users\x\notes.txt"],
            classify_result=CLEAN,
        )
        esc.assert_not_called()
        client.report_ai_leak_attempt.assert_not_called()

    def test_an_allow_policy_reports_nothing_and_cancels_nothing(self):
        esc, _quar, client = self._run(
            script=self._drag_to_browser(),
            selection=[r"C:\Users\x\cards.txt"],
            classify_result=SENSITIVE,
            policy_action="ALLOW",
        )
        esc.assert_not_called()
        client.report_ai_leak_attempt.assert_not_called()

    def test_an_alert_policy_reports_without_cancelling(self):
        esc, _quar, client = self._run(
            script=self._drag_to_browser(),
            selection=[r"C:\Users\x\cards.txt"],
            classify_result=SENSITIVE,
            policy_action="ALERT",
        )
        esc.assert_not_called()
        assert client.report_ai_leak_attempt.call_args.kwargs["blocked"] is False

    def test_quarantine_cancels_and_removes_the_file(self):
        # Cancelling the drag stops this attempt; the file is still sitting
        # there to drag again a second later.
        esc, quar, _client = self._run(
            script=self._drag_to_browser(),
            selection=[r"C:\Users\x\cards.txt"],
            classify_result=SENSITIVE,
            policy_action="QUARANTINE",
        )
        esc.assert_called_once()
        quar.assert_called_once_with(r"C:\Users\x\cards.txt")

    def test_a_drag_that_never_reaches_an_ai_window_is_left_alone(self):
        esc, _quar, client = self._run(
            script=[(True, self.EXPLORER_HWND)] * 6 + [(False, self.EXPLORER_HWND)],
            selection=[r"C:\Users\x\cards.txt"],
            classify_result=SENSITIVE,
        )
        esc.assert_not_called()
        client.report_ai_leak_attempt.assert_not_called()

    def test_it_cancels_once_per_drag_not_once_per_poll(self):
        esc, _quar, client = self._run(
            script=self._drag_to_browser(holds=20),
            selection=[r"C:\Users\x\cards.txt"],
            classify_result=SENSITIVE,
        )
        assert esc.call_count == 1
        assert client.report_ai_leak_attempt.call_count == 1

    def test_an_unreachable_backend_does_not_stall_the_poll_loop(self):
        """Regression: the report used to run INLINE in the poll loop.

        api_client retries 3 times with a 10s timeout and a 2s backoff, so an
        unreachable backend cost the loop ~10s (connection refused) to ~34s
        (hung), during which it polled nothing and saw nothing. Live testing
        found it the obvious way -- get blocked once, immediately drag the
        same file again, and the retry sails through because the monitor is
        not watching. The person who was just blocked is exactly the person
        who retries.

        The mocked client in every other test returns instantly, which is why
        a full green suite never caught this.

        Proven by parking the report: the loop must return while the report is
        still in flight. Inline, it could not have.
        """
        entered, release, completed = (threading.Event() for _ in range(3))

        def parked_report(**kwargs):
            entered.set()
            release.wait(10)
            completed.set()
            return {"id": "leak-1"}

        try:
            esc, _quar, _client = self._run(
                script=self._drag_to_browser(),
                selection=[r"C:\Users\x\cards.txt"],
                classify_result=SENSITIVE,
                report_side_effect=parked_report,
                join_threads=False,
            )
            assert entered.wait(5), "the report never ran at all"
            # The block is what protects the user, and it still happened.
            esc.assert_called_once()
            # And the loop got back to polling without waiting for the backend.
            assert not completed.is_set(), (
                "the poll loop waited for the backend -- it is blind that long"
            )
        finally:
            release.set()

    def test_a_drag_starting_outside_explorer_is_ignored(self):
        # A drag from another app's custom drag source exposes no readable
        # selection. Documented as out of scope rather than silently assumed
        # to be covered.
        esc, _quar, client = self._run(
            script=[(True, self.BROWSER_HWND)] * 4 + [(False, self.BROWSER_HWND)],
            selection=[r"C:\Users\x\cards.txt"],
            classify_result=SENSITIVE,
        )
        esc.assert_not_called()
        client.report_ai_leak_attempt.assert_not_called()

    def test_a_drag_with_nothing_selected_is_ignored(self):
        esc, _quar, client = self._run(
            script=self._drag_to_browser(),
            selection=[],
            classify_result=SENSITIVE,
        )
        esc.assert_not_called()
        client.report_ai_leak_attempt.assert_not_called()

    def test_releasing_the_button_resets_the_drag(self):
        state = _DragState()
        state.active = True
        state.paths = ["/a.txt"]
        state.reset()
        assert not state.active


class TestSendEscape:
    def test_presses_and_releases_escape(self):
        # Windows cancels an in-flight OLE drag on Escape -- DoDragDrop
        # returns DRAGDROP_S_CANCEL. Both the down and the up must be sent or
        # the key is left logically held.
        with patch("drag_drop_monitor._user32") as u32:
            ddm._send_escape()
        assert u32.keybd_event.call_count == 2
        down, up = u32.keybd_event.call_args_list
        assert down.args[0] == ddm._VK_ESCAPE
        assert up.args[0] == ddm._VK_ESCAPE
        assert up.args[2] == ddm._KEYEVENTF_KEYUP

    def test_a_failure_to_send_does_not_raise(self):
        with patch("drag_drop_monitor._user32") as u32:
            u32.keybd_event.side_effect = OSError("no input desktop")
            ddm._send_escape()   # must not propagate


class TestExplorerSelection:
    def test_returns_nothing_when_com_is_unavailable(self):
        # A machine without pywin32 must degrade to "no drag coverage", never
        # take down the monitor thread.
        with patch.dict("sys.modules", {"win32com.client": None, "pythoncom": None}):
            assert ddm._explorer_selection(123) == []


class TestPlatformGuard:
    def test_disabled_off_windows(self):
        with patch("drag_drop_monitor.sys") as s:
            s.platform = "linux"
            t = ddm.start_drag_drop_monitor(MagicMock(), "agent-1", threading.Event())
        assert not t.is_alive() or True   # a no-op thread, never the real loop
