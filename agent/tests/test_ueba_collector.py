import threading
from datetime import datetime
from unittest.mock import MagicMock, patch

from agent_state import AgentState
from ueba_collector import _ueba_loop, _get_os_user


def _run_one_iteration(client, state, fake_hour):
    """Run _ueba_loop for exactly one iteration by stopping it after the
    first collect interval elapses, with datetime.now() pinned to fake_hour."""
    stop = threading.Event()

    call_count = {"n": 0}
    real_wait = stop.wait

    def fake_wait(timeout=None):
        call_count["n"] += 1
        # First wait() call lets the loop body run once; the second wait()
        # call (start of the next iteration) sets stop so the loop exits
        # right after that single body execution.
        if call_count["n"] >= 2:
            stop.set()
        return real_wait(0)  # don't actually sleep

    fake_now = datetime(2026, 1, 1, fake_hour, 0, 0)
    with patch.object(stop, "wait", side_effect=fake_wait), \
         patch("ueba_collector.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        _ueba_loop(client, "agent-1", "user-1", state, stop)


class TestUebaLoop:
    def test_posts_file_access_event_during_work_hours(self):
        client = MagicMock()
        client.post_ueba_event.return_value = {"id": "e1"}
        state = AgentState()
        state.increment_file_access()

        _run_one_iteration(client, state, fake_hour=14)  # 2 PM

        client.post_ueba_event.assert_called_once()
        _, kwargs = client.post_ueba_event.call_args
        assert kwargs["event_type"] == "FILE_ACCESS"

    def test_posts_after_hours_event_late_at_night(self):
        client = MagicMock()
        client.post_ueba_event.return_value = {"id": "e1"}
        state = AgentState()
        state.increment_file_access()

        _run_one_iteration(client, state, fake_hour=23)  # 11 PM

        _, kwargs = client.post_ueba_event.call_args
        assert kwargs["event_type"] == "AFTER_HOURS_ACCESS"

    def test_posts_after_hours_event_early_morning(self):
        client = MagicMock()
        client.post_ueba_event.return_value = {"id": "e1"}
        state = AgentState()
        state.increment_file_access()

        _run_one_iteration(client, state, fake_hour=5)  # 5 AM

        _, kwargs = client.post_ueba_event.call_args
        assert kwargs["event_type"] == "AFTER_HOURS_ACCESS"

    def test_file_access_event_carries_total_bytes_as_mb(self):
        client = MagicMock()
        client.post_ueba_event.return_value = {"id": "e1"}
        state = AgentState()
        state.increment_file_access(size_bytes=5 * 1024 * 1024)   # 5 MB
        state.increment_file_access(size_bytes=3 * 1024 * 1024)   # 3 MB

        _run_one_iteration(client, state, fake_hour=14)

        _, kwargs = client.post_ueba_event.call_args
        assert kwargs["metadata"]["sizeMB"] == 8.0

    def test_after_hours_threshold_is_configurable(self):
        # 17:00 (5 PM) should count as after-hours once AFTER_HOURS_START is
        # lowered from the 19 (7 PM) default -- e.g. AFTER_HOURS_START=17.
        client = MagicMock()
        client.post_ueba_event.return_value = {"id": "e1"}
        state = AgentState()
        state.increment_file_access()

        with patch("ueba_collector._AFTER_HOURS_START", 17):
            _run_one_iteration(client, state, fake_hour=17)

        _, kwargs = client.post_ueba_event.call_args
        assert kwargs["event_type"] == "AFTER_HOURS_ACCESS"

    def test_no_events_posted_when_counters_are_zero(self):
        client = MagicMock()
        state = AgentState()

        _run_one_iteration(client, state, fake_hour=14)

        client.post_ueba_event.assert_not_called()

    def test_posts_clipboard_copy_event(self):
        client = MagicMock()
        client.post_ueba_event.return_value = {"id": "e1"}
        state = AgentState()
        state.flag_sensitive_clipboard()

        _run_one_iteration(client, state, fake_hour=14)

        _, kwargs = client.post_ueba_event.call_args
        assert kwargs["event_type"] == "CLIPBOARD_COPY"
        assert kwargs["metadata"]["count"] == 1

    def test_counters_are_reset_after_flush(self):
        client = MagicMock()
        client.post_ueba_event.return_value = {"id": "e1"}
        state = AgentState()
        state.increment_file_access()

        _run_one_iteration(client, state, fake_hour=14)

        fc, cc = state.pop_counters()
        assert (fc, cc) == (0, 0)


class TestGetOsUser:
    def test_falls_back_to_unknown_when_no_env_vars(self):
        with patch.dict("os.environ", {}, clear=True):
            assert _get_os_user() == "unknown-user"

    def test_uses_username_env_var(self):
        with patch.dict("os.environ", {"USERNAME": "alice"}, clear=True):
            assert _get_os_user() == "alice"
