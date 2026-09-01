import threading
from unittest.mock import MagicMock, patch

from app_file_monitor import _app_file_monitor_loop


def _run_one_iteration(client, state, app_rule_resolver=None):
    # wait() runs BEFORE the work in this loop's shape (same as
    # _policy_refresh_loop), so the 1st wait() call must return WITHOUT
    # setting stop (letting one processing pass happen), and the 2nd call
    # (top of the next iteration) sets it, before a second pass can start.
    stop = threading.Event()
    call_count = {"n": 0}

    def fake_wait(timeout=None):
        call_count["n"] += 1
        if call_count["n"] >= 2:
            stop.set()

    with patch.object(stop, "wait", side_effect=fake_wait):
        _app_file_monitor_loop(client, "agent-1", state, stop, app_rule_resolver)


class TestAppFileMonitorLoop:
    def test_does_nothing_when_no_sensitive_files_tracked(self):
        client = MagicMock()
        state = MagicMock()
        state.sensitive_files.return_value = {}

        _run_one_iteration(client, state)

        client.create_incident.assert_not_called()

    def test_reports_incident_when_restricted_app_holds_a_tracked_file(self):
        client = MagicMock()
        client.create_incident.return_value = {"id": "inc-1"}
        state = MagicMock()
        state.sensitive_files.return_value = {
            "C:/dlp-watch/secret.txt": {"policy": {"id": "p1"}, "risk_score": 0.9, "flagged_at": 0.0},
        }
        app_rules = MagicMock()

        with patch(
            "app_file_monitor._find_restricted_app_holding_file",
            return_value=("TeamViewer remote access", 4821),
        ):
            _run_one_iteration(client, state, app_rules)

        client.create_incident.assert_called_once()
        _, kwargs = client.create_incident.call_args
        assert kwargs["policy_id"] == "p1"
        assert kwargs["channel"] == "FILE"
        assert "TeamViewer remote access" in kwargs["evidence"]
        assert "4821" in kwargs["evidence"]

    def test_no_incident_when_no_restricted_app_holds_the_file(self):
        client = MagicMock()
        state = MagicMock()
        state.sensitive_files.return_value = {
            "C:/dlp-watch/secret.txt": {"policy": {"id": "p1"}, "risk_score": 0.9, "flagged_at": 0.0},
        }

        with patch("app_file_monitor._find_restricted_app_holding_file", return_value=None):
            _run_one_iteration(client, state, MagicMock())

        client.create_incident.assert_not_called()

    def test_respects_per_file_per_app_report_cooldown(self):
        client = MagicMock()
        client.create_incident.return_value = {"id": "inc-1"}
        state = MagicMock()
        state.sensitive_files.return_value = {
            "C:/dlp-watch/secret.txt": {"policy": {"id": "p1"}, "risk_score": 0.9, "flagged_at": 0.0},
        }

        stop = threading.Event()
        call_count = {"n": 0}

        def fake_wait(timeout=None):
            call_count["n"] += 1
            # 3rd wait() call sets stop -- so exactly 2 full processing
            # passes happen first (checked at the top of the loop, AFTER
            # each wait() returns but BEFORE the 3rd one).
            if call_count["n"] >= 3:
                stop.set()

        with patch.object(stop, "wait", side_effect=fake_wait), \
             patch(
                 "app_file_monitor._find_restricted_app_holding_file",
                 return_value=("TeamViewer remote access", 4821),
             ):
            _app_file_monitor_loop(client, "agent-1", state, stop, MagicMock())

        # Two poll iterations happened, but the second is within the 60s
        # cooldown for the same (file, app) pair -- only one report.
        client.create_incident.assert_called_once()
