import json
import threading
from unittest.mock import MagicMock, patch

import main


class TestLoadSaveState:
    def test_load_state_returns_empty_dict_when_file_missing(self, tmp_path):
        missing = tmp_path / "state.json"
        with patch.object(main, "_STATE_FILE", missing):
            assert main._load_state() == {}

    def test_save_then_load_roundtrip(self, tmp_path):
        state_file = tmp_path / "state.json"
        with patch.object(main, "_STATE_FILE", state_file):
            main._save_state({"agent_id": "a1", "agent_token": "t1"})
            assert main._load_state() == {"agent_id": "a1", "agent_token": "t1"}

    def test_load_state_returns_empty_dict_on_corrupt_json(self, tmp_path):
        state_file = tmp_path / "state.json"
        state_file.write_text("not valid json{{{")
        with patch.object(main, "_STATE_FILE", state_file):
            assert main._load_state() == {}


class TestPolicyRefreshLoop:
    def test_refreshes_periodically(self):
        resolver = MagicMock()
        stop = threading.Event()
        resolver.refresh.side_effect = lambda: stop.set()  # stop after one refresh

        main._policy_refresh_loop(resolver, 0, stop)

        resolver.refresh.assert_called_once()

    def test_does_not_refresh_if_already_stopped(self):
        resolver = MagicMock()
        stop = threading.Event()
        stop.set()

        main._policy_refresh_loop(resolver, 0, stop)

        resolver.refresh.assert_not_called()

    def test_does_not_refresh_if_stop_fires_during_the_wait(self):
        resolver = MagicMock()
        stop = threading.Event()
        stop.wait = lambda timeout: (stop.set(), True)[1]  # stop mid-wait

        main._policy_refresh_loop(resolver, 5, stop)

        resolver.refresh.assert_not_called()


class TestEnroll:
    def test_returns_enrollment_result_on_success(self):
        client = MagicMock()
        client.enroll.return_value = {"id": "agent-1", "hostname": "host1", "token": "tok"}
        result = main._enroll(client)
        assert result == {"id": "agent-1", "hostname": "host1", "token": "tok"}

    def test_returns_none_when_enrollment_fails(self):
        client = MagicMock()
        client.enroll.return_value = None
        result = main._enroll(client)
        assert result is None
