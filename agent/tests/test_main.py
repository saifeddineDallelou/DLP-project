import json
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
