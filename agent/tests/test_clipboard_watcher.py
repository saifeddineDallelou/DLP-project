from unittest.mock import patch, MagicMock

from clipboard_watcher import _mask, _scan_copied_files


class TestMask:
    def test_short_text_returned_unmasked(self):
        assert _mask("short") == "short"

    def test_long_text_is_masked_in_the_middle(self):
        text = "SSN is 123-45-6789, please keep this confidential and safe"
        masked = _mask(text)
        assert masked.startswith(text[:15])
        assert "***[MASKED]***" in masked
        assert masked.endswith(text[:100][-5:])

    def test_truncates_to_100_chars_before_masking(self):
        text = "a" * 500
        masked = _mask(text)
        # only the first 100 chars are considered at all
        assert len(masked) < 500


class TestScanCopiedFiles:
    def _client(self, classify_result):
        client = MagicMock()
        client.classify.return_value = classify_result
        client.report_ai_leak_attempt.return_value = {"id": "leak-1"}
        return client

    def test_skips_nonexistent_paths(self):
        client = self._client({"risk_score": 0.9})
        blocker = MagicMock()
        state = MagicMock()

        _scan_copied_files(("C:/does/not/exist.txt",), client, "agent-1", state, blocker)

        client.classify.assert_not_called()

    def test_skips_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        client = self._client({"risk_score": 0.9})
        blocker = MagicMock()
        state = MagicMock()

        _scan_copied_files((str(f),), client, "agent-1", state, blocker)

        client.classify.assert_not_called()

    def test_low_risk_file_is_not_reported(self, tmp_path):
        f = tmp_path / "notes.txt"
        f.write_text("just some ordinary notes")
        client = self._client({"risk_score": 0.1, "detections": []})
        blocker = MagicMock()
        state = MagicMock()

        _scan_copied_files((str(f),), client, "agent-1", state, blocker)

        client.report_ai_leak_attempt.assert_not_called()

    def test_high_risk_file_blocked_when_ai_window_active(self, tmp_path):
        f = tmp_path / "secret.txt"
        f.write_text("card number 4111111111111111")
        detections = [{"type": "CREDIT_CARD"}]
        client = self._client({"risk_score": 0.95, "detections": detections})
        blocker = MagicMock()
        blocker.check_and_block.return_value = "BLOCK"
        state = MagicMock()

        _scan_copied_files((str(f),), client, "agent-1", state, blocker)

        blocker.check_and_block.assert_called_once()
        _, kwargs = blocker.check_and_block.call_args
        assert kwargs["detections"] == detections
        client.report_ai_leak_attempt.assert_called_once()
        _, kwargs = client.report_ai_leak_attempt.call_args
        assert kwargs["blocked"] is True
        state.flag_sensitive_clipboard.assert_not_called()

    def test_high_risk_file_flags_state_when_no_ai_window(self, tmp_path):
        f = tmp_path / "secret.txt"
        f.write_text("card number 4111111111111111")
        client = self._client({"risk_score": 0.95, "detections": [{"type": "CREDIT_CARD"}]})
        blocker = MagicMock()
        blocker.check_and_block.return_value = None
        state = MagicMock()

        _scan_copied_files((str(f),), client, "agent-1", state, blocker)

        state.flag_sensitive_clipboard.assert_called_once()
        _, kwargs = client.report_ai_leak_attempt.call_args
        assert kwargs["blocked"] is False

    def test_allow_action_skips_report_entirely(self, tmp_path):
        f = tmp_path / "secret.txt"
        f.write_text("card number 4111111111111111")
        client = self._client({"risk_score": 0.95, "detections": [{"type": "CREDIT_CARD"}]})
        blocker = MagicMock()
        blocker.check_and_block.return_value = "ALLOW"
        state = MagicMock()

        _scan_copied_files((str(f),), client, "agent-1", state, blocker)

        client.report_ai_leak_attempt.assert_not_called()
        state.flag_sensitive_clipboard.assert_not_called()

    def test_skips_files_with_no_extractable_text(self, tmp_path):
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\nnotarealpng")
        client = self._client({"risk_score": 0.9})
        blocker = MagicMock()
        state = MagicMock()

        with patch("clipboard_watcher.extract", return_value=None):
            _scan_copied_files((str(f),), client, "agent-1", state, blocker)

        client.classify.assert_not_called()

    def test_classifier_unavailable_is_skipped_gracefully(self, tmp_path):
        f = tmp_path / "secret.txt"
        f.write_text("card number 4111111111111111")
        client = self._client(None)
        blocker = MagicMock()
        state = MagicMock()

        _scan_copied_files((str(f),), client, "agent-1", state, blocker)

        blocker.check_and_block.assert_not_called()
