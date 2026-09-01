from unittest.mock import patch, MagicMock

from clipboard_watcher import _mask, _scan_copied_files, _check_restricted_app


class TestCheckRestrictedApp:
    def test_returns_none_when_no_app_rule_resolver(self):
        client = MagicMock()
        result = _check_restricted_app(client, "agent-1", None, None, [], 0.9)
        assert result is None
        client.create_incident.assert_not_called()

    def test_returns_none_when_foreground_app_does_not_match(self):
        client = MagicMock()
        app_rules = MagicMock()
        app_rules.match.return_value = None
        with patch("clipboard_watcher._get_foreground_title", return_value="Untitled - Notepad"):
            result = _check_restricted_app(client, "agent-1", app_rules, None, [], 0.9)
        assert result is None
        client.create_incident.assert_not_called()

    def test_blocks_and_creates_incident_when_restricted_app_matches(self):
        client = MagicMock()
        client.create_incident.return_value = {"id": "inc-1"}
        app_rules = MagicMock()
        app_rules.match.return_value = "TeamViewer remote access"
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "BLOCK", "name": "PCI-DSS"}
        detections = [{"rule": "PCI-DSS", "type": "credit_card"}]

        with patch("clipboard_watcher._get_foreground_title", return_value="TeamViewer"), \
             patch("clipboard_watcher.pyperclip.copy") as mock_copy:
            result = _check_restricted_app(client, "agent-1", app_rules, resolver, detections, 0.95)

        assert result == "BLOCK"
        mock_copy.assert_called_once()
        resolver.resolve.assert_called_once_with(detections)
        client.create_incident.assert_called_once()
        _, kwargs = client.create_incident.call_args
        assert kwargs["policy_id"] == "p1"
        assert kwargs["channel"] == "CLIPBOARD"
        assert "TeamViewer remote access" in kwargs["evidence"]

    def test_allow_action_does_not_clear_clipboard_or_report(self):
        client = MagicMock()
        app_rules = MagicMock()
        app_rules.match.return_value = "TeamViewer remote access"
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "ALLOW", "name": "Allow Policy"}

        with patch("clipboard_watcher._get_foreground_title", return_value="TeamViewer"), \
             patch("clipboard_watcher.pyperclip.copy") as mock_copy:
            result = _check_restricted_app(client, "agent-1", app_rules, resolver, [], 0.9)

        assert result == "ALLOW"
        mock_copy.assert_not_called()
        client.create_incident.assert_not_called()

    def test_quarantine_action_clears_clipboard_and_reports(self):
        client = MagicMock()
        client.create_incident.return_value = {"id": "inc-1"}
        app_rules = MagicMock()
        app_rules.match.return_value = "WinRAR archiver"
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "QUARANTINE", "name": "PCI-DSS"}

        with patch("clipboard_watcher._get_foreground_title", return_value="WinRAR"), \
             patch("clipboard_watcher.pyperclip.copy") as mock_copy:
            result = _check_restricted_app(client, "agent-1", app_rules, resolver, [], 0.9)

        assert result == "QUARANTINE"
        mock_copy.assert_called_once()
        client.create_incident.assert_called_once()

    def test_no_resolver_defaults_to_block(self):
        client = MagicMock()
        client.create_incident.return_value = {"id": "inc-1"}
        app_rules = MagicMock()
        app_rules.match.return_value = "TeamViewer remote access"

        with patch("clipboard_watcher._get_foreground_title", return_value="TeamViewer"), \
             patch("clipboard_watcher.pyperclip.copy") as mock_copy:
            result = _check_restricted_app(client, "agent-1", app_rules, None, [], 0.9)

        assert result == "BLOCK"
        mock_copy.assert_called_once()


class TestCheckRestrictedAppReviewRequest:
    def _capture_thread_target(self):
        captured = {}
        def fake_thread(target, **kwargs):
            captured["fn"] = target
            return MagicMock()
        return captured, fake_thread

    def test_requests_review_with_note_but_never_touches_clipboard_again(self):
        client = MagicMock()
        client.create_incident.return_value = {"id": "inc-1"}
        client.request_review_incident.return_value = {"id": "inc-1", "reviewRequested": True}
        app_rules = MagicMock()
        app_rules.match.return_value = "TeamViewer remote access"
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "BLOCK", "name": "PCI-DSS"}
        captured, fake_thread = self._capture_thread_target()

        with patch("clipboard_watcher._get_foreground_title", return_value="TeamViewer"), \
             patch("clipboard_watcher.pyperclip.copy") as mock_copy, \
             patch("clipboard_watcher.threading.Thread", side_effect=fake_thread), \
             patch("clipboard_watcher.prompt_review_request", return_value="Looked legitimate to me"):
            result = _check_restricted_app(client, "agent-1", app_rules, resolver, [], 0.9)
            assert result == "BLOCK"
            captured["fn"]()  # run the "background thread" synchronously, patches still active

        # The clipboard clear (block message) is the only copy() call.
        mock_copy.assert_called_once_with("[BLOCKED BY DLP - Sensitive content detected]")
        client.request_review_incident.assert_called_once_with("inc-1", "Looked legitimate to me")

    def test_review_request_with_no_note_still_flags_it(self):
        client = MagicMock()
        client.create_incident.return_value = {"id": "inc-1"}
        client.request_review_incident.return_value = {"id": "inc-1", "reviewRequested": True}
        app_rules = MagicMock()
        app_rules.match.return_value = "TeamViewer remote access"
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "BLOCK", "name": "PCI-DSS"}
        captured, fake_thread = self._capture_thread_target()

        with patch("clipboard_watcher._get_foreground_title", return_value="TeamViewer"), \
             patch("clipboard_watcher.pyperclip.copy"), \
             patch("clipboard_watcher.threading.Thread", side_effect=fake_thread), \
             patch("clipboard_watcher.prompt_review_request", return_value=""):
            _check_restricted_app(client, "agent-1", app_rules, resolver, [], 0.9)
            captured["fn"]()

        client.request_review_incident.assert_called_once_with("inc-1", None)

    def test_dismissed_prompt_does_not_request_review(self):
        client = MagicMock()
        client.create_incident.return_value = {"id": "inc-1"}
        app_rules = MagicMock()
        app_rules.match.return_value = "TeamViewer remote access"
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "BLOCK", "name": "PCI-DSS"}
        captured, fake_thread = self._capture_thread_target()

        with patch("clipboard_watcher._get_foreground_title", return_value="TeamViewer"), \
             patch("clipboard_watcher.pyperclip.copy"), \
             patch("clipboard_watcher.threading.Thread", side_effect=fake_thread), \
             patch("clipboard_watcher.prompt_review_request", return_value=None):
            _check_restricted_app(client, "agent-1", app_rules, resolver, [], 0.9)
            captured["fn"]()

        client.request_review_incident.assert_not_called()

    def test_no_review_prompt_offered_for_allow_action(self):
        client = MagicMock()
        app_rules = MagicMock()
        app_rules.match.return_value = "TeamViewer remote access"
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "ALLOW", "name": "Allow Policy"}

        with patch("clipboard_watcher._get_foreground_title", return_value="TeamViewer"), \
             patch("clipboard_watcher.pyperclip.copy"), \
             patch("clipboard_watcher.threading.Thread") as mock_thread:
            _check_restricted_app(client, "agent-1", app_rules, resolver, [], 0.9)

        mock_thread.assert_not_called()


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
        # check_and_block() already reports internally for any non-None,
        # non-ALLOW outcome (see its docstring) -- _scan_copied_files must
        # NOT report again itself, or the same event gets double-recorded.
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
        client.report_ai_leak_attempt.assert_not_called()
        state.flag_sensitive_clipboard.assert_not_called()

    def test_high_risk_file_flags_state_when_no_ai_window(self, tmp_path):
        # check_and_block() returns None without reporting anything when no
        # AI window is active yet -- the delayed path reports later if/when
        # one opens, so _scan_copied_files must not report here either.
        f = tmp_path / "secret.txt"
        f.write_text("card number 4111111111111111")
        detections = [{"type": "CREDIT_CARD"}]
        client = self._client({"risk_score": 0.95, "detections": detections})
        blocker = MagicMock()
        blocker.check_and_block.return_value = None
        state = MagicMock()

        _scan_copied_files((str(f),), client, "agent-1", state, blocker)

        state.flag_sensitive_clipboard.assert_called_once()
        _, kwargs = state.flag_sensitive_clipboard.call_args
        assert kwargs["detections"] == detections
        assert kwargs["risk_score"] == 0.95
        client.report_ai_leak_attempt.assert_not_called()

    def test_restricted_app_blocks_the_copied_file_when_no_ai_window(self, tmp_path):
        # When check_and_block() finds no AI window, _scan_copied_files must
        # still check restricted apps before deferring to the delayed path.
        f = tmp_path / "secret.txt"
        f.write_text("card number 4111111111111111")
        client = self._client({"risk_score": 0.95, "detections": [{"type": "CREDIT_CARD"}]})
        client.create_incident.return_value = {"id": "inc-1"}
        blocker = MagicMock()
        blocker.check_and_block.return_value = None
        state = MagicMock()
        app_rules = MagicMock()
        app_rules.match.return_value = "TeamViewer remote access"
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "BLOCK", "name": "PCI-DSS"}

        with patch("clipboard_watcher._get_foreground_title", return_value="TeamViewer"), \
             patch("clipboard_watcher.pyperclip.copy"):
            _scan_copied_files((str(f),), client, "agent-1", state, blocker, resolver, app_rules)

        client.create_incident.assert_called_once()
        state.flag_sensitive_clipboard.assert_not_called()  # handled immediately, not deferred

    def test_quarantine_action_moves_the_copied_file(self, tmp_path):
        f = tmp_path / "secret.txt"
        f.write_text("card number 4111111111111111")
        client = self._client({"risk_score": 0.95, "detections": [{"type": "CREDIT_CARD"}]})
        blocker = MagicMock()
        blocker.check_and_block.return_value = "QUARANTINE"
        state = MagicMock()

        with patch("clipboard_watcher.quarantine_file") as mock_quarantine:
            _scan_copied_files((str(f),), client, "agent-1", state, blocker)

        mock_quarantine.assert_called_once_with(str(f))

    def test_block_action_does_not_touch_the_copied_file(self, tmp_path):
        f = tmp_path / "secret.txt"
        f.write_text("card number 4111111111111111")
        client = self._client({"risk_score": 0.95, "detections": [{"type": "CREDIT_CARD"}]})
        blocker = MagicMock()
        blocker.check_and_block.return_value = "BLOCK"
        state = MagicMock()

        with patch("clipboard_watcher.quarantine_file") as mock_quarantine:
            _scan_copied_files((str(f),), client, "agent-1", state, blocker)

        mock_quarantine.assert_not_called()

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
