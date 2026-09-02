import threading
from unittest.mock import patch, MagicMock

import clipboard_watcher as cw
from clipboard_watcher import _scan_copied_files, _check_restricted_app
from evidence import safe_sample


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


class TestReportedSampleNeverCarriesRawContent:
    """
    The tests that used to sit here asserted the bug as if it were the spec:
    `test_short_text_returned_unmasked` asserted _mask("short") == "short",
    and the long-text test asserted the output starts with text[:15] -- which
    on "SSN is 123-45-6789, ..." keeps "SSN is 123-45-6". Both passed, and a
    real payment card still reached the database intact.

    These assert the property that actually matters: whatever the agent
    reports, the raw sensitive value is not in it.
    """

    CARD = "4111 1111 1111 1111"
    SSN = "123-45-6789"

    def _detections(self):
        # Shaped like real classifier output -- values already masked by
        # classifier/src/engine.py before the agent ever sees them.
        return [
            {"type": "credit_card", "value": "****-****-****-1111", "rule": "PCI-DSS", "confidence": 0.95},
            {"type": "ssn", "value": "***-**-6789", "rule": "HIPAA", "confidence": 0.9},
        ]

    def test_short_sensitive_value_is_never_echoed(self):
        # The exact failure found in live testing: a 19-character card number
        # fell under the old 30-character threshold and was stored verbatim.
        sample = safe_sample(self._detections())
        assert self.CARD not in sample
        assert "4111" not in sample

    def test_masked_values_from_the_classifier_are_preserved(self):
        sample = safe_sample(self._detections())
        assert "****-****-****-1111" in sample
        assert "***-**-6789" in sample

    def test_reports_type_and_compliance_rule_so_it_stays_useful(self):
        sample = safe_sample(self._detections())
        assert "credit_card" in sample
        assert "PCI-DSS" in sample

    def test_prefix_carries_context_without_content(self):
        sample = safe_sample(self._detections(), prefix="FILE:payroll.xlsx")
        assert sample.startswith("FILE:payroll.xlsx")
        assert self.CARD not in sample

    def test_keyword_detections_report_no_value(self):
        # A keyword's "value" is a word from the user's document. Not a secret,
        # but still their content -- the type and rule are enough.
        sample = safe_sample([
            {"type": "keyword", "value": "confidential salary data", "rule": "INTERNAL"},
        ])
        assert "confidential salary data" not in sample
        assert "keyword" in sample
        assert "INTERNAL" in sample

    def test_caps_length_and_summarises_the_remainder(self):
        many = [
            {"type": f"type{i}", "value": f"***{i}", "rule": "GDPR"}
            for i in range(12)
        ]
        sample = safe_sample(many)
        assert len(sample) <= 100
        assert "more" in sample

    def test_describes_the_finding_when_there_is_nothing_to_name(self):
        assert safe_sample([]) != ""
        assert safe_sample(None) != ""

    def test_ignores_malformed_detection_entries(self):
        sample = safe_sample([None, "junk", {"type": "ssn", "value": "***-**-1234", "rule": "HIPAA"}])
        assert "***-**-1234" in sample


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

class TestRecopyAfterABlock:
    """
    Regression: a re-copy immediately after a block used to be invisible.

    `prev` was set to the sensitive text, then the blocker overwrote the
    clipboard -- but `prev` was never updated to reflect that. So if the user
    copied the same text again before the next poll (which is exactly what
    someone does when a paste comes out as the block message), the
    `current == prev` check at the top of the loop read it as "nothing
    changed" and skipped it: not classified, not blocked, not logged. The
    data sat in the clipboard, pasteable, and `prev` stayed stuck on it so it
    never fired for that content again.

    Found by live-testing: blocked once, copied again, pasted into ChatGPT
    successfully, and the agent log had nothing at all for the second copy.
    """

    SENSITIVE = "Sarah Okafor, Manchester"

    def _drive(self, clipboard_script):
        """Run the real loop over a scripted clipboard, one entry per poll."""
        steps = iter(clipboard_script)
        stop = threading.Event()
        seen = []

        def fake_paste():
            try:
                return next(steps)
            except StopIteration:
                stop.set()
                return ""

        client = MagicMock()
        client.classify.side_effect = lambda text=None, **kw: (
            seen.append(text)
            or {"risk_score": 0.7, "sensitive": True,
                "detections": [{"type": "edm:customers:row", "value": "1 record(s)",
                                "rule": "GDPR", "confidence": 0.99}]}
        )
        blocker = MagicMock()
        blocker.check_and_block.return_value = "BLOCK"

        with patch("clipboard_watcher.pyperclip.paste", side_effect=fake_paste), \
             patch("clipboard_watcher._get_clipboard_files", return_value=()), \
             patch("clipboard_watcher.time.monotonic", return_value=1.0):
            cw._clipboard_loop(client, "agent-1", MagicMock(), stop, blocker)

        return seen, blocker

    def test_recopying_the_same_content_after_a_block_is_still_caught(self):
        # poll 1: user copies sensitive        -> detected, blocked
        # poll 2: user re-copied it ALREADY    -> must be detected AGAIN
        seen, blocker = self._drive([self.SENSITIVE, self.SENSITIVE])

        assert blocker.check_and_block.call_count == 2, (
            "the re-copy was skipped as 'unchanged' -- it is unblocked and "
            "unlogged, and the sensitive text stays on the clipboard"
        )
        assert seen == [self.SENSITIVE, self.SENSITIVE]

    def test_the_agents_own_block_message_is_still_never_classified(self):
        # The normal path: block, the clear lands, the loop sees its own
        # message and must skip it without a classify round trip.
        seen, blocker = self._drive([self.SENSITIVE, cw._DLP_BLOCK_MSG, cw._DLP_BLOCK_MSG])

        assert seen == [self.SENSITIVE]
        assert blocker.check_and_block.call_count == 1

    def test_unrelated_repeated_content_is_still_only_classified_once(self):
        # The dedup that `prev` exists for must survive: content that was NOT
        # blocked should not be re-classified on every poll.
        steps = ["ordinary meeting notes"] * 3
        stop = threading.Event()
        seen = []
        it = iter(steps)

        def fake_paste():
            try: return next(it)
            except StopIteration:
                stop.set(); return ""

        client = MagicMock()
        client.classify.side_effect = lambda text=None, **kw: (
            seen.append(text) or {"risk_score": 0.0, "sensitive": False, "detections": []}
        )
        blocker = MagicMock()
        with patch("clipboard_watcher.pyperclip.paste", side_effect=fake_paste), \
             patch("clipboard_watcher._get_clipboard_files", return_value=()):
            cw._clipboard_loop(client, "agent-1", MagicMock(), stop, blocker)

        assert len(seen) == 1, "non-sensitive content must not be re-classified every poll"
