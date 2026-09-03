import time
from unittest.mock import MagicMock, patch, ANY

import pytest

from file_watcher import _risk_to_severity, _DLPHandler, _find_restricted_app_holding_file, severity_for


class TestFindRestrictedAppHoldingFile:
    def test_returns_none_without_a_resolver(self):
        assert _find_restricted_app_holding_file(None, "C:/dlp-watch/secret.txt") is None

    def test_returns_none_when_no_process_matches_the_watchlist(self):
        app_rules = MagicMock()
        app_rules.match.return_value = None
        proc = MagicMock()
        proc.info = {"pid": 111, "name": "notepad.exe"}
        with patch("file_watcher.psutil.process_iter", return_value=[proc]):
            result = _find_restricted_app_holding_file(app_rules, "C:/dlp-watch/secret.txt")
        assert result is None

    def test_returns_none_when_matched_process_does_not_have_the_file_open(self):
        app_rules = MagicMock()
        app_rules.match.return_value = "TeamViewer remote access"
        proc = MagicMock()
        proc.info = {"pid": 111, "name": "teamviewer.exe"}
        proc.open_files.return_value = [MagicMock(path="C:/other/file.txt")]
        with patch("file_watcher.psutil.process_iter", return_value=[proc]):
            result = _find_restricted_app_holding_file(app_rules, "C:/dlp-watch/secret.txt")
        assert result is None

    def test_returns_label_and_pid_when_a_restricted_process_has_the_file_open(self):
        app_rules = MagicMock()
        app_rules.match.return_value = "TeamViewer remote access"
        proc = MagicMock()
        proc.info = {"pid": 4821, "name": "teamviewer.exe"}
        proc.open_files.return_value = [MagicMock(path="C:/dlp-watch/secret.txt")]
        with patch("file_watcher.psutil.process_iter", return_value=[proc]):
            result = _find_restricted_app_holding_file(app_rules, "C:/dlp-watch/secret.txt")
        assert result == ("TeamViewer remote access", 4821)

    def test_skips_processes_that_raise_access_denied(self):
        import psutil as real_psutil
        app_rules = MagicMock()
        app_rules.match.return_value = "TeamViewer remote access"
        bad_proc = MagicMock()
        bad_proc.info = {"pid": 1, "name": "teamviewer.exe"}
        bad_proc.open_files.side_effect = real_psutil.AccessDenied(pid=1)
        good_proc = MagicMock()
        good_proc.info = {"pid": 2, "name": "teamviewer.exe"}
        good_proc.open_files.return_value = [MagicMock(path="C:/dlp-watch/secret.txt")]
        with patch("file_watcher.psutil.process_iter", return_value=[bad_proc, good_proc]):
            result = _find_restricted_app_holding_file(app_rules, "C:/dlp-watch/secret.txt")
        assert result == ("TeamViewer remote access", 2)


class TestRiskToSeverity:
    @pytest.mark.parametrize("score,expected", [
        (0.95, "CRITICAL"),
        (0.9, "CRITICAL"),
        (0.89, "HIGH"),
        (0.7, "HIGH"),
        (0.69, "MEDIUM"),
        (0.51, "MEDIUM"),
    ])
    def test_thresholds(self, score, expected):
        assert _risk_to_severity(score) == expected


class TestIsExcluded:
    def test_excludes_dir_names(self, tmp_path):
        d = tmp_path / "node_modules"
        d.mkdir()
        f = d / "index.js"
        f.write_text("x")
        assert _DLPHandler._is_excluded(str(f)) is True

    def test_excludes_office_temp_lock_files(self, tmp_path):
        f = tmp_path / "~$report.docx"
        f.write_text("x")
        assert _DLPHandler._is_excluded(str(f)) is True

    def test_excludes_temp_extensions(self, tmp_path):
        f = tmp_path / "download.crdownload"
        f.write_text("x")
        assert _DLPHandler._is_excluded(str(f)) is True

    def test_excludes_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        assert _DLPHandler._is_excluded(str(f)) is True

    def test_excludes_missing_file(self, tmp_path):
        f = tmp_path / "missing.txt"
        assert _DLPHandler._is_excluded(str(f)) is True

    def test_allows_normal_file(self, tmp_path):
        f = tmp_path / "report.txt"
        f.write_text("some real content")
        assert _DLPHandler._is_excluded(str(f)) is False

    def test_excludes_oversized_file(self, tmp_path):
        f = tmp_path / "huge.txt"
        f.write_bytes(b"0")
        with patch("file_watcher.Path.stat") as mock_stat:
            mock_stat.return_value = MagicMock(st_size=21 * 1024 * 1024)
            assert _DLPHandler._is_excluded(str(f)) is True


class TestCheckLargeFile:
    def test_reports_large_file_transfer_event(self, tmp_path):
        f = tmp_path / "video.mp4"
        f.write_bytes(b"x" * 1000)
        client = MagicMock()
        client.post_ueba_event.return_value = {"id": "e1"}
        handler = _DLPHandler(client, "agent-1")

        with patch("file_watcher._LARGE_FILE_THRESHOLD_BYTES", 500):
            handler._check_large_file(str(f))

        client.post_ueba_event.assert_called_once()
        _, kwargs = client.post_ueba_event.call_args
        assert kwargs["event_type"] == "LARGE_FILE_TRANSFER"
        assert kwargs["metadata"]["filename"] == "video.mp4"

    def test_does_not_report_small_files(self, tmp_path):
        f = tmp_path / "small.txt"
        f.write_bytes(b"x" * 10)
        client = MagicMock()
        handler = _DLPHandler(client, "agent-1")

        with patch("file_watcher._LARGE_FILE_THRESHOLD_BYTES", 500):
            handler._check_large_file(str(f))

        client.post_ueba_event.assert_not_called()

    def test_does_not_report_excluded_directories(self, tmp_path):
        d = tmp_path / "node_modules"
        d.mkdir()
        f = d / "bundle.js"
        f.write_bytes(b"x" * 1000)
        client = MagicMock()
        handler = _DLPHandler(client, "agent-1")

        with patch("file_watcher._LARGE_FILE_THRESHOLD_BYTES", 500):
            handler._check_large_file(str(f))

        client.post_ueba_event.assert_not_called()

    def test_respects_its_own_cooldown(self, tmp_path):
        f = tmp_path / "video.mp4"
        f.write_bytes(b"x" * 1000)
        client = MagicMock()
        client.post_ueba_event.return_value = {"id": "e1"}
        handler = _DLPHandler(client, "agent-1")

        with patch("file_watcher._LARGE_FILE_THRESHOLD_BYTES", 500):
            handler._check_large_file(str(f))
            handler._check_large_file(str(f))  # within cooldown

        client.post_ueba_event.assert_called_once()

    def test_does_not_interfere_with_content_scan_cooldown(self, tmp_path):
        # _check_large_file uses its OWN cooldown dict -- calling it (from
        # _process, for every file) must not throttle the separate
        # content-scan cooldown for a small, non-large file.
        f = tmp_path / "secret.txt"
        f.write_text("SSN: 123-45-6789")
        client = MagicMock()
        client.classify.return_value = {"risk_score": 0.95, "detections": [{"type": "SSN"}]}
        client.create_incident.return_value = {"id": "inc-1"}
        handler = _DLPHandler(client, "agent-1")

        handler._process(str(f))

        client.create_incident.assert_called_once()


class TestWithinCooldown:
    def test_first_call_not_in_cooldown(self):
        handler = _DLPHandler(MagicMock(), "agent-1")
        assert handler._within_cooldown("C:/some/file.txt") is False

    def test_second_call_within_window_is_cooldown(self):
        handler = _DLPHandler(MagicMock(), "agent-1")
        handler._within_cooldown("C:/some/file.txt")
        assert handler._within_cooldown("C:/some/file.txt") is True

    def test_different_paths_have_independent_cooldowns(self):
        handler = _DLPHandler(MagicMock(), "agent-1")
        handler._within_cooldown("C:/a.txt")
        assert handler._within_cooldown("C:/b.txt") is False


class TestProcess:
    def test_skips_excluded_files(self, tmp_path):
        client = MagicMock()
        handler = _DLPHandler(client, "agent-1")
        f = tmp_path / "empty.txt"
        f.write_text("")

        handler._process(str(f))

        client.classify.assert_not_called()

    def test_creates_incident_for_sensitive_file(self, tmp_path):
        client = MagicMock()
        client.classify.return_value = {
            "risk_score": 0.95, "detections": [{"type": "SSN"}],
        }
        client.create_incident.return_value = {"id": "inc-1"}
        state = MagicMock()
        handler = _DLPHandler(client, "agent-1", state)

        f = tmp_path / "secret.txt"
        f.write_text("SSN: 123-45-6789")

        handler._process(str(f))

        state.increment_file_access.assert_called_once()
        client.create_incident.assert_called_once()
        _, kwargs = client.create_incident.call_args
        assert kwargs["severity"] == "CRITICAL"
        assert kwargs["channel"] == "FILE"

    def test_increment_file_access_receives_real_file_size(self, tmp_path):
        client = MagicMock()
        client.classify.return_value = {"risk_score": 0.95, "detections": [{"type": "SSN"}]}
        state = MagicMock()
        handler = _DLPHandler(client, "agent-1", state)

        f = tmp_path / "secret.txt"
        content = "SSN: 123-45-6789"
        f.write_text(content)
        handler._process(str(f))

        state.increment_file_access.assert_called_once_with(len(content.encode()))

    def test_uses_default_policy_id_without_a_resolver(self, tmp_path):
        client = MagicMock()
        detections = [{"type": "SSN", "rule": "HIPAA"}]
        client.classify.return_value = {"risk_score": 0.95, "detections": detections}
        handler = _DLPHandler(client, "agent-1")  # no policy_resolver passed

        f = tmp_path / "secret.txt"
        f.write_text("SSN: 123-45-6789")
        handler._process(str(f))

        _, kwargs = client.create_incident.call_args
        assert kwargs["policy_id"] == "seed-policy-pii-001"

    def test_uses_policy_resolver_when_supplied(self, tmp_path):
        client = MagicMock()
        detections = [{"type": "credit_card", "rule": "PCI-DSS"}]
        client.classify.return_value = {"risk_score": 0.95, "detections": detections}
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "pci-dss-policy-id", "action": "BLOCK", "name": "PCI-DSS"}
        handler = _DLPHandler(client, "agent-1", policy_resolver=resolver)

        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")
        handler._process(str(f))

        # The channel decides which response is even possible: a file at
        # rest cannot be blocked in flight, a paste cannot be quarantined.
        resolver.resolve.assert_called_once_with(
            detections, channel="FILE", risk_score=ANY)
        _, kwargs = client.create_incident.call_args
        assert kwargs["policy_id"] == "pci-dss-policy-id"

    def test_allow_action_is_recorded_for_audit_not_silently_skipped(self, tmp_path):
        """ALLOW used to return without a trace.

        That made a sanctioned exception indistinguishable from a hole: there
        was no way to answer "how often did we let sensitive data through on
        purpose", which is exactly the setting an attacker or a careless
        admin would widen. It is recorded now -- auditable, with
        actionTaken=ALLOW so it never reads as a block.
        """
        client = MagicMock()
        detections = [{"type": "credit_card", "rule": "PCI-DSS"}]
        client.classify.return_value = {"risk_score": 0.95, "detections": detections}
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "pci-dss-policy-id", "action": "ALLOW", "name": "PCI-DSS"}
        handler = _DLPHandler(client, "agent-1", policy_resolver=resolver)

        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")
        handler._process(str(f))

        client.create_incident.assert_called_once()
        assert client.create_incident.call_args.kwargs["action_taken"] == "ALLOW"

    def test_an_allowed_file_is_left_exactly_where_it_is(self, tmp_path):
        # Recording the exception must not start enforcing it.
        client = MagicMock()
        client.classify.return_value = {
            "risk_score": 0.95,
            "detections": [{"type": "credit_card", "rule": "PCI-DSS"}],
        }
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p", "action": "ALLOW", "name": "PCI-DSS"}
        handler = _DLPHandler(client, "agent-1", policy_resolver=resolver)

        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")
        with patch("file_watcher.quarantine_file") as quar:
            handler._process(str(f))

        quar.assert_not_called()
        assert f.exists()

    def test_the_incident_records_the_action_that_was_taken(self, tmp_path):
        # ALERT and QUARANTINE are otherwise the same row, and an analyst
        # cannot tell whether the file was moved or left where it was.
        client = MagicMock()
        client.classify.return_value = {
            "risk_score": 0.95,
            "detections": [{"type": "credit_card", "rule": "PCI-DSS"}],
        }
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p", "action": "ALERT", "name": "PCI-DSS"}
        handler = _DLPHandler(client, "agent-1", policy_resolver=resolver)

        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")
        handler._process(str(f))

        assert client.create_incident.call_args.kwargs["action_taken"] == "ALERT"

    def test_quarantine_action_moves_the_file_and_notes_it_in_evidence(self, tmp_path):
        client = MagicMock()
        detections = [{"type": "credit_card", "rule": "PCI-DSS"}]
        client.classify.return_value = {"risk_score": 0.95, "detections": detections}
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "pci-dss-policy-id", "action": "QUARANTINE", "name": "PCI-DSS"}
        handler = _DLPHandler(client, "agent-1", policy_resolver=resolver)

        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")
        quarantine_dir = tmp_path / "quarantine"

        with patch("file_watcher.quarantine_file") as mock_quarantine:
            mock_quarantine.return_value = str(quarantine_dir / "12345_card.txt")
            handler._process(str(f))

        mock_quarantine.assert_called_once_with(str(f))
        _, kwargs = client.create_incident.call_args
        assert "QUARANTINED" in kwargs["evidence"]

    def test_incident_evidence_notes_the_real_process_holding_the_file(self, tmp_path):
        client = MagicMock()
        detections = [{"type": "credit_card", "rule": "PCI-DSS"}]
        client.classify.return_value = {"risk_score": 0.95, "detections": detections}
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "pci-dss-policy-id", "action": "BLOCK", "name": "PCI-DSS"}
        app_rules = MagicMock()
        handler = _DLPHandler(client, "agent-1", policy_resolver=resolver, app_rule_resolver=app_rules)

        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")

        with patch("file_watcher._find_restricted_app_holding_file", return_value=("TeamViewer remote access", 4821)):
            handler._process(str(f))

        _, kwargs = client.create_incident.call_args
        assert "TeamViewer remote access" in kwargs["evidence"]
        assert "4821" in kwargs["evidence"]

    def test_incident_evidence_stays_plain_when_no_restricted_app_holds_the_file(self, tmp_path):
        client = MagicMock()
        detections = [{"type": "credit_card", "rule": "PCI-DSS"}]
        client.classify.return_value = {"risk_score": 0.95, "detections": detections}
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "pci-dss-policy-id", "action": "BLOCK", "name": "PCI-DSS"}
        handler = _DLPHandler(client, "agent-1", policy_resolver=resolver)

        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")
        handler._process(str(f))

        _, kwargs = client.create_incident.call_args
        assert kwargs["evidence"] == "card.txt"

    def test_block_action_does_not_touch_the_file(self, tmp_path):
        client = MagicMock()
        detections = [{"type": "credit_card", "rule": "PCI-DSS"}]
        client.classify.return_value = {"risk_score": 0.95, "detections": detections}
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "pci-dss-policy-id", "action": "BLOCK", "name": "PCI-DSS"}
        handler = _DLPHandler(client, "agent-1", policy_resolver=resolver)

        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")

        with patch("file_watcher.quarantine_file") as mock_quarantine:
            handler._process(str(f))

        mock_quarantine.assert_not_called()
        assert f.exists()
        _, kwargs = client.create_incident.call_args
        assert kwargs["evidence"] == "card.txt"

    def test_clean_file_does_not_create_incident(self, tmp_path):
        client = MagicMock()
        client.classify.return_value = {"risk_score": 0.1, "detections": []}
        handler = _DLPHandler(client, "agent-1")

        f = tmp_path / "clean.txt"
        f.write_text("nothing sensitive here")

        handler._process(str(f))

        client.create_incident.assert_not_called()

    def test_classifier_unavailable_skips_gracefully(self, tmp_path):
        client = MagicMock()
        client.classify.return_value = None
        handler = _DLPHandler(client, "agent-1")

        f = tmp_path / "secret.txt"
        f.write_text("SSN: 123-45-6789")

        handler._process(str(f))

        client.create_incident.assert_not_called()

class TestSeverityRespectsWhoDecided:
    """
    Policy.severity was stored, editable in the dashboard, shown on the
    Policies page -- and read by nothing. Every incident's severity came from
    the risk score alone, so an admin marking a policy HIGH changed nothing,
    and a permitted match could be filed as CRITICAL: "we let this through on
    purpose" and "this is an emergency" in the same row.
    """

    def test_the_admin_s_severity_wins_over_the_risk_score(self):
        # The whole point of the field. Purview works this way: severity is
        # the admin's judgement of the rule, not a restatement of the
        # detector's confidence.
        policy = {"id": "p", "action": "BLOCK", "severity": "MEDIUM"}
        assert severity_for(policy, 0.98) == "MEDIUM"

    def test_an_allow_is_never_an_emergency(self):
        # Whatever the content scores, permitting it is a decision that it is
        # acceptable. CRITICAL next to ALLOW is a contradiction an analyst
        # has to resolve by guessing.
        policy = {"id": "p", "action": "ALLOW", "severity": "CRITICAL"}
        assert severity_for(policy, 0.99) == "LOW"

    def test_allow_is_capped_even_when_the_policy_says_nothing(self):
        assert severity_for({"id": "p", "action": "ALLOW"}, 0.99) == "LOW"

    def test_it_falls_back_to_the_risk_score_when_no_severity_is_set(self):
        # Which is what every monitor did unconditionally before.
        policy = {"id": "p", "action": "BLOCK"}
        assert severity_for(policy, 0.95) == "CRITICAL"
        assert severity_for(policy, 0.75) == "HIGH"
        assert severity_for(policy, 0.60) == "MEDIUM"

    def test_no_policy_at_all_still_works(self):
        assert severity_for(None, 0.95) == "CRITICAL"

    def test_a_lowercase_severity_is_normalised(self):
        # It arrives from an API as whatever the caller stored.
        assert severity_for({"id": "p", "action": "BLOCK", "severity": "high"}, 0.2) == "HIGH"

    def test_the_action_is_matched_case_insensitively(self):
        assert severity_for({"id": "p", "action": "allow", "severity": "CRITICAL"}, 0.99) == "LOW"

    def test_the_risk_score_is_still_recorded_on_the_incident(self, tmp_path):
        # Severity says how much to care; the risk score is the evidence
        # behind it and must not be lost when the admin overrides.
        client = MagicMock()
        client.classify.return_value = {
            "risk_score": 0.97,
            "detections": [{"type": "credit_card", "rule": "PCI-DSS"}],
        }
        resolver = MagicMock()
        resolver.resolve.return_value = {
            "id": "p", "action": "ALERT", "name": "PCI-DSS", "severity": "LOW",
        }
        handler = _DLPHandler(client, "agent-1", policy_resolver=resolver)

        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")
        handler._process(str(f))

        kwargs = client.create_incident.call_args.kwargs
        assert kwargs["severity"] == "LOW"        # the admin's call
        assert kwargs["risk_score"] == 0.97       # the evidence, intact
