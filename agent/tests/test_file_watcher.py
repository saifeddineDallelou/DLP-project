import time
from unittest.mock import MagicMock, patch

import pytest

from file_watcher import _risk_to_severity, _DLPHandler


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

        resolver.resolve.assert_called_once_with(detections)
        _, kwargs = client.create_incident.call_args
        assert kwargs["policy_id"] == "pci-dss-policy-id"

    def test_allow_action_skips_incident_creation(self, tmp_path):
        client = MagicMock()
        detections = [{"type": "credit_card", "rule": "PCI-DSS"}]
        client.classify.return_value = {"risk_score": 0.95, "detections": detections}
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "pci-dss-policy-id", "action": "ALLOW", "name": "PCI-DSS"}
        handler = _DLPHandler(client, "agent-1", policy_resolver=resolver)

        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")
        handler._process(str(f))

        client.create_incident.assert_not_called()

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
