import threading
from unittest.mock import patch, MagicMock

import pytest

import file_dialog_monitor
from file_dialog_monitor import _candidate_paths, _active_ai_platform


@pytest.fixture(autouse=True)
def _reset_platform_url_cache():
    # _active_ai_platform's address-bar result is cached at module level
    # (shared across the whole polling loop in production) -- reset it
    # before each test so results don't leak between tests.
    file_dialog_monitor._platform_url_cache = None
    file_dialog_monitor._platform_url_cache_time = 0.0
    yield


class TestCandidatePaths:
    def test_empty_string_returns_empty_list(self):
        assert _candidate_paths("") == []
        assert _candidate_paths("   ") == []

    def test_single_bare_filename(self):
        assert _candidate_paths("report.docx") == ["report.docx"]

    def test_multiple_quoted_filenames(self):
        raw = '"a.txt" "b.pdf" "c.xlsx"'
        assert _candidate_paths(raw) == ["a.txt", "b.pdf", "c.xlsx"]

    def test_single_quoted_filename(self):
        assert _candidate_paths('"report.docx"') == ["report.docx"]


class TestActiveAiPlatform:
    def test_returns_platform_when_window_title_matches(self):
        with patch(
            "file_dialog_monitor._enum_all_windows",
            return_value=[(111, "Untitled - Notepad"), (222, "ChatGPT - Google Chrome")],
        ):
            assert _active_ai_platform() == "OPENAI_CHATGPT"

    def test_returns_none_when_nothing_matches(self):
        with patch(
            "file_dialog_monitor._enum_all_windows",
            return_value=[(111, "Untitled - Notepad"), (222, "Calculator")],
        ):
            assert _active_ai_platform() is None

    def test_falls_back_to_address_bar_when_title_is_rewritten(self):
        # Simulates ChatGPT renaming its tab to the conversation topic --
        # the title no longer mentions the platform, but the URL still does.
        with patch(
            "file_dialog_monitor._enum_all_windows",
            return_value=[(333, "Excel file request - Google Chrome")],
        ), patch(
            "file_dialog_monitor._detect_platform_via_address_bar",
            return_value="OPENAI_CHATGPT",
        ) as mock_url_check:
            assert _active_ai_platform() == "OPENAI_CHATGPT"
        mock_url_check.assert_called_once_with(333)

    def test_does_not_check_address_bar_for_non_browser_windows(self):
        with patch(
            "file_dialog_monitor._enum_all_windows",
            return_value=[(111, "Untitled - Notepad")],
        ), patch(
            "file_dialog_monitor._detect_platform_via_address_bar",
        ) as mock_url_check:
            assert _active_ai_platform() is None
        mock_url_check.assert_not_called()

    def test_address_bar_result_is_cached_within_ttl(self):
        # This is the fix for the reported "works but too slow" bug: the
        # dialog loop calls _active_ai_platform() on every 0.1s poll, so an
        # uncached UI Automation call here would make every single poll slow
        # again, re-opening the double-click race it was meant to close.
        with patch(
            "file_dialog_monitor._enum_all_windows",
            return_value=[(333, "Excel file request - Google Chrome")],
        ), patch(
            "file_dialog_monitor._detect_platform_via_address_bar",
            return_value="OPENAI_CHATGPT",
        ) as mock_url_check:
            _active_ai_platform()
            _active_ai_platform()
            _active_ai_platform()
        assert mock_url_check.call_count == 1


class TestDialogMonitorLoopActionBranching:
    """
    Drives _dialog_monitor_loop for exactly one iteration with every Win32
    call mocked out (no real dialog, no real window) -- safe to call
    directly, unlike screenshot_monitor's loop which registers real global
    keyboard hooks.
    """

    def _run_one_iteration(self, client, resolver, filename_text, folder=""):
        stop = threading.Event()

        def fake_wait(timeout=None):
            stop.set()

        with patch.object(stop, "wait", side_effect=fake_wait), \
             patch("file_dialog_monitor._find_dialog_windows", return_value=[111]), \
             patch("file_dialog_monitor._active_ai_platform", return_value="OPENAI_CHATGPT"), \
             patch("file_dialog_monitor._get_dialog_folder", return_value=folder), \
             patch("file_dialog_monitor._get_dialog_filename", return_value=filename_text), \
             patch("file_dialog_monitor._close_dialog") as mock_close:
            file_dialog_monitor._dialog_monitor_loop(client, "agent-1", stop, resolver)
        return mock_close

    def test_block_action_closes_dialog(self, tmp_path):
        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")
        client = MagicMock()
        detections = [{"type": "credit_card", "rule": "PCI-DSS"}]
        client.classify.return_value = {"risk_score": 0.95, "detections": detections}
        client.report_ai_leak_attempt.return_value = {"id": "leak-1"}
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "BLOCK", "name": "PCI-DSS"}

        mock_close = self._run_one_iteration(client, resolver, str(f))

        resolver.resolve.assert_called_once_with(detections)
        mock_close.assert_called_once_with(111)
        _, kwargs = client.report_ai_leak_attempt.call_args
        assert kwargs["blocked"] is True

    def test_allow_action_does_not_close_dialog_or_report(self, tmp_path):
        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")
        client = MagicMock()
        client.classify.return_value = {"risk_score": 0.95, "detections": [{"type": "credit_card", "rule": "PCI-DSS"}]}
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "ALLOW", "name": "Allow Policy"}

        mock_close = self._run_one_iteration(client, resolver, str(f))

        mock_close.assert_not_called()
        client.report_ai_leak_attempt.assert_not_called()

    def test_alert_action_reports_without_closing_dialog(self, tmp_path):
        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")
        client = MagicMock()
        client.classify.return_value = {"risk_score": 0.95, "detections": [{"type": "credit_card", "rule": "PCI-DSS"}]}
        client.report_ai_leak_attempt.return_value = {"id": "leak-1"}
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "ALERT", "name": "Alert Policy"}

        mock_close = self._run_one_iteration(client, resolver, str(f))

        mock_close.assert_not_called()
        _, kwargs = client.report_ai_leak_attempt.call_args
        assert kwargs["blocked"] is False

    def test_no_resolver_defaults_to_block(self, tmp_path):
        f = tmp_path / "card.txt"
        f.write_text("4111111111111111")
        client = MagicMock()
        client.classify.return_value = {"risk_score": 0.95, "detections": []}
        client.report_ai_leak_attempt.return_value = {"id": "leak-1"}

        mock_close = self._run_one_iteration(client, None, str(f))

        mock_close.assert_called_once_with(111)
