import time
from unittest.mock import patch, MagicMock

import pytest

import ai_domain_monitor as aidm
from ai_domain_monitor import AiBlocker, _detect_platform_in_text, _is_browser_window


class TestDetectPlatformInText:
    @pytest.mark.parametrize("title,expected", [
        ("ChatGPT - Google Chrome", "OPENAI_CHATGPT"),
        ("Claude", "ANTHROPIC_CLAUDE"),  # bare title, as Chrome shows for claude.ai
        ("Gemini - Google Gemini", "GOOGLE_GEMINI"),
        ("Grok | x.ai", "GROK"),
        ("DeepSeek Chat", "DEEPSEEK"),
    ])
    def test_matches_known_platforms(self, title, expected):
        assert _detect_platform_in_text(title) == expected

    def test_no_match_for_unrelated_title(self):
        assert _detect_platform_in_text("Untitled - Notepad") is None

    def test_case_insensitive(self):
        assert _detect_platform_in_text("CHATGPT") == "OPENAI_CHATGPT"


class TestAiBlocker:
    def _make_blocker(self, policy_resolver=None):
        client = MagicMock()
        client.report_ai_leak_attempt.return_value = {"id": "incident-1"}
        return AiBlocker(client, "agent-1", policy_resolver), client

    def test_returns_none_when_no_ai_platform_active(self):
        blocker, client = self._make_blocker()
        with patch.object(blocker, "_detect_platform", return_value=(None, "")):
            result = blocker.check_and_block(t_detect=time.monotonic())
        assert result is None
        client.report_ai_leak_attempt.assert_not_called()

    def test_clears_clipboard_and_reports_when_platform_active(self):
        blocker, client = self._make_blocker()
        with patch.object(blocker, "_detect_platform", return_value=("ANTHROPIC_CLAUDE", "window='Claude'")):
            with patch("ai_domain_monitor.pyperclip.copy") as mock_copy:
                result = blocker.check_and_block(t_detect=time.monotonic(), risk_score=0.9)

        assert result == "BLOCK"  # no policy_resolver supplied -> defaults to BLOCK
        mock_copy.assert_called_once_with("[BLOCKED BY DLP - Sensitive content detected]")
        client.report_ai_leak_attempt.assert_called_once()
        _, kwargs = client.report_ai_leak_attempt.call_args
        assert kwargs["platform"] == "ANTHROPIC_CLAUDE"
        assert kwargs["blocked"] is True

    def test_allow_action_does_not_clear_clipboard_or_report(self):
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "ALLOW", "name": "Allow Policy"}
        blocker, client = self._make_blocker(policy_resolver=resolver)
        with patch.object(blocker, "_detect_platform", return_value=("ANTHROPIC_CLAUDE", "window='Claude'")):
            with patch("ai_domain_monitor.pyperclip.copy") as mock_copy:
                result = blocker.check_and_block(t_detect=time.monotonic(), detections=[{"rule": "GDPR"}])

        assert result == "ALLOW"
        mock_copy.assert_not_called()
        client.report_ai_leak_attempt.assert_not_called()

    def test_alert_action_reports_but_does_not_clear_clipboard(self):
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "ALERT", "name": "Alert Policy"}
        blocker, client = self._make_blocker(policy_resolver=resolver)
        with patch.object(blocker, "_detect_platform", return_value=("ANTHROPIC_CLAUDE", "window='Claude'")):
            with patch("ai_domain_monitor.pyperclip.copy") as mock_copy:
                result = blocker.check_and_block(t_detect=time.monotonic(), detections=[{"rule": "GDPR"}])

        assert result == "ALERT"
        mock_copy.assert_not_called()
        client.report_ai_leak_attempt.assert_called_once()
        _, kwargs = client.report_ai_leak_attempt.call_args
        assert kwargs["blocked"] is False

    def test_quarantine_action_behaves_like_block(self):
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "QUARANTINE", "name": "Quarantine Policy"}
        blocker, client = self._make_blocker(policy_resolver=resolver)
        with patch.object(blocker, "_detect_platform", return_value=("ANTHROPIC_CLAUDE", "window='Claude'")):
            with patch("ai_domain_monitor.pyperclip.copy") as mock_copy:
                result = blocker.check_and_block(t_detect=time.monotonic(), detections=[{"rule": "GDPR"}])

        assert result == "QUARANTINE"
        mock_copy.assert_called_once()
        _, kwargs = client.report_ai_leak_attempt.call_args
        assert kwargs["blocked"] is True

    def test_passes_detections_to_policy_resolver(self):
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "BLOCK", "name": None}
        blocker, client = self._make_blocker(policy_resolver=resolver)
        detections = [{"rule": "PCI-DSS"}]
        with patch.object(blocker, "_detect_platform", return_value=("GROK", "x")):
            with patch("ai_domain_monitor.pyperclip.copy"):
                blocker.check_and_block(t_detect=time.monotonic(), detections=detections)

        resolver.resolve.assert_called_once_with(detections)

    def test_clipboard_clear_respects_cooldown(self):
        blocker, client = self._make_blocker()
        with patch.object(blocker, "_detect_platform", return_value=("GROK", "window='Grok'")):
            with patch("ai_domain_monitor.pyperclip.copy") as mock_copy:
                blocker.check_and_block(t_detect=time.monotonic())
                blocker.check_and_block(t_detect=time.monotonic())  # within 5s cooldown

        assert mock_copy.call_count == 1

    def test_alert_report_respects_per_platform_cooldown(self):
        blocker, client = self._make_blocker()
        with patch.object(blocker, "_detect_platform", return_value=("GROK", "window='Grok'")):
            with patch("ai_domain_monitor.pyperclip.copy"):
                blocker.check_and_block(t_detect=time.monotonic())
                blocker.check_and_block(t_detect=time.monotonic())  # within 60s alert cooldown

        assert client.report_ai_leak_attempt.call_count == 1

    def test_different_platforms_have_independent_alert_cooldowns(self):
        blocker, client = self._make_blocker()
        with patch("ai_domain_monitor.pyperclip.copy"):
            with patch.object(blocker, "_detect_platform", return_value=("GROK", "x")):
                blocker.check_and_block(t_detect=time.monotonic())
            with patch.object(blocker, "_detect_platform", return_value=("DEEPSEEK", "y")):
                blocker.check_and_block(t_detect=time.monotonic())

        assert client.report_ai_leak_attempt.call_count == 2

    def test_clipboard_clear_failure_does_not_prevent_reporting(self):
        blocker, client = self._make_blocker()
        with patch.object(blocker, "_detect_platform", return_value=("GROK", "x")):
            with patch("ai_domain_monitor.pyperclip.copy", side_effect=Exception("clipboard busy")):
                result = blocker.check_and_block(t_detect=time.monotonic())

        assert result == "BLOCK"
        client.report_ai_leak_attempt.assert_called_once()


class TestIsBrowserWindow:
    @pytest.mark.parametrize("title", [
        "ChatGPT - Google Chrome",
        "New Tab - Microsoft Edge",
        "Mozilla Firefox",
        "Untitled - Brave",
    ])
    def test_recognizes_browser_windows(self, title):
        assert _is_browser_window(title) is True

    @pytest.mark.parametrize("title", [
        "Untitled - Notepad",
        "Calculator",
        "client_data.txt - Microsoft Word",
    ])
    def test_ignores_non_browser_windows(self, title):
        assert _is_browser_window(title) is False


class TestDetectPlatformViaAddressBar:
    def _fake_edit(self, text):
        edit = MagicMock()
        edit.window_text.return_value = text
        return edit

    def test_matches_platform_in_address_bar_text(self):
        fake_window = MagicMock()
        fake_window.descendants.return_value = [self._fake_edit("chatgpt.com/c/abc123")]
        with patch("ai_domain_monitor.Desktop") as mock_desktop:
            mock_desktop.return_value.window.return_value = fake_window
            result = aidm._detect_platform_via_address_bar(12345)
        assert result == "OPENAI_CHATGPT"

    def test_returns_none_when_no_edit_matches(self):
        fake_window = MagicMock()
        fake_window.descendants.return_value = [self._fake_edit("example.com")]
        with patch("ai_domain_monitor.Desktop") as mock_desktop:
            mock_desktop.return_value.window.return_value = fake_window
            result = aidm._detect_platform_via_address_bar(12345)
        assert result is None

    def test_returns_none_on_uia_failure(self):
        with patch("ai_domain_monitor.Desktop", side_effect=Exception("no such window")):
            result = aidm._detect_platform_via_address_bar(12345)
        assert result is None

    def test_stops_scanning_after_twenty_edits(self):
        fake_window = MagicMock()
        # 25 non-matching edits followed by a matching one past the cap --
        # should NOT be found, proving the scan bound is respected.
        edits = [self._fake_edit("nothing here") for _ in range(25)] + [self._fake_edit("claude.ai")]
        fake_window.descendants.return_value = edits
        with patch("ai_domain_monitor.Desktop") as mock_desktop:
            mock_desktop.return_value.window.return_value = fake_window
            result = aidm._detect_platform_via_address_bar(12345)
        assert result is None


class TestAiBlockerDetectPlatformTiers:
    def _make_blocker(self):
        return AiBlocker(MagicMock(), "agent-1")

    def test_tier1_window_title_short_circuits_before_url_check(self):
        blocker = self._make_blocker()
        with patch(
            "ai_domain_monitor._enum_all_windows",
            return_value=[(1, "ChatGPT - Google Chrome")],
        ), patch("ai_domain_monitor._detect_platform_via_address_bar") as mock_url:
            plat, detail = blocker._detect_platform()
        assert plat == "OPENAI_CHATGPT"
        assert "window=" in detail
        mock_url.assert_not_called()

    def test_tier2_falls_back_to_url_when_title_is_rewritten(self):
        blocker = self._make_blocker()
        with patch(
            "ai_domain_monitor._enum_all_windows",
            return_value=[(1, "Excel file request - Google Chrome")],
        ), patch(
            "ai_domain_monitor._detect_platform_via_address_bar",
            return_value="OPENAI_CHATGPT",
        ):
            plat, detail = blocker._detect_platform()
        assert plat == "OPENAI_CHATGPT"
        assert "url-in-tab=" in detail

    def test_tier2_result_is_cached_within_ttl(self):
        blocker = self._make_blocker()
        with patch(
            "ai_domain_monitor._enum_all_windows",
            return_value=[(1, "Excel file request - Google Chrome")],
        ), patch(
            "ai_domain_monitor._detect_platform_via_address_bar",
            return_value="OPENAI_CHATGPT",
        ) as mock_url:
            blocker._detect_platform()
            blocker._detect_platform()  # within _URL_CACHE_TTL
        assert mock_url.call_count == 1

    def test_tier3_process_fallback_when_no_title_or_url_match(self):
        blocker = self._make_blocker()
        with patch("ai_domain_monitor._enum_all_windows", return_value=[(1, "Untitled - Notepad")]), \
             patch("ai_domain_monitor._scan_processes_raw", return_value=("ANTHROPIC_CLAUDE", "claude")):
            plat, detail = blocker._detect_platform()
        assert plat == "ANTHROPIC_CLAUDE"
        assert "process=" in detail

    def test_address_bar_only_checked_for_browser_windows(self):
        blocker = self._make_blocker()
        with patch(
            "ai_domain_monitor._enum_all_windows",
            return_value=[(1, "Untitled - Notepad")],
        ), patch(
            "ai_domain_monitor._detect_platform_via_address_bar",
        ) as mock_url, patch(
            "ai_domain_monitor._scan_processes_raw", return_value=(None, ""),
        ):
            blocker._detect_platform()
        mock_url.assert_not_called()


class TestScanProcessesRaw:
    def test_matches_known_process_keyword(self):
        fake_proc = MagicMock()
        fake_proc.info = {"name": "Claude.exe"}
        with patch("ai_domain_monitor.psutil.process_iter", return_value=[fake_proc]):
            plat, name = aidm._scan_processes_raw()
        assert plat == "ANTHROPIC_CLAUDE"
        assert name == "claude"

    def test_no_match_returns_none(self):
        fake_proc = MagicMock()
        fake_proc.info = {"name": "notepad.exe"}
        with patch("ai_domain_monitor.psutil.process_iter", return_value=[fake_proc]):
            plat, name = aidm._scan_processes_raw()
        assert plat is None
        assert name == ""
