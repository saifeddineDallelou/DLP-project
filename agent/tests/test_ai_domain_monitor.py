import threading
import time
from unittest.mock import patch, MagicMock

import pytest

import ai_domain_monitor as aidm
from ai_domain_monitor import AiBlocker, _detect_platform_in_text, _is_browser_window, _ai_monitor_loop


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
        assert kwargs["policy_id"] is None  # no resolver -> no policy to link

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
        assert kwargs["policy_id"] == "p1"

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
        assert kwargs["policy_id"] == "p1"

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

    def test_clip_clear_cooldown_is_independent_per_platform(self):
        # A block on one platform must NOT suppress a block on a DIFFERENT
        # platform detected moments later -- e.g. paste into Grok, then
        # Gemini 3s later, are two separate leak attempts and each must be
        # independently blocked, not silently let through because a
        # different platform's clear timer is still cooling down.
        blocker, client = self._make_blocker()
        with patch("ai_domain_monitor.pyperclip.copy") as mock_copy:
            with patch.object(blocker, "_detect_platform", return_value=("GROK", "x")):
                result1 = blocker.check_and_block(t_detect=time.monotonic())
            with patch.object(blocker, "_detect_platform", return_value=("GOOGLE_GEMINI", "y")):
                result2 = blocker.check_and_block(t_detect=time.monotonic())

        assert result1 == "BLOCK"
        assert result2 == "BLOCK"
        assert mock_copy.call_count == 2
        _, kwargs = client.report_ai_leak_attempt.call_args
        assert kwargs["blocked"] is True

    def test_clipboard_clear_failure_does_not_prevent_reporting(self):
        blocker, client = self._make_blocker()
        with patch.object(blocker, "_detect_platform", return_value=("GROK", "x")):
            with patch("ai_domain_monitor.pyperclip.copy", side_effect=Exception("clipboard busy")):
                result = blocker.check_and_block(t_detect=time.monotonic())

        assert result == "BLOCK"
        client.report_ai_leak_attempt.assert_called_once()


class TestBlockWithReviewRequest:
    def _make_blocker(self):
        client = MagicMock()
        client.report_ai_leak_attempt.return_value = {"id": "attempt-1"}
        return AiBlocker(client, "agent-1"), client

    def _capture_thread_target(self):
        """Collect every spawned thread target and run them in order.

        Reporting now happens on its own thread, and the review prompt is
        offered from INSIDE that thread -- so draining has to keep going as
        running one target spawns another. Capturing only the last target
        would silently stop at the report and never reach the prompt."""
        captured = {"targets": []}

        def fake_thread(target, **kwargs):
            captured["targets"].append(target)
            return MagicMock()

        def run_all():
            i = 0
            while i < len(captured["targets"]):
                captured["targets"][i]()
                i += 1

        captured["run_all"] = run_all
        return captured, fake_thread

    def test_requests_review_with_note_but_never_touches_clipboard(self):
        blocker, client = self._make_blocker()
        client.request_review_ai_leak_attempt.return_value = {"id": "attempt-1", "reviewRequested": True}
        captured, fake_thread = self._capture_thread_target()

        with patch.object(blocker, "_detect_platform", return_value=("ANTHROPIC_CLAUDE", "window='Claude'")), \
             patch("ai_domain_monitor.pyperclip.copy") as mock_copy, \
             patch("ai_domain_monitor.threading.Thread", side_effect=fake_thread), \
             patch("ai_domain_monitor.prompt_review_request", return_value="Looked legitimate to me"):
            result = blocker.check_and_block(t_detect=time.monotonic(), risk_score=0.9)
            assert result == "BLOCK"
            captured["run_all"]()  # run the "background threads" synchronously, patches still active

        # The clipboard clear (block message) is the only copy() call --
        # nothing ever restores the original content.
        mock_copy.assert_called_once_with("[BLOCKED BY DLP - Sensitive content detected]")
        client.request_review_ai_leak_attempt.assert_called_once_with("attempt-1", "Looked legitimate to me")

    def test_review_request_with_no_note_still_flags_it(self):
        blocker, client = self._make_blocker()
        client.request_review_ai_leak_attempt.return_value = {"id": "attempt-1", "reviewRequested": True}
        captured, fake_thread = self._capture_thread_target()

        with patch.object(blocker, "_detect_platform", return_value=("ANTHROPIC_CLAUDE", "x")), \
             patch("ai_domain_monitor.pyperclip.copy"), \
             patch("ai_domain_monitor.threading.Thread", side_effect=fake_thread), \
             patch("ai_domain_monitor.prompt_review_request", return_value=""):
            blocker.check_and_block(t_detect=time.monotonic())
            captured["run_all"]()

        client.request_review_ai_leak_attempt.assert_called_once_with("attempt-1", None)

    def test_dismissed_prompt_does_not_request_review(self):
        blocker, client = self._make_blocker()
        captured, fake_thread = self._capture_thread_target()

        with patch.object(blocker, "_detect_platform", return_value=("ANTHROPIC_CLAUDE", "x")), \
             patch("ai_domain_monitor.pyperclip.copy"), \
             patch("ai_domain_monitor.threading.Thread", side_effect=fake_thread), \
             patch("ai_domain_monitor.prompt_review_request", return_value=None):
            blocker.check_and_block(t_detect=time.monotonic())
            captured["run_all"]()

        client.request_review_ai_leak_attempt.assert_not_called()

    def test_no_review_prompt_offered_for_alert_action(self):
        # ALERT never clears the clipboard, so there is nothing worth
        # prompting about. It IS still reported, with blocked=False -- and
        # that report runs on its own thread now, so "no thread spawned"
        # would only be asserting that reporting is synchronous, which is
        # exactly what it must not be. Assert the actual intent instead.
        blocker, client = self._make_blocker()
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "ALERT", "name": "Alert Policy"}
        blocker = AiBlocker(client, "agent-1", policy_resolver=resolver)
        captured, fake_thread = self._capture_thread_target()

        with patch.object(blocker, "_detect_platform", return_value=("ANTHROPIC_CLAUDE", "x")),              patch("ai_domain_monitor.threading.Thread", side_effect=fake_thread),              patch("ai_domain_monitor.prompt_review_request") as mock_prompt:
            blocker.check_and_block(t_detect=time.monotonic())
            captured["run_all"]()

        mock_prompt.assert_not_called()
        client.request_review_ai_leak_attempt.assert_not_called()
        assert client.report_ai_leak_attempt.call_args.kwargs["blocked"] is False


class TestAiMonitorLoop:
    """_ai_monitor_loop is the DELAYED path: it fires when a sensitive
    clipboard copy happened while no AI window was open yet, then an AI tab
    gets opened within the flag window. It must resolve the SAME policy the
    immediate check would have -- i.e. carry the original classify()
    detections through via AgentState.sensitive_clip_context(), not resolve
    against an empty list (which always falls back to the default policy)."""

    def _run_one_iteration(self, state, blocker):
        stop = threading.Event()
        blocker.check_and_block.side_effect = lambda **kwargs: (stop.set(), "BLOCK")[1]
        _ai_monitor_loop("agent-1", state, stop, blocker)

    def test_passes_carried_detections_to_check_and_block(self):
        state = MagicMock()
        state.clipboard_flagged_recently.return_value = True
        state.sensitive_clip_monotonic.return_value = time.monotonic()
        detections = [{"rule": "PCI-DSS", "type": "credit_card"}]
        state.sensitive_clip_context.return_value = {
            "detections": detections, "risk_score": 0.9, "content_sample": "card ****1111",
        }
        blocker = MagicMock()

        self._run_one_iteration(state, blocker)

        _, kwargs = blocker.check_and_block.call_args
        assert kwargs["detections"] == detections
        assert kwargs["risk_score"] == 0.9
        assert kwargs["content_sample"] == "card ****1111"
        assert kwargs["source_tag"] == "CLIPBOARD_DELAYED"

    def test_falls_back_to_sensible_defaults_when_context_is_empty(self):
        state = MagicMock()
        state.clipboard_flagged_recently.return_value = True
        state.sensitive_clip_monotonic.return_value = time.monotonic()
        state.sensitive_clip_context.return_value = {}
        blocker = MagicMock()

        self._run_one_iteration(state, blocker)

        _, kwargs = blocker.check_and_block.call_args
        assert kwargs["detections"] is None
        assert kwargs["risk_score"] == 0.95
        assert kwargs["content_sample"] == ""

    def test_skips_check_when_nothing_recently_flagged(self):
        state = MagicMock()
        state.clipboard_flagged_recently.return_value = False
        blocker = MagicMock()
        stop = MagicMock()
        stop.is_set.side_effect = [False, True]  # run exactly one iteration

        _ai_monitor_loop("agent-1", state, stop, blocker)

        blocker.check_and_block.assert_not_called()


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
    @pytest.fixture(autouse=True)
    def _neutral_foreground(self):
        # _detect_platform now consults the FOREGROUND window before scanning
        # every window, so these tier tests must pin it to something that
        # matches nothing -- otherwise they pick up whatever real window is
        # focused on the machine running them and become non-deterministic.
        # The foreground-priority behaviour itself is covered separately below.
        with patch("ai_domain_monitor._get_foreground_window", return_value=(0, "")):
            yield

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
             patch("ai_domain_monitor._scan_processes_raw", return_value=[(999, "claude", "ANTHROPIC_CLAUDE")]), \
             patch("ai_domain_monitor._window_owner_pids", return_value={999}):
            plat, detail = blocker._detect_platform()
        assert plat == "ANTHROPIC_CLAUDE"
        assert "process=" in detail

    def test_tier3_ignores_process_match_without_a_visible_window(self):
        # A name match on a headless background/helper process (e.g. this
        # dev machine's own Claude Code subprocesses, all named "claude")
        # must NOT be mistaken for the AI platform actually in use -- see
        # _window_owner_pids.
        blocker = self._make_blocker()
        with patch("ai_domain_monitor._enum_all_windows", return_value=[(1, "Untitled - Notepad")]), \
             patch("ai_domain_monitor._scan_processes_raw", return_value=[(999, "claude", "ANTHROPIC_CLAUDE")]), \
             patch("ai_domain_monitor._window_owner_pids", return_value=set()):  # pid 999 owns no window
            plat, detail = blocker._detect_platform()
        assert plat is None

    def test_foreground_platform_wins_over_another_open_ai_window(self):
        # The bug this exists for: a paste into a focused ChatGPT tab was
        # recorded as ANTHROPIC_CLAUDE, because an always-open Claude Code
        # window matched earlier in the window enumeration. Blocking was
        # correct; the platform on the incident was not.
        blocker = self._make_blocker()
        with patch(
            "ai_domain_monitor._get_foreground_window",
            return_value=(42, "ChatGPT - Google Chrome"),
        ), patch(
            "ai_domain_monitor._enum_all_windows",
            # Claude Code first, exactly as the enumeration returned it live.
            return_value=[(1, "✳ Claude Code"), (42, "ChatGPT - Google Chrome")],
        ):
            plat, detail = blocker._detect_platform()
        assert plat == "OPENAI_CHATGPT"
        assert "foreground=" in detail

    def test_foreground_browser_url_is_checked_before_other_windows(self):
        # ChatGPT renames its tab to the conversation topic once you start
        # chatting, so the focused window's TITLE matches nothing -- which is
        # precisely how a background Claude Code window won the attribution.
        blocker = self._make_blocker()
        with patch(
            "ai_domain_monitor._get_foreground_window",
            return_value=(42, "Quarterly figures - Google Chrome"),
        ), patch(
            "ai_domain_monitor._enum_all_windows",
            return_value=[(1, "✳ Claude Code"), (42, "Quarterly figures - Google Chrome")],
        ), patch(
            "ai_domain_monitor._detect_platform_via_address_bar",
            return_value="OPENAI_CHATGPT",
        ):
            plat, detail = blocker._detect_platform()
        assert plat == "OPENAI_CHATGPT"
        assert "foreground-url=" in detail

    def test_background_ai_window_still_detected_when_foreground_is_not_ai(self):
        # Attribution changed; blocking did not. An AI tab sitting in the
        # background is still a live paste target and must still be found.
        blocker = self._make_blocker()
        with patch(
            "ai_domain_monitor._get_foreground_window",
            return_value=(7, "Untitled - Notepad"),
        ), patch(
            "ai_domain_monitor._enum_all_windows",
            return_value=[(7, "Untitled - Notepad"), (1, "ChatGPT - Google Chrome")],
        ), patch("ai_domain_monitor._detect_platform_via_address_bar", return_value=None):
            plat, detail = blocker._detect_platform()
        assert plat == "OPENAI_CHATGPT"
        assert "window=" in detail

    def test_foreground_non_browser_does_not_trigger_an_address_bar_read(self):
        blocker = self._make_blocker()
        with patch(
            "ai_domain_monitor._get_foreground_window",
            return_value=(7, "Untitled - Notepad"),
        ), patch(
            "ai_domain_monitor._enum_all_windows",
            return_value=[(7, "Untitled - Notepad")],
        ), patch(
            "ai_domain_monitor._detect_platform_via_address_bar",
        ) as mock_url, patch("ai_domain_monitor._scan_processes_raw", return_value=[]):
            blocker._detect_platform()
        # Tier 2 may still consult it for OTHER browser windows, but the
        # foreground shortcut must not have fired for a non-browser.
        for call in mock_url.call_args_list:
            assert call.args[0] != 7

    def test_address_bar_only_checked_for_browser_windows(self):
        blocker = self._make_blocker()
        with patch(
            "ai_domain_monitor._enum_all_windows",
            return_value=[(1, "Untitled - Notepad")],
        ), patch(
            "ai_domain_monitor._detect_platform_via_address_bar",
        ) as mock_url, patch(
            "ai_domain_monitor._scan_processes_raw", return_value=[],
        ):
            blocker._detect_platform()
        mock_url.assert_not_called()


class TestScanProcessesRaw:
    def test_matches_known_process_keyword(self):
        fake_proc = MagicMock()
        fake_proc.info = {"pid": 1234, "name": "Claude.exe"}
        with patch("ai_domain_monitor.psutil.process_iter", return_value=[fake_proc]):
            matches = aidm._scan_processes_raw()
        assert matches == [(1234, "claude", "ANTHROPIC_CLAUDE")]

    def test_no_match_returns_empty_list(self):
        fake_proc = MagicMock()
        fake_proc.info = {"pid": 1234, "name": "notepad.exe"}
        with patch("ai_domain_monitor.psutil.process_iter", return_value=[fake_proc]):
            matches = aidm._scan_processes_raw()
        assert matches == []

    def test_returns_every_matching_process_not_just_the_first(self):
        procs = [MagicMock(info={"pid": 1, "name": "claude.exe"}), MagicMock(info={"pid": 2, "name": "chatgpt.exe"})]
        with patch("ai_domain_monitor.psutil.process_iter", return_value=procs):
            matches = aidm._scan_processes_raw()
        assert matches == [(1, "claude", "ANTHROPIC_CLAUDE"), (2, "chatgpt", "OPENAI_CHATGPT")]


class TestWindowOwnerPids:
    def test_collects_pid_for_each_window_via_win32_api(self):
        def fake_get_pid(hwnd, pid_ref):
            pid_ref._obj.value = 4242 if hwnd == 111 else 5555

        with patch("ai_domain_monitor.ctypes.windll.user32.GetWindowThreadProcessId", side_effect=fake_get_pid):
            pids = aidm._window_owner_pids([(111, "Notepad"), (222, "Chrome")])
        assert pids == {4242, 5555}

    def test_empty_window_list_returns_empty_set(self):
        assert aidm._window_owner_pids([]) == set()
