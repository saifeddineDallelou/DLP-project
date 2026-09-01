import queue
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

import screenshot_monitor
from screenshot_monitor import _is_sensitive, _matched_keyword, _KEYWORD_RULE, _SENSITIVE_KEYWORDS, _SENSITIVE_FILENAME_KW


class TestMatchedKeyword:
    def test_returns_the_matched_keyword(self):
        assert _matched_keyword("payroll_2026.xlsx - Excel") == "payroll"

    def test_returns_none_for_ordinary_window(self):
        assert _matched_keyword("Untitled - Notepad") is None

    def test_returns_a_filename_keyword_for_office_file(self):
        assert _matched_keyword("client_invoice.xlsx - Excel") in ("client", "invoice")

    def test_is_sensitive_still_reflects_whether_a_keyword_matched(self):
        assert _is_sensitive("payroll_2026.xlsx - Excel") is True
        assert _is_sensitive("Untitled - Notepad") is False


class TestKeywordRule:
    def test_every_sensitive_keyword_has_a_compliance_rule(self):
        for kw in _SENSITIVE_KEYWORDS | _SENSITIVE_FILENAME_KW:
            assert kw in _KEYWORD_RULE, f"{kw!r} has no compliance rule mapping"

    @pytest.mark.parametrize("keyword,expected_rule", [
        ("ssn", "HIPAA"),
        ("medical", "HIPAA"),
        ("iban", "PCI-DSS"),
        ("bank", "PCI-DSS"),
        ("confidential", "INTERNAL"),
        ("password", "INTERNAL"),
        ("salary", "GDPR"),
        ("client", "GDPR"),
    ])
    def test_maps_keyword_to_the_expected_rule(self, keyword, expected_rule):
        assert _KEYWORD_RULE[keyword] == expected_rule


class TestIsSensitive:
    @pytest.mark.parametrize("title", [
        "payroll_2026.xlsx - Excel",
        "Client Confidential Report - Word",
        "salary_bands.docx - Microsoft Word",
        "Password Manager - Chrome",
        "Internal Budget Review",
    ])
    def test_matches_sensitive_keywords(self, title):
        assert _is_sensitive(title) is True

    def test_matches_office_file_with_sensitive_filename(self):
        assert _is_sensitive("client_invoice.xlsx - Excel") is True

    def test_office_extension_alone_is_not_enough(self):
        # .xlsx present, but filename part has no sensitive keyword
        assert _is_sensitive("random_numbers.xlsx - Excel") is False

    def test_ordinary_window_is_not_sensitive(self):
        assert _is_sensitive("Untitled - Notepad") is False
        assert _is_sensitive("YouTube - Google Chrome") is False

    def test_case_insensitive(self):
        assert _is_sensitive("CONFIDENTIAL REPORT") is True


class TestContentCheckAsync:
    """
    _content_check_async is the OCR-content-check path -- the one path in
    this module that actually calls classify() and gets back compliance-
    tagged detections, so it's what needs to thread those detections into
    the event queue for the policy resolver downstream in _screenshot_loop.
    """

    def test_queues_detections_when_sensitive(self):
        client = MagicMock()
        client.classify.return_value = {
            "risk_score": 0.9,
            "detections": [{"type": "credit_card", "rule": "PCI-DSS"}],
        }
        q: queue.Queue = queue.Queue()

        with patch("screenshot_monitor.pytesseract.image_to_string", return_value="card 4111111111111111"), \
             patch("screenshot_monitor._clipboard_has_image", return_value=True), \
             patch("screenshot_monitor.pyperclip.copy"):
            screenshot_monitor._content_check_async(MagicMock(), "some title", time.monotonic(), client, q)

        policy, source_tag, title, t_event, cleared, detections = q.get_nowait()
        assert policy["action"] == "BLOCK"  # no policy_resolver supplied -> defaults to BLOCK
        assert cleared is True
        assert source_tag == "OCR_CONTENT"
        assert detections == [{"type": "credit_card", "rule": "PCI-DSS"}]

    def test_resolves_policy_from_detections_and_skips_clear_for_allow(self):
        client = MagicMock()
        detections = [{"type": "credit_card", "rule": "PCI-DSS"}]
        client.classify.return_value = {"risk_score": 0.9, "detections": detections}
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "ALLOW", "name": "Allow Policy"}
        q: queue.Queue = queue.Queue()

        with patch("screenshot_monitor.pytesseract.image_to_string", return_value="card 4111111111111111"), \
             patch("screenshot_monitor._clipboard_has_image", return_value=True), \
             patch("screenshot_monitor.pyperclip.copy") as mock_copy:
            screenshot_monitor._content_check_async(MagicMock(), "title", time.monotonic(), client, q, resolver)

        resolver.resolve.assert_called_once_with(detections)
        mock_copy.assert_not_called()
        policy, *_rest, cleared, _detections = q.get_nowait()
        assert policy["action"] == "ALLOW"
        assert cleared is False

    def test_alert_action_does_not_clear_clipboard(self):
        client = MagicMock()
        client.classify.return_value = {"risk_score": 0.9, "detections": []}
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "ALERT", "name": None}
        q: queue.Queue = queue.Queue()

        with patch("screenshot_monitor.pytesseract.image_to_string", return_value="some ocr text"), \
             patch("screenshot_monitor._clipboard_has_image", return_value=True), \
             patch("screenshot_monitor.pyperclip.copy") as mock_copy:
            screenshot_monitor._content_check_async(MagicMock(), "title", time.monotonic(), client, q, resolver)

        mock_copy.assert_not_called()
        policy, *_rest, cleared, _detections = q.get_nowait()
        assert policy["action"] == "ALERT"
        assert cleared is False

    def test_queues_nothing_when_ocr_text_too_short(self):
        client = MagicMock()
        q: queue.Queue = queue.Queue()
        with patch("screenshot_monitor.pytesseract.image_to_string", return_value="hi"):
            screenshot_monitor._content_check_async(MagicMock(), "title", time.monotonic(), client, q)
        assert q.empty()
        client.classify.assert_not_called()

    def test_queues_nothing_when_risk_is_low(self):
        client = MagicMock()
        client.classify.return_value = {"risk_score": 0.2, "detections": []}
        q: queue.Queue = queue.Queue()
        with patch("screenshot_monitor.pytesseract.image_to_string", return_value="just some regular text here"):
            screenshot_monitor._content_check_async(MagicMock(), "title", time.monotonic(), client, q)
        assert q.empty()

    def test_queues_nothing_when_classifier_unavailable(self):
        client = MagicMock()
        client.classify.return_value = None
        q: queue.Queue = queue.Queue()
        with patch("screenshot_monitor.pytesseract.image_to_string", return_value="some real ocr text here"):
            screenshot_monitor._content_check_async(MagicMock(), "title", time.monotonic(), client, q)
        assert q.empty()


class TestStartScreenshotMonitor:
    def test_passes_policy_resolver_through_to_worker_thread(self):
        # Thread is mocked so this never actually runs _screenshot_loop (which
        # registers real global keyboard hooks -- not safe to execute in a
        # unit test); this only checks the resolver is wired through.
        resolver = MagicMock()
        client = MagicMock()
        stop = threading.Event()

        with patch("screenshot_monitor.sys.platform", "win32"), \
             patch("screenshot_monitor.threading.Thread") as mock_thread:
            screenshot_monitor.start_screenshot_monitor(client, "agent-1", stop, resolver)

        _, kwargs = mock_thread.call_args
        args = kwargs["args"]
        assert args[0] is client
        assert args[1] == "agent-1"
        assert args[3] is stop
        assert args[4] is resolver

    def test_disabled_on_non_windows_without_touching_resolver(self):
        resolver = MagicMock()
        stop = threading.Event()
        with patch("screenshot_monitor.sys.platform", "linux"):
            t = screenshot_monitor.start_screenshot_monitor(MagicMock(), "agent-1", stop, resolver)
        assert isinstance(t, threading.Thread)
        resolver.resolve.assert_not_called()
