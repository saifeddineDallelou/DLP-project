import base64
import glob
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

import upload_guard
from upload_guard import extract_blob, make_upload_check


@pytest.fixture(autouse=True)
def _reset_window():
    """The repeat window is module-level, as it is for a real agent."""
    upload_guard._REPEATS.__init__(upload_guard._REPEATS._cooldown)
    yield


SENSITIVE = {
    "risk_score": 0.95,
    "detections": [{"type": "credit_card", "rule": "PCI-DSS"}],
}
CLEAN = {"risk_score": 0.0, "detections": []}


def _client(classify=SENSITIVE):
    client = MagicMock()
    client.classify.return_value = classify
    client.create_incident.return_value = {"id": "inc-1"}
    client.repeat_incident.return_value = {"id": "inc-1", "attempts": 2}
    return client


def _resolver():
    r = MagicMock()
    r.resolve.return_value = {"id": "p1", "action": "BLOCK", "name": "PCI-DSS",
                              "severity": "HIGH"}
    return r


class TestUploadCheck:
    """
    Opera draws its own recent-files panel inside the browser window, so no
    Windows dialog is created and the file-dialog monitor has nothing to find.
    A live test uploaded a sensitive CSV that way and it went straight up,
    while the same file through Explorer was blocked.

    The extension can see it, and asks this.
    """

    def test_a_sensitive_file_is_blocked(self):
        with patch("upload_guard.offer_review"):
            check = make_upload_check(_client(), "agent-1", _resolver())
            assert check("cards.csv", "4111111111111111", "OPENAI_CHATGPT") is True

    def test_a_clean_file_is_allowed(self):
        check = make_upload_check(_client(CLEAN), "agent-1", _resolver())
        assert check("notes.txt", "the meeting is at four", "OPENAI_CHATGPT") is False

    def test_unreadable_content_is_not_treated_as_sensitive(self):
        # An image the content script could not read as text. Blocking on no
        # evidence would stop every avatar upload in the browser.
        client = _client()
        check = make_upload_check(client, "agent-1", _resolver())
        assert check("photo.png", "   ", "OPENAI_CHATGPT") is False
        client.classify.assert_not_called()

    def test_a_dead_classifier_does_not_wedge_the_browser(self):
        # The page is waiting on this answer before the user can continue.
        # The other channels let content through when the classifier is down,
        # and a browser that cannot upload anything is worse than the gap.
        client = _client()
        client.classify.return_value = None
        check = make_upload_check(client, "agent-1", _resolver())
        assert check("cards.csv", "4111111111111111", "OPENAI_CHATGPT") is False

    def test_a_block_is_recorded_with_the_filename(self):
        client = _client()
        with patch("upload_guard.offer_review"):
            make_upload_check(client, "agent-1", _resolver())(
                "cards.csv", "4111111111111111", "OPENAI_CHATGPT")

        client.create_incident.assert_called_once()
        kwargs = client.create_incident.call_args.kwargs
        assert kwargs["channel"] == "FILE_UPLOAD"
        assert "cards.csv" in kwargs["evidence"]
        assert "OPENAI_CHATGPT" in kwargs["evidence"]

    def test_a_block_tells_the_user(self):
        # A block nobody can see is indistinguishable from the site being
        # broken.
        client = _client()
        with patch("upload_guard.offer_review") as offer:
            make_upload_check(client, "agent-1", _resolver())(
                "cards.csv", "4111111111111111", "OPENAI_CHATGPT")
        offer.assert_called_once()
        assert offer.call_args[0][1] == "incident"

    def test_the_same_file_again_counts_instead_of_filing_a_row(self):
        client = _client()
        with patch("upload_guard.offer_review"):
            check = make_upload_check(client, "agent-1", _resolver())
            for _ in range(3):
                assert check("cards.csv", "4111111111111111", "OPENAI_CHATGPT") is True

        # Blocked all three times, recorded once, counted twice.
        assert client.create_incident.call_count == 1
        assert client.repeat_incident.call_count == 2

    def test_a_different_file_is_its_own_incident(self):
        client = _client()
        with patch("upload_guard.offer_review"):
            check = make_upload_check(client, "agent-1", _resolver())
            check("cards.csv", "4111111111111111", "OPENAI_CHATGPT")
            check("payroll.csv", "4111111111111111", "OPENAI_CHATGPT")

        assert client.create_incident.call_count == 2
        assert client.repeat_incident.call_count == 0

    def test_the_evidence_carries_no_file_content(self):
        # The whole point of safe_sample: the snippet is built from masked
        # detections, never the bytes the user picked.
        client = _client()
        with patch("upload_guard.offer_review"):
            make_upload_check(client, "agent-1", _resolver())(
                "cards.csv", "4111111111111111", "OPENAI_CHATGPT")

        evidence = client.create_incident.call_args.kwargs["evidence"]
        assert "4111111111111111" not in evidence

    def test_it_works_without_a_policy_resolver(self):
        client = _client()
        with patch("upload_guard.offer_review"):
            assert make_upload_check(client, "agent-1", None)(
                "cards.csv", "4111111111111111", "OPENAI_CHATGPT") is True


def _xlsx_bytes(value="4111111111111111"):
    """A real .xlsx, because the point is that it is a ZIP and not text."""
    import openpyxl
    wb = openpyxl.Workbook()
    wb.active["A1"] = "card"
    wb.active["A2"] = value
    fd, path = tempfile.mkstemp(suffix=".xlsx")
    os.close(fd)
    try:
        wb.save(path)
        with open(path, "rb") as fh:
            return base64.b64encode(fh.read()).decode()
    finally:
        os.unlink(path)


class TestContainerFormats:
    """
    A .xlsx is a ZIP and a .pdf is a binary. Reading either as text in the
    browser produces mojibake, so the extension skipped them -- and a customer
    database is almost never a .txt. The bytes come over instead and the
    agent's own extractor, the same one file_watcher uses, reads them.
    """

    def test_a_spreadsheet_of_card_numbers_is_read(self):
        text = extract_blob("customers.xlsx", _xlsx_bytes())
        assert "4111111111111111" in text

    def test_a_spreadsheet_of_card_numbers_is_blocked(self):
        client = _client()
        with patch("upload_guard.offer_review"):
            check = make_upload_check(client, "agent-1", _resolver())
            assert check("customers.xlsx", "", "OPENAI_CHATGPT", _xlsx_bytes()) is True
        # The classifier saw the extracted cell, not the ZIP header.
        assert "4111111111111111" in client.classify.call_args.kwargs["text"]

    def test_a_format_the_extractor_does_not_know_is_not_written_to_disk(self):
        # Writing an arbitrary upload to disk to see what happens is not
        # something a DLP agent should do.
        jpeg_magic = bytes([0xFF, 0xD8, 0xFF])
        assert extract_blob("holiday.jpg", base64.b64encode(jpeg_magic).decode()) == ""

    def test_an_oversized_blob_is_refused(self):
        big = base64.b64encode(b"x" * (upload_guard._MAX_BLOB_BYTES + 1)).decode()
        assert extract_blob("huge.xlsx", big) == ""

    def test_undecodable_bytes_do_not_raise(self):
        assert extract_blob("customers.xlsx", "not base64 at all !!!") == ""

    def test_the_temp_copy_is_always_deleted(self):
        # It holds the very content this module exists to stop leaving. The
        # DLP agent must not be the thing that drops a copy in %TEMP%.
        before = set(glob.glob(os.path.join(tempfile.gettempdir(), "dlp-upload-*")))
        extract_blob("customers.xlsx", _xlsx_bytes())
        with patch("upload_guard.extract", side_effect=RuntimeError("boom")):
            extract_blob("customers.xlsx", _xlsx_bytes())
        after = set(glob.glob(os.path.join(tempfile.gettempdir(), "dlp-upload-*")))
        assert after == before

    def test_a_text_file_still_takes_the_text_path(self):
        client = _client()
        with patch("upload_guard.offer_review"):
            check = make_upload_check(client, "agent-1", _resolver())
            assert check("cards.csv", "4111111111111111", "OPENAI_CHATGPT") is True
        assert client.classify.call_args.kwargs["text"] == "4111111111111111"
