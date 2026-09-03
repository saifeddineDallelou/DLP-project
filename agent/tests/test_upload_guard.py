from unittest.mock import MagicMock, patch

import pytest

import upload_guard
from upload_guard import make_upload_check


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
