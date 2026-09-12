from unittest.mock import MagicMock, call, patch

import pytest

import print_monitor
from print_monitor import PrintJobGuard, clean_title, document_path, handle_new_job

SENSITIVE = {
    "risk_score": 0.95,
    "detections": [{"type": "credit_card", "rule": "PCI-DSS"}],
}
CLEAN = {"risk_score": 0.05, "detections": []}


@pytest.fixture(autouse=True)
def _reset_window():
    print_monitor._REPEATS.__init__(print_monitor._REPEATS._cooldown)
    yield


def _client(classify=SENSITIVE):
    client = MagicMock()
    client.classify.return_value = classify
    client.create_incident.return_value = {"id": "inc-1"}
    client.repeat_incident.return_value = {"id": "inc-1", "attempts": 2}
    return client


def _resolver(action="BLOCK"):
    r = MagicMock()
    r.resolve.return_value = {"id": "p1", "action": action, "name": "PCI-DSS",
                              "severity": "HIGH"}
    return r


def _job(document="payroll_2026.xlsx - Excel", job_id=7):
    return {"printer": "HP LaserJet", "jobId": job_id, "document": document,
            "user": "MMD", "pages": 3}


class TestDocumentName:
    def test_a_real_path_is_recognised(self, tmp_path):
        f = tmp_path / "cards.csv"
        f.write_text("4111111111111111", encoding="utf-8")
        assert document_path(str(f)) == str(f)

    def test_a_title_that_merely_looks_like_a_path_is_not_read_as_one(self):
        assert document_path("C:\\Reports\\nothing-here.xlsx") is None

    def test_an_empty_document_name_resolves_to_nothing(self):
        assert document_path("") is None

    def test_the_printing_applications_decoration_is_stripped(self):
        assert clean_title("payroll_2026.xlsx - Excel") == "payroll_2026.xlsx"
        assert clean_title("Microsoft Word - contract.docx") == "contract.docx"
        assert clean_title("notes.txt - Notepad") == "notes.txt"

    def test_a_plain_name_survives_unchanged(self):
        assert clean_title("quarterly summary") == "quarterly summary"


class TestAssessment:
    """Content beats a name whenever there is content to read."""

    def test_a_resolvable_file_is_classified_by_its_content(self, tmp_path):
        f = tmp_path / "boring-name.txt"
        f.write_text("4111111111111111", encoding="utf-8")
        client = _client()
        risk, detections, basis = PrintJobGuard(client, "a1", _resolver()).assess(
            _job(document=str(f)))

        assert basis == "content"
        assert risk == 0.95
        client.classify.assert_called_once()

    def test_a_name_only_job_falls_back_to_the_title_heuristic(self):
        client = _client()
        risk, detections, basis = PrintJobGuard(client, "a1", _resolver()).assess(_job())

        assert basis == "title"
        assert risk == print_monitor.TITLE_CONFIDENCE
        assert detections[0]["value"] == "payroll"
        client.classify.assert_not_called()

    def test_an_unremarkable_name_scores_nothing(self):
        risk, detections, basis = PrintJobGuard(_client(), "a1", _resolver()).assess(
            _job(document="shopping list - Notepad"))

        assert risk == 0.0
        assert detections == []

    def test_a_dead_classifier_falls_back_to_the_name(self, tmp_path):
        # A weaker answer beats no answer, and the job is released either way
        # if the name is unremarkable.
        f = tmp_path / "payroll_2026.xlsx"
        f.write_text("nothing readable here", encoding="utf-8")
        client = _client()
        client.classify.return_value = None
        risk, detections, basis = PrintJobGuard(client, "a1", _resolver()).assess(
            _job(document=str(f)))

        assert basis == "title"
        assert detections[0]["value"] == "payroll"


class TestDecision:
    def test_a_sensitive_job_is_cancelled(self):
        client = _client()
        with patch("print_monitor.delete_job", return_value=True) as delete, \
             patch("print_monitor.offer_review"):
            outcome = PrintJobGuard(client, "a1", _resolver()).decide(_job())

        assert outcome == "deleted"
        delete.assert_called_once_with("HP LaserJet", 7)
        client.create_incident.assert_called_once()

    def test_the_incident_is_filed_on_the_print_channel(self):
        client = _client()
        with patch("print_monitor.delete_job", return_value=True), \
             patch("print_monitor.offer_review"):
            PrintJobGuard(client, "a1", _resolver()).decide(_job())

        kwargs = client.create_incident.call_args.kwargs
        assert kwargs["channel"] == "PRINT"
        assert "payroll_2026.xlsx" in kwargs["evidence"]

    def test_the_record_says_how_the_job_was_judged(self):
        # A matched card number and a suggestive filename are not equally
        # strong, and the queue has to let an analyst tell them apart.
        client = _client()
        with patch("print_monitor.delete_job", return_value=True), \
             patch("print_monitor.offer_review"):
            PrintJobGuard(client, "a1", _resolver()).decide(_job())

        assert "by title" in client.create_incident.call_args.kwargs["evidence"]

    def test_a_cancel_that_failed_is_not_recorded_as_a_block(self):
        # The pages came out. Recording BLOCK would say otherwise.
        client = _client()
        with patch("print_monitor.delete_job", return_value=False), \
             patch("print_monitor.offer_review"):
            PrintJobGuard(client, "a1", _resolver()).decide(_job())

        kwargs = client.create_incident.call_args.kwargs
        assert kwargs["action_taken"] == "ALERT"
        assert "allowed to print" in kwargs["evidence"]

    def test_a_cancel_that_worked_is_recorded_as_a_block(self):
        client = _client()
        with patch("print_monitor.delete_job", return_value=True), \
             patch("print_monitor.offer_review"):
            PrintJobGuard(client, "a1", _resolver()).decide(_job())

        assert client.create_incident.call_args.kwargs["action_taken"] == "BLOCK"

    def test_a_clean_job_is_left_alone(self):
        client = _client()
        with patch("print_monitor.delete_job") as delete:
            outcome = PrintJobGuard(client, "a1", _resolver()).decide(
                _job(document="shopping list - Notepad"))

        assert outcome == "clean"
        delete.assert_not_called()
        client.create_incident.assert_not_called()

    def test_alert_records_the_job_without_cancelling_it(self):
        client = _client()
        with patch("print_monitor.delete_job") as delete, \
             patch("print_monitor.offer_review"):
            outcome = PrintJobGuard(client, "a1", _resolver("ALERT")).decide(_job())

        assert outcome == "alert"
        delete.assert_not_called()
        client.create_incident.assert_called_once()

    def test_below_every_rung_records_nothing(self):
        client = _client()
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "NONE", "name": "PCI-DSS"}
        assert PrintJobGuard(client, "a1", resolver).decide(_job()) == "not-covered"
        client.create_incident.assert_not_called()

    def test_the_policy_is_resolved_for_the_print_channel(self):
        resolver = _resolver()
        with patch("print_monitor.delete_job", return_value=True), \
             patch("print_monitor.offer_review"):
            PrintJobGuard(_client(), "a1", resolver).decide(_job())

        assert resolver.resolve.call_args.kwargs["channel"] == "PRINT"


class TestPauseAndRelease:
    """
    Polling for a job and then cancelling it is a race. Pausing it first is a
    decision -- but only if every path releases it again.
    """

    def test_the_job_is_paused_before_anything_is_classified(self):
        order = []
        client = _client(CLEAN)
        with patch("print_monitor.pause_job", side_effect=lambda *a: order.append("pause") or True), \
             patch("print_monitor.resume_job", side_effect=lambda *a: order.append("resume") or True):
            guard = PrintJobGuard(client, "a1", _resolver())
            with patch.object(guard, "decide", side_effect=lambda j: order.append("decide") or "clean"):
                handle_new_job(guard, _job())

        assert order == ["pause", "decide", "resume"]

    def test_a_clean_job_is_resumed(self):
        with patch("print_monitor.pause_job", return_value=True), \
             patch("print_monitor.resume_job", return_value=True) as resume:
            handle_new_job(PrintJobGuard(_client(), "a1", _resolver()),
                           _job(document="shopping list - Notepad"))
        resume.assert_called_once_with("HP LaserJet", 7)

    def test_a_cancelled_job_is_not_resumed(self):
        # Resuming a deleted job is meaningless at best; at worst it prints.
        with patch("print_monitor.pause_job", return_value=True), \
             patch("print_monitor.delete_job", return_value=True), \
             patch("print_monitor.resume_job") as resume, \
             patch("print_monitor.offer_review"):
            outcome = handle_new_job(PrintJobGuard(_client(), "a1", _resolver()), _job())

        assert outcome == "deleted"
        resume.assert_not_called()

    def test_a_crash_in_the_decision_still_releases_the_job(self):
        # A DLP agent that leaves the office print queue frozen because a
        # microservice restarted gets uninstalled, not fixed.
        guard = PrintJobGuard(_client(), "a1", _resolver())
        with patch("print_monitor.pause_job", return_value=True), \
             patch("print_monitor.resume_job", return_value=True) as resume, \
             patch.object(guard, "decide", side_effect=RuntimeError("boom")):
            outcome = handle_new_job(guard, _job())

        assert outcome == "error"
        resume.assert_called_once()

    def test_a_job_that_could_not_be_paused_is_not_resumed(self):
        # Nothing was paused, so there is nothing to release -- resuming a job
        # the agent never paused could release one a human paused on purpose.
        with patch("print_monitor.pause_job", return_value=False), \
             patch("print_monitor.resume_job") as resume:
            handle_new_job(PrintJobGuard(_client(), "a1", _resolver()),
                           _job(document="shopping list - Notepad"))
        resume.assert_not_called()

    def test_a_job_that_could_not_be_paused_is_still_judged(self):
        with patch("print_monitor.pause_job", return_value=False), \
             patch("print_monitor.delete_job", return_value=True) as delete, \
             patch("print_monitor.offer_review"):
            handle_new_job(PrintJobGuard(_client(), "a1", _resolver()), _job())
        delete.assert_called_once()


class TestRepeats:
    def test_printing_the_same_document_again_counts_onto_one_incident(self):
        client = _client()
        guard = PrintJobGuard(client, "a1", _resolver())
        with patch("print_monitor.delete_job", return_value=True), \
             patch("print_monitor.offer_review"):
            guard.decide(_job(job_id=7))
            guard.decide(_job(job_id=8))       # a new job, the same document

        client.create_incident.assert_called_once()
        client.repeat_incident.assert_called_once_with("inc-1")

    def test_a_different_document_is_its_own_incident(self):
        client = _client()
        guard = PrintJobGuard(client, "a1", _resolver())
        with patch("print_monitor.delete_job", return_value=True), \
             patch("print_monitor.offer_review"):
            guard.decide(_job(document="payroll_2026.xlsx - Excel", job_id=7))
            guard.decide(_job(document="client_contract.docx - Word", job_id=8))

        assert client.create_incident.call_count == 2


class TestQueueTracking:
    def test_jobs_already_queued_at_startup_are_not_judged(self):
        # They were submitted before anything was watching, and pausing a
        # half-printed job to classify it is not this agent's business.
        stop = MagicMock()
        stop.is_set.side_effect = [False, True]
        stop.wait.return_value = None

        with patch("print_monitor.list_printers", return_value=["HP LaserJet"]), \
             patch("print_monitor.list_jobs", return_value=[_job()]), \
             patch("print_monitor.handle_new_job") as handle:
            print_monitor._print_loop(_client(), "a1", stop, _resolver())

        handle.assert_not_called()

    def test_a_new_job_is_handled_once(self):
        stop = MagicMock()
        stop.is_set.side_effect = [False, False, True]
        stop.wait.return_value = None

        with patch("print_monitor.list_printers", return_value=["HP LaserJet"]), \
             patch("print_monitor.list_jobs", side_effect=[[], [_job()], [_job()]]), \
             patch("print_monitor.handle_new_job") as handle:
            print_monitor._print_loop(_client(), "a1", stop, _resolver())

        assert handle.call_count == 1

    def test_a_finished_job_is_forgotten_so_a_recycled_id_is_seen_again(self):
        # The spooler reuses job ids. A set that only ever grows would ignore
        # the second job to carry a given number.
        stop = MagicMock()
        stop.is_set.side_effect = [False, False, False, True]
        stop.wait.return_value = None

        with patch("print_monitor.list_printers", return_value=["HP LaserJet"]), \
             patch("print_monitor.list_jobs", side_effect=[[], [_job()], [], [_job()]]), \
             patch("print_monitor.handle_new_job") as handle:
            print_monitor._print_loop(_client(), "a1", stop, _resolver())

        assert handle.call_count == 2
