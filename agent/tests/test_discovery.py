import os
import time
from unittest.mock import MagicMock

import pytest

from discovery import (
    Finding,
    ScanResult,
    format_report,
    iter_files,
    scan_tree,
    _MAX_FILE_SIZE,
)

SILENT = MagicMock()


def _client(results):
    """
    results is either a classify() response (recognised by its risk_score key)
    returned for everything, or a map of text-substring -> response so a test
    can give different files different verdicts.
    """
    client = MagicMock()
    if isinstance(results, dict) and "risk_score" in results:
        client.classify.return_value = results
    else:
        def classify(text=None):
            for key, value in results.items():
                if key in (text or ""):
                    return value
            return {"risk_score": 0.0, "detections": []}
        client.classify.side_effect = classify
    return client


def _extract(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None


SENSITIVE = {
    "risk_score": 0.95,
    "detections": [
        {"type": "credit_card", "value": "****-****-****-1111", "rule": "PCI-DSS"},
    ],
}
CLEAN = {"risk_score": 0.05, "detections": []}


class TestIterFiles:
    def test_walks_nested_directories(self, tmp_path):
        (tmp_path / "a.txt").write_text("a")
        sub = tmp_path / "sub" / "deeper"
        sub.mkdir(parents=True)
        (sub / "b.txt").write_text("b")

        found = {os.path.basename(p) for p in iter_files(str(tmp_path))}
        assert found == {"a.txt", "b.txt"}

    def test_prunes_dependency_and_build_directories(self, tmp_path):
        # These are enormous, machine-generated, and produce only noise.
        # Skipping them is the difference between a scan that finishes and
        # one that does not.
        (tmp_path / "keep.txt").write_text("x")
        for junk in ("node_modules", "__pycache__", "dist", ".git"):
            d = tmp_path / junk
            d.mkdir()
            (d / "ignored.txt").write_text("x")

        found = {os.path.basename(p) for p in iter_files(str(tmp_path))}
        assert found == {"keep.txt"}

    def test_include_globs_restrict_the_walk(self, tmp_path):
        (tmp_path / "a.pdf").write_text("x")
        (tmp_path / "b.txt").write_text("x")

        found = {os.path.basename(p) for p in iter_files(str(tmp_path), include=["*.pdf"])}
        assert found == {"a.pdf"}

    def test_exclude_globs_win(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        (tmp_path / "skipme.txt").write_text("x")

        found = {os.path.basename(p) for p in iter_files(str(tmp_path), exclude=["skip*"])}
        assert found == {"a.txt"}

    def test_glob_matching_is_case_insensitive(self, tmp_path):
        (tmp_path / "REPORT.PDF").write_text("x")
        found = {os.path.basename(p) for p in iter_files(str(tmp_path), include=["*.pdf"])}
        assert found == {"REPORT.PDF"}


class TestScanTree:
    def test_reports_a_sensitive_file(self, tmp_path):
        (tmp_path / "cards.txt").write_text("4111 1111 1111 1111")

        result = scan_tree(str(tmp_path), _client(SENSITIVE), _extract, logger_=SILENT)

        assert len(result.findings) == 1
        assert result.findings[0].rule == "PCI-DSS"
        assert result.findings[0].types == ["credit_card"]

    def test_ignores_a_clean_file(self, tmp_path):
        (tmp_path / "notes.txt").write_text("nothing interesting")

        result = scan_tree(str(tmp_path), _client(CLEAN), _extract, logger_=SILENT)

        assert result.findings == []
        assert result.files_scanned == 1

    def test_separates_sensitive_from_clean_in_one_tree(self, tmp_path):
        (tmp_path / "cards.txt").write_text("CARDDATA")
        (tmp_path / "readme.txt").write_text("harmless")

        result = scan_tree(
            str(tmp_path), _client({"CARDDATA": SENSITIVE}), _extract, logger_=SILENT,
        )

        assert len(result.findings) == 1
        assert result.findings[0].path.endswith("cards.txt")
        assert result.files_scanned == 2

    def test_honours_the_threshold(self, tmp_path):
        (tmp_path / "borderline.txt").write_text("x")
        borderline = {"risk_score": 0.6, "detections": [{"type": "email", "rule": "GDPR"}]}

        strict = scan_tree(str(tmp_path), _client(borderline), _extract, threshold=0.8, logger_=SILENT)
        loose = scan_tree(str(tmp_path), _client(borderline), _extract, threshold=0.5, logger_=SILENT)

        assert strict.findings == []
        assert len(loose.findings) == 1

    def test_skips_an_empty_file(self, tmp_path):
        (tmp_path / "empty.txt").write_text("")
        result = scan_tree(str(tmp_path), _client(SENSITIVE), _extract, logger_=SILENT)
        assert result.files_scanned == 0
        assert result.files_skipped == 1

    def test_skips_a_file_over_the_size_cap(self, tmp_path, monkeypatch):
        big = tmp_path / "huge.bin"
        big.write_text("x")
        monkeypatch.setattr("discovery.os.path.getsize", lambda _p: _MAX_FILE_SIZE + 1)

        result = scan_tree(str(tmp_path), _client(SENSITIVE), _extract, logger_=SILENT)

        assert result.files_scanned == 0
        assert result.files_skipped == 1

    def test_stops_at_max_files(self, tmp_path):
        for i in range(10):
            (tmp_path / f"f{i}.txt").write_text("x")

        result = scan_tree(str(tmp_path), _client(CLEAN), _extract, max_files=3, logger_=SILENT)

        assert result.files_scanned == 3

    def test_one_unreadable_file_does_not_abort_the_scan(self, tmp_path):
        (tmp_path / "good.txt").write_text("CARDDATA")
        (tmp_path / "bad.txt").write_text("x")

        def flaky_extract(path):
            if path.endswith("bad.txt"):
                raise OSError("permission denied")
            return _extract(path)

        result = scan_tree(
            str(tmp_path), _client({"CARDDATA": SENSITIVE}), flaky_extract, logger_=SILENT,
        )

        assert result.errors == 1
        assert len(result.findings) == 1   # the good file was still scanned

    def test_a_classifier_outage_does_not_abort_the_scan(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        (tmp_path / "b.txt").write_text("x")
        client = MagicMock()
        client.classify.side_effect = [None, SENSITIVE]

        result = scan_tree(str(tmp_path), client, _extract, logger_=SILENT)

        assert result.errors == 1
        assert len(result.findings) == 1

    def test_a_classifier_exception_is_contained(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        client = MagicMock()
        client.classify.side_effect = RuntimeError("connection reset")

        result = scan_tree(str(tmp_path), client, _extract, logger_=SILENT)

        assert result.errors == 1
        assert result.findings == []

    def test_never_modifies_anything_it_scans(self, tmp_path):
        # A discovery scan finds and reports. A crawler with write authority
        # over a file share is a very different risk to sign off on.
        f = tmp_path / "cards.txt"
        f.write_text("4111 1111 1111 1111")
        before = (f.read_text(), f.stat().st_size)

        scan_tree(str(tmp_path), _client(SENSITIVE), _extract, logger_=SILENT)

        assert f.exists()
        assert (f.read_text(), f.stat().st_size) == before

    def test_records_size_and_modified_time_for_triage(self, tmp_path):
        f = tmp_path / "cards.txt"
        f.write_text("4111 1111 1111 1111")

        result = scan_tree(str(tmp_path), _client(SENSITIVE), _extract, logger_=SILENT)

        assert result.findings[0].size_bytes == f.stat().st_size
        assert result.findings[0].modified > 0

    def test_handles_an_empty_tree(self, tmp_path):
        result = scan_tree(str(tmp_path), _client(SENSITIVE), _extract, logger_=SILENT)
        assert result.files_seen == 0
        assert result.findings == []


class TestScanResult:
    def test_counts_detections_per_compliance_rule(self):
        r = ScanResult(root="/x", started_at=time.time())
        r.findings = [
            Finding("/a", 1, 0.9, [{"type": "credit_card", "rule": "PCI-DSS"}], "PCI-DSS", 0),
            Finding("/b", 1, 0.9, [{"type": "ssn", "rule": "HIPAA"},
                                   {"type": "credit_card", "rule": "PCI-DSS"}], "HIPAA", 0),
        ]
        assert r.by_rule() == {"PCI-DSS": 2, "HIPAA": 1}

    def test_orders_rules_by_frequency(self):
        r = ScanResult(root="/x", started_at=time.time())
        r.findings = [
            Finding("/a", 1, 0.9, [{"type": "email", "rule": "GDPR"}], "GDPR", 0),
            Finding("/b", 1, 0.9, [{"type": "ssn", "rule": "HIPAA"}], "HIPAA", 0),
            Finding("/c", 1, 0.9, [{"type": "ssn", "rule": "HIPAA"}], "HIPAA", 0),
        ]
        assert list(r.by_rule())[0] == "HIPAA"


class TestFormatReport:
    def _result(self, findings):
        r = ScanResult(root="C:/share", started_at=time.time() - 3)
        r.finished_at = time.time()
        r.files_seen = 100
        r.files_scanned = 90
        r.findings = findings
        return r

    def test_states_plainly_when_nothing_was_found(self):
        text = format_report(self._result([]))
        assert "No sensitive data found at rest" in text

    def test_lists_findings_by_risk(self):
        text = format_report(self._result([
            Finding("/low", 1, 0.6, [{"type": "email", "rule": "GDPR"}], "GDPR", 0),
            Finding("/high", 1, 0.99, [{"type": "credit_card", "rule": "PCI-DSS"}], "PCI-DSS", 0),
        ]))
        assert text.index("/high") < text.index("/low")

    def test_summarises_by_compliance_rule(self):
        text = format_report(self._result([
            Finding("/a", 1, 0.9, [{"type": "ssn", "rule": "HIPAA"}], "HIPAA", 0),
        ]))
        assert "HIPAA" in text

    def test_says_it_changed_nothing(self):
        assert "Read-only" in format_report(self._result([]))

    def test_never_prints_an_unmasked_value(self):
        # Findings carry classifier detections, whose values are already
        # masked. The report must not become a place a secret is written to
        # a terminal, a log file or a ticket.
        text = format_report(self._result([
            Finding("/a", 1, 0.9,
                    [{"type": "credit_card", "value": "****-****-****-1111", "rule": "PCI-DSS"}],
                    "PCI-DSS", 0),
        ]))
        assert "4111" not in text
