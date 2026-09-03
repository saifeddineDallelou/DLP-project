import threading
import time

from repeat_window import RepeatWindow, fingerprint


class TestFingerprint:
    """
    A stable id for WHAT was involved, so a repeat can be told from a new
    event -- the distinction a timer alone cannot make.
    """

    def test_the_same_content_fingerprints_the_same(self):
        a = fingerprint("FILE:cards.csv", [{"type": "credit_card"}])
        b = fingerprint("FILE:cards.csv", [{"type": "credit_card"}])
        assert a == b

    def test_different_content_fingerprints_differently(self):
        a = fingerprint("FILE:cards.csv", [{"type": "credit_card"}])
        b = fingerprint("FILE:payroll.xlsx", [{"type": "ssn"}])
        assert a != b

    def test_detection_order_does_not_matter(self):
        # The classifier makes no promise about ordering, and the same
        # findings rearranged are not a new leak.
        a = fingerprint("x", [{"type": "iban"}, {"type": "ssn"}])
        b = fingerprint("x", [{"type": "ssn"}, {"type": "iban"}])
        assert a == b

    def test_the_same_file_with_different_findings_is_a_different_event(self):
        # The file was edited between drags: same name, new content.
        a = fingerprint("FILE:notes.txt", [{"type": "email"}])
        b = fingerprint("FILE:notes.txt", [{"type": "credit_card"}])
        assert a != b

    def test_it_holds_no_readable_content(self):
        # It lives in memory for the length of a window and must not become
        # somewhere sensitive data lives.
        fp = fingerprint("Sarah Okafor, Manchester", [{"type": "edm:customers:row"}])
        assert "Sarah" not in fp and "Okafor" not in fp
        assert len(fp) == 64

    def test_no_detections_is_not_an_error(self):
        assert len(fingerprint("something", None)) == 64
        assert len(fingerprint("something", [])) == 64


class TestRepeatWindow:
    """
    Retesting a block ten times should leave one row saying it happened ten
    times, not ten rows saying it happened. A queue of near-identical rows is
    a queue nobody reads.
    """

    def test_the_first_occurrence_is_a_new_event(self):
        w = RepeatWindow()
        assert w.repeat_of("GROK", "fp-1") is None

    def test_the_same_content_repeats_onto_the_open_record(self):
        w = RepeatWindow()
        assert w.repeat_of("GROK", "fp-1") is None
        w.opened("GROK", "att-1")
        assert w.repeat_of("GROK", "fp-1") == "att-1"
        assert w.repeat_of("GROK", "fp-1") == "att-1"

    def test_different_content_is_a_new_event_however_soon(self):
        # The bug this whole module exists to prevent: copy a file, get
        # blocked, then something DIFFERENT ten seconds later gets folded
        # into the first row with no warning of its own.
        w = RepeatWindow()
        w.repeat_of("GROK", "fp-1")
        w.opened("GROK", "att-1")
        assert w.repeat_of("GROK", "fp-2") is None

    def test_a_new_event_stops_repeating_onto_the_old_record(self):
        w = RepeatWindow()
        w.repeat_of("GROK", "fp-1")
        w.opened("GROK", "att-1")
        w.repeat_of("GROK", "fp-2")          # claims the window
        # The old record must not come back if the first content returns
        # before a new record was registered.
        assert w.repeat_of("GROK", "fp-1") is None

    def test_the_same_content_after_the_window_is_a_new_event(self):
        w = RepeatWindow(cooldown=0.05)
        w.repeat_of("GROK", "fp-1")
        w.opened("GROK", "att-1")
        time.sleep(0.08)
        assert w.repeat_of("GROK", "fp-1") is None

    def test_scopes_do_not_suppress_each_other(self):
        # A block on Grok must never silence a block on Gemini three seconds
        # later; each is its own attempt.
        w = RepeatWindow()
        w.repeat_of("GROK", "fp-1")
        w.opened("GROK", "att-1")
        assert w.repeat_of("GEMINI", "fp-1") is None

    def test_a_window_with_no_record_yet_reports_a_new_event(self):
        # Between claiming the window and registering the record there is no
        # id to count onto. A duplicate row is a far better failure than a
        # block that goes unrecorded.
        w = RepeatWindow()
        assert w.repeat_of("GROK", "fp-1") is None
        assert w.repeat_of("GROK", "fp-1") is None

    def test_opened_ignores_a_missing_id(self):
        # The backend was unreachable, so there is no row to count onto.
        w = RepeatWindow()
        w.repeat_of("GROK", "fp-1")
        w.opened("GROK", None)
        assert w.repeat_of("GROK", "fp-1") is None

    def test_forget_drops_the_window(self):
        w = RepeatWindow()
        w.repeat_of("GROK", "fp-1")
        w.opened("GROK", "att-1")
        w.forget("GROK")
        assert w.repeat_of("GROK", "fp-1") is None

    def test_it_is_safe_across_threads(self):
        # Monitors report from their own threads; a lost update here would
        # mean either a missing row or a double-counted one.
        w = RepeatWindow()
        w.repeat_of("GROK", "fp-1")
        w.opened("GROK", "att-1")

        results = []
        barrier = threading.Barrier(8)

        def _hit():
            barrier.wait()
            results.append(w.repeat_of("GROK", "fp-1"))

        threads = [threading.Thread(target=_hit) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=3)

        assert results == ["att-1"] * 8
