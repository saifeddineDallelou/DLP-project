import time

from agent_state import AgentState


def test_starts_with_no_recent_flag():
    state = AgentState()
    assert state.clipboard_flagged_recently() is False
    assert state.sensitive_clip_monotonic() == 0.0


def test_flag_sensitive_clipboard_marks_recent():
    state = AgentState()
    state.flag_sensitive_clipboard()
    assert state.clipboard_flagged_recently(within_seconds=30.0) is True
    assert state.sensitive_clip_monotonic() > 0.0


def test_clipboard_flagged_recently_respects_window():
    state = AgentState()
    state.flag_sensitive_clipboard()
    assert state.clipboard_flagged_recently(within_seconds=0.0) is False


def test_flag_sensitive_clipboard_increments_copy_count():
    state = AgentState()
    state.flag_sensitive_clipboard()
    state.flag_sensitive_clipboard()
    fc, cc = state.pop_counters()
    assert fc == 0
    assert cc == 2


def test_increment_file_access_accumulates_bytes():
    state = AgentState()
    state.increment_file_access(size_bytes=1000)
    state.increment_file_access(size_bytes=2000)
    assert state.pop_file_bytes() == 3000


def test_pop_file_bytes_resets_to_zero():
    state = AgentState()
    state.increment_file_access(size_bytes=500)
    state.pop_file_bytes()
    assert state.pop_file_bytes() == 0


def test_increment_file_access_defaults_to_zero_bytes():
    state = AgentState()
    state.increment_file_access()
    assert state.pop_file_bytes() == 0


def test_increment_file_access_ignores_negative_bytes():
    state = AgentState()
    state.increment_file_access(size_bytes=-100)
    assert state.pop_file_bytes() == 0


def test_pop_file_bytes_is_independent_of_pop_counters():
    state = AgentState()
    state.increment_file_access(size_bytes=500)
    fc, cc = state.pop_counters()
    assert fc == 1
    assert state.pop_file_bytes() == 500  # not reset by pop_counters()


def test_increment_file_access():
    state = AgentState()
    state.increment_file_access()
    state.increment_file_access()
    state.increment_file_access()
    fc, cc = state.pop_counters()
    assert fc == 3
    assert cc == 0


def test_pop_counters_resets_to_zero():
    state = AgentState()
    state.increment_file_access()
    state.flag_sensitive_clipboard()
    state.pop_counters()
    fc, cc = state.pop_counters()
    assert (fc, cc) == (0, 0)


def test_sensitive_clip_context_starts_empty():
    state = AgentState()
    assert state.sensitive_clip_context() == {}


def test_flag_sensitive_clipboard_carries_context_forward():
    state = AgentState()
    detections = [{"rule": "PCI-DSS", "type": "credit_card"}]
    state.flag_sensitive_clipboard(detections=detections, risk_score=0.9, content_sample="card ****1111")

    ctx = state.sensitive_clip_context()
    assert ctx["detections"] == detections
    assert ctx["risk_score"] == 0.9
    assert ctx["content_sample"] == "card ****1111"


def test_flag_sensitive_clipboard_defaults_detections_to_empty_list():
    state = AgentState()
    state.flag_sensitive_clipboard()
    assert state.sensitive_clip_context()["detections"] == []


def test_flag_sensitive_clipboard_overwrites_previous_context():
    state = AgentState()
    state.flag_sensitive_clipboard(detections=[{"rule": "HIPAA"}], risk_score=0.6)
    state.flag_sensitive_clipboard(detections=[{"rule": "GDPR"}], risk_score=0.7)

    ctx = state.sensitive_clip_context()
    assert ctx["detections"] == [{"rule": "GDPR"}]
    assert ctx["risk_score"] == 0.7


def test_sensitive_files_starts_empty():
    state = AgentState()
    assert state.sensitive_files() == {}


def test_mark_sensitive_file_is_tracked():
    state = AgentState()
    policy = {"id": "p1", "action": "BLOCK"}
    state.mark_sensitive_file("C:/dlp-watch/secret.txt", policy, 0.95)

    files = state.sensitive_files()
    assert "C:/dlp-watch/secret.txt" in files
    assert files["C:/dlp-watch/secret.txt"]["policy"] == policy
    assert files["C:/dlp-watch/secret.txt"]["risk_score"] == 0.95

def test_sensitive_files_prunes_entries_older_than_max_age(monkeypatch):
    state = AgentState()
    state.mark_sensitive_file("C:/dlp-watch/old.txt", {"id": "p1"}, 0.9)

    real_monotonic = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real_monotonic() + 400)
    assert state.sensitive_files(max_age_seconds=300.0) == {}

def test_mark_sensitive_file_overwrites_previous_entry_for_same_path():
    state = AgentState()
    state.mark_sensitive_file("C:/dlp-watch/secret.txt", {"id": "p1"}, 0.5)
    state.mark_sensitive_file("C:/dlp-watch/secret.txt", {"id": "p2"}, 0.9)

    files = state.sensitive_files()
    assert len(files) == 1
    assert files["C:/dlp-watch/secret.txt"]["policy"]["id"] == "p2"
