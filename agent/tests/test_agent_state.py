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
