import time
import threading


class AgentState:
    """Thread-safe shared state passed to every agent module."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_sensitive_clip: float = 0.0  # monotonic timestamp
        self.file_access_count: int = 0
        self.clipboard_copy_count: int = 0

    # ── Writers (called from worker threads) ──────────────────────────────────

    def flag_sensitive_clipboard(self) -> None:
        with self._lock:
            self._last_sensitive_clip = time.monotonic()
            self.clipboard_copy_count += 1

    def increment_file_access(self) -> None:
        with self._lock:
            self.file_access_count += 1

    # ── Readers ───────────────────────────────────────────────────────────────

    def clipboard_flagged_recently(self, within_seconds: float = 30.0) -> bool:
        with self._lock:
            return (time.monotonic() - self._last_sensitive_clip) < within_seconds

    def sensitive_clip_monotonic(self) -> float:
        """Return the monotonic timestamp of the last sensitive clipboard flag."""
        with self._lock:
            return self._last_sensitive_clip

    def pop_counters(self) -> tuple:
        """Return (file_count, clipboard_count) and reset both to zero."""
        with self._lock:
            fc = self.file_access_count
            cc = self.clipboard_copy_count
            self.file_access_count = 0
            self.clipboard_copy_count = 0
            return fc, cc
