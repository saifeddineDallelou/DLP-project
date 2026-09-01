import time
import threading


class AgentState:
    """Thread-safe shared state passed to every agent module."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_sensitive_clip: float = 0.0  # monotonic timestamp
        # classify() result that triggered the flag -- carried forward so the
        # AI monitor's delayed path can resolve the SAME policy the immediate
        # check would have, instead of resolving against an empty detection
        # list (which always falls back to the default policy).
        self._sensitive_clip_context: dict = {}
        self.file_access_count: int = 0
        self.file_access_bytes: int = 0
        self.clipboard_copy_count: int = 0
        # path -> {policy, risk_score, flagged_at} for files file_watcher.py
        # has classified as sensitive -- lets app_file_monitor.py's periodic
        # poll check restricted-app processes' open files against files that
        # were flagged sometime in the last few minutes, not only in the
        # exact instant file_watcher reacted to the filesystem event.
        self._sensitive_files: dict[str, dict] = {}

    # ── Writers (called from worker threads) ──────────────────────────────────

    def flag_sensitive_clipboard(
        self,
        detections: list | None = None,
        risk_score: float | None = None,
        content_sample: str | None = None,
    ) -> None:
        with self._lock:
            self._last_sensitive_clip = time.monotonic()
            self.clipboard_copy_count += 1
            self._sensitive_clip_context = {
                "detections":     detections or [],
                "risk_score":     risk_score,
                "content_sample": content_sample,
            }

    def increment_file_access(self, size_bytes: int = 0) -> None:
        with self._lock:
            self.file_access_count += 1
            self.file_access_bytes += max(0, size_bytes)

    def mark_sensitive_file(self, path: str, policy: dict, risk_score: float) -> None:
        with self._lock:
            self._sensitive_files[path] = {
                "policy": policy, "risk_score": risk_score, "flagged_at": time.monotonic(),
            }

    # ── Readers ───────────────────────────────────────────────────────────────

    def clipboard_flagged_recently(self, within_seconds: float = 30.0) -> bool:
        with self._lock:
            return (time.monotonic() - self._last_sensitive_clip) < within_seconds

    def sensitive_clip_monotonic(self) -> float:
        """Return the monotonic timestamp of the last sensitive clipboard flag."""
        with self._lock:
            return self._last_sensitive_clip

    def sensitive_clip_context(self) -> dict:
        """Return the classify() result (detections/risk_score/content_sample)
        captured by the flag that's currently active."""
        with self._lock:
            return dict(self._sensitive_clip_context)

    def pop_counters(self) -> tuple:
        """Return (file_count, clipboard_count) and reset both to zero."""
        with self._lock:
            fc = self.file_access_count
            cc = self.clipboard_copy_count
            self.file_access_count = 0
            self.clipboard_copy_count = 0
            return fc, cc

    def pop_file_bytes(self) -> int:
        """Return total bytes seen across increment_file_access() calls since
        the last pop, and reset to zero. Separate from pop_counters() so
        existing (file_count, clipboard_count) callers are unaffected."""
        with self._lock:
            b = self.file_access_bytes
            self.file_access_bytes = 0
            return b

    def sensitive_files(self, max_age_seconds: float = 300.0) -> dict[str, dict]:
        """Return currently-tracked sensitive files (path -> {policy,
        risk_score, flagged_at}), pruning entries older than max_age_seconds
        (default 5 min -- long enough for a restricted app to plausibly get
        around to opening a just-flagged file, short enough that a stale
        entry doesn't keep generating incidents for a file that's long since
        stopped being relevant)."""
        now = time.monotonic()
        with self._lock:
            self._sensitive_files = {
                p: info for p, info in self._sensitive_files.items()
                if now - info["flagged_at"] < max_age_seconds
            }
            return dict(self._sensitive_files)
