"""
Is this the same thing again, or something new?

Every channel that records a block needs the same answer, and for the same
reason: retesting the same file ten times should leave one row saying it
happened ten times, not ten rows saying it happened. A queue full of
near-identical rows is a queue nobody reads.

WHY THIS IS KEYED ON CONTENT, NOT TIME
The AI path learned this the hard way. It grouped by a per-platform timer, so
anything inside sixty seconds counted as the same event -- copy a file, get
blocked, copy something *different* ten seconds later, and the second leak was
folded into the first row's counter with no warning of its own. Two different
pieces of data caught leaving, one row, one popup.

Time cannot tell a repeat from a new leak. Only the content can. A window
belongs to the content that opened it: different content is a different event
however soon it follows, and the same content after the window closes opens a
new one.

This is the fourth channel to need it, so it lives here rather than being
copied a fourth time.
"""

from __future__ import annotations

import hashlib
import threading
import time

# One minute. Long enough that a burst of retries collapses into a single row,
# short enough that a genuinely repeated action later in the day is recorded
# as the separate event it is.
DEFAULT_COOLDOWN = 60.0


def fingerprint(content_sample: str, detections: list | None = None) -> str:
    """A stable id for WHAT was involved, so a repeat can be told from a new event.

    Built from the already-masked sample and the detection types, never from
    raw content -- this is held in memory for the length of a window and must
    not become somewhere sensitive data lives.

    Detection types are sorted because the classifier makes no promise about
    their order, and the same findings in a different order are not a new leak.
    """
    types = ",".join(sorted((d.get("type") or "") for d in (detections or [])))
    return hashlib.sha256(f"{content_sample}|{types}".encode("utf-8", "replace")).hexdigest()


class RepeatWindow:
    """Tracks, per scope, which record repeats should be counted onto.

    `scope` separates things that must not suppress each other -- a platform,
    a channel, a window handle. A block on Grok must never silence a block on
    Gemini three seconds later; each is its own attempt and deserves its own
    evaluation.
    """

    def __init__(self, cooldown: float = DEFAULT_COOLDOWN) -> None:
        self._cooldown = cooldown
        self._lock = threading.Lock()
        self._opened_at: dict[str, float] = {}
        self._content: dict[str, str] = {}
        self._record: dict[str, str] = {}

    def repeat_of(self, scope: str, print_: str) -> str | None:
        """The id of the record this repeats, or None if it is a new event.

        Claims the window when it returns None: the caller is expected to
        create a record and hand its id back via `opened()`. Between those two
        calls the window has no record to count onto, so a second caller in
        that gap also gets None and files its own row -- a duplicate is a far
        better failure than a block that goes unrecorded.
        """
        now = time.monotonic()
        with self._lock:
            same_content = print_ == self._content.get(scope)
            fresh = (now - self._opened_at.get(scope, 0.0)) < self._cooldown
            if same_content and fresh:
                existing = self._record.get(scope)
                if existing:
                    return existing
            # New event: different content, or the window has closed.
            self._opened_at[scope] = now
            self._content[scope] = print_
            self._record.pop(scope, None)
            return None

    def opened(self, scope: str, record_id: str | None) -> None:
        """Remember the record repeats should accumulate onto."""
        if not record_id:
            return
        with self._lock:
            self._record[scope] = record_id

    def forget(self, scope: str) -> None:
        """Drop a scope's window -- used when its target goes away entirely."""
        with self._lock:
            self._opened_at.pop(scope, None)
            self._content.pop(scope, None)
            self._record.pop(scope, None)
