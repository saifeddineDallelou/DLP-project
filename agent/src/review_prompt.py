"""
Block-notification prompt for the end user.

The block itself is always silent and immediate -- this is never called
before the clipboard is cleared, only after, and it never changes what got
blocked. All this dialog does is let the worker flag the block for an admin
to look at, with an optional short note about why. There is no "unblock
yourself" action here on purpose: a normal worker can request a review, but
only an admin decides what actually happens next (see adminNote on the
Incident/AiLeakAttempt models).
"""

import tkinter as tk
from tkinter import ttk
from loguru import logger

_TIMEOUT_SECONDS = 25.0


def prompt_review_request(reason: str, timeout: float = _TIMEOUT_SECONDS) -> str | None:
    """
    Show a small modal dialog telling the user their content was blocked,
    with an optional note field and a "Request Review" button that flags the
    block for an admin -- it never restores or unblocks anything itself.

    Blocks the CALLING thread until the user responds or the timeout
    elapses -- callers must invoke this from their own background thread,
    never from a monitor's main poll loop, so the block itself (already
    applied before this is ever called) is never delayed by it.

    Returns the note text (possibly an empty string, if the user requested
    review without typing anything) if "Request Review" was clicked, or None
    if dismissed, closed, or timed out with no action.
    """
    result: dict = {"requested": False, "note": ""}

    try:
        root = tk.Tk()
    except Exception as exc:
        # No display / Tk unavailable (e.g. running as a service with no
        # desktop session) -- fail closed, same as a dismissed prompt.
        logger.debug(f"[REVIEW-PROMPT] Could not create dialog: {exc}")
        return None

    try:
        root.title("DLP - Sensitive content blocked")
        root.attributes("-topmost", True)
        root.resizable(False, False)

        frame = ttk.Frame(root, padding=16)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Blocked by DLP", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(frame, text=reason, wraplength=340, justify="left").pack(anchor="w", pady=(4, 12))
        ttk.Label(frame, text="Add a note for the reviewer (optional):").pack(anchor="w")

        entry = ttk.Entry(frame, width=48)
        entry.pack(pady=(4, 12))
        entry.focus_set()

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill="x")

        def _request_review() -> None:
            result["requested"] = True
            result["note"] = entry.get().strip()
            root.destroy()

        def _dismiss() -> None:
            root.destroy()

        ttk.Button(btn_row, text="Request Review", command=_request_review).pack(side="right")
        ttk.Button(btn_row, text="Dismiss", command=_dismiss).pack(side="right", padx=(0, 8))
        entry.bind("<Return>", lambda _e: _request_review())

        root.protocol("WM_DELETE_WINDOW", _dismiss)
        root.after(int(timeout * 1000), _dismiss)

        root.update_idletasks()
        w, h = root.winfo_width(), root.winfo_height()
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"+{(sw - w) // 2}+{(sh - h) // 3}")

        root.mainloop()
    except Exception as exc:
        logger.debug(f"[REVIEW-PROMPT] Dialog error: {exc}")
        return None

    return result["note"] if result["requested"] else None
