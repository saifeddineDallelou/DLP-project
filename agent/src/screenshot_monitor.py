"""
Screenshot monitor: detects a screenshot via a clipboard-image poll, with a
best-effort keyboard hook for Print Screen / Win+Shift+S as a fallback.

The keyboard hook is NOT reliable on Windows 10/11: PrtScn and Win+Shift+S are
handled by the Shell's Snip & Sketch subsystem before they reach a normal
SetWindowsHookEx-based global hook, regardless of process privilege --
confirmed by testing with admin rights, which made no difference. Rather than
depend on intercepting the keypress, the primary mechanism polls the clipboard
(same technique as clipboard_watcher.py) and reacts the moment an image shows
up there, which is true regardless of how the screenshot was triggered.

BLOCKING STRATEGY — the clipboard clear happens inline in the poll loop (or,
if the keyboard hook does happen to fire in some environment, in its own hook
thread) so it lands as fast as the detection mechanism allows, before the
user can switch windows and paste. Async work (UEBA event, incident
creation) is queued to the main monitor loop.
"""

import os
import shutil
import sys
import queue
import threading
import ctypes
import ctypes.wintypes
import time
from datetime import datetime
import pyperclip
from loguru import logger

from api_client import DLPApiClient
from policy_resolver import PolicyResolver, DEFAULT_POLICY_ID

_POLICY_ID      = DEFAULT_POLICY_ID  # fallback when no PolicyResolver is supplied
_COOLDOWN_SECS  = 5.0    # min seconds between reactions (debounce rapid presses)
_CHECK_INTERVAL = 0.2    # seconds between clipboard-image polls / queue drains
_OCR_MAX_CLASSIFY = 5_000  # max chars of OCR'd text sent to the classifier

_CF_BITMAP = 2   # CF_BITMAP
_CF_DIB    = 8   # CF_DIB

_DLP_BLOCK_MSG  = "[BLOCKED BY DLP - Screenshot cleared]"

# ── OCR setup ──────────────────────────────────────────────────────────────
# The title-keyword check below is a heuristic that only catches sensitive
# content when the WINDOW happens to be named suggestively -- a file called
# "test.txt" full of card numbers won't match any keyword. OCR reads what's
# actually in the captured image and runs it through the same classifier
# every other monitor uses, so screenshot detection is judged the same way
# as file/clipboard/file-picker content instead of guessing from a title.
try:
    import pytesseract
    from PIL import ImageGrab

    _tesseract_path = shutil.which("tesseract") or r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if os.path.isfile(_tesseract_path):
        pytesseract.pytesseract.tesseract_cmd = _tesseract_path
        _OCR_AVAILABLE = True
    else:
        logger.warning(
            "[SCREENSHOT] Tesseract-OCR not found -- content-based screenshot "
            "detection disabled, falling back to title-keyword heuristic only"
        )
        _OCR_AVAILABLE = False
except ImportError:
    logger.warning(
        "[SCREENSHOT] pytesseract/Pillow not installed -- content-based "
        "screenshot detection disabled, falling back to title-keyword heuristic only"
    )
    _OCR_AVAILABLE = False

# Window title substrings that classify a screenshot as sensitive. This is a
# heuristic on the title text, not real content classification -- a
# screenshot has no extractable text the way a file/clipboard payload does,
# so there's no classifier engine call here. Widen this list as needed.
_SENSITIVE_KEYWORDS = frozenset({
    "confidential", "client", "customer", "salary", "payroll",
    "ssn", "iban", "carte", "bancaire",
    "password", "secret", "dlp",
    "invoice", "contract", "budget",
    "personal", "private", "restricted", "internal",
    "bank", "account", "tax", "medical",
})

# Office file title format: "report_client.xlsx - Microsoft Excel"
_SENSITIVE_FILENAME_KW = frozenset({
    "client", "customer", "confidential", "invoice", "contract", "budget", "report",
})
_OFFICE_EXTS = frozenset({".xlsx", ".xls", ".docx", ".doc", ".pptx", ".ppt", ".pdf"})

# Which compliance rule a matched title/filename keyword implies -- same rule
# vocabulary as classifier/src/dictionaries.py -- so the title heuristic can
# hand the policy resolver a synthetic detection instead of an empty list
# (which always falls back to the default policy regardless of the keyword).
_KEYWORD_RULE: dict[str, str] = {
    "confidential": "INTERNAL", "secret": "INTERNAL", "restricted": "INTERNAL",
    "password": "INTERNAL", "internal": "INTERNAL", "dlp": "INTERNAL",
    "contract": "INTERNAL", "budget": "INTERNAL", "report": "INTERNAL",
    "salary": "GDPR", "payroll": "GDPR", "personal": "GDPR", "private": "GDPR",
    "client": "GDPR", "customer": "GDPR", "tax": "GDPR",
    "ssn": "HIPAA", "medical": "HIPAA",
    "iban": "PCI-DSS", "carte": "PCI-DSS", "bancaire": "PCI-DSS",
    "bank": "PCI-DSS", "account": "PCI-DSS", "invoice": "PCI-DSS",
}


# ── Windows helpers ───────────────────────────────────────────────────────────

def _get_foreground_title() -> str:
    try:
        user32 = ctypes.windll.user32
        hwnd   = user32.GetForegroundWindow()
        length = user32.GetWindowTextLengthW(hwnd)
        if length == 0:
            return ""
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        return buf.value
    except Exception:
        return ""


def _matched_keyword(title: str) -> str | None:
    """Return the sensitive keyword the title (or, for an Office file, its
    filename) matched, or None if it doesn't look sensitive."""
    lower = title.lower()
    for kw in _SENSITIVE_KEYWORDS:
        if kw in lower:
            return kw
    for ext in _OFFICE_EXTS:
        if ext in lower:
            filename_part = lower.split(" - ")[0].strip()
            for kw in _SENSITIVE_FILENAME_KW:
                if kw in filename_part:
                    return kw
    return None


def _is_sensitive(title: str) -> bool:
    return _matched_keyword(title) is not None


def _clipboard_seq() -> int:
    """Monotonically increasing counter Windows bumps on every clipboard
    write, from any process -- cheap way to detect "something changed"
    without doing per-format content comparisons. Doesn't require an open
    clipboard handle."""
    try:
        return ctypes.windll.user32.GetClipboardSequenceNumber()
    except Exception:
        return -1


def _clipboard_has_image() -> bool:
    """True if the clipboard currently holds a bitmap. Also doesn't require
    an open handle, so it's safe to call right before pyperclip.copy()."""
    try:
        user32 = ctypes.windll.user32
        return bool(
            user32.IsClipboardFormatAvailable(_CF_BITMAP)
            or user32.IsClipboardFormatAvailable(_CF_DIB)
        )
    except Exception:
        return False


def _content_check_async(
    image,
    title: str,
    t_detect: float,
    client: DLPApiClient,
    event_q: "queue.Queue[tuple]",
    policy_resolver: PolicyResolver | None = None,
) -> None:
    """
    Runs in its own thread (OCR + a network classify call are too slow for
    the main poll loop). Catches sensitive content the title heuristic
    missed -- e.g. a boringly-named file. If the fast title-based path
    already cleared the clipboard, _clipboard_has_image() will be False by
    the time this finishes and it skips, so the same screenshot never gets
    reported twice.
    """
    try:
        text = pytesseract.image_to_string(image) or ""
    except Exception as exc:
        logger.debug(f"[SCREENSHOT] OCR failed: {exc}")
        return

    if len(text.strip()) < 5:
        return

    result = client.classify(text=text[:_OCR_MAX_CLASSIFY])
    if result is None:
        logger.warning("[SCREENSHOT] Classifier unavailable -- skipping OCR content check")
        return

    risk_score = result.get("risk_score", 0.0)
    if risk_score <= 0.5:
        logger.debug(f"[SCREENSHOT] OCR content check: clean (risk={risk_score:.2f})")
        return

    detections = result.get("detections", [])
    logger.warning(
        f"[SCREENSHOT] OCR content check found sensitive text the title "
        f"heuristic missed | risk={risk_score:.2f} | types="
        f"{[d['type'] for d in detections]}"
    )

    policy = (
        policy_resolver.resolve(detections, channel="SCREENSHOT")
        if policy_resolver
        else {"id": _POLICY_ID, "action": "BLOCK", "name": None}
    )

    cleared = False
    if policy["action"] not in ("ALLOW", "ALERT") and _clipboard_has_image():
        try:
            pyperclip.copy(_DLP_BLOCK_MSG)
            cleared = True
        except Exception:
            pass

    event_q.put_nowait((policy, "OCR_CONTENT", title, t_detect, cleared, detections))


# ── Main loop ─────────────────────────────────────────────────────────────────

def _screenshot_loop(
    client: DLPApiClient,
    agent_id: str,
    user_id: str,
    stop: threading.Event,
    policy_resolver: PolicyResolver | None = None,
) -> None:
    # Queue carries: (policy: dict|None, source_tag: str, title: str,
    #                 t_event: float, cleared: bool, detections: list)
    # policy is None for a harmless screenshot -- otherwise {"id","action","name"}
    event_q: queue.Queue[tuple] = queue.Queue()

    # Shared cooldown state -- accessed from the poll loop (main thread) and,
    # if it happens to fire, the keyboard hook's own thread.
    _last_action = [0.0]     # mutable single-element list for nonlocal mutation
    _cb_lock     = threading.Lock()

    def _handle_detection(source_tag: str) -> None:
        """
        Shared by both detection paths:
          1. Enforces cooldown
          2. Reads the foreground window title
          3. If sensitive: immediately clears the clipboard -- this is the
             actual block
          4. Pushes event tuple to queue for async reporting in the main loop
        """
        now = time.monotonic()
        with _cb_lock:
            if now - _last_action[0] < _COOLDOWN_SECS:
                return
            _last_action[0] = now

        title       = _get_foreground_title()
        matched_kw  = _matched_keyword(title)
        cleared     = False
        policy      = None
        detections: list = []

        if matched_kw:
            # No classify() call happens on this path (title-heuristic only),
            # but the matched keyword still implies a compliance rule (see
            # _KEYWORD_RULE), so build a synthetic detection from it rather
            # than resolving against an empty list -- an empty list always
            # falls back to the default policy regardless of which keyword
            # actually matched.
            detections = [{
                "type":       "keyword",
                "value":      matched_kw,
                "rule":       _KEYWORD_RULE.get(matched_kw, "INTERNAL"),
                "confidence": 0.6,
            }]
            policy = (
                policy_resolver.resolve(detections, channel="SCREENSHOT")
                if policy_resolver
                else {"id": _POLICY_ID, "action": "BLOCK", "name": None}
            )
            if policy["action"] not in ("ALLOW", "ALERT"):
                try:
                    pyperclip.copy(_DLP_BLOCK_MSG)
                    cleared = True
                except Exception:
                    pass

        event_q.put_nowait((policy, source_tag, title, now, cleared, detections))

    # Best-effort keyboard hook -- kept as a fast path in case it does fire in
    # some environment/Windows configuration; see module docstring for why it
    # can't be relied on for PrtScn/Win+Shift+S specifically.
    _kb = None
    hotkeys_ok = 0
    try:
        import keyboard as _kb
        for key_combo, name in [
            ("print screen",    "PRINT_SCREEN"),
            ("windows+shift+s", "WIN_SHIFT_S"),
        ]:
            try:
                _kb.add_hotkey(key_combo, lambda name=name: _handle_detection(name))
                hotkeys_ok += 1
                logger.info(f"[SCREENSHOT] Hotkey registered: {key_combo}")
            except Exception as exc:
                logger.warning(f"[SCREENSHOT] Could not register '{key_combo}': {exc}")
    except ImportError:
        logger.warning(
            "[SCREENSHOT] 'keyboard' library not installed -- "
            "hook fallback disabled, clipboard-image poll still active"
        )

    logger.info(
        f"[SCREENSHOT] Loop started -- clipboard-image poll every {_CHECK_INTERVAL}s "
        f"(primary detection), {hotkeys_ok} keyboard hook(s) as best-effort fallback"
    )

    last_seq = _clipboard_seq()

    while not stop.is_set():
        # ── Primary: clipboard-image poll ────────────────────────────────────
        seq = _clipboard_seq()
        if seq != last_seq:
            last_seq = seq
            if _clipboard_has_image():
                # A single screenshot can bump the clipboard sequence number
                # more than once in quick succession (the OS/capture tool
                # writing the image in stages) -- without gating on the SAME
                # cooldown _handle_detection already uses, that would spawn a
                # second independent OCR+classify+incident cycle for what is
                # really one screenshot. Snapshot the cooldown state BEFORE
                # calling _handle_detection (which updates it as a side
                # effect), so both the title-check and the OCR spawn agree on
                # whether this is a genuinely new event.
                now = time.monotonic()
                with _cb_lock:
                    already_handled_recently = now - _last_action[0] < _COOLDOWN_SECS

                _handle_detection("CLIPBOARD_IMAGE")

                # Thorough path: OCR the actual image content in the
                # background in case the title heuristic just missed it.
                # Grab the image on THIS thread immediately (clipboard
                # content can change again before a background thread gets
                # scheduled), hand the pixels off, and let the classify
                # round-trip happen off the poll loop.
                if _OCR_AVAILABLE and not already_handled_recently:
                    try:
                        image = ImageGrab.grabclipboard()
                    except Exception as exc:
                        image = None
                        logger.debug(f"[SCREENSHOT] Could not grab clipboard image: {exc}")
                    if image is not None and not isinstance(image, list):
                        threading.Thread(
                            target=_content_check_async,
                            args=(image, _get_foreground_title(), time.monotonic(), client, event_q, policy_resolver),
                            daemon=True,
                            name="screenshot-ocr",
                        ).start()

        # Drain queued events (async reporting; the blocking already happened)
        while True:
            try:
                policy, source_tag, title, t_event, cleared, detections = event_q.get_nowait()
            except queue.Empty:
                break

            if policy is None:
                logger.info(
                    f"[SCREENSHOT] {source_tag} -- harmless screenshot, no action "
                    f"(window='{title[:70]}')"
                )
                continue

            action = policy["action"]
            if action == "ALLOW":
                logger.debug(
                    f"[SCREENSHOT] Sensitive window captured but policy "
                    f"'{policy.get('name') or 'default'}' allows it -- no report (window='{title[:70]}')"
                )
                continue

            # Sensitive screenshot, policy says ALERT / BLOCK / QUARANTINE
            logger.critical(
                f"[SCREENSHOT] !! Sensitive window captured: '{title}'"
            )
            if action in ("BLOCK", "QUARANTINE"):
                if cleared:
                    logger.success(
                        "[SCREENSHOT] Image cleared from clipboard - capture blocked"
                    )
                else:
                    logger.warning(
                        "[SCREENSHOT] Could not clear clipboard -- block may have failed"
                    )
            else:
                logger.warning("[SCREENSHOT] Policy set to ALERT -- reporting without blocking")

            ts = datetime.now().isoformat()

            ueba = client.post_ueba_event(
                agent_id=agent_id,
                user_id=user_id,
                event_type="SCREENSHOT",
                metadata={
                    "window_title": title[:255],
                    "key":          source_tag,
                    "blocked":      cleared,
                    "timestamp":    ts,
                },
            )
            if ueba:
                logger.success(
                    f"[SCREENSHOT] UEBA event posted: id={ueba.get('id')}"
                )
            else:
                logger.error("[SCREENSHOT] Failed to post UEBA event")

            incident = client.create_incident(
                agent_id=agent_id,
                policy_id=policy["id"],
                severity="HIGH",
                channel="SCREENSHOT",
                evidence=title[:255],
                risk_score=0.75,
            )
            if incident:
                logger.success(
                    f"[SCREENSHOT] Incident created: "
                    f"id={incident.get('id')} [HIGH] blocked={cleared}"
                )
            else:
                logger.error("[SCREENSHOT] Failed to create incident")

        stop.wait(_CHECK_INTERVAL)

    if _kb is not None:
        try:
            _kb.unhook_all()
        except Exception:
            pass


# ── Public entry point ────────────────────────────────────────────────────────

def start_screenshot_monitor(
    client: DLPApiClient,
    agent_id: str,
    stop: threading.Event,
    policy_resolver: PolicyResolver | None = None,
) -> threading.Thread:
    if sys.platform != "win32":
        logger.warning(
            "[SCREENSHOT] Non-Windows platform -- screenshot monitor disabled"
        )
        return threading.Thread(target=lambda: None, daemon=True)

    user_id = (
        os.environ.get("USERNAME")
        or os.environ.get("USER")
        or "unknown-user"
    )

    t = threading.Thread(
        target=_screenshot_loop,
        args=(client, agent_id, user_id, stop, policy_resolver),
        daemon=True,
        name="screenshot-monitor",
    )
    t.start()
    logger.info(
        "Screenshot monitor started  "
        "(clipboard-image poll, PrtScn/Win+Shift+S hook as fallback)"
    )
    return t
