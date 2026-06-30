"""
Screenshot monitor: hooks Print Screen and Win+Shift+S globally.

BLOCKING STRATEGY — the clipboard clear happens INSIDE the keyboard hook
callback (runs in keyboard's own hook thread) so it fires within ~2 ms of the
keypress, before the user can switch windows and paste.  Async work (UEBA
event, incident creation) is queued to the main monitor loop.
"""

import os
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

_POLICY_ID      = "seed-policy-pii-001"
_COOLDOWN_SECS  = 5.0    # min seconds between reactions (debounce rapid presses)
_CHECK_INTERVAL = 0.5    # seconds between event-queue drains

_DLP_BLOCK_MSG  = "[BLOCKED BY DLP - Screenshot cleared]"

# Window title substrings that classify a screenshot as sensitive
_SENSITIVE_KEYWORDS = frozenset({
    "confidential", "client", "salary", "payroll",
    "ssn", "iban", "carte", "bancaire",
    "password", "secret", "dlp",
})

# Office file title format: "report_client.xlsx - Microsoft Excel"
_SENSITIVE_FILENAME_KW = frozenset({"client", "confidential"})
_OFFICE_EXTS = frozenset({".xlsx", ".xls", ".docx", ".doc", ".pptx", ".ppt", ".pdf"})


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


def _is_sensitive(title: str) -> bool:
    lower = title.lower()
    for kw in _SENSITIVE_KEYWORDS:
        if kw in lower:
            return True
    for ext in _OFFICE_EXTS:
        if ext in lower:
            filename_part = lower.split(" - ")[0].strip()
            for kw in _SENSITIVE_FILENAME_KW:
                if kw in filename_part:
                    return True
    return False


# ── Main loop ─────────────────────────────────────────────────────────────────

def _screenshot_loop(
    client: DLPApiClient,
    agent_id: str,
    user_id: str,
    stop: threading.Event,
) -> None:
    try:
        import keyboard as _kb
    except ImportError:
        logger.error(
            "[SCREENSHOT] 'keyboard' library not installed -- "
            "run: pip install keyboard"
        )
        return

    # Queue carries: (sensitive: bool, key_name: str, title: str,
    #                 t_event: float, cleared: bool)
    event_q: queue.Queue[tuple] = queue.Queue()

    # Shared cooldown state accessed from keyboard hook thread + main loop thread
    _last_action = [0.0]     # mutable single-element list for nonlocal mutation
    _cb_lock     = threading.Lock()

    def _make_hook(key_name: str):
        """
        Returns a hotkey callback that:
          1. Enforces cooldown (in the hook thread — fast path)
          2. Reads the foreground window title (~1 ms)
          3. If sensitive: immediately clears the clipboard (~1 ms) — this is the
             actual block; happens before the user can switch and paste
          4. Pushes event tuple to queue for async reporting in the main loop
        """
        def _cb():
            now = time.monotonic()
            with _cb_lock:
                if now - _last_action[0] < _COOLDOWN_SECS:
                    return
                _last_action[0] = now

            title     = _get_foreground_title()
            sensitive = _is_sensitive(title)
            cleared   = False

            if sensitive:
                try:
                    pyperclip.copy(_DLP_BLOCK_MSG)
                    cleared = True
                except Exception:
                    pass

            event_q.put_nowait((sensitive, key_name, title, now, cleared))

        return _cb

    # Register hotkeys
    hotkeys_ok = 0
    for key_combo, name in [
        ("print screen",    "PRINT_SCREEN"),
        ("windows+shift+s", "WIN_SHIFT_S"),
    ]:
        try:
            _kb.add_hotkey(key_combo, _make_hook(name))
            hotkeys_ok += 1
            logger.info(f"[SCREENSHOT] Hotkey registered: {key_combo}")
        except Exception as exc:
            logger.warning(f"[SCREENSHOT] Could not register '{key_combo}': {exc}")

    if hotkeys_ok == 0:
        logger.error("[SCREENSHOT] No hotkeys registered -- monitor disabled")
        return

    logger.info("[SCREENSHOT] Loop started -- waiting for screenshot keys")

    while not stop.is_set():
        # Drain queued events (async reporting; the blocking already happened)
        while True:
            try:
                sensitive, key_name, title, t_event, cleared = event_q.get_nowait()
            except queue.Empty:
                break

            if not sensitive:
                logger.info(
                    f"[SCREENSHOT] {key_name} -- harmless screenshot, no action "
                    f"(window='{title[:70]}')"
                )
                continue

            # Sensitive screenshot
            logger.critical(
                f"[SCREENSHOT] !! Sensitive window captured: '{title}'"
            )
            if cleared:
                logger.success(
                    "[SCREENSHOT] Image cleared from clipboard - capture blocked"
                )
            else:
                logger.warning(
                    "[SCREENSHOT] Could not clear clipboard -- block may have failed"
                )

            ts = datetime.now().isoformat()

            ueba = client.post_ueba_event(
                agent_id=agent_id,
                user_id=user_id,
                event_type="SCREENSHOT",
                metadata={
                    "window_title": title[:255],
                    "key":          key_name,
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
                policy_id=_POLICY_ID,
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

    try:
        _kb.unhook_all()
    except Exception:
        pass


# ── Public entry point ────────────────────────────────────────────────────────

def start_screenshot_monitor(
    client: DLPApiClient,
    agent_id: str,
    stop: threading.Event,
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
        args=(client, agent_id, user_id, stop),
        daemon=True,
        name="screenshot-monitor",
    )
    t.start()
    logger.info(
        "Screenshot monitor started  "
        "(Print Screen + Win+Shift+S, clipboard cleared in hook callback)"
    )
    return t
