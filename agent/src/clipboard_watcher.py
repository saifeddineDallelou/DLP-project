"""
Clipboard watcher — polls at 0.3 s for text content changes.

On sensitive detection, immediately calls blocker.check_and_block() to scan
for an active AI window in the SAME event cycle.  If no AI window is found at
that instant, flags state so the AI monitor's 1-second loop can catch it when
the user later opens an AI platform.

Also polls the CF_HDROP clipboard format, which is what Windows uses when a
FILE is copied (Ctrl+C on a file in Explorer) rather than text -- pyperclip
only reads CF_TEXT/CF_UNICODETEXT, so a copied file is otherwise invisible
here even though pasting it into an AI upload box is the same leak vector.
"""

import ctypes
import os
import time
import threading
import pyperclip
from loguru import logger

from api_client      import DLPApiClient
from agent_state     import AgentState
from ai_domain_monitor import AiBlocker
from file_extractor  import extract

_POLL_INTERVAL   = 0.3    # seconds between polls (down from 2 s)
_MAX_CLASSIFY    = 5_000  # max chars sent to classifier
_LOG_ALIVE_EVERY = 100    # alive log every 100 polls ≈ every 30 s
_MAX_FILE_SIZE   = 20 * 1024 * 1024  # skip anything larger, same cap as file_watcher

_DLP_BLOCK_MSG = "[BLOCKED BY DLP - Sensitive content detected]"

_CF_HDROP = 15  # Windows clipboard format id for a file-drop list


def _mask(text: str) -> str:
    t = text[:100]
    if len(t) > 30:
        return t[:15] + "***[MASKED]***" + t[-5:]
    return t


def _get_clipboard_files() -> tuple[str, ...]:
    """Return the file paths on the clipboard if it holds a CF_HDROP file-drop
    list (i.e. a file was copied in Explorer), else an empty tuple."""
    user32  = ctypes.windll.user32
    shell32 = ctypes.windll.shell32
    user32.GetClipboardData.restype    = ctypes.c_void_p
    user32.GetClipboardData.argtypes   = [ctypes.c_uint]
    # argtypes matter here: without them ctypes may pass the HDROP handle as a
    # 32-bit int and truncate it on 64-bit Windows, corrupting the handle.
    shell32.DragQueryFileW.restype  = ctypes.c_uint
    shell32.DragQueryFileW.argtypes = [
        ctypes.c_void_p, ctypes.c_uint, ctypes.c_wchar_p, ctypes.c_uint,
    ]

    if not user32.OpenClipboard(None):
        return ()
    try:
        if not user32.IsClipboardFormatAvailable(_CF_HDROP):
            return ()
        hdrop = user32.GetClipboardData(_CF_HDROP)
        if not hdrop:
            return ()
        count = shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0)
        paths = []
        for i in range(count):
            length = shell32.DragQueryFileW(hdrop, i, None, 0)
            buf = ctypes.create_unicode_buffer(length + 1)
            shell32.DragQueryFileW(hdrop, i, buf, length + 1)
            paths.append(buf.value)
        return tuple(paths)
    except Exception as exc:
        logger.debug(f"[CLIPBOARD] CF_HDROP read error: {exc}")
        return ()
    finally:
        user32.CloseClipboard()


def _scan_copied_files(
    files: tuple[str, ...],
    client: DLPApiClient,
    agent_id: str,
    state: AgentState,
    blocker: AiBlocker,
) -> None:
    """Classify each copied file the same way clipboard text is classified,
    and block/report exactly like the text path does."""
    for path in files:
        if not os.path.isfile(path):
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size == 0 or size > _MAX_FILE_SIZE:
            continue

        text = extract(path)
        if not text:
            continue

        t_change = time.monotonic()
        filename = os.path.basename(path)

        result = client.classify(text=text[:_MAX_CLASSIFY])
        if result is None:
            logger.warning(f"[CLIPBOARD] Classifier unavailable -- skipping copied file {filename}")
            continue

        risk_score: float = result.get("risk_score", 0.0)
        detections: list  = result.get("detections", [])
        types = [d["type"] for d in detections]

        logger.info(
            f"[CLIPBOARD] Copied file classified | file={filename} | "
            f"risk={risk_score:.3f} | types={types}"
        )

        if risk_score <= 0.5:
            continue

        logger.warning(
            f"[CLIPBOARD] !! SENSITIVE FILE COPIED | file={filename} | "
            f"risk={risk_score:.2f} | types={types}"
        )

        sample = f"FILE:{filename} | {_mask(text)}"

        action_taken = blocker.check_and_block(
            t_detect=t_change,
            content_sample=sample,
            risk_score=risk_score,
            source_tag="CLIPBOARD_FILE",
            detections=detections,
        )

        if action_taken is None:
            state.flag_sensitive_clipboard()
            logger.warning(
                "[CLIPBOARD] No AI window active now -- "
                "flagged for AI monitor (will block within 1 s of opening AI tab)"
            )
            action_taken = "ALERT"  # still worth an audit record below, just not blocked yet

        if action_taken == "ALLOW":
            continue  # policy says let this through -- no audit record either

        attempt = client.report_ai_leak_attempt(
            agent_id=agent_id,
            platform="OTHER_AI",
            method="CLIPBOARD",
            content_sample=sample,
            risk_score=risk_score,
            blocked=(action_taken in ("BLOCK", "QUARANTINE")),
        )
        if attempt:
            logger.success(
                f"[CLIPBOARD] File leak attempt recorded: id={attempt.get('id')} | action={action_taken}"
            )
        else:
            logger.error("[CLIPBOARD] Failed to record file leak attempt -- backend may be down")


def _clipboard_loop(
    client: DLPApiClient,
    agent_id: str,
    state: AgentState,
    stop: threading.Event,
    blocker: AiBlocker,
) -> None:
    prev        = ""
    prev_files: tuple[str, ...] = ()
    poll_num    = 0
    error_count = 0

    logger.info("[CLIPBOARD] Loop started -- polling every 0.3 s")

    while not stop.is_set():
        poll_num += 1

        if poll_num % _LOG_ALIVE_EVERY == 0:
            logger.debug(
                f"[CLIPBOARD] Alive | poll=#{poll_num} | "
                f"errors={error_count} | prev_len={len(prev)}"
            )

        # ── Copied FILE (CF_HDROP) — Ctrl+C on a file in Explorer ────────────
        files = _get_clipboard_files()
        if files != prev_files:
            prev_files = files
            if files:
                logger.info(
                    f"[CLIPBOARD] File(s) copied | count={len(files)} | "
                    f"{[os.path.basename(f) for f in files]}"
                )
                _scan_copied_files(files, client, agent_id, state, blocker)

        try:
            current = pyperclip.paste()
            error_count = 0
        except Exception as exc:
            error_count += 1
            logger.warning(f"[CLIPBOARD] Read error (#{error_count}): {exc}")
            stop.wait(_POLL_INTERVAL)
            continue

        if not current or current == prev:
            stop.wait(_POLL_INTERVAL)
            continue

        # Skip our own block messages to avoid a classification round-trip
        if current.startswith(_DLP_BLOCK_MSG[:20]):
            prev = current
            stop.wait(_POLL_INTERVAL)
            continue

        # Clipboard changed — record the detection time before the (slow) classify call
        t_change = time.monotonic()
        prev = current

        content_len = len(current.strip())
        logger.info(
            f"[CLIPBOARD] Content changed | len={len(current)} | poll=#{poll_num}"
        )

        if content_len < 5:
            logger.debug("[CLIPBOARD] Too short to classify, skipping")
            stop.wait(_POLL_INTERVAL)
            continue

        result = client.classify(text=current[:_MAX_CLASSIFY])
        if result is None:
            logger.warning("[CLIPBOARD] Classifier unavailable -- skipping")
            stop.wait(_POLL_INTERVAL)
            continue

        risk_score: float = result.get("risk_score", 0.0)
        detections: list  = result.get("detections", [])
        types = [d["type"] for d in detections]

        logger.info(
            f"[CLIPBOARD] Classified | risk={risk_score:.3f} | "
            f"sensitive={result.get('sensitive')} | types={types}"
        )

        if risk_score > 0.5:
            logger.warning(
                f"[CLIPBOARD] !! SENSITIVE CONTENT DETECTED | "
                f"risk={risk_score:.2f} | types={types}"
            )

            # ── IMMEDIATE CHECK: is an AI window open right now? ──────────────
            action_taken = blocker.check_and_block(
                t_detect=t_change,
                content_sample=_mask(current),
                risk_score=risk_score,
                source_tag="CLIPBOARD",
                detections=detections,
            )

            if action_taken == "ALLOW":
                logger.debug("[CLIPBOARD] Policy allows this content -- no block, no report")
            else:
                if action_taken in ("BLOCK", "QUARANTINE"):
                    logger.warning(
                        "[CLIPBOARD] Immediate block applied -- "
                        "AI window was active at copy time"
                    )
                elif action_taken == "ALERT":
                    logger.warning("[CLIPBOARD] Policy set to ALERT -- reporting without blocking")
                else:
                    # No AI window open yet — flag state so the 1 s AI monitor
                    # loop will block when the user navigates to one.
                    state.flag_sensitive_clipboard()
                    logger.warning(
                        "[CLIPBOARD] No AI window active now -- "
                        "flagged for AI monitor (will block within 1 s of opening AI tab)"
                    )

                # Always record the clipboard leak attempt for audit trail
                # (unless the policy said ALLOW, handled above)
                blocked = action_taken in ("BLOCK", "QUARANTINE")
                attempt = client.report_ai_leak_attempt(
                    agent_id=agent_id,
                    platform="OTHER_AI",
                    method="CLIPBOARD",
                    content_sample=_mask(current),
                    risk_score=risk_score,
                    blocked=blocked,
                )
                if attempt:
                    logger.success(
                        f"[CLIPBOARD] Leak attempt recorded: id={attempt.get('id')} | "
                        f"blocked={blocked}"
                    )
                else:
                    logger.error("[CLIPBOARD] Failed to record attempt -- backend may be down")

        stop.wait(_POLL_INTERVAL)


def start_clipboard_watcher(
    client: DLPApiClient,
    agent_id: str,
    state: AgentState,
    stop: threading.Event,
    blocker: AiBlocker,
) -> threading.Thread:
    t = threading.Thread(
        target=_clipboard_loop,
        args=(client, agent_id, state, stop, blocker),
        daemon=True,
        name="clipboard-watcher",
    )
    t.start()
    logger.info("Clipboard watcher started  (poll every 0.3 s, alive log every 30 s)")
    return t
