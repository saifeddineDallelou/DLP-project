"""
Clipboard watcher — polls at 0.3 s for text content changes.

On sensitive detection, immediately calls blocker.check_and_block() to scan
for an active AI window in the SAME event cycle.  If no AI window is found at
that instant, flags state so the AI monitor's 1-second loop can catch it when
the user later opens an AI platform.
"""

import time
import threading
import pyperclip
from loguru import logger

from api_client      import DLPApiClient
from agent_state     import AgentState
from ai_domain_monitor import AiBlocker

_POLL_INTERVAL   = 0.3    # seconds between polls (down from 2 s)
_MAX_CLASSIFY    = 5_000  # max chars sent to classifier
_LOG_ALIVE_EVERY = 100    # alive log every 100 polls ≈ every 30 s

_DLP_BLOCK_MSG = "[BLOCKED BY DLP - Sensitive content detected]"


def _mask(text: str) -> str:
    t = text[:100]
    if len(t) > 30:
        return t[:15] + "***[MASKED]***" + t[-5:]
    return t


def _clipboard_loop(
    client: DLPApiClient,
    agent_id: str,
    state: AgentState,
    stop: threading.Event,
    blocker: AiBlocker,
) -> None:
    prev        = ""
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
            blocked = blocker.check_and_block(
                t_detect=t_change,
                content_sample=_mask(current),
                risk_score=risk_score,
                source_tag="CLIPBOARD",
            )

            if blocked:
                logger.warning(
                    "[CLIPBOARD] Immediate block applied -- "
                    "AI window was active at copy time"
                )
            else:
                # No AI window open yet — flag state so the 1 s AI monitor
                # loop will block when the user navigates to one.
                state.flag_sensitive_clipboard()
                logger.warning(
                    "[CLIPBOARD] No AI window active now -- "
                    "flagged for AI monitor (will block within 1 s of opening AI tab)"
                )

            # Always record the clipboard leak attempt for audit trail
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
