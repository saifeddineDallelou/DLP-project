import time
import threading
import pyperclip
from loguru import logger

from api_client import DLPApiClient
from agent_state import AgentState

_POLL_INTERVAL   = 2.0    # seconds between polls
_MAX_CLASSIFY    = 5_000  # max chars sent to classifier
_LOG_ALIVE_EVERY = 10     # log a heartbeat every N polls (~20 s)


def _mask(text: str) -> str:
    """Show first 15 and last 5 chars; hide the middle."""
    t = text[:100]
    if len(t) > 30:
        return t[:15] + "***[MASKED]***" + t[-5:]
    return t


def _clipboard_loop(
    client: DLPApiClient,
    agent_id: str,
    state: AgentState,
    stop: threading.Event,
) -> None:
    prev        = ""
    poll_num    = 0
    error_count = 0

    logger.info("[CLIPBOARD] Loop started -- polling every 2s")

    while not stop.is_set():
        poll_num += 1

        # Periodic alive log so the user can confirm the thread is running
        if poll_num % _LOG_ALIVE_EVERY == 0:
            logger.debug(
                f"[CLIPBOARD] Alive | poll=#{poll_num} | "
                f"errors={error_count} | prev_len={len(prev)}"
            )

        try:
            current = pyperclip.paste()
            error_count = 0  # reset on success
        except Exception as exc:
            error_count += 1
            logger.warning(f"[CLIPBOARD] Read error (#{error_count}): {exc}")
            stop.wait(_POLL_INTERVAL)
            continue

        if not current:
            stop.wait(_POLL_INTERVAL)
            continue

        if current == prev:
            stop.wait(_POLL_INTERVAL)
            continue

        # Clipboard changed
        prev = current
        content_len = len(current.strip())
        logger.info(
            f"[CLIPBOARD] Content changed | len={len(current)} | "
            f"stripped_len={content_len} | poll=#{poll_num}"
        )

        if content_len < 5:
            logger.debug("[CLIPBOARD] Too short to classify, skipping")
            stop.wait(_POLL_INTERVAL)
            continue

        result = client.classify(text=current[:_MAX_CLASSIFY])
        if result is None:
            logger.warning("[CLIPBOARD] Classifier unavailable -- skipping this change")
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
            logger.warning("[CLIPBOARD] !! BLOCKING -- reporting AI leak attempt")

            state.flag_sensitive_clipboard()

            attempt = client.report_ai_leak_attempt(
                agent_id=agent_id,
                platform="OTHER_AI",
                method="CLIPBOARD",
                content_sample=_mask(current),
                risk_score=risk_score,
                blocked=True,
            )
            if attempt:
                logger.success(f"[CLIPBOARD] Attempt recorded: id={attempt.get('id')}")
            else:
                logger.error("[CLIPBOARD] Failed to record attempt -- backend may be down")

        stop.wait(_POLL_INTERVAL)


def start_clipboard_watcher(
    client: DLPApiClient,
    agent_id: str,
    state: AgentState,
    stop: threading.Event,
) -> threading.Thread:
    t = threading.Thread(
        target=_clipboard_loop,
        args=(client, agent_id, state, stop),
        daemon=True,
        name="clipboard-watcher",
    )
    t.start()
    logger.info("Clipboard watcher started  (poll every 2s, alive log every 20s)")
    return t
