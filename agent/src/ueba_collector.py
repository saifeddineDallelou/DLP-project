import os
import threading
from datetime import datetime
from loguru import logger

from api_client import DLPApiClient
from agent_state import AgentState

_COLLECT_INTERVAL = 60.0  # seconds between UEBA event flushes
_AFTER_HOURS_START = 19   # 7 PM
_AFTER_HOURS_END   = 7    # 7 AM


def _get_os_user() -> str:
    return (
        os.environ.get("USERNAME")
        or os.environ.get("USER")
        or os.environ.get("LOGNAME")
        or "unknown-user"
    )


def _ueba_loop(
    client: DLPApiClient,
    agent_id: str,
    user_id: str,
    state: AgentState,
    stop: threading.Event,
) -> None:
    while not stop.is_set():
        stop.wait(_COLLECT_INTERVAL)
        if stop.is_set():
            break

        file_count, clip_count = state.pop_counters()
        hour = datetime.now().hour
        is_after_hours = (hour >= _AFTER_HOURS_START) or (hour < _AFTER_HOURS_END)

        if file_count > 0:
            event_type = "AFTER_HOURS_ACCESS" if is_after_hours else "FILE_ACCESS"
            result = client.post_ueba_event(
                agent_id=agent_id,
                user_id=user_id,
                event_type=event_type,
                metadata={
                    "count": file_count,
                    "hour": hour,
                    "note": "after-hours file activity detected" if is_after_hours
                            else "file access activity detected",
                },
            )
            if result:
                logger.info(f"[UEBA] {event_type} event posted (files={file_count})")
            else:
                logger.warning(f"[UEBA] Failed to post {event_type} event")

        if clip_count > 0:
            result = client.post_ueba_event(
                agent_id=agent_id,
                user_id=user_id,
                event_type="CLIPBOARD_COPY",
                metadata={
                    "count": clip_count,
                    "hour": hour,
                    "note": "sensitive clipboard detections in this window",
                },
            )
            if result:
                logger.info(f"[UEBA] CLIPBOARD_COPY event posted (count={clip_count})")
            else:
                logger.warning("[UEBA] Failed to post CLIPBOARD_COPY event")


def start_ueba_collector(
    client: DLPApiClient,
    agent_id: str,
    state: AgentState,
    stop: threading.Event,
) -> threading.Thread:
    user_id = _get_os_user()
    logger.info(f"UEBA collector started  (flush every 60s | user={user_id})")
    t = threading.Thread(
        target=_ueba_loop,
        args=(client, agent_id, user_id, state, stop),
        daemon=True,
        name="ueba-collector",
    )
    t.start()
    return t
