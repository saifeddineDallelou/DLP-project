"""
Periodic poll for the "real relation" restricted-app<->file check
(_find_restricted_app_holding_file in file_watcher.py).

file_watcher.py only calls that check at the exact instant it reacts to a
filesystem event -- a process that opens the file a few seconds later (after
the event already fired) would be missed entirely. This loop re-checks
every _POLL_INTERVAL against AgentState's rolling list of recently-flagged
sensitive files (see AgentState.mark_sensitive_file / .sensitive_files),
closing most of that timing gap without needing ETW/a kernel driver -- the
residual gap is now "opened and closed within one poll interval", not
"opened any time after the original file event".
"""

import threading
import time
from loguru import logger

from api_client import DLPApiClient
from agent_state import AgentState
from file_watcher import _find_restricted_app_holding_file, severity_for

_POLL_INTERVAL  = 2.0    # seconds between polls
_REPORT_COOLDOWN = 60.0  # min seconds between repeat incidents for the same (file, app) pair


def _app_file_monitor_loop(
    client: DLPApiClient,
    agent_id: str,
    state: AgentState,
    stop: threading.Event,
    app_rule_resolver=None,
) -> None:
    last_reported: dict[tuple[str, str], float] = {}  # (path, label) -> monotonic time

    logger.info(f"[APP-FILE] Loop started -- polling every {_POLL_INTERVAL}s")

    while not stop.is_set():
        stop.wait(_POLL_INTERVAL)
        if stop.is_set():
            break

        files = state.sensitive_files()
        if not files:
            continue

        for path, info in files.items():
            held_by = _find_restricted_app_holding_file(app_rule_resolver, path)
            if not held_by:
                continue
            label, pid = held_by

            now = time.monotonic()
            key = (path, label)
            if now - last_reported.get(key, 0.0) < _REPORT_COOLDOWN:
                continue
            last_reported[key] = now

            policy     = info["policy"]
            risk_score = info["risk_score"]
            logger.warning(
                f"[APP-FILE] Restricted app '{label}' (PID {pid}) has sensitive file open: {path}"
            )
            incident = client.create_incident(
                agent_id=agent_id,
                policy_id=policy.get("id"),
                severity=severity_for(policy, risk_score),
                channel="FILE",
                evidence=f"{path} [open in {label}, PID {pid}]",
                risk_score=risk_score,
                action_taken=policy.get("action"),
            )
            if incident:
                logger.success(f"[APP-FILE] Incident REPORTED  id={incident.get('id')}")
            else:
                logger.error("[APP-FILE] Failed to report incident")


def start_app_file_monitor(
    client: DLPApiClient,
    agent_id: str,
    state: AgentState,
    stop: threading.Event,
    app_rule_resolver=None,
) -> threading.Thread:
    t = threading.Thread(
        target=_app_file_monitor_loop,
        args=(client, agent_id, state, stop, app_rule_resolver),
        daemon=True,
        name="app-file-monitor",
    )
    t.start()
    logger.info(f"App file monitor started  ({_POLL_INTERVAL}s poll, catches restricted apps opening a sensitive file after the fact)")
    return t
