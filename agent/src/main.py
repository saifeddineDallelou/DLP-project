import os
import sys
import json
import time
import platform
import socket
import threading
from pathlib import Path

from dotenv import load_dotenv
from loguru import logger

# Load .env from agent root (one level up from src/)
_ENV_PATH = Path(__file__).parent.parent / ".env"
load_dotenv(_ENV_PATH)

from agent_state        import AgentState
from api_client         import DLPApiClient
from file_watcher       import start_watcher
from clipboard_watcher  import start_clipboard_watcher
from ai_domain_monitor  import start_ai_domain_monitor
from ueba_collector     import start_ueba_collector

_STATE_FILE = Path(__file__).parent.parent / "state.json"

_BANNER = """
+--------------------------------------------------+
|   DLP Agent v1.0  --  Data Loss Prevention       |
|   Platform: Simulated Endpoint Agent             |
|   Modules : File / Clipboard / AI-Domain / UEBA  |
+--------------------------------------------------+"""


def _load_state() -> dict:
    if _STATE_FILE.exists():
        try:
            return json.loads(_STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_state(state: dict) -> None:
    _STATE_FILE.write_text(json.dumps(state, indent=2))


def _enroll(client: DLPApiClient) -> dict | None:
    hostname = socket.gethostname()
    os_info  = f"{platform.system()} {platform.release()}"
    logger.info(f"Enrolling | hostname={hostname} | os={os_info}")
    result = client.enroll(hostname=hostname, os_info=os_info)
    if result:
        logger.success(f"Enrolled  | agent_id={result['id']}")
    else:
        logger.error("Enrollment failed -- backend may be offline or hostname already enrolled")
    return result


def _heartbeat_loop(
    client: DLPApiClient,
    agent_id: str,
    interval: int,
    stop: threading.Event,
) -> None:
    while not stop.is_set():
        result = client.heartbeat(agent_id)
        if result:
            logger.debug(f"Heartbeat OK | status={result.get('status')}")
        else:
            logger.warning("Heartbeat failed -- will retry next interval")
        stop.wait(interval)


def main() -> None:
    print(_BANNER, flush=True)

    backend_url        = os.getenv("BACKEND_URL",        "http://localhost:3001")
    classifier_url     = os.getenv("CLASSIFIER_URL",     "http://localhost:8000")
    watch_dir          = os.getenv("WATCH_DIR",          str(Path.home() / "dlp-watch"))
    heartbeat_interval = int(os.getenv("HEARTBEAT_INTERVAL", "30"))

    logger.info(f"Backend    : {backend_url}")
    logger.info(f"Classifier : {classifier_url}")
    logger.info(f"Heartbeat  : every {heartbeat_interval}s")

    # Ensure watch folder exists
    watch_path = Path(watch_dir)
    watch_path.mkdir(parents=True, exist_ok=True)
    logger.info(f"Watch dir  : {watch_path}")

    # Load saved agent state
    saved = _load_state()
    agent_id    = saved.get("agent_id")
    agent_token = saved.get("agent_token")

    client = DLPApiClient(backend_url, classifier_url, agent_token)

    if agent_id and agent_token:
        logger.info(f"Resuming   : agent_id={agent_id}")
    else:
        result = _enroll(client)
        if result:
            agent_id    = result["id"]
            agent_token = result["token"]
            client.agent_token = agent_token
            _save_state({"agent_id": agent_id, "agent_token": agent_token})
        else:
            logger.warning("Continuing without enrollment -- reporting will fail")

    # ── Shared state (thread-safe counters / flags) ───────────────────────────
    shared = AgentState()
    stop   = threading.Event()

    # ── 1. Heartbeat ──────────────────────────────────────────────────────────
    if agent_id and agent_token:
        threading.Thread(
            target=_heartbeat_loop,
            args=(client, agent_id, heartbeat_interval, stop),
            daemon=True,
            name="heartbeat",
        ).start()
        logger.info("[1/4] Heartbeat thread started")

    # ── 2. File watcher ───────────────────────────────────────────────────────
    observer = start_watcher(str(watch_path), client, agent_id or "", shared)
    logger.info("[2/4] File watcher started")

    # ── 3. Clipboard watcher ──────────────────────────────────────────────────
    start_clipboard_watcher(client, agent_id or "", shared, stop)
    logger.info("[3/4] Clipboard watcher started")

    # ── 4. AI domain monitor ──────────────────────────────────────────────────
    start_ai_domain_monitor(client, agent_id or "", shared, stop)
    logger.info("[4/4] AI domain monitor started")

    # ── 5. UEBA collector (background flush) ─────────────────────────────────
    start_ueba_collector(client, agent_id or "", shared, stop)
    logger.info("[+]   UEBA collector started")

    logger.success(f"DLP Agent fully operational -- watching '{watch_path}'")
    logger.info("Press Ctrl+C to stop\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Shutting down...")
        stop.set()
        observer.stop()
        observer.join()
        logger.info("DLP Agent stopped")


if __name__ == "__main__":
    main()
