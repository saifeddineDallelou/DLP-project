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
from screenshot_monitor import start_screenshot_monitor
from app_launch_monitor import start_app_launch_monitor

_STATE_FILE = Path(__file__).parent.parent / "state.json"

_BANNER = """
+--------------------------------------------------+
|   DLP Agent v1.0  --  Data Loss Prevention       |
|   Platform: Simulated Endpoint Agent             |
|   Modules : File / Clipboard / AI-Domain / UEBA  |
|             Screenshot / App-Launch              |
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
    heartbeat_interval = int(os.getenv("HEARTBEAT_INTERVAL", "30"))

    # Support WATCH_DIRS (comma-separated) with fallback to legacy WATCH_DIR
    _raw = (
        os.getenv("WATCH_DIRS")
        or os.getenv("WATCH_DIR")
        or str(Path.home() / "dlp-watch")
    )
    watch_dirs: list[str] = [d.strip() for d in _raw.split(",") if d.strip()]

    logger.info(f"Backend    : {backend_url}")
    logger.info(f"Classifier : {classifier_url}")
    logger.info(f"Heartbeat  : every {heartbeat_interval}s")

    # Ensure every watch folder exists
    watch_paths: list[Path] = []
    for raw_dir in watch_dirs:
        p = Path(raw_dir)
        p.mkdir(parents=True, exist_ok=True)
        watch_paths.append(p)
        logger.info(f"Watch dir  : {p}")

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
        logger.info("[1/7] Heartbeat thread started")

    # ── 2. File watcher ───────────────────────────────────────────────────────
    observer = start_watcher([str(p) for p in watch_paths], client, agent_id or "", shared)
    logger.info("[2/7] File watcher started")

    # ── 4. AI domain monitor (creates AiBlocker shared with clipboard watcher) ──
    _ai_thread, blocker = start_ai_domain_monitor(client, agent_id or "", shared, stop)
    logger.info("[4/7] AI domain monitor started")

    # ── 3. Clipboard watcher (receives blocker for immediate check-and-block) ──
    start_clipboard_watcher(client, agent_id or "", shared, stop, blocker)
    logger.info("[3/7] Clipboard watcher started")

    # ── 5. UEBA collector (background flush) ─────────────────────────────────
    start_ueba_collector(client, agent_id or "", shared, stop)
    logger.info("[5/7] UEBA collector started")

    # ── 6. Screenshot monitor ─────────────────────────────────────────────────
    start_screenshot_monitor(client, agent_id or "", stop)
    logger.info("[6/7] Screenshot monitor started")

    # ── 7. App launch monitor ─────────────────────────────────────────────────
    start_app_launch_monitor(client, agent_id or "", stop)
    logger.info("[7/7] App launch monitor started")

    logger.success(
        f"DLP Agent fully operational -- "
        f"watching {len(watch_paths)} folder(s) | 7 monitors active"
    )
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
