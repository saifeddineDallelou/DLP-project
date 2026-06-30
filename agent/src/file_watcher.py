import os
import base64
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from loguru import logger

from api_client import DLPApiClient
from agent_state import AgentState

POLICY_ID = "seed-policy-pii-001"
_TEXT_LIMIT = 10_000   # max chars to send for text files
_BINARY_LIMIT = 8_192  # max bytes to send for binary files


def _risk_to_severity(risk_score: float) -> str:
    if risk_score >= 0.9:
        return "CRITICAL"
    if risk_score >= 0.7:
        return "HIGH"
    return "MEDIUM"


class _DLPHandler(FileSystemEventHandler):
    def __init__(self, client: DLPApiClient, agent_id: str, state: AgentState | None = None):
        super().__init__()
        self.client = client
        self.agent_id = agent_id
        self.state = state
        self._cooldown: dict[str, float] = {}

    def _within_cooldown(self, path: str) -> bool:
        now = time.time()
        if now - self._cooldown.get(path, 0) < 2.0:
            return True
        self._cooldown[path] = now
        return False

    def _read_file(self, file_path: str) -> tuple[str | None, str | None]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="strict") as f:
                return f.read(_TEXT_LIMIT), None
        except (UnicodeDecodeError, UnicodeError):
            pass
        except (PermissionError, OSError) as e:
            logger.warning(f"Cannot read {file_path}: {e}")
            return None, None

        try:
            with open(file_path, "rb") as f:
                raw = f.read(_BINARY_LIMIT)
            return None, base64.b64encode(raw).decode("ascii")
        except (PermissionError, OSError) as e:
            logger.warning(f"Cannot read binary {file_path}: {e}")
            return None, None

    def _process(self, file_path: str) -> None:
        if not os.path.isfile(file_path):
            return
        if self._within_cooldown(file_path):
            return

        filename = os.path.basename(file_path)
        logger.info(f"Scanning: {filename}")
        if self.state:
            self.state.increment_file_access()

        text, file_b64 = self._read_file(file_path)
        if text is None and file_b64 is None:
            return

        result = self.client.classify(text=text, file_b64=file_b64)
        if result is None:
            logger.warning(f"Classifier unavailable — skipping {filename}")
            return

        risk_score: float = result.get("risk_score", 0.0)
        detections: list = result.get("detections", [])

        if risk_score > 0.5:
            severity = _risk_to_severity(risk_score)
            types = [d["type"] for d in detections]
            logger.warning(
                f"SENSITIVE DETECTED | {filename} | risk={risk_score:.2f} | "
                f"severity={severity} | types={types}"
            )
            incident = self.client.create_incident(
                agent_id=self.agent_id,
                policy_id=POLICY_ID,
                severity=severity,
                channel="FILE",
                evidence=filename,
                risk_score=risk_score,
            )
            if incident:
                logger.success(f"Incident created: id={incident.get('id')} [{severity}]")
            else:
                logger.error(f"Failed to report incident for {filename}")
        else:
            logger.debug(f"Clean: {filename} (risk={risk_score:.2f})")

    def on_created(self, event):
        if not event.is_directory:
            self._process(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process(event.src_path)


def start_watcher(
    watch_dir: str,
    client: DLPApiClient,
    agent_id: str,
    state: AgentState | None = None,
) -> Observer:
    observer = Observer()
    observer.schedule(_DLPHandler(client, agent_id, state), watch_dir, recursive=True)
    observer.start()
    logger.info(f"File watcher active: {watch_dir}")
    return observer
