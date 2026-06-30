import os
import time
import threading
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from loguru import logger

from api_client     import DLPApiClient
from agent_state    import AgentState
from file_extractor import extract

POLICY_ID      = "seed-policy-pii-001"
_CLASSIFY_LIMIT = 10_000   # max chars sent to classifier per file
_MAX_FILE_SIZE  = 20 * 1024 * 1024  # 20 MB — skip anything larger
_COOLDOWN_SECS  = 2.0      # minimum seconds between re-scans of the same file

# ── Exclusion rules ───────────────────────────────────────────────────────────

_EXCLUDED_DIR_NAMES = frozenset({
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".tox", "dist", "build", ".mypy_cache", ".pytest_cache",
})

_EXCLUDED_PREFIXES = ("~$",)  # Office temp lock files

_EXCLUDED_EXTENSIONS = frozenset({
    ".tmp", ".crdownload", ".part", ".temp",
    ".swp", ".lock", ".ldb",
})


def _risk_to_severity(risk_score: float) -> str:
    if risk_score >= 0.9:
        return "CRITICAL"
    if risk_score >= 0.7:
        return "HIGH"
    return "MEDIUM"


# ── Handler ───────────────────────────────────────────────────────────────────

class _DLPHandler(FileSystemEventHandler):
    """
    Single handler instance shared across all watched directories.
    Thread-safe: watchdog may dispatch events from multiple emitter threads.
    """

    def __init__(self, client: DLPApiClient, agent_id: str, state: AgentState | None = None):
        super().__init__()
        self.client   = client
        self.agent_id = agent_id
        self.state    = state
        self._cooldown: dict[str, float] = {}
        self._lock = threading.Lock()   # guards cooldown dict across emitter threads

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _within_cooldown(self, path: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if now - self._cooldown.get(path, 0.0) < _COOLDOWN_SECS:
                return True
            self._cooldown[path] = now
        return False

    @staticmethod
    def _is_excluded(file_path: str) -> bool:
        path = Path(file_path)

        # Skip excluded directory names anywhere in the path
        for part in path.parts:
            if part in _EXCLUDED_DIR_NAMES:
                return True

        name = path.name
        # Office temp lock files
        if name.startswith(_EXCLUDED_PREFIXES):
            return True

        # Incomplete download / temp extensions
        if path.suffix.lower() in _EXCLUDED_EXTENSIONS:
            return True

        # Size guard
        try:
            size = path.stat().st_size
            if size > _MAX_FILE_SIZE:
                logger.debug(
                    f"[FILE-WATCHER] Skipped (too large: "
                    f"{size // (1024 * 1024)} MB): {name}"
                )
                return True
            if size == 0:
                return True
        except OSError:
            return True

        return False

    # ── Core scan logic ───────────────────────────────────────────────────────

    def _process(self, file_path: str) -> None:
        if not os.path.isfile(file_path):
            return
        if self._is_excluded(file_path):
            return
        if self._within_cooldown(file_path):
            return

        filename = os.path.basename(file_path)
        ext      = Path(file_path).suffix.lower()
        logger.info(f"[FILE-WATCHER] Scanning: {filename}  (ext={ext or 'none'})")

        if self.state:
            self.state.increment_file_access()

        # Extract text using format-aware extractor
        text = extract(file_path)
        if not text:
            logger.debug(f"[FILE-WATCHER] No extractable text: {filename}")
            return

        result = self.client.classify(text=text[:_CLASSIFY_LIMIT])
        if result is None:
            logger.warning(f"[FILE-WATCHER] Classifier unavailable — skipping {filename}")
            return

        risk_score: float = result.get("risk_score", 0.0)
        detections: list  = result.get("detections", [])

        if risk_score > 0.5:
            severity = _risk_to_severity(risk_score)
            types    = [d["type"] for d in detections]
            logger.warning(
                f"[FILE-WATCHER] SENSITIVE: {filename} | "
                f"risk={risk_score:.2f} | severity={severity} | types={types}"
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
                logger.success(
                    f"[FILE-WATCHER] Incident created: "
                    f"id={incident.get('id')} [{severity}]"
                )
            else:
                logger.error(f"[FILE-WATCHER] Failed to report incident for {filename}")
        else:
            logger.debug(f"[FILE-WATCHER] Clean: {filename}  (risk={risk_score:.2f})")

    # ── watchdog callbacks ────────────────────────────────────────────────────

    def on_created(self, event):
        if not event.is_directory:
            self._process(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process(event.src_path)


# ── Public entry point ────────────────────────────────────────────────────────

def start_watcher(
    watch_dirs: list[str],
    client: DLPApiClient,
    agent_id: str,
    state: AgentState | None = None,
) -> Observer:
    """
    Schedule all *watch_dirs* on a single Observer with a shared handler.
    One Observer thread pool handles events from all directories.
    """
    handler  = _DLPHandler(client, agent_id, state)
    observer = Observer()

    for d in watch_dirs:
        observer.schedule(handler, d, recursive=True)
        logger.info(f"[FILE-WATCHER] Scheduled: {d}")

    observer.start()
    logger.info(f"[FILE-WATCHER] Watching {len(watch_dirs)} folder(s)")
    return observer
