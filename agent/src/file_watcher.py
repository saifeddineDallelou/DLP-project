import os
import time
import threading
import psutil
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from loguru import logger

from api_client       import DLPApiClient
from agent_state      import AgentState
from file_extractor   import extract
from policy_resolver  import PolicyResolver, DEFAULT_POLICY_ID
from quarantine       import quarantine_file

POLICY_ID      = DEFAULT_POLICY_ID  # fallback when no PolicyResolver is supplied
_CLASSIFY_LIMIT = 10_000   # max chars sent to classifier per file
_MAX_FILE_SIZE  = 20 * 1024 * 1024  # 20 MB — skip anything larger for CONTENT classification
_COOLDOWN_SECS  = 2.0      # minimum seconds between re-scans of the same file

# A large file transfer is its own behavioral signal, independent of content
# classification -- a 500 MB video/zip has no extractable text and would
# otherwise never be scrutinized at all (the _MAX_FILE_SIZE guard above
# exists to skip expensive text extraction, not to hide large transfers from
# UEBA). Checked BEFORE that guard so it isn't silently excluded by it.
_LARGE_FILE_THRESHOLD_BYTES = int(os.getenv("LARGE_FILE_THRESHOLD_MB", "100")) * 1024 * 1024


def _get_os_user() -> str:
    return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown-user"


def _find_restricted_app_holding_file(app_rule_resolver, file_path: str) -> tuple[str, int] | None:
    """
    Return (label, pid) if a restricted-app process (see app_rule_resolver.py)
    currently has `file_path` open, else None.

    This is a REAL causal relationship -- not a coincidence of window focus
    like the clipboard-timing check in clipboard_watcher.py -- proc.open_files()
    queries the process's actual open file handles (same mechanism Task
    Manager's "handles" view uses), no kernel driver or elevation required
    for same-user processes.

    Only iterates processes whose name already matches the restricted-apps
    list (typically a handful), not every running process, and each one's
    open_files() call is skipped on the first permission/lookup error rather
    than retried, to keep this cheap enough to run on every sensitive-file
    detection.
    """
    if not app_rule_resolver:
        return None
    target = os.path.normcase(os.path.abspath(file_path))

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = proc.info.get("name") or ""
            label = app_rule_resolver.match(name)
            if not label:
                continue
            for f in proc.open_files():
                if os.path.normcase(os.path.abspath(f.path)) == target:
                    return label, proc.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return None

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


# An ALLOW is a decision that this content is permitted. Rendering it
# CRITICAL puts "we let this through on purpose" and "this is an emergency"
# in the same row, which is a contradiction an analyst has to resolve by
# guessing. Permitted matches are recorded for audit, not for alarm.
_ALLOWED_SEVERITY = "LOW"


def _risk_to_severity(risk_score: float) -> str:
    """Severity implied by the content alone, when a policy has not set one."""
    if risk_score >= 0.9:
        return "CRITICAL"
    if risk_score >= 0.7:
        return "HIGH"
    return "MEDIUM"


def severity_for(policy: dict | None, risk_score: float) -> str:
    """How severe this incident is, in the order that respects who decided.

    1. An ALLOW is capped: whatever the data scores, permitting it is not an
       emergency.
    2. The POLICY's severity, when the admin set one. This field existed on
       Policy, was editable in the dashboard, displayed on the Policies page
       -- and read by nothing. An admin setting a policy to HIGH changed
       nothing at all.
    3. Otherwise derive it from the risk score, which is what every monitor
       did unconditionally before.

    The risk score stays on the incident either way, so the evidence behind
    the number is never lost -- what changes is who gets to decide what it
    means. Purview works the same way: severity is the admin's judgement of
    the rule, not a restatement of the detector's confidence.
    """
    if policy and str(policy.get("action") or "").upper() == "ALLOW":
        return _ALLOWED_SEVERITY
    configured = policy.get("severity") if policy else None
    if configured:
        return str(configured).upper()
    return _risk_to_severity(risk_score)


# ── Handler ───────────────────────────────────────────────────────────────────

class _DLPHandler(FileSystemEventHandler):
    """
    Single handler instance shared across all watched directories.
    Thread-safe: watchdog may dispatch events from multiple emitter threads.
    """

    def __init__(
        self,
        client: DLPApiClient,
        agent_id: str,
        state: AgentState | None = None,
        policy_resolver: PolicyResolver | None = None,
        app_rule_resolver=None,
    ):
        super().__init__()
        self.client            = client
        self.agent_id          = agent_id
        self.state             = state
        self.policy_resolver   = policy_resolver
        self.app_rule_resolver = app_rule_resolver
        self._cooldown: dict[str, float] = {}
        # Separate from _cooldown -- large-file checks run on EVERY file
        # (not just ones that pass _is_excluded), so sharing _cooldown would
        # let a normal small file's large-file check consume the timer slot
        # the content-classification cooldown below also needs.
        self._large_file_cooldown: dict[str, float] = {}
        self._lock = threading.Lock()   # guards cooldown dicts across emitter threads

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _within_cooldown(self, path: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if now - self._cooldown.get(path, 0.0) < _COOLDOWN_SECS:
                return True
            self._cooldown[path] = now
        return False

    def _within_large_file_cooldown(self, path: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if now - self._large_file_cooldown.get(path, 0.0) < _COOLDOWN_SECS:
                return True
            self._large_file_cooldown[path] = now
        return False

    def _check_large_file(self, file_path: str) -> None:
        """Report a large file transfer as its own UEBA signal, independent
        of content classification -- see _LARGE_FILE_THRESHOLD_BYTES."""
        if self._is_excluded_by_name(file_path):
            return
        try:
            size = os.path.getsize(file_path)
        except OSError:
            return
        if size <= _LARGE_FILE_THRESHOLD_BYTES:
            return
        if self._within_large_file_cooldown(file_path):
            return

        filename = os.path.basename(file_path)
        size_mb = round(size / (1024 * 1024), 1)
        logger.warning(f"[FILE-WATCHER] Large file transfer: {filename} ({size_mb} MB)")
        result = self.client.post_ueba_event(
            agent_id=self.agent_id,
            user_id=_get_os_user(),
            event_type="LARGE_FILE_TRANSFER",
            metadata={"filename": filename, "sizeMB": size_mb, "hour": datetime.now().hour},
        )
        if not result:
            logger.warning("[FILE-WATCHER] Failed to report large file transfer event")

    @staticmethod
    def _is_excluded_by_name(file_path: str) -> bool:
        """Directory/filename-based exclusions only (no size check) -- shared
        by _is_excluded (content-classification path) and _check_large_file
        (which deliberately does NOT apply the size-based exclusion below,
        since that exists to skip expensive text extraction, not to hide
        large transfers from UEBA)."""
        path = Path(file_path)

        for part in path.parts:
            if part in _EXCLUDED_DIR_NAMES:
                return True

        name = path.name
        if name.startswith(_EXCLUDED_PREFIXES):
            return True

        if path.suffix.lower() in _EXCLUDED_EXTENSIONS:
            return True

        return False

    @staticmethod
    def _is_excluded(file_path: str) -> bool:
        path = Path(file_path)

        if _DLPHandler._is_excluded_by_name(file_path):
            return True

        # Size guard
        try:
            size = path.stat().st_size
            if size > _MAX_FILE_SIZE:
                logger.debug(
                    f"[FILE-WATCHER] Skipped (too large: "
                    f"{size // (1024 * 1024)} MB): {path.name}"
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

        # Independent of the exclusion/cooldown checks below -- see
        # _check_large_file's docstring for why it must not be skipped by
        # the size-based exclusion that's about to run.
        self._check_large_file(file_path)

        if self._is_excluded(file_path):
            return
        if self._within_cooldown(file_path):
            return

        filename = os.path.basename(file_path)
        ext      = Path(file_path).suffix.lower()
        logger.info(f"[FILE-WATCHER] Scanning: {filename}  (ext={ext or 'none'})")

        if self.state:
            try:
                size_bytes = os.path.getsize(file_path)
            except OSError:
                size_bytes = 0
            self.state.increment_file_access(size_bytes)

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
            types    = [d["type"] for d in detections]
            # Resolve the policy FIRST: severity now depends on it, both for
            # the admin's configured value and for the ALLOW cap.
            policy   = self.policy_resolver.resolve(detections, channel="FILE", risk_score=risk_score) if self.policy_resolver else {"id": POLICY_ID, "action": "BLOCK"}
            severity = severity_for(policy, risk_score)

            if policy["action"] == "NONE":
                # Below every rung of the policy's risk ladder. Distinct from
                # ALLOW, which is a decision to permit and is recorded --
                # NONE means this confidence is not covered at all.
                logger.debug(
                    f"[FILE-WATCHER] {filename} risk={risk_score:.2f} is below every "
                    f"tier of '{policy.get('name') or policy['id']}' -- not covered"
                )
                return

            if policy["action"] == "ALLOW":
                # Recorded, not silent.
                #
                # ALLOW used to return here without a trace, which made a
                # sanctioned exception indistinguishable from a hole: there
                # was no way to answer "how often did we let sensitive data
                # through on purpose". An exception nobody can count is not an
                # exception, it is an unmonitored gap -- and it is exactly the
                # setting an attacker or a careless admin would widen.
                #
                # Filed as an incident with actionTaken=ALLOW and status
                # ALLOWED, so it is auditable without sitting in the triage
                # queue alongside things that need a human.
                logger.info(
                    f"[FILE-WATCHER] ALLOWED: {filename} | risk={risk_score:.2f} | "
                    f"types={types} | policy='{policy.get('name') or policy['id']}' "
                    f"-- sanctioned, recorded for audit"
                )
                self.client.create_incident(
                    agent_id=self.agent_id,
                    policy_id=policy["id"],
                    severity=severity,
                    channel="FILE",
                    evidence=filename,
                    risk_score=risk_score,
                    action_taken="ALLOW",
                )
                return

            logger.warning(
                f"[FILE-WATCHER] SENSITIVE: {filename} | "
                f"risk={risk_score:.2f} | severity={severity} | types={types} | "
                f"policy={policy['id']} | action={policy['action']}"
            )

            evidence = filename

            # Record this file so app_file_monitor.py's periodic poll can
            # keep checking restricted-app processes' open files against it
            # for a while after this instant -- not every process that will
            # eventually open this file has it open RIGHT NOW.
            if self.state:
                self.state.mark_sensitive_file(file_path, policy, risk_score)

            # A REAL app<->file relationship (the process actually has this
            # file open -- see _find_restricted_app_holding_file), not just
            # "this app happened to be focused when something unrelated
            # changed on the clipboard" the way clipboard_watcher.py's check
            # works. Only meaningful here because file_watcher already knows
            # a real, on-disk, sensitive file -- there's nothing to hold a
            # handle to on the clipboard/dialog paths.
            held_by = _find_restricted_app_holding_file(self.app_rule_resolver, file_path)
            if held_by:
                label, pid = held_by
                evidence += f" [open in {label}, PID {pid}]"
                logger.warning(
                    f"[FILE-WATCHER] {filename} is currently open in restricted app "
                    f"'{label}' (PID {pid})"
                )

            if policy["action"] == "QUARANTINE":
                # Unlike clipboard/dialog/screenshot, a file sitting at rest
                # in a watched folder has no "in-flight transmission" to
                # block -- QUARANTINE's distinct action here is removing the
                # file itself so it can't be picked up again.
                quarantined_path = quarantine_file(file_path)
                if quarantined_path:
                    evidence += f" [QUARANTINED -> {quarantined_path}]"

            incident = self.client.create_incident(
                agent_id=self.agent_id,
                policy_id=policy["id"],
                severity=severity,
                channel="FILE",
                evidence=evidence,
                risk_score=risk_score,
                # ALERT and QUARANTINE produce the same row otherwise, and an
                # analyst cannot tell whether the file was moved or left where
                # it was.
                action_taken=policy["action"],
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

    def on_moved(self, event):
        # Most editors (Notepad, VS Code, Word...) save an existing file by
        # writing a temp file and renaming it over the original, which arrives
        # here as a move rather than a "modified" event. Scan the destination.
        if not event.is_directory:
            self._process(event.dest_path)


# ── Public entry point ────────────────────────────────────────────────────────

def start_watcher(
    watch_dirs: list[str],
    client: DLPApiClient,
    agent_id: str,
    state: AgentState | None = None,
    policy_resolver: PolicyResolver | None = None,
    app_rule_resolver=None,
) -> Observer:
    """
    Schedule all *watch_dirs* on a single Observer with a shared handler.
    One Observer thread pool handles events from all directories.
    """
    handler  = _DLPHandler(client, agent_id, state, policy_resolver, app_rule_resolver)
    observer = Observer()

    for d in watch_dirs:
        observer.schedule(handler, d, recursive=True)
        logger.info(f"[FILE-WATCHER] Scheduled: {d}")

    observer.start()
    logger.info(f"[FILE-WATCHER] Watching {len(watch_dirs)} folder(s)")
    return observer
