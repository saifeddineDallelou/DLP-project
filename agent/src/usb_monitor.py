"""
USB monitor -- the removable-drive channel.

WHY THIS EXISTS
USB has been a Channel in the schema and a BehaviorEventType (USB_INSERT)
since the first migration, the Reports page offered it as a filter, and UEBA
weighted it at 20% of a user's risk score. Nothing implemented it. Plug in a
stick, copy the entire customer database onto it, and the agent noticed
nothing -- while a single paste of one card number into a browser was stopped
dead. It was the largest gap in the product, and the easiest exfiltration
route in the building.

It was also two dead signals, not one. `avgUsbFrequency` is computed from
USB_INSERT events that never arrived, so the `usb` component of every risk
score was permanently zero -- and because it carries 20% of the weight, real
findings sat at MEDIUM (0.64) where they belonged at HIGH (0.80). A metric
nothing feeds does not read as absent; it reads as "nothing to worry about".

WHAT IT CAN AND CANNOT DO
Windows will not let a user-mode process veto a file write. Stopping the copy
mid-flight needs a filesystem filter driver -- signed, installed with
administrator rights, and an entirely different kind of software from this.
What a user-mode agent CAN do is see the file land and remove it immediately,
which is what happens here: watchdog reports the write, the content is
classified, and a sensitive file is moved off the volume within roughly a
second of appearing.

That is a genuinely weaker guarantee than the clipboard block, and this module
does not pretend otherwise. There is a window -- small, but real -- in which
the file exists on the stick, and a user who pulls the drive out inside that
window keeps the data. The incident says REMOVED, never "blocked", because
those are different claims and the record should make the one the evidence
supports. See the limitations section of the project documentation.

WHY THE FILE IS MOVED, NOT DELETED
The enforcement goal is that the copy does not leave on the stick. Deleting it
achieves that; so does moving it into the local quarantine folder, and the
move cannot destroy the only copy of something. The original the user copied
FROM is untouched either way -- this module never writes to, moves, or deletes
anything on a fixed disk.

SAFETY
Everything here is gated on the drive type being DRIVE_REMOVABLE, checked
twice: once when the volume appears, and again immediately before any file is
moved. A path that does not resolve to a currently-removable volume is left
alone. The blast radius of a bug in the drive-type check is the difference
between acting on a memory stick and acting on somebody's C: drive, so it is
not checked once and remembered.
"""

from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from loguru import logger
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from api_client import DLPApiClient
from file_extractor import extract
from policy_resolver import PolicyResolver, DEFAULT_POLICY_ID
from quarantine import quarantine_file
from repeat_window import RepeatWindow, fingerprint
from review_prompt import offer_review

# GetDriveType return values. Only the first is acted on -- a network share or
# a fixed disk is somebody else's channel.
DRIVE_REMOVABLE = 2

# How often the drive table is re-read. A stick takes a second or two to
# mount anyway, and this loop costs one bitmask read.
_POLL_INTERVAL = 2.0

# Matches file_watcher's caps, so "sensitive" means the same thing whether a
# file is found in a watched folder or on a stick.
_CLASSIFY_LIMIT = 10_000
_MAX_FILE_SIZE = 20 * 1024 * 1024
_RISK_THRESHOLD = 0.5

# A copy in progress is reported by watchdog the moment the file is created,
# which is typically before any of its bytes are there. Reading it then means
# classifying an empty file and concluding it is clean -- the worst possible
# answer. Wait for the size to stop changing first.
_SETTLE_INTERVAL = 0.4
_SETTLE_TIMEOUT = 20.0

# A big copy onto removable media is a behavioural signal in its own right,
# whatever the content turns out to be: a 4 GB archive has no extractable text
# and would otherwise pass without a trace.
_LARGE_FILE_THRESHOLD_BYTES = int(os.getenv("LARGE_FILE_THRESHOLD_MB", "100")) * 1024 * 1024

# Re-copying the same file is one event with a count, not a new row each time
# -- the same rule every other channel follows. Module-level because a real
# agent runs for days and has to remember what it already reported.
_REPEATS = RepeatWindow()

_EXCLUDED_PREFIXES = ("~$", ".")
_EXCLUDED_EXTENSIONS = frozenset({
    ".tmp", ".crdownload", ".part", ".temp", ".swp", ".lock", ".ldb",
})
# Windows and the drive's own housekeeping write these; they are not the user
# copying anything.
_EXCLUDED_DIR_NAMES = frozenset({
    "System Volume Information", "$RECYCLE.BIN", ".Trashes", ".Spotlight-V100",
})


def _get_os_user() -> str:
    return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown-user"


# ── Windows drive enumeration ────────────────────────────────────────────────
#
# Every signature is declared explicitly. ctypes defaults an undeclared
# return type to c_int, which silently truncates anything wider -- the same
# defaulting cost the drop interceptor a working mouse hook and an afternoon,
# and a truncated drive bitmask here would simply stop reporting the high
# letters with no error at all.

def _kernel32():
    k = ctypes.windll.kernel32
    k.GetLogicalDrives.restype = ctypes.c_uint32
    k.GetLogicalDrives.argtypes = []
    k.GetDriveTypeW.restype = ctypes.c_uint32
    k.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    k.GetVolumeInformationW.restype = ctypes.c_int
    k.GetVolumeInformationW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p, ctypes.c_uint32,
    ]
    k.GetDiskFreeSpaceExW.restype = ctypes.c_int
    k.GetDiskFreeSpaceExW.argtypes = [
        ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64),
    ]
    return k


def drive_type(root: str) -> int:
    """The Windows drive type for a volume root such as 'E:\\'."""
    try:
        return int(_kernel32().GetDriveTypeW(root))
    except Exception:
        return 0


def is_removable(root: str) -> bool:
    return drive_type(root) == DRIVE_REMOVABLE


def removable_drives() -> set[str]:
    """Every removable volume currently mounted, as roots ('E:\\')."""
    try:
        mask = int(_kernel32().GetLogicalDrives())
    except Exception:
        return set()

    found: set[str] = set()
    for i in range(26):
        if not mask & (1 << i):
            continue
        root = f"{chr(ord('A') + i)}:\\"
        if is_removable(root):
            found.add(root)
    return found


def volume_info(root: str) -> dict:
    """Label and capacity for a volume, for the UEBA event's metadata.

    Best effort: a stick with no label, or one yanked between the drive
    appearing and this call, reports what it can rather than failing the
    insert event that matters more.
    """
    info = {"drive": root, "volumeLabel": "", "sizeMB": 0}
    try:
        k = _kernel32()
        name = ctypes.create_unicode_buffer(261)
        fs = ctypes.create_unicode_buffer(261)
        if k.GetVolumeInformationW(root, name, 261, None, None, None, fs, 261):
            info["volumeLabel"] = name.value
        total = ctypes.c_uint64(0)
        if k.GetDiskFreeSpaceExW(root, None, ctypes.byref(total), None):
            info["sizeMB"] = int(total.value / (1024 * 1024))
    except Exception as exc:
        logger.debug(f"[USB] Could not read volume info for {root}: {exc}")
    return info


def drive_of(path: str) -> str:
    """The volume root a path sits on ('E:\\file.csv' -> 'E:\\')."""
    drive = os.path.splitdrive(os.path.abspath(path))[0]
    return f"{drive}\\" if drive else ""


# ── File assessment ──────────────────────────────────────────────────────────

def _is_excluded(path: str) -> bool:
    p = Path(path)
    for part in p.parts:
        if part in _EXCLUDED_DIR_NAMES:
            return True
    if p.name.startswith(_EXCLUDED_PREFIXES):
        return True
    return p.suffix.lower() in _EXCLUDED_EXTENSIONS


def wait_until_settled(path: str, timeout: float = _SETTLE_TIMEOUT) -> int | None:
    """Block until the file stops growing, and return its final size.

    watchdog announces a file the instant it is created, which during a copy
    is before its contents exist. Classifying it then reads zero bytes and
    calls the file clean -- a sensitive file waved through because it was
    looked at too early. Returns None if the file vanished or never settled.
    """
    deadline = time.monotonic() + timeout
    last = -1
    while time.monotonic() < deadline:
        try:
            size = os.path.getsize(path)
        except OSError:
            return None
        if size == last and size > 0:
            return size
        last = size
        time.sleep(_SETTLE_INTERVAL)
    return last if last > 0 else None


def safe_to_remove(path: str) -> bool:
    """Is this path something this module is allowed to move?

    The second of the two drive-type checks. The first happened when the
    volume appeared, possibly minutes ago; drive letters are reused, and a
    stick that was E: can be gone with a mapped network share or a mounted
    image in its place by the time a queued file is processed. Nothing here
    may touch a path that is not, right now, on a removable volume.
    """
    if sys.platform != "win32":
        return False
    root = drive_of(path)
    if not root or not is_removable(root):
        logger.error(
            f"[USB] REFUSING to act on '{path}' -- {root or 'no drive'} is not "
            f"a removable volume (type={drive_type(root) if root else 'n/a'})"
        )
        return False
    return os.path.isfile(path)


class UsbFileScanner:
    """Decides what happens to one file that appeared on a removable volume.

    Kept separate from the watchdog handler so the decision can be tested
    without a filesystem event, and so the two drive-type checks bracket
    exactly the code that acts.
    """

    def __init__(
        self,
        client: DLPApiClient,
        agent_id: str,
        policy_resolver: PolicyResolver | None = None,
        state=None,
    ) -> None:
        self.client = client
        self.agent_id = agent_id
        self.policy_resolver = policy_resolver
        self.state = state
        self._lock = threading.Lock()
        self._seen: dict[str, float] = {}

    def _recently_scanned(self, path: str) -> bool:
        """A single copy fires created + several modified events."""
        now = time.monotonic()
        with self._lock:
            if now - self._seen.get(path, 0.0) < 2.0:
                return True
            self._seen[path] = now
        return False

    def scan(self, path: str) -> str:
        """Assess one file. Returns a short outcome tag, for tests and logs."""
        if _is_excluded(path):
            return "excluded"
        if self._recently_scanned(path):
            return "debounced"

        size = wait_until_settled(path)
        if not size:
            return "vanished"

        drive = drive_of(path)
        name = os.path.basename(path)

        self._report_large_transfer(path, name, size)

        if size > _MAX_FILE_SIZE:
            # Too big to extract text from, but the transfer itself was just
            # reported above, so it is not invisible -- only unclassified.
            logger.info(f"[USB] '{name}' too large to classify ({size // (1024 * 1024)} MB)")
            return "too-large"

        text = extract(path)
        if not text:
            logger.debug(f"[USB] No extractable text: {name}")
            return "no-text"

        result = self.client.classify(text=text[:_CLASSIFY_LIMIT])
        if result is None:
            # Same choice every other channel makes: an unreachable classifier
            # is not evidence of anything, and quarantining a user's files on
            # a guess is worse than the gap.
            logger.warning(f"[USB] Classifier unavailable -- '{name}' not checked")
            return "classifier-down"

        risk = result.get("risk_score", 0.0)
        detections = result.get("detections", [])
        if risk <= _RISK_THRESHOLD:
            logger.info(f"[USB] '{name}' clean (risk={risk:.2f})")
            return "clean"

        return self._act(path, name, drive, risk, detections)

    def _report_large_transfer(self, path: str, name: str, size: int) -> None:
        """A large copy onto removable media, whatever it contains.

        Feeds the volume side of the UEBA baseline, which a 4 GB archive with
        no extractable text would otherwise never reach.
        """
        if size <= _LARGE_FILE_THRESHOLD_BYTES:
            return
        size_mb = round(size / (1024 * 1024), 1)
        logger.warning(f"[USB] Large transfer to removable media: {name} ({size_mb} MB)")
        self.client.post_ueba_event(
            agent_id=self.agent_id,
            user_id=_get_os_user(),
            event_type="LARGE_FILE_TRANSFER",
            metadata={
                "filename": name,
                "sizeMB": size_mb,
                "hour": datetime.now().hour,
                "destination": drive_of(path),
                "removable": True,
            },
        )

    def _act(self, path: str, name: str, drive: str, risk: float,
             detections: list) -> str:
        """Enforce the policy for a file that classified sensitive."""
        policy = (
            self.policy_resolver.resolve(detections, channel="USB", risk_score=risk)
            if self.policy_resolver
            else {"id": DEFAULT_POLICY_ID, "action": "BLOCK", "name": None}
        )
        action = policy.get("action") or "BLOCK"

        if action == "NONE":
            # Below every rung of the policy's ladder: not covered at this
            # confidence. Distinct from ALLOW, which is a decision to permit
            # and is recorded.
            logger.debug(f"[USB] '{name}' risk={risk:.2f} below every tier -- not covered")
            return "not-covered"

        logger.critical(
            f"[USB] !! Sensitive file on removable media | file={name} | drive={drive} | "
            f"risk={risk:.2f} | types={[d.get('type') for d in detections]}"
        )

        removed_to = None
        if action in ("BLOCK", "QUARANTINE"):
            if safe_to_remove(path):
                removed_to = quarantine_file(path)
                if removed_to:
                    logger.success(f"[USB] '{name}' removed from {drive}")
                else:
                    logger.error(f"[USB] Could not remove '{name}' from {drive}")
            else:
                logger.error(f"[USB] '{name}' left in place -- not a removable volume")
        elif action == "ALLOW":
            logger.debug(f"[USB] Policy '{policy.get('name')}' allows '{name}'")
        else:
            logger.warning(f"[USB] Policy set to ALERT -- recording '{name}' without removing it")

        self._record(path, name, drive, risk, detections, policy, removed_to)
        return "removed" if removed_to else action.lower()

    def _record(self, path, name, drive, risk, detections, policy, removed_to) -> None:
        """File the incident, counting a repeat rather than adding a row."""
        from file_watcher import severity_for

        print_ = fingerprint(f"USB:{name}", detections)
        scope = f"USB:{drive}"

        repeat_of = _REPEATS.repeat_of(scope, print_)
        if repeat_of:
            counted = self.client.repeat_incident(repeat_of)
            if counted:
                logger.info(
                    f"[USB] Repeat copy counted  id={repeat_of}  "
                    f"attempts={counted.get('attempts')}"
                )
            else:
                logger.error(f"[USB] Could not count repeat onto {repeat_of}")
            return

        # REMOVED, not "blocked". The write itself could not be prevented --
        # see the module docstring -- and an incident that claims a block on
        # this evidence makes the stronger claim than the facts support.
        state = "removed" if removed_to else f"left in place ({policy.get('action')})"

        # What was actually DONE, which is not always what the policy said to
        # do. actionTaken is the Action enum, so a stop that could not be
        # carried out is recorded as ALERT -- seen and written down, not
        # stopped -- rather than leaving a BLOCK claim that the evidence
        # field contradicts two columns away. The drag-drop channel drew the
        # same line between INTERCEPTED and CANCELLED for the same reason.
        taken = policy.get("action")
        if taken in ("BLOCK", "QUARANTINE") and not removed_to:
            taken = "ALERT"

        incident = self.client.create_incident(
            agent_id=self.agent_id,
            policy_id=policy.get("id"),
            severity=severity_for(policy, risk),
            channel="USB",
            evidence=f"{name} [copied to removable {drive} -- {state}]"[:255],
            risk_score=risk,
            action_taken=taken,
        )
        if not incident:
            logger.error("[USB] Failed to record removable-media incident")
            return

        logger.success(f"[USB] Incident REPORTED  id={incident.get('id')}")
        _REPEATS.opened(scope, incident.get("id"))

        if removed_to and incident.get("id"):
            # The file is gone from the stick. Without a word from us that is
            # indistinguishable from the copy having failed, or from the drive
            # being faulty.
            offer_review(
                self.client, "incident", incident["id"],
                f"'{name}' was removed from {drive}: it contains sensitive data.",
                "USB",
            )


class _UsbEventHandler(FileSystemEventHandler):
    """Bridges watchdog events onto the scanner, one thread per file.

    Off the emitter thread deliberately: wait_until_settled can sit for
    seconds on a slow copy, and watchdog dispatches from a single thread per
    observer -- blocking it would leave every other file written in that time
    unseen.
    """

    def __init__(self, scanner: UsbFileScanner) -> None:
        super().__init__()
        self.scanner = scanner

    def _spawn(self, path: str) -> None:
        threading.Thread(
            target=self._safe_scan, args=(path,), daemon=True, name="usb-scan",
        ).start()

    def _safe_scan(self, path: str) -> None:
        try:
            self.scanner.scan(path)
        except Exception as exc:
            # A raising handler thread would die silently and take that one
            # file's coverage with it. Everything else keeps working.
            logger.error(f"[USB] Scan of '{path}' failed: {exc}")

    def on_created(self, event) -> None:
        if not event.is_directory:
            self._spawn(event.src_path)

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self._spawn(event.src_path)

    def on_moved(self, event) -> None:
        # A file dragged onto the stick and then renamed there is still a file
        # that arrived on the stick.
        dest = getattr(event, "dest_path", None)
        if dest and not event.is_directory:
            self._spawn(dest)


def _usb_loop(
    client: DLPApiClient,
    agent_id: str,
    stop: threading.Event,
    policy_resolver: PolicyResolver | None,
    state,
) -> None:
    scanner = UsbFileScanner(client, agent_id, policy_resolver, state)
    user_id = _get_os_user()
    watched: dict[str, Observer] = {}
    known = removable_drives()

    if known:
        # Drives already present at startup are watched but NOT reported as
        # inserts: the agent restarting is not the user plugging anything in,
        # and a fabricated insert would be a fabricated UEBA signal.
        for root in known:
            _watch(root, scanner, watched)
        logger.info(f"[USB] Already mounted at startup: {sorted(known)}")

    while not stop.is_set():
        stop.wait(_POLL_INTERVAL)
        if stop.is_set():
            break

        try:
            current = removable_drives()
        except Exception as exc:
            logger.error(f"[USB] Could not enumerate drives: {exc}")
            continue

        for root in sorted(current - known):
            info = volume_info(root)
            logger.warning(
                f"[USB] Removable drive inserted: {root} "
                f"'{info['volumeLabel']}' ({info['sizeMB']} MB)"
            )
            result = client.post_ueba_event(
                agent_id=agent_id,
                user_id=user_id,
                event_type="USB_INSERT",
                metadata={**info, "hour": datetime.now().hour},
            )
            if result:
                logger.success(f"[USB] USB_INSERT event posted for {root}")
            else:
                logger.error(f"[USB] Failed to post USB_INSERT event for {root}")
            _watch(root, scanner, watched)

        for root in sorted(known - current):
            logger.info(f"[USB] Removable drive removed: {root}")
            _unwatch(root, watched)
            # The window belonged to a volume that is gone. Keeping it would
            # let the next stick in that letter inherit a repeat count from a
            # different drive entirely.
            _REPEATS.forget(f"USB:{root}")

        known = current

    for root in list(watched):
        _unwatch(root, watched)


def _watch(root: str, scanner: UsbFileScanner, watched: dict) -> None:
    if root in watched:
        return
    try:
        observer = Observer()
        observer.schedule(_UsbEventHandler(scanner), root, recursive=True)
        observer.start()
        watched[root] = observer
        logger.info(f"[USB] Watching {root} for files copied to it")
    except Exception as exc:
        # A drive that cannot be watched is still worth having reported as
        # inserted -- the UEBA signal does not depend on the file watch.
        logger.error(f"[USB] Could not watch {root}: {exc}")


def _unwatch(root: str, watched: dict) -> None:
    observer = watched.pop(root, None)
    if not observer:
        return
    try:
        observer.stop()
        observer.join(timeout=2)
    except Exception as exc:
        logger.debug(f"[USB] Error stopping watch on {root}: {exc}")


def start_usb_monitor(
    client: DLPApiClient,
    agent_id: str,
    stop: threading.Event,
    policy_resolver: PolicyResolver | None = None,
    state=None,
) -> threading.Thread:
    if sys.platform != "win32":
        logger.warning("[USB] Non-Windows platform -- USB monitor disabled")
        return threading.Thread(target=lambda: None, daemon=True)

    t = threading.Thread(
        target=_usb_loop,
        args=(client, agent_id, stop, policy_resolver, state),
        daemon=True,
        name="usb-monitor",
    )
    t.start()
    logger.info(f"USB monitor started  (removable drives polled every {_POLL_INTERVAL}s)")
    return t
