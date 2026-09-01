"""
Real file quarantine -- gives the QUARANTINE policy action behavior actually
distinct from BLOCK.

BLOCK stops an in-flight transmission (clear the clipboard, cancel a file
dialog) but leaves the source file exactly where it was -- the user can
immediately try again. QUARANTINE additionally moves the sensitive file
itself out of reach, into a locked-down local folder, so a repeat attempt
with the same file isn't possible.

Only meaningful where a real file path exists (file_watcher.py,
clipboard_watcher.py's file-copy path, file_dialog_monitor.py) -- clipboard
TEXT and a screenshot's clipboard IMAGE have no backing file to move, so
QUARANTINE has nothing extra to do there and behaves like BLOCK, same as
before.
"""

import os
import shutil
import time
from pathlib import Path
from loguru import logger

_QUARANTINE_DIR = Path(
    os.environ.get("LOCALAPPDATA") or str(Path.home())
) / "DLP-Agent" / "quarantine"


def quarantine_file(path: str) -> str | None:
    """
    Move a sensitive file into the local quarantine folder, prefixed with a
    timestamp to avoid collisions with a same-named file quarantined earlier.

    Returns the new quarantined path on success, or None if the move failed
    (already gone, permissions, in use by another process) -- callers should
    treat that as "quarantine unavailable this time", not raise, since the
    BLOCK-equivalent action (clipboard clear / dialog cancel) already
    happened independently and shouldn't be undone by a failed extra step.
    """
    try:
        src = Path(path)
        if not src.is_file():
            logger.warning(f"[QUARANTINE] '{path}' no longer exists -- nothing to move")
            return None

        _QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        # Nanosecond precision -- int(time.time()) alone can collide when two
        # same-named files (from different source folders) get quarantined
        # within the same second.
        dest = _QUARANTINE_DIR / f"{time.time_ns()}_{src.name}"
        shutil.move(str(src), str(dest))
        logger.warning(f"[QUARANTINE] Moved '{src.name}' -> '{dest}'")
        return str(dest)
    except Exception as exc:
        logger.error(f"[QUARANTINE] Failed to quarantine '{path}': {exc}")
        return None
