"""
Uploads that never touch a Windows dialog.

Opera draws its own recent-files panel inside the browser window: click
attach in ChatGPT and a list of recent downloads and clipboard items appears,
already inside the page. No Windows dialog is created, so file_dialog_monitor
has nothing to find -- a live test uploaded a sensitive CSV that way and it
went straight up, while the same file through Explorer was blocked.

The only place that upload is visible is inside the page, which is where the
extension already is. The content script sees the file the instant it is
chosen and can clear it before the page's own handler reads it; this module
answers the one question it cannot answer for itself -- is this sensitive?

It deliberately does the same things the other channels do on a block: an
incident with the filename, a repeat count instead of a pile of rows, and a
popup telling the user what happened. A block the user cannot see is
indistinguishable from the site being broken.
"""

from __future__ import annotations

import base64
import os
import tempfile

from loguru import logger

from api_client import DLPApiClient
from file_extractor import extract
from evidence import safe_sample
from repeat_window import RepeatWindow, fingerprint
from review_prompt import offer_review

# Same cap the other file paths use, so one file does not become a
# multi-megabyte classify round trip while a user waits on the page.
_MAX_CLASSIFY = 5_000

# A .xlsx or .pdf is a ZIP or a binary container: reading it as text in the
# browser yields mojibake, so the extension used to skip those formats
# entirely and every one of them uploaded unchecked. That is the format a
# customer database is actually IN. The bytes come over instead, and the
# agent's existing extractor -- the same one file_watcher uses -- reads them.
#
# Capped because the page is blocked waiting on this answer. A spreadsheet
# worth stealing is far below this; a 200 MB video is not worth the wait, and
# has nothing extractable in it anyway.
_MAX_BLOB_BYTES = 8 * 1024 * 1024

# Only formats the extractor actually understands. Writing an arbitrary upload
# to disk to see what happens is not something this should do.
_EXTRACTABLE_EXTS = frozenset({
    ".pdf", ".docx", ".xlsx", ".pptx",
})

# Below this the classifier's own callers treat content as not worth acting
# on, and matching them keeps one definition of "sensitive" across channels.
_RISK_THRESHOLD = 0.5

_REPEATS = RepeatWindow()


def extract_blob(name: str, blob_b64: str) -> str:
    """Read a binary container the browser could not read as text.

    The bytes are written to a temp file because every extractor in
    file_extractor works from a path -- python-docx, openpyxl and pypdf all
    want a file, and reimplementing them against a buffer to avoid one write
    would be a second copy of the hardest code here.

    The temp file is deleted on every path including failure. It holds the
    sensitive content this whole module exists to stop leaving, and leaving it
    in %TEMP% would mean the DLP agent is the thing that dropped a copy of the
    customer list somewhere world-readable.
    """
    ext = os.path.splitext(name)[1].lower()
    if ext not in _EXTRACTABLE_EXTS:
        return ""
    try:
        raw = base64.b64decode(blob_b64, validate=False)
    except Exception as exc:
        logger.warning(f"[UPLOAD] Could not decode '{name}': {exc}")
        return ""
    if not raw or len(raw) > _MAX_BLOB_BYTES:
        return ""

    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=ext, prefix="dlp-upload-")
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
        return extract(path) or ""
    except Exception as exc:
        logger.warning(f"[UPLOAD] Could not read '{name}': {exc}")
        return ""
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def make_upload_check(client: DLPApiClient, agent_id: str, policy_resolver=None):
    """Build the callback browser_sensor hands page uploads to.

    Returns (name, text, platform, blob_b64) -> bool, where True means "stop
    this".
    """

    def _check(name: str, text: str, platform: str, blob_b64: str = "") -> bool:
        if not text.strip() and blob_b64:
            # A container format. The browser cannot read it, the agent can.
            text = extract_blob(name, blob_b64)

        if not text.strip():
            # An image, or a format nothing here can read. Saying "block" on
            # no evidence would stop every avatar upload in the browser; this
            # path only ever claims what it can show.
            return False

        result = client.classify(text=text[:_MAX_CLASSIFY])
        if result is None:
            # Classifier down. The other channels let content through in this
            # case rather than blocking on an unknown, and a browser hung on a
            # dead service is worse than the gap it was covering.
            logger.warning(f"[UPLOAD] Classifier unavailable -- '{name}' not checked")
            return False

        risk = result.get("risk_score", 0.0)
        detections = result.get("detections", [])
        if risk <= _RISK_THRESHOLD:
            logger.info(f"[UPLOAD] '{name}' clean (risk={risk:.2f}) -- allowed to {platform}")
            return False

        logger.warning(
            f"[UPLOAD] !! BLOCKED in-page upload | file={name} | platform={platform} | "
            f"risk={risk:.2f} | types={[d.get('type') for d in detections]}"
        )

        _record(client, agent_id, policy_resolver, name, platform, risk, detections)
        return True

    return _check


def _record(client, agent_id, policy_resolver, name, platform, risk, detections) -> None:
    """File the incident, counting a repeat rather than adding a row."""
    sample = safe_sample(detections, prefix=f"UPLOAD:{name}")
    scope = platform or "BROWSER"
    print_ = fingerprint(sample, detections)

    repeat_of = _REPEATS.repeat_of(scope, print_)
    if repeat_of:
        counted = client.repeat_incident(repeat_of)
        if counted:
            logger.info(
                f"[UPLOAD] Repeat blocked upload counted  id={repeat_of}  "
                f"attempts={counted.get('attempts')}"
            )
        else:
            logger.error(f"[UPLOAD] Could not count repeat onto {repeat_of}")
        return

    policy = (policy_resolver.resolve(detections, channel="FILE_UPLOAD",
                                      risk_score=risk)
              if policy_resolver else {"id": None, "action": "BLOCK", "name": None})

    from file_watcher import severity_for
    incident = client.create_incident(
        agent_id=agent_id,
        policy_id=policy.get("id"),
        severity=severity_for(policy, risk),
        channel="FILE_UPLOAD",
        evidence=f"{name} [in-page upload to {platform}]"[:255],
        risk_score=risk,
        action_taken=policy.get("action"),
    )
    if not incident:
        logger.error("[UPLOAD] Failed to record blocked upload")
        return

    logger.success(f"[UPLOAD] Incident REPORTED  id={incident.get('id')}")
    _REPEATS.opened(scope, incident.get("id"))
    if incident.get("id"):
        offer_review(
            client, "incident", incident["id"],
            f"'{name}' was blocked from being uploaded to {platform}.",
            "UPLOAD",
        )
