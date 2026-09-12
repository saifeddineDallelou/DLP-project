"""
Print monitor -- the PRINT channel.

WHY THIS EXISTS
PRINT was a Channel in the schema and an icon on the Reports page, and nothing
implemented it. Printing is the oldest exfiltration route there is and the one
no network control can see: a card list that cannot be pasted, dragged,
uploaded or copied to a stick could still be sent to the printer by the door.

PAUSE FIRST, THEN DECIDE
The drag-and-drop channel taught this lesson expensively. Polling for a job
and then cancelling it is a race, and a race against a fast printer is one the
agent loses silently -- the pages are out, and the incident claims a block
that did not happen.

Windows offers a way not to race. A spooled job can be PAUSED, and a paused
job prints nothing until somebody resumes it. So the instant a job appears it
is paused -- before anything is classified, before the document is even read
-- and only then is the decision made. Clean work is resumed and prints
normally; sensitive work is deleted while still paused. The user sees a brief
hesitation in the print queue instead of a leak.

Every path resumes. A classifier that is down, a document that cannot be read,
an exception anywhere in the decision: the job is released. A DLP agent that
leaves the office printer queue frozen because a microservice restarted would
be removed from every machine in the building by lunchtime, and rightly.

WHAT IT CAN SEE
Not the rendered page. A spooled job is the printer driver's own format --
EMF, PostScript, a vendor blob -- and reading it means shipping a print
processor, which is a driver-level component and a different kind of software
from this agent.

What a job does carry is its document name, and often a real path: Notepad and
most viewers submit the file they printed. So there are two tiers, strongest
first -- if the document name resolves to a file on disk, that file's CONTENT
is extracted and classified exactly as every other channel classifies content;
otherwise the name itself is judged by the shared title heuristic, at the
lower confidence a name deserves. The second tier is a heuristic and is
recorded as one.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import re
import sys
import threading

from loguru import logger

from api_client import DLPApiClient
from file_extractor import extract
from policy_resolver import PolicyResolver, DEFAULT_POLICY_ID
from repeat_window import RepeatWindow, fingerprint
from review_prompt import offer_review
from title_heuristic import TITLE_CONFIDENCE, matched_keyword, synthetic_detection

# EnumPrinters flags: printers attached here, plus network printers this user
# has connected. A job sent to either leaves the building just as well.
PRINTER_ENUM_LOCAL = 0x00000002
PRINTER_ENUM_CONNECTIONS = 0x00000004

# SetJob commands.
JOB_CONTROL_PAUSE = 1
JOB_CONTROL_RESUME = 2
JOB_CONTROL_DELETE = 5

# Fast, because a job must be paused before the spooler hands it to the
# device. This is one spooler call per printer and costs nothing measurable.
_POLL_INTERVAL = 0.5

_CLASSIFY_LIMIT = 10_000
_MAX_FILE_SIZE = 20 * 1024 * 1024
_RISK_THRESHOLD = 0.5

_REPEATS = RepeatWindow()

# "Microsoft Word - contract.docx", "cards.csv - Notepad", "Print job 3 of
# report.pdf". The document name is what the printing application chose to
# call it, and every application chooses differently.
_APP_SUFFIXES = re.compile(
    r"\s+-\s+(Microsoft\s+\w+|Notepad|WordPad|Excel|Word|PowerPoint|"
    r"Adobe\s+\w+|Google\s+Chrome|Microsoft\s+Edge|Opera|Firefox)\s*$",
    re.IGNORECASE,
)
_APP_PREFIXES = re.compile(r"^(Microsoft\s+\w+|Adobe\s+\w+)\s+-\s+", re.IGNORECASE)


class SYSTEMTIME(ctypes.Structure):
    # ctypes.wintypes does not define this one, and the field only exists here
    # to keep the struct the size the spooler expects: get the layout wrong and
    # every field AFTER it is read from the wrong offset.
    _fields_ = [(name, wt.WORD) for name in (
        "wYear", "wMonth", "wDayOfWeek", "wDay",
        "wHour", "wMinute", "wSecond", "wMilliseconds",
    )]


class JOB_INFO_1W(ctypes.Structure):
    _fields_ = [
        ("JobId", wt.DWORD),
        ("pPrinterName", wt.LPWSTR),
        ("pMachineName", wt.LPWSTR),
        ("pUserName", wt.LPWSTR),
        ("pDocument", wt.LPWSTR),
        ("pDatatype", wt.LPWSTR),
        ("pStatus", wt.LPWSTR),
        ("Status", wt.DWORD),
        ("Priority", wt.DWORD),
        ("Position", wt.DWORD),
        ("TotalPages", wt.DWORD),
        ("PagesPrinted", wt.DWORD),
        ("Submitted", SYSTEMTIME),
    ]


class PRINTER_INFO_1W(ctypes.Structure):
    _fields_ = [
        ("Flags", wt.DWORD),
        ("pDescription", wt.LPWSTR),
        ("pName", wt.LPWSTR),
        ("pComment", wt.LPWSTR),
    ]


def _winspool():
    """The spooler API, with every signature declared.

    ctypes defaults an undeclared return type to c_int. A printer HANDLE is
    64-bit on a 64-bit process, so an undeclared OpenPrinterW would hand back
    a truncated handle that fails every subsequent call with an error naming
    something that is plainly there -- which is exactly how the drop
    interceptor's first live run was lost.
    """
    w = ctypes.WinDLL("winspool.drv")
    w.OpenPrinterW.restype = wt.BOOL
    w.OpenPrinterW.argtypes = [wt.LPWSTR, ctypes.POINTER(wt.HANDLE), ctypes.c_void_p]
    w.ClosePrinter.restype = wt.BOOL
    w.ClosePrinter.argtypes = [wt.HANDLE]
    w.EnumJobsW.restype = wt.BOOL
    w.EnumJobsW.argtypes = [
        wt.HANDLE, wt.DWORD, wt.DWORD, wt.DWORD, wt.LPBYTE,
        wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD),
    ]
    w.EnumPrintersW.restype = wt.BOOL
    w.EnumPrintersW.argtypes = [
        wt.DWORD, wt.LPWSTR, wt.DWORD, wt.LPBYTE,
        wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD),
    ]
    w.SetJobW.restype = wt.BOOL
    w.SetJobW.argtypes = [wt.HANDLE, wt.DWORD, wt.DWORD, wt.LPBYTE, wt.DWORD]
    return w


def list_printers() -> list[str]:
    """Every printer this user can send a job to."""
    try:
        w = _winspool()
        flags = PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS
        needed = wt.DWORD(0)
        returned = wt.DWORD(0)
        w.EnumPrintersW(flags, None, 1, None, 0, ctypes.byref(needed), ctypes.byref(returned))
        if not needed.value:
            return []
        buf = ctypes.create_string_buffer(needed.value)
        if not w.EnumPrintersW(flags, None, 1, ctypes.cast(buf, wt.LPBYTE),
                               needed.value, ctypes.byref(needed), ctypes.byref(returned)):
            return []
        infos = ctypes.cast(buf, ctypes.POINTER(PRINTER_INFO_1W))
        return [infos[i].pName for i in range(returned.value) if infos[i].pName]
    except Exception as exc:
        logger.debug(f"[PRINT] Could not enumerate printers: {exc}")
        return []


def list_jobs(printer: str) -> list[dict]:
    """Queued jobs on one printer, as plain dicts.

    Plain dicts rather than the ctypes structures on purpose: the buffer they
    point into is freed the moment this returns, and a struct that outlives
    its buffer reads whatever is in that memory next.
    """
    handle = wt.HANDLE()
    try:
        w = _winspool()
        if not w.OpenPrinterW(printer, ctypes.byref(handle), None):
            return []
    except Exception as exc:
        logger.debug(f"[PRINT] Could not open '{printer}': {exc}")
        return []

    try:
        needed = wt.DWORD(0)
        returned = wt.DWORD(0)
        w.EnumJobsW(handle, 0, 256, 1, None, 0, ctypes.byref(needed), ctypes.byref(returned))
        if not needed.value:
            return []
        buf = ctypes.create_string_buffer(needed.value)
        if not w.EnumJobsW(handle, 0, 256, 1, ctypes.cast(buf, wt.LPBYTE),
                           needed.value, ctypes.byref(needed), ctypes.byref(returned)):
            return []
        jobs = ctypes.cast(buf, ctypes.POINTER(JOB_INFO_1W))
        return [
            {
                "printer": printer,
                "jobId": int(jobs[i].JobId),
                "document": jobs[i].pDocument or "",
                "user": jobs[i].pUserName or "",
                "pages": int(jobs[i].TotalPages),
            }
            for i in range(returned.value)
        ]
    except Exception as exc:
        logger.debug(f"[PRINT] Could not enumerate jobs on '{printer}': {exc}")
        return []
    finally:
        try:
            _winspool().ClosePrinter(handle)
        except Exception:
            pass


def _control(printer: str, job_id: int, command: int) -> bool:
    handle = wt.HANDLE()
    try:
        w = _winspool()
        if not w.OpenPrinterW(printer, ctypes.byref(handle), None):
            return False
        try:
            return bool(w.SetJobW(handle, job_id, 0, None, command))
        finally:
            w.ClosePrinter(handle)
    except Exception as exc:
        logger.debug(f"[PRINT] Job control {command} failed on {printer}#{job_id}: {exc}")
        return False


def pause_job(printer: str, job_id: int) -> bool:
    return _control(printer, job_id, JOB_CONTROL_PAUSE)


def resume_job(printer: str, job_id: int) -> bool:
    return _control(printer, job_id, JOB_CONTROL_RESUME)


def delete_job(printer: str, job_id: int) -> bool:
    return _control(printer, job_id, JOB_CONTROL_DELETE)


def document_path(document: str) -> str | None:
    """The real file this job printed, if the document name names one.

    Notepad and most viewers submit a full path; Office submits a decorated
    title. Only an existing file is returned, so a title that merely looks
    path-shaped is never read as one.
    """
    if not document:
        return None
    candidate = document.strip().strip('"')
    try:
        if os.path.isfile(candidate):
            return candidate
    except (OSError, ValueError):
        return None
    return None


def clean_title(document: str) -> str:
    """The document name with the printing application's decoration removed."""
    title = _APP_SUFFIXES.sub("", document or "").strip()
    title = _APP_PREFIXES.sub("", title).strip()
    return title or (document or "")


class PrintJobGuard:
    """Decides what happens to one spooled job, while it is paused."""

    def __init__(
        self,
        client: DLPApiClient,
        agent_id: str,
        policy_resolver: PolicyResolver | None = None,
    ) -> None:
        self.client = client
        self.agent_id = agent_id
        self.policy_resolver = policy_resolver

    def assess(self, job: dict) -> tuple[float, list, str]:
        """What this job contains: (risk, detections, how we know).

        Two tiers, strongest first. Content beats a name every time, so a file
        that resolves on disk is read rather than guessed at -- a boringly
        named file full of card numbers is exactly what a name-only check
        misses.
        """
        document = job.get("document") or ""
        path = document_path(document)

        if path:
            try:
                if os.path.getsize(path) <= _MAX_FILE_SIZE:
                    text = extract(path)
                    if text:
                        result = self.client.classify(text=text[:_CLASSIFY_LIMIT])
                        if result is not None:
                            return (result.get("risk_score", 0.0),
                                    result.get("detections", []),
                                    "content")
                        # Classifier down. Fall through to the name: a weaker
                        # answer is better than no answer, and the job is
                        # released either way if the name is unremarkable.
                        logger.warning(f"[PRINT] Classifier unavailable for '{path}'")
            except OSError as exc:
                logger.debug(f"[PRINT] Could not read '{path}': {exc}")

        keyword = matched_keyword(clean_title(document))
        if keyword:
            return TITLE_CONFIDENCE, [synthetic_detection(keyword)], "title"
        return 0.0, [], "title"

    def decide(self, job: dict) -> str:
        """Assess a paused job and act. Returns a short outcome tag.

        The caller has already paused it and will resume it unless this
        returns "deleted" -- which is the only outcome where the pages must
        not come out.
        """
        risk, detections, basis = self.assess(job)
        document = job.get("document") or ""

        if risk <= _RISK_THRESHOLD:
            logger.debug(f"[PRINT] '{document[:70]}' clean (risk={risk:.2f}, by {basis})")
            return "clean"

        policy = (
            self.policy_resolver.resolve(detections, channel="PRINT", risk_score=risk)
            if self.policy_resolver
            else {"id": DEFAULT_POLICY_ID, "action": "BLOCK", "name": None}
        )
        action = policy.get("action") or "BLOCK"

        if action == "NONE":
            # Below every rung of the policy's ladder: not covered at this
            # confidence, and nothing to record.
            return "not-covered"

        logger.critical(
            f"[PRINT] !! Sensitive print job | document={document[:70]} | "
            f"printer={job.get('printer')} | risk={risk:.2f} | by={basis}"
        )

        deleted = False
        if action in ("BLOCK", "QUARANTINE"):
            deleted = delete_job(job.get("printer", ""), job.get("jobId", 0))
            if deleted:
                logger.success(f"[PRINT] Job {job.get('jobId')} cancelled -- nothing printed")
            else:
                logger.error(f"[PRINT] Could not cancel job {job.get('jobId')}")
        elif action == "ALLOW":
            logger.debug(f"[PRINT] Policy '{policy.get('name')}' allows this job")
        else:
            logger.warning("[PRINT] Policy set to ALERT -- recording without cancelling")

        self._record(job, risk, detections, policy, basis, deleted)
        return "deleted" if deleted else action.lower()

    def _record(self, job, risk, detections, policy, basis, deleted) -> None:
        from file_watcher import severity_for

        document = job.get("document") or ""
        printer = job.get("printer") or ""
        scope = f"PRINT:{printer}"
        print_ = fingerprint(f"PRINT:{clean_title(document)}", detections)

        repeat_of = _REPEATS.repeat_of(scope, print_)
        if repeat_of:
            counted = self.client.repeat_incident(repeat_of)
            if counted:
                logger.info(
                    f"[PRINT] Repeat print attempt counted  id={repeat_of}  "
                    f"attempts={counted.get('attempts')}"
                )
            else:
                logger.error(f"[PRINT] Could not count repeat onto {repeat_of}")
            return

        # The basis is on the record because the two tiers are not equally
        # strong, and an analyst reading the queue has to be able to tell a
        # matched card number from a suggestive filename.
        state = "cancelled" if deleted else f"allowed to print ({policy.get('action')})"

        # What was actually DONE, which is not always what the policy said to
        # do. actionTaken is the Action enum, so a stop that could not be
        # carried out is recorded as ALERT -- seen and written down, not
        # stopped -- rather than leaving a BLOCK claim that the evidence
        # field contradicts two columns away. The drag-drop channel drew the
        # same line between INTERCEPTED and CANCELLED for the same reason.
        taken = policy.get("action")
        if taken in ("BLOCK", "QUARANTINE") and not deleted:
            taken = "ALERT"

        incident = self.client.create_incident(
            agent_id=self.agent_id,
            policy_id=policy.get("id"),
            severity=severity_for(policy, risk),
            channel="PRINT",
            evidence=f"{clean_title(document)} [printed to {printer} -- {state}; "
                     f"detected by {basis}]"[:255],
            risk_score=risk,
            action_taken=taken,
        )
        if not incident:
            logger.error("[PRINT] Failed to record print incident")
            return

        logger.success(f"[PRINT] Incident REPORTED  id={incident.get('id')}")
        _REPEATS.opened(scope, incident.get("id"))

        if deleted and incident.get("id"):
            # The job vanished from the queue. Without a word from us that is
            # indistinguishable from the printer being broken.
            offer_review(
                self.client, "incident", incident["id"],
                f"A print job of '{clean_title(document)[:60]}' was cancelled: "
                f"it contains sensitive data.",
                "PRINT",
            )


def handle_new_job(guard: PrintJobGuard, job: dict) -> str:
    """Pause, decide, and always release -- unless the job was deleted.

    The pause is what turns this from a race into a decision. Everything after
    it is wrapped so that no failure can leave a job frozen in the queue: a
    printer nobody can print to is a worse outcome than the leak this is
    trying to stop, and it is the kind of failure that gets an agent
    uninstalled rather than fixed.
    """
    printer = job.get("printer", "")
    job_id = job.get("jobId", 0)

    paused = pause_job(printer, job_id)
    if not paused:
        # Nothing to release, and no guarantee of winning the race -- but a
        # job that cannot be paused can still be cancelled and recorded.
        logger.warning(
            f"[PRINT] Could not pause job {job_id} on '{printer}' -- "
            f"racing it instead"
        )

    try:
        outcome = guard.decide(job)
    except Exception as exc:
        logger.error(f"[PRINT] Decision failed for job {job_id}: {exc}")
        outcome = "error"

    if outcome != "deleted" and paused:
        if not resume_job(printer, job_id):
            logger.error(
                f"[PRINT] Could not resume job {job_id} on '{printer}' -- "
                f"it may need releasing by hand"
            )
    return outcome


def _print_loop(
    client: DLPApiClient,
    agent_id: str,
    stop: threading.Event,
    policy_resolver: PolicyResolver | None,
) -> None:
    guard = PrintJobGuard(client, agent_id, policy_resolver)
    seen: set[tuple[str, int]] = set()
    printers = list_printers()
    logger.info(f"[PRINT] Watching {len(printers)} printer(s): {printers}")

    # Jobs already queued when the agent starts are adopted as seen, not
    # judged: they were submitted before anything was watching, and pausing a
    # stranger's half-printed job to classify it is not this agent's business.
    for printer in printers:
        for job in list_jobs(printer):
            seen.add((printer, job["jobId"]))

    ticks = 0
    while not stop.is_set():
        ticks += 1
        # Re-read the printer list occasionally: one gets added, or a network
        # printer connects, and a printer nobody is watching is a channel
        # nobody is watching.
        if ticks % 60 == 0:
            printers = list_printers() or printers

        current: set[tuple[str, int]] = set()
        for printer in printers:
            for job in list_jobs(printer):
                key = (printer, job["jobId"])
                current.add(key)
                if key in seen:
                    continue
                seen.add(key)
                logger.info(
                    f"[PRINT] New job {job['jobId']} on '{printer}': "
                    f"'{job['document'][:70]}'"
                )
                handle_new_job(guard, job)

        # Job ids are recycled by the spooler, so a finished job has to be
        # forgotten or its id coming round again is silently ignored.
        seen &= current
        stop.wait(_POLL_INTERVAL)


def start_print_monitor(
    client: DLPApiClient,
    agent_id: str,
    stop: threading.Event,
    policy_resolver: PolicyResolver | None = None,
) -> threading.Thread:
    if sys.platform != "win32":
        logger.warning("[PRINT] Non-Windows platform -- print monitor disabled")
        return threading.Thread(target=lambda: None, daemon=True)

    t = threading.Thread(
        target=_print_loop,
        args=(client, agent_id, stop, policy_resolver),
        daemon=True,
        name="print-monitor",
    )
    t.start()
    logger.info(f"Print monitor started  (spooler polled every {_POLL_INTERVAL}s, jobs paused while judged)")
    return t
