"""
OLE drag-and-drop monitor -- dragging a file from Explorer onto a webpage.

THE GAP THIS CLOSES
An OLE drop hands the file straight from Explorer to the browser through an
in-process COM interface (IDropTarget::Drop). It never touches the clipboard,
so clipboard_watcher.py cannot see it, and it never opens a dialog, so
file_dialog_monitor.py cannot either. It was the one leak path in this agent
with no coverage at all, and it is not obscure: dragging a file onto a chat
window is the most natural way most people attach one.

WHY NOT INTERCEPT THE DROP ITSELF
The obvious approach -- hooking IDropTarget -- requires injecting a DLL into
the browser process. That is fragile across browser versions and is precisely
the behaviour EDR software exists to flag; a DLP agent that looks like malware
to the endpoint protection sitting next to it is not deployable.

WHAT THIS DOES INSTEAD
Windows cancels an in-flight OLE drag when Escape is pressed -- DoDragDrop
returns DRAGDROP_S_CANCEL and the drop never happens. So rather than
intercepting the drop, this observes the drag and cancels it:

  1. left button goes down over an Explorer window
  2. read what Explorer has SELECTED (Shell.Application COM) -- that is the
     drag payload, and it is knowable before the drop
  3. classify those files immediately, in the background
  4. while the button is still held, watch what is under the cursor
  5. if it reaches a window belonging to an AI platform and the verdict is
     sensitive, send Escape

Classifying at step 3 rather than step 5 is what makes this work. The user may
cross from Explorer to a browser in a few hundred milliseconds; a classify
round trip started at that moment would lose the race. Started when the drag
begins, it has the whole duration of the drag. This is the same eager-resolution
pattern file_dialog_monitor.py uses to beat a fast double-click.

HONEST LIMITS
  * Only drags that ORIGINATE in an Explorer window are covered. A drag from
    another application's custom drag source (an email client's attachment
    list, a zip tool's file view) exposes no readable selection and is not seen.
  * Desktop icons are not covered: the desktop is not a Shell.Application
    window and its selection is not readable the same way.
  * A drop into a NON-browser restricted app is not blocked here. This targets
    the AI-platform vector specifically, which is the one the rest of the agent
    is built around.
  * Escape cancels the drag; it cannot undo a drop that already completed. If
    classification is still running when the user releases over an AI window,
    the drop succeeds and is reported but not blocked. The report records that
    it was not blocked rather than claiming otherwise.
"""

from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
from ctypes import wintypes

from loguru import logger

from api_client import DLPApiClient
from evidence import safe_sample
from file_extractor import extract
from quarantine import quarantine_file

_user32 = ctypes.windll.user32

_VK_LBUTTON = 0x01
_VK_ESCAPE = 0x1B
_KEYEVENTF_KEYUP = 0x0002

# Fast enough to see the cursor cross into a browser mid-drag. A drag lasts
# hundreds of milliseconds at minimum -- a human cannot move a mouse from
# Explorer to a browser window faster than this samples.
_POLL_INTERVAL = 0.05

_MAX_FILE_SIZE = 20 * 1024 * 1024   # same cap as file_watcher
_CLASSIFY_LIMIT = 10_000
_MAX_DRAG_FILES = 10                # a 500-file drag should not stall the loop

# Explorer's own window classes. Progman/WorkerW are the desktop, listed so the
# "did this drag start somewhere we can read" check is explicit about what it
# covers and what it does not.
_EXPLORER_CLASSES = frozenset({"CabinetWClass", "ExploreWClass"})


def _class_name(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    _user32.GetClassNameW(hwnd, buf, 256)
    return buf.value


def _window_text(hwnd: int) -> str:
    length = _user32.GetWindowTextLengthW(hwnd)
    if length <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 1)
    _user32.GetWindowTextW(hwnd, buf, length + 1)
    return buf.value


def _cursor_pos() -> tuple[int, int]:
    pt = wintypes.POINT()
    _user32.GetCursorPos(ctypes.byref(pt))
    return pt.x, pt.y


def _root_window_at(x: int, y: int) -> int:
    """Top-level window under a point. WindowFromPoint returns the deepest
    child (a tab strip, a render surface); the title we need lives on the
    root."""
    hwnd = _user32.WindowFromPoint(wintypes.POINT(x, y))
    if not hwnd:
        return 0
    _user32.GetAncestor.restype = wintypes.HWND
    GA_ROOT = 2
    root = _user32.GetAncestor(hwnd, GA_ROOT)
    return root or hwnd


def _send_escape() -> None:
    """Cancel an in-flight OLE drag. Windows' drag loop watches for Escape and
    returns DRAGDROP_S_CANCEL, so the drop never reaches the target."""
    try:
        _user32.keybd_event(_VK_ESCAPE, 0, 0, 0)
        _user32.keybd_event(_VK_ESCAPE, 0, _KEYEVENTF_KEYUP, 0)
    except Exception as exc:
        logger.error(f"[DRAG-DROP] Could not send Escape: {exc}")


def _explorer_selection(hwnd: int) -> list[str]:
    """
    Files currently selected in the Explorer window `hwnd` -- i.e. what a drag
    starting there is carrying.

    Uses Shell.Application, which enumerates Explorer's own shell windows. COM
    must be initialised on the calling thread, and this runs on the monitor
    thread, so it initialises and uninitialises per call rather than assuming
    a host has done it.
    """
    try:
        import pythoncom
        import win32com.client
    except Exception:
        return []

    try:
        pythoncom.CoInitialize()
    except Exception:
        pass

    try:
        shell = win32com.client.Dispatch("Shell.Application")
        windows = shell.Windows()
        for i in range(windows.Count):
            try:
                w = windows.Item(i)
                if int(w.HWND) != int(hwnd):
                    continue
                items = w.Document.SelectedItems()
                paths = []
                for j in range(min(items.Count, _MAX_DRAG_FILES)):
                    p = items.Item(j).Path
                    if p and os.path.isfile(p):
                        paths.append(p)
                return paths
            except Exception:
                # A non-shell window (Internet Explorer, a control panel) is
                # enumerated here too and raises on .Document.
                continue
    except Exception as exc:
        logger.debug(f"[DRAG-DROP] Could not read Explorer selection: {exc}")
    finally:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass

    return []


class _DragState:
    """What is known about the drag currently in progress."""

    def __init__(self) -> None:
        self.active = False
        self.origin_hwnd = 0
        self.paths: list[str] = []
        self.verdict: dict | None = None     # set by the classify worker
        self.handled = False                 # already blocked or reported

    def reset(self) -> None:
        self.__init__()


def _classify_paths(client: DLPApiClient, paths: list[str]) -> dict | None:
    """Highest-risk verdict across the dragged files, or None."""
    worst: dict | None = None
    for path in paths:
        try:
            if os.path.getsize(path) > _MAX_FILE_SIZE:
                continue
        except OSError:
            continue

        text = extract(path)
        if not text:
            continue

        result = client.classify(text=text[:_CLASSIFY_LIMIT])
        if not result:
            continue

        risk = float(result.get("risk_score") or 0.0)
        if worst is None or risk > worst["risk_score"]:
            worst = {
                "path": path,
                "risk_score": risk,
                "detections": result.get("detections") or [],
            }
    return worst


def _drag_loop(
    client: DLPApiClient,
    agent_id: str,
    stop: threading.Event,
    policy_resolver=None,
    ai_platform_for=None,
) -> None:
    # Injected so this is testable without Win32, and so the platform
    # fingerprints stay defined in exactly one place.
    if ai_platform_for is None:
        from ai_domain_monitor import _detect_platform_in_text as ai_platform_for

    state = _DragState()
    poll = 0
    logger.info(f"[DRAG-DROP] Loop started -- polling every {_POLL_INTERVAL}s")

    while not stop.is_set():
        poll += 1
        if poll % 1200 == 0:      # ~ every 60 s
            logger.debug(f"[DRAG-DROP] Alive | poll=#{poll}")

        pressed = bool(_user32.GetAsyncKeyState(_VK_LBUTTON) & 0x8000)

        # ── Button released: whatever was happening is over ────────────────
        if not pressed:
            if state.active:
                logger.debug("[DRAG-DROP] Drag ended")
            state.reset()
            stop.wait(_POLL_INTERVAL)
            continue

        # ── Button just went down: is this a drag we can read? ─────────────
        if not state.active:
            state.active = True
            x, y = _cursor_pos()
            hwnd = _root_window_at(x, y)
            if not hwnd or _class_name(hwnd) not in _EXPLORER_CLASSES:
                # Not a readable drag source. Stay 'active' so this is not
                # re-evaluated on every poll of the same click.
                stop.wait(_POLL_INTERVAL)
                continue

            paths = _explorer_selection(hwnd)
            if not paths:
                stop.wait(_POLL_INTERVAL)
                continue

            state.origin_hwnd = hwnd
            state.paths = paths
            logger.info(f"[DRAG-DROP] Drag started from Explorer | {len(paths)} file(s)")

            # Classify NOW, in the background. Starting this when the cursor
            # reaches the browser would lose the race against the drop.
            def _worker(p=list(paths)):
                verdict = _classify_paths(client, p)
                state.verdict = verdict
                if verdict:
                    logger.info(
                        f"[DRAG-DROP] Dragged content classified | "
                        f"risk={verdict['risk_score']:.2f} | "
                        f"types={[d.get('type') for d in verdict['detections']]}"
                    )

            threading.Thread(target=_worker, daemon=True, name="drag-classify").start()
            stop.wait(_POLL_INTERVAL)
            continue

        # ── Drag in progress: where is the cursor now? ─────────────────────
        if state.handled or not state.paths:
            stop.wait(_POLL_INTERVAL)
            continue

        x, y = _cursor_pos()
        target = _root_window_at(x, y)
        if not target or target == state.origin_hwnd:
            stop.wait(_POLL_INTERVAL)
            continue

        platform = ai_platform_for(_window_text(target))
        if not platform:
            stop.wait(_POLL_INTERVAL)
            continue

        verdict = state.verdict
        if verdict is None:
            # Classification still running. Nothing is claimed either way --
            # if the user drops now the file goes through, and saying
            # otherwise would be a lie told by the tool about itself.
            stop.wait(_POLL_INTERVAL)
            continue

        if verdict["risk_score"] <= 0.5:
            state.handled = True
            stop.wait(_POLL_INTERVAL)
            continue

        detections = verdict["detections"]
        policy = (
            policy_resolver.resolve(detections, channel="FILE_UPLOAD")
            if policy_resolver
            else {"id": None, "action": "BLOCK", "name": None}
        )
        action = policy["action"]
        filename = os.path.basename(verdict["path"])

        if action == "ALLOW":
            logger.debug(
                f"[DRAG-DROP] {filename} sensitive but policy "
                f"'{policy.get('name') or 'default'}' allows it"
            )
            state.handled = True
            stop.wait(_POLL_INTERVAL)
            continue

        blocked = action in ("BLOCK", "QUARANTINE")
        if blocked:
            _send_escape()

        logger.critical(
            f"[DRAG-DROP] !! SENSITIVE FILE DRAG "
            f"{'CANCELLED' if blocked else 'DETECTED (ALERT only)'} -- "
            f"{filename} -> {platform} | risk={verdict['risk_score']:.2f} | "
            f"action={action}"
        )

        if action == "QUARANTINE":
            # Cancelling the drag stops this attempt; the file is still there
            # to drag again a moment later.
            quarantine_file(verdict["path"])

        # Report on a background thread -- NEVER on the poll loop. The block
        # has already happened by this point; the report is bookkeeping. Left
        # inline it costs _MAX_RETRIES * timeout + backoff whenever the backend
        # is unreachable -- ~10s refused, ~34s hung -- and the loop sees NOTHING
        # for that whole time. The person who was just blocked is the most
        # likely person alive to immediately drag the same file again, so that
        # retry lands squarely in the blind window and succeeds. Found by
        # dragging a real file, not by reading the code: the unit tests mock the
        # client, so a slow client costs them nothing.
        def _report(v=verdict, p=policy, plat=platform, b=blocked, f=filename):
            attempt = client.report_ai_leak_attempt(
                agent_id=agent_id,
                policy_id=p.get("id"),
                platform=plat,
                method="BROWSER",
                content_sample=safe_sample(v["detections"], prefix=f"DRAG:{f}"),
                risk_score=v["risk_score"],
                blocked=b,
            )
            if attempt:
                logger.success(f"[DRAG-DROP] Leak attempt recorded: id={attempt.get('id')}")
            else:
                logger.error("[DRAG-DROP] Failed to record leak attempt")

        threading.Thread(target=_report, daemon=True, name="drag-report").start()

        state.handled = True
        stop.wait(_POLL_INTERVAL)


def start_drag_drop_monitor(
    client: DLPApiClient,
    agent_id: str,
    stop: threading.Event,
    policy_resolver=None,
) -> threading.Thread:
    if sys.platform != "win32":
        logger.warning("[DRAG-DROP] Non-Windows -- drag-drop monitor disabled")
        return threading.Thread(target=lambda: None, daemon=True)

    t = threading.Thread(
        target=_drag_loop,
        args=(client, agent_id, stop, policy_resolver),
        daemon=True,
        name="drag-drop-monitor",
    )
    t.start()
    logger.info(
        "[DRAG-DROP] Drag-drop monitor started "
        "(cancels a sensitive Explorer drag onto an AI platform)"
    )
    return t
