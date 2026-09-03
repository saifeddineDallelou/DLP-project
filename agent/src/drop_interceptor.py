"""
Stopping a drop instead of racing it.

THE PROBLEM WITH POLLING
The drag monitor watched for "cursor over an AI window" on a timer and sent
ESC when it saw one. A practised drop lands between two samples: the file is
delivered, and the cancel arrives after the fact -- which is worse than doing
nothing, because the popup then claims a block that did not happen.

Making the timer faster narrowed the window and could never close it. A drop
is a single instant; any interval has an inside.

WHAT THIS DOES INSTEAD
A low-level mouse hook is called by Windows for every mouse event BEFORE the
event is delivered to any application, and a hook that returns non-zero
swallows it. So when the button is released over an AI window with a
sensitive drag in flight, the release never reaches the browser -- there is no
drop to be too late for -- and ESC then cancels the drag the source is still
running.

WHY THIS IS SAFE TO DO SYSTEM-WIDE
A global mouse hook that misbehaves breaks clicking everywhere, so the
callback is written to do almost nothing:

  * It returns immediately unless ARMED, which only the drag monitor does,
    only while a classified-sensitive drag is actually in progress.
  * Armed, it does two cheap USER32 calls and a set lookup.
  * Any exception at all falls through to CallNextHookEx. There is no path
    where a bug here can swallow an ordinary click.

Windows also silently removes a hook that takes too long (see
LowLevelHooksTimeout), which is a second reason the callback holds no locks
and does no I/O.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import threading

from loguru import logger

_WH_MOUSE_LL = 14
_WM_LBUTTONUP = 0x0202
_HC_ACTION = 0

_VK_ESCAPE = 0x1B
_KEYEVENTF_KEYUP = 0x0002

try:
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
except Exception:                                    # pragma: no cover
    _user32 = None
    _kernel32 = None


class _POINT(ctypes.Structure):
    _fields_ = [("x", wt.LONG), ("y", wt.LONG)]


class _MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("pt", _POINT),
        ("mouseData", wt.DWORD),
        ("flags", wt.DWORD),
        ("time", wt.DWORD),
        ("dwExtraInfo", ctypes.POINTER(wt.ULONG)),
    ]


_HOOKPROC = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_int, wt.WPARAM, ctypes.POINTER(_MSLLHOOKSTRUCT)
)

# Declared explicitly, because ctypes defaults every return type to c_int.
#
# On 64-bit Windows that silently truncates every HANDLE these functions
# return: GetModuleHandleW came back as the low 32 bits of a real module
# handle, SetWindowsHookExW rejected it, and the hook failed to install with
# error 126 (ERROR_MOD_NOT_FOUND) -- a "module not found" for a module that
# was found, then cut in half.
if _user32 is not None:
    _kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
    _kernel32.GetModuleHandleW.restype = wt.HMODULE

    _user32.SetWindowsHookExW.argtypes = [ctypes.c_int, _HOOKPROC, wt.HMODULE, wt.DWORD]
    _user32.SetWindowsHookExW.restype = wt.HHOOK

    _user32.CallNextHookEx.argtypes = [
        wt.HHOOK, ctypes.c_int, wt.WPARAM, ctypes.POINTER(_MSLLHOOKSTRUCT)
    ]
    _user32.CallNextHookEx.restype = ctypes.c_long

    _user32.UnhookWindowsHookEx.argtypes = [wt.HHOOK]
    _user32.UnhookWindowsHookEx.restype = wt.BOOL

    # Takes POINT by value, and returns a handle that must not be truncated.
    _user32.WindowFromPoint.argtypes = [_POINT]
    _user32.WindowFromPoint.restype = wt.HWND

    _user32.GetAncestor.argtypes = [wt.HWND, wt.UINT]
    _user32.GetAncestor.restype = wt.HWND

# ── Armed state ─────────────────────────────────────────────────────────────
#
# Plain module-level values, read without a lock. The callback runs on the
# hook thread for every mouse event in the system and must not block on
# anything: a torn read here costs one drop's interception, while holding a
# lock could cost the machine its mouse.
_armed = False
_targets: frozenset[int] = frozenset()

# Set when a release was actually swallowed, so the drag monitor can report a
# block it knows happened rather than one it assumes did.
_intercepted = threading.Event()

_hook_handle = None
_thread: threading.Thread | None = None


def arm(target_hwnds) -> None:
    """A sensitive drag is in flight; these windows must not receive it."""
    global _armed, _targets
    _targets = frozenset(int(h) for h in target_hwnds if h)
    _armed = bool(_targets)


def disarm() -> None:
    """The drag is over, one way or another."""
    global _armed, _targets
    _armed = False
    _targets = frozenset()


def take_interception() -> bool:
    """Did the hook swallow a release since this was last asked?"""
    if _intercepted.is_set():
        _intercepted.clear()
        return True
    return False


def _root_of(hwnd) -> int:
    # GA_ROOT: a drop lands on a child control, and what we know are
    # top-level windows.
    #
    # Normalised to int: HWND comes back from ctypes as a pointer object,
    # and a pointer is never equal to the integer handle in _targets.
    root = _user32.GetAncestor(hwnd, 2) or hwnd
    return int(root) if root else 0


def _callback(code, wparam, lparam):
    try:
        if code != _HC_ACTION or not _armed or wparam != _WM_LBUTTONUP:
            return _user32.CallNextHookEx(None, code, wparam, lparam)

        pt = lparam[0].pt
        target = _root_of(_user32.WindowFromPoint(pt))
        if target not in _targets:
            return _user32.CallNextHookEx(None, code, wparam, lparam)

        # Swallow the release. The browser never learns the button came up,
        # so no drop is delivered; the source is still in its drag loop, and
        # ESC ends it cleanly.
        _intercepted.set()
        _user32.keybd_event(_VK_ESCAPE, 0, 0, 0)
        _user32.keybd_event(_VK_ESCAPE, 0, _KEYEVENTF_KEYUP, 0)
        return 1
    except Exception:
        # Never let a bug in here eat an ordinary click.
        try:
            return _user32.CallNextHookEx(None, code, wparam, lparam)
        except Exception:
            return 0


# Kept alive at module scope: if the ctypes trampoline is garbage collected
# while Windows still holds the pointer, the next mouse event calls freed
# memory.
_callback_ref = None


def start(stop: threading.Event) -> threading.Thread | None:
    """Install the hook on its own thread with a message pump.

    A low-level hook is dispatched to the installing thread's message queue,
    so that thread must pump messages or the hook silently stops firing and
    Windows eventually drops it.

    Returns None when the hook cannot be installed -- the drag monitor then
    keeps its polling behaviour, which is what it did before this existed.
    """
    global _thread, _callback_ref

    if _user32 is None:
        logger.warning("[DROP] No user32 -- drop interception unavailable")
        return None

    ready = threading.Event()

    def _run():
        global _hook_handle, _callback_ref
        _callback_ref = _HOOKPROC(_callback)
        _hook_handle = _user32.SetWindowsHookExW(
            _WH_MOUSE_LL, _callback_ref, _kernel32.GetModuleHandleW(None), 0
        )
        if not _hook_handle:
            logger.error(
                f"[DROP] Could not install the mouse hook "
                f"(error {ctypes.get_last_error()}) -- falling back to polling"
            )
            ready.set()
            return

        logger.info("[DROP] Drop interception active")
        ready.set()

        msg = wt.MSG()
        while not stop.is_set():
            # Timed, not blocking: GetMessageW would sit here forever and the
            # thread would never notice `stop`.
            if _user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
                _user32.TranslateMessage(ctypes.byref(msg))
                _user32.DispatchMessageW(ctypes.byref(msg))
            else:
                stop.wait(0.01)

        _user32.UnhookWindowsHookEx(_hook_handle)
        _hook_handle = None
        logger.info("[DROP] Drop interception stopped")

    _thread = threading.Thread(target=_run, daemon=True, name="drop-interceptor")
    _thread.start()
    ready.wait(timeout=3)
    return _thread if _hook_handle else None
