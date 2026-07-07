"""
File-picker monitor — polls for native "Open File" dialogs (class #32770,
the Windows Common Item Dialog used whenever a browser's "Attach file"
button is clicked), reads the selected filename before the user can confirm
it, and classifies + cancels the dialog if the file is sensitive and a known
AI platform window is currently open.

This is a different leak vector from clipboard_watcher.py: picking a file
through a native dialog never touches the clipboard, so that watcher can't
see it. There is no simple global hook for "a file was chosen in a dialog"
the way there is for keyboard/clipboard, so this polls window state instead
(same approach ai_domain_monitor.py already uses for window titles).

AI-platform detection here reuses the system-wide window-title scan from
ai_domain_monitor.py rather than checking the dialog's *owner* window: for
Chromium-based browsers the file dialog is frequently owned by an internal,
untitled helper window rather than the visible tab window, so owner-title
checks silently miss every real browser dialog.
"""

import ctypes
import ctypes.wintypes as wt
import os
import re
import sys
import threading
from loguru import logger
from pywinauto import Desktop

from api_client import DLPApiClient
from ai_domain_monitor import _detect_platform_in_text, _enum_all_window_titles
from file_extractor import extract

# Matches a Windows absolute path (drive-letter or UNC) anywhere in a string --
# used to pull the current folder out of the dialog's address-bar accessible
# name (e.g. "Address: C:\Users\...\dlp-watch"), whatever the Windows display
# language calls the "Address:" label itself.
_PATH_RE = re.compile(r"[A-Za-z]:\\[^\r\n]*|\\\\[^\r\n]*")

_POLL_INTERVAL    = 0.4    # seconds between polls
_MAX_CLASSIFY     = 5_000  # max chars sent to classifier
_MAX_FILE_SIZE    = 20 * 1024 * 1024
_DIALOG_CLASS     = "#32770"  # standard Windows common-dialog class
_FILENAME_CTRL_ID = 0x47C     # "File name:" combo box in the modern IFileDialog

_WM_GETTEXTLENGTH = 0x000E
_WM_GETTEXT       = 0x000D
_WM_CLOSE         = 0x0010

_user32 = ctypes.windll.user32
# HWNDs are documented by Microsoft to fit in 32 bits even on 64-bit Windows
# (unlike the GlobalAlloc-backed HDROP handle in clipboard_watcher.py, which
# needed explicit 64-bit argtypes) -- these are set for correctness anyway.
_user32.GetDlgItem.restype  = wt.HWND
_user32.GetDlgItem.argtypes = [wt.HWND, ctypes.c_int]

_WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)

# ── Known-folder resolution ─────────────────────────────────────────────────
# Desktop, Downloads etc. are Windows "known folders" -- Explorer's address
# bar shows these by their localized display name ("Bureau" on a French
# install) instead of a literal path, so _PATH_RE alone can't find them. Build
# a {display name -> real path} map once via the Shell API so the lookup
# works regardless of Windows display language.

class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort), ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]

class _SHFILEINFO(ctypes.Structure):
    _fields_ = [
        ("hIcon", ctypes.c_void_p), ("iIcon", ctypes.c_int), ("dwAttributes", ctypes.c_ulong),
        ("szDisplayName", ctypes.c_wchar * 260), ("szTypeName", ctypes.c_wchar * 80),
    ]

_SHGFI_DISPLAYNAME = 0x000000200

_KNOWN_FOLDER_GUIDS = {
    "Desktop":   "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
    "Downloads": "{374DE290-123F-4565-9164-39C4925E467B}",
    "Documents": "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
    "Pictures":  "{33E28130-4E1E-4676-835A-98395C3BC3BB}",
    "Music":     "{4BD8D571-6D19-48D3-BE97-422220080E43}",
    "Videos":    "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}",
}


def _known_folder_path(guid_str: str) -> str | None:
    guid = _GUID()
    if ctypes.windll.ole32.CLSIDFromString(guid_str, ctypes.byref(guid)) != 0:
        return None
    ptr = ctypes.c_wchar_p()
    hr = ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(ptr))
    if hr != 0 or not ptr.value:
        return None
    path = ptr.value
    ctypes.windll.ole32.CoTaskMemFree(ptr)
    return path


def _display_name_for(path: str) -> str | None:
    info = _SHFILEINFO()
    ctypes.windll.shell32.SHGetFileInfoW(
        path, 0, ctypes.byref(info), ctypes.sizeof(info), _SHGFI_DISPLAYNAME,
    )
    return info.szDisplayName or None


def _build_known_folder_map() -> dict[str, str]:
    mapping: dict[str, str] = {}
    for guid in _KNOWN_FOLDER_GUIDS.values():
        path = _known_folder_path(guid)
        if not path:
            continue
        display = _display_name_for(path)
        if display:
            mapping[display.strip().lower()] = path
    return mapping


try:
    _KNOWN_FOLDER_MAP = _build_known_folder_map()
except Exception as exc:
    logger.warning(f"[FILE-DIALOG] Could not build known-folder map: {exc}")
    _KNOWN_FOLDER_MAP = {}


def _active_ai_platform() -> str | None:
    """Return a matched AI platform name if any currently visible window
    title mentions one, else None."""
    for title in _enum_all_window_titles():
        platform = _detect_platform_in_text(title)
        if platform:
            return platform
    return None


def _find_dialog_windows() -> list[int]:
    """Return HWNDs of visible top-level windows using the standard common
    dialog class -- what File Open/Save dialogs are built from."""
    hwnds: list[int] = []

    def _cb(hwnd, _lparam):
        try:
            if not _user32.IsWindowVisible(hwnd):
                return True
            buf = ctypes.create_unicode_buffer(64)
            _user32.GetClassNameW(hwnd, buf, 64)
            if buf.value == _DIALOG_CLASS:
                hwnds.append(hwnd)
        except Exception:
            pass
        return True

    try:
        _user32.EnumWindows(_WNDENUMPROC(_cb), 0)
    except Exception as exc:
        logger.debug(f"[FILE-DIALOG] EnumWindows error: {exc}")
    return hwnds


def _get_dialog_filename(hwnd_dialog: int) -> str:
    """Read the current text of the dialog's 'File name' field."""
    edit_hwnd = _user32.GetDlgItem(hwnd_dialog, _FILENAME_CTRL_ID)
    if not edit_hwnd:
        return ""
    length = _user32.SendMessageW(edit_hwnd, _WM_GETTEXTLENGTH, 0, 0)
    if length <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 1)
    _user32.SendMessageW(edit_hwnd, _WM_GETTEXT, length + 1, buf)
    return buf.value.strip().strip('"')


def _get_dialog_folder(hwnd_dialog: int) -> str | None:
    """Resolve the folder the dialog is currently browsing via UI Automation.

    The filename field only ever holds the bare selected name once a user
    single-clicks a file (verified empirically), never the full path -- and
    the classic CDM_GETFOLDERPATH/CDM_GETFILEPATH messages don't work against
    the modern IFileDialog browsers use (also verified empirically, they
    return nothing). The address toolbar's accessible name does contain the
    full path as plain text, e.g. "Address: C:\\Users\\...\\dlp-watch", so we
    pattern-match the path out of it instead of relying on the label text
    (which is Windows-display-language dependent).
    """
    try:
        win = Desktop(backend="uia").window(handle=hwnd_dialog)
        for toolbar in win.descendants(control_type="ToolBar"):
            name = toolbar.window_text()
            if ": " not in name:
                continue
            value = name.partition(": ")[2].strip()
            if not value:
                continue

            match = _PATH_RE.search(value)
            if match:
                return match.group(0).rstrip("\\")

            # Known/special folder shown by its localized display name
            # (e.g. "Bureau" for Desktop) instead of a literal path.
            resolved = _KNOWN_FOLDER_MAP.get(value.lower())
            if resolved:
                return resolved
    except Exception as exc:
        logger.debug(f"[FILE-DIALOG] Could not resolve current folder via UIA: {exc}")
    return None


def _close_dialog(hwnd_dialog: int) -> None:
    """Cancel the dialog so the flagged file can't actually be picked."""
    try:
        _user32.PostMessageW(hwnd_dialog, _WM_CLOSE, 0, 0)
    except Exception as exc:
        logger.error(f"[FILE-DIALOG] Failed to close dialog: {exc}")


def _candidate_paths(raw: str) -> list[str]:
    """The filename field holds one bare path, or several quoted paths when
    multiple files are selected: "a.txt" "b.pdf" """
    raw = raw.strip()
    if not raw:
        return []
    if '"' in raw:
        return [p for p in raw.split('"') if p.strip()]
    return [raw]


def _dialog_monitor_loop(
    client: DLPApiClient,
    agent_id: str,
    stop: threading.Event,
) -> None:
    # hwnd -> last filename text already classified, so we don't re-scan on
    # every poll while the user is still just browsing with nothing typed
    seen: dict[int, str] = {}
    poll_num = 0

    logger.info("[FILE-DIALOG] Loop started -- polling every 0.4 s")

    while not stop.is_set():
        poll_num += 1
        if poll_num % 150 == 0:  # ~ every 60 s
            logger.debug(f"[FILE-DIALOG] Alive | poll=#{poll_num}")

        for hwnd in list(seen):
            if not _user32.IsWindow(hwnd):
                del seen[hwnd]

        dialogs = _find_dialog_windows()
        if not dialogs:
            stop.wait(_POLL_INTERVAL)
            continue

        logger.info(f"[FILE-DIALOG] Dialog window(s) open: {len(dialogs)}")

        platform = _active_ai_platform()
        if not platform:
            logger.info(
                "[FILE-DIALOG] Dialog open but no AI platform window title matched -- "
                f"visible titles: {_enum_all_window_titles()[:15]}"
            )
            stop.wait(_POLL_INTERVAL)
            continue

        logger.info(f"[FILE-DIALOG] AI platform active: {platform}")

        for hwnd in dialogs:
            filename_text = _get_dialog_filename(hwnd)
            logger.info(f"[FILE-DIALOG] hwnd={hwnd} filename field: {filename_text!r}")
            if not filename_text or seen.get(hwnd) == filename_text:
                continue
            seen[hwnd] = filename_text

            folder: str | None = None  # resolved lazily, at most once per hwnd tick
            for name in _candidate_paths(filename_text):
                path = name
                if not os.path.isfile(path):
                    # Bare filename from a single-click selection -- resolve
                    # against the dialog's current folder instead.
                    if folder is None:
                        folder = _get_dialog_folder(hwnd) or ""
                    path = os.path.join(folder, name) if folder else path
                if not os.path.isfile(path):
                    logger.debug(f"[FILE-DIALOG] Could not resolve '{name}' to a real file")
                    continue
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                if size == 0 or size > _MAX_FILE_SIZE:
                    continue

                text = extract(path)
                if not text:
                    continue

                result = client.classify(text=text[:_MAX_CLASSIFY])
                if result is None:
                    logger.warning("[FILE-DIALOG] Classifier unavailable -- skipping")
                    continue

                risk_score: float = result.get("risk_score", 0.0)
                detections: list  = result.get("detections", [])
                types = [d["type"] for d in detections]
                filename = os.path.basename(path)

                logger.info(
                    f"[FILE-DIALOG] {filename} classified | platform={platform} | "
                    f"risk={risk_score:.3f} | types={types}"
                )

                if risk_score <= 0.5:
                    continue

                logger.critical(
                    f"[FILE-DIALOG] !! SENSITIVE FILE PICK BLOCKED -- {filename} "
                    f"-> {platform} | risk={risk_score:.2f} | types={types}"
                )
                _close_dialog(hwnd)

                attempt = client.report_ai_leak_attempt(
                    agent_id=agent_id,
                    platform=platform,
                    method="BROWSER",
                    content_sample=f"FILE:{filename}"[:100],
                    risk_score=risk_score,
                    blocked=True,
                )
                if attempt:
                    logger.success(f"[FILE-DIALOG] Leak attempt recorded: id={attempt.get('id')}")
                else:
                    logger.error("[FILE-DIALOG] Failed to record leak attempt -- backend may be down")

        stop.wait(_POLL_INTERVAL)


def start_file_dialog_monitor(
    client: DLPApiClient,
    agent_id: str,
    stop: threading.Event,
) -> threading.Thread:
    if sys.platform != "win32":
        logger.warning("[FILE-DIALOG] Non-Windows -- file dialog monitor disabled")
        return threading.Thread(target=lambda: None, daemon=True)

    t = threading.Thread(
        target=_dialog_monitor_loop,
        args=(client, agent_id, stop),
        daemon=True,
        name="file-dialog-monitor",
    )
    t.start()
    logger.info("File dialog monitor started  (0.4 s poll, cancels sensitive file picks in AI tabs)")
    return t
