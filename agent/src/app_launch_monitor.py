"""
App launch monitor: polls psutil every 15 s for newly spawned processes.

Whitelist approach — ONLY watchlisted processes (archive tools, remote-access,
FTP, tunneling, screen recording, etc.) generate UEBA events.  Everything else
is tracked internally for PID deduplication but never posted to the backend.
This keeps the UEBA event table focused on genuinely exfiltration-relevant
process launches.
"""

import os
import threading
from datetime import datetime
import psutil
from loguru import logger

from api_client import DLPApiClient

_POLL_INTERVAL = 15.0   # seconds between process scans

# (executable name substring, human label, severity)
# Checked as: keyword in proc_name.lower()
# More-specific entries must come before less-specific ones (e.g. "7zg" before "7z")
_WATCHLIST: list[tuple[str, str]] = [
    # Archive / compression (exfiltration vector)
    ("7zg",                "7-Zip GUI"),
    ("7z",                 "7-Zip archiver"),
    ("winrar",             "WinRAR archiver"),
    ("winzip",             "WinZip archiver"),
    ("peazip",             "PeaZip archiver"),
    ("bandizip",           "Bandizip archiver"),
    # Remote access / screen sharing
    ("teamviewer",         "TeamViewer remote access"),
    ("anydesk",            "AnyDesk remote access"),
    ("chromeremotedesktop","Chrome Remote Desktop"),
    ("radmin",             "Radmin remote access"),
    ("ammyy",              "Ammyy Admin"),
    ("logmein",            "LogMeIn remote access"),
    ("uvnc",               "UltraVNC"),
    ("tigervnc",           "TigerVNC"),
    ("realvnc",            "RealVNC"),
    ("vncviewer",          "VNC Viewer"),
    # FTP / SFTP file transfer
    ("filezilla",          "FileZilla FTP"),
    ("winscp",             "WinSCP SFTP"),
    ("smartftp",           "SmartFTP"),
    ("coreftp",            "CoreFTP"),
    ("ftp",                "FTP client"),
    # Cloud sync / upload
    ("megasync",           "MEGA cloud sync"),
    # Network tunneling / SSH
    ("ngrok",              "ngrok tunnel"),
    ("frpc",               "frp client tunnel"),
    ("putty",              "PuTTY SSH"),
    ("kitty",              "KiTTY SSH"),
    ("plink",              "Plink SSH"),
    # USB / disk tools
    ("usbdeview",          "USB enumerator"),
    ("diskpart",           "DiskPart disk utility"),
    ("format",             "Disk format utility"),
    # Screen recording
    ("obs64",              "OBS Studio recording"),
    ("obs32",              "OBS Studio recording (32-bit)"),
    ("obs",                "OBS Studio"),
    ("camtasia",           "Camtasia recording"),
    ("bandicam",           "Bandicam recording"),
    ("fraps",              "FRAPS capture"),
    ("action",             "Action! recording"),
    # Packet capture
    ("wireshark",          "Wireshark packet capture"),
    ("rawcap",             "RawCap capture"),
    # P2P / torrent (large-file exfil vector)
    ("utorrent",           "uTorrent"),
    ("qbittorrent",        "qBittorrent"),
    ("bittorrent",         "BitTorrent"),
    ("transmission",       "Transmission torrent"),
]


def _check_watchlist(proc_name_lower: str) -> str | None:
    """Return human label if process matches watchlist, else None."""
    for keyword, label in _WATCHLIST:
        if keyword in proc_name_lower:
            return label
    return None


def _app_launch_loop(
    client: DLPApiClient,
    agent_id: str,
    user_id: str,
    stop: threading.Event,
) -> None:
    # Seed with all currently running PIDs so startup noise is ignored
    known_pids: set[int] = set()
    try:
        for proc in psutil.process_iter(["pid"]):
            try:
                known_pids.add(proc.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as exc:
        logger.debug(f"[APP-LAUNCH] Initial seed error: {exc}")

    logger.info(
        f"[APP-LAUNCH] Loop started -- scanning every 15 s "
        f"(seeded {len(known_pids)} existing PIDs, whitelist-only reporting)"
    )

    while not stop.is_set():
        stop.wait(_POLL_INTERVAL)
        if stop.is_set():
            break

        try:
            current_pids: set[int] = set()
            watchlist_hits: list[tuple[int, str, str]] = []   # (pid, name, label)

            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    pid  = proc.pid
                    name = (proc.info.get("name") or "").strip()
                    current_pids.add(pid)

                    if pid not in known_pids and name:
                        label = _check_watchlist(name.lower())
                        if label:
                            watchlist_hits.append((pid, name, label))
                        # All new PIDs are tracked internally; non-watchlisted
                        # processes are silently absorbed into known_pids below.

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            known_pids = current_pids

            for pid, name, label in watchlist_hits:
                logger.warning(
                    f"[APP-LAUNCH] !! WATCHLIST  {name} (pid={pid})  -- {label}"
                )
                result = client.post_ueba_event(
                    agent_id=agent_id,
                    user_id=user_id,
                    event_type="APP_LAUNCH",
                    metadata={
                        "process_name": name,
                        "pid":          pid,
                        "watch_label":  label,
                        "timestamp":    datetime.now().isoformat(),
                    },
                )
                if result is None:
                    logger.debug(
                        f"[APP-LAUNCH] Backend unavailable -- "
                        f"event for '{name}' not posted"
                    )

        except Exception as exc:
            logger.warning(f"[APP-LAUNCH] Scan error: {exc}")


# ── Public entry point ────────────────────────────────────────────────────────

def start_app_launch_monitor(
    client: DLPApiClient,
    agent_id: str,
    stop: threading.Event,
) -> threading.Thread:
    user_id = (
        os.environ.get("USERNAME")
        or os.environ.get("USER")
        or "unknown-user"
    )

    t = threading.Thread(
        target=_app_launch_loop,
        args=(client, agent_id, user_id, stop),
        daemon=True,
        name="app-launch-monitor",
    )
    t.start()
    logger.info(
        "App launch monitor started  "
        "(process scan every 15 s, whitelist-only UEBA reporting)"
    )
    return t
