"""
AI domain monitor: scans ALL open window titles (not just foreground) every 10 s.
Uses EnumWindows so ChatGPT in Opera GX is detected even when not focused.
"""

import sys
import time
import threading
import ctypes
import ctypes.wintypes
import psutil
import pyperclip
from loguru import logger

from api_client import DLPApiClient
from agent_state import AgentState

_POLL_INTERVAL      = 10.0   # seconds between window scans
_ALERT_COOLDOWN     = 60.0   # min seconds between API reports for the same platform
_CLIP_CLEAR_COOLDOWN = 5.0   # min seconds between clipboard clears (prevents spam)

# Keyword → AiPlatform enum value (checked in order — more specific first)
_WINDOW_KEYWORDS: list[tuple[str, str]] = [
    # OpenAI / ChatGPT
    ("chat.openai.com",        "OPENAI_CHATGPT"),
    ("chatgpt.com",            "OPENAI_CHATGPT"),
    ("chatgpt",                "OPENAI_CHATGPT"),
    ("openai",                 "OPENAI_CHATGPT"),
    # Anthropic / Claude
    ("claude.ai",              "ANTHROPIC_CLAUDE"),
    ("anthropic",              "ANTHROPIC_CLAUDE"),
    # Note: "claude" alone is skipped here — matched via process name (claude.exe)
    # Google
    ("gemini.google.com",      "GOOGLE_GEMINI"),
    ("bard.google.com",        "GOOGLE_GEMINI"),
    ("gemini",                 "GOOGLE_GEMINI"),
    # Microsoft
    ("copilot.microsoft.com",  "MICROSOFT_COPILOT"),
    ("bing.com/chat",          "MICROSOFT_COPILOT"),
    ("bing chat",              "MICROSOFT_COPILOT"),
    ("github copilot",         "MICROSOFT_COPILOT"),
    ("copilot",                "MICROSOFT_COPILOT"),
    # Perplexity
    ("perplexity.ai",          "PERPLEXITY"),
    ("perplexity",             "PERPLEXITY"),
    # Poe
    ("poe.com",                "POE"),
    # Character.AI
    ("character.ai",           "CHARACTER_AI"),
    ("character ai",           "CHARACTER_AI"),
    # Mistral
    ("chat.mistral.ai",        "MISTRAL"),
    ("mistral.ai",             "MISTRAL"),
    ("mistral",                "MISTRAL"),
    # Grok / xAI
    ("grok.com",               "GROK"),
    ("grok.x.com",             "GROK"),
    ("x.ai",                   "GROK"),
    ("grok",                   "GROK"),
    # Meta AI
    ("meta.ai",                "META_AI"),
    ("meta ai",                "META_AI"),
    # DeepSeek
    ("chat.deepseek.com",      "DEEPSEEK"),
    ("deepseek.com",           "DEEPSEEK"),
    ("deepseek",               "DEEPSEEK"),
    # HuggingFace
    ("huggingface.co/chat",    "HUGGINGFACE"),
    ("hugging face chat",      "HUGGINGFACE"),
    ("huggingface",            "HUGGINGFACE"),
    # You.com
    ("you.com",                "YOU_COM"),
    # Pi.ai
    ("pi.ai",                  "PI_AI"),
    ("inflection",             "PI_AI"),
    # Groq
    ("groq.com",               "GROQ"),
    # Cohere
    ("cohere.com",             "COHERE"),
    ("cohere",                 "COHERE"),
    # Other known AI tools
    ("writesonic",             "OTHER_AI"),
    ("jasper.ai",              "OTHER_AI"),
    ("notion ai",              "OTHER_AI"),
    ("duckduckgo.com/aichat",  "OTHER_AI"),
    ("phind.com",              "OTHER_AI"),
    ("phind",                  "OTHER_AI"),
    ("qwen",                   "OTHER_AI"),
    ("poe.com",                "POE"),
]

# Native desktop AI app process-name substrings → AiPlatform enum value
_PROCESS_KEYWORDS: list[tuple[str, str]] = [
    ("chatgpt",   "OPENAI_CHATGPT"),
    ("claude",    "ANTHROPIC_CLAUDE"),
    ("gemini",    "GOOGLE_GEMINI"),
    ("copilot",   "MICROSOFT_COPILOT"),
    ("perplexity","PERPLEXITY"),
    ("deepseek",  "DEEPSEEK"),
    ("mistral",   "MISTRAL"),
    ("grok",      "GROK"),
]


# ── Windows API helpers ───────────────────────────────────────────────────────

_WNDENUMPROC = ctypes.WINFUNCTYPE(
    ctypes.c_bool,
    ctypes.wintypes.HWND,
    ctypes.wintypes.LPARAM,
)


def _enum_all_window_titles() -> list[str]:
    """Return titles of all currently visible windows."""
    titles: list[str] = []

    def _cb(hwnd, _lparam):
        try:
            if not ctypes.windll.user32.IsWindowVisible(hwnd):
                return True
            length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
            val = buf.value.strip()
            if val:
                titles.append(val)
        except Exception:
            pass
        return True

    try:
        ctypes.windll.user32.EnumWindows(_WNDENUMPROC(_cb), 0)
    except Exception as exc:
        logger.debug(f"[AI-MONITOR] EnumWindows error: {exc}")
    return titles


def _get_foreground_title() -> str:
    """Foreground window title (quick check first)."""
    try:
        user32 = ctypes.windll.user32
        hwnd   = user32.GetForegroundWindow()
        length = user32.GetWindowTextLengthW(hwnd)
        if length == 0:
            return ""
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        return buf.value
    except Exception:
        return ""


# ── Detection logic ───────────────────────────────────────────────────────────

def _detect_platform_in_text(text: str) -> str | None:
    lower = text.lower()
    for keyword, plat in _WINDOW_KEYWORDS:
        if keyword in lower:
            return plat
    return None


def _scan_processes() -> tuple[str | None, str]:
    """Scan process names for known native AI desktop apps."""
    try:
        for proc in psutil.process_iter(["name"]):
            try:
                name = (proc.info.get("name") or "").lower().replace(".exe", "")
                for keyword, plat in _PROCESS_KEYWORDS:
                    if keyword in name:
                        return plat, name
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as exc:
        logger.debug(f"[AI-MONITOR] psutil error: {exc}")
    return None, ""


# ── Main loop ─────────────────────────────────────────────────────────────────

def _ai_monitor_loop(
    client: DLPApiClient,
    agent_id: str,
    state: AgentState,
    stop: threading.Event,
) -> None:
    last_alerted: dict[str, float] = {}   # platform -> monotonic time of last API report
    last_clip_clear: float = 0.0          # monotonic time of last clipboard clear
    poll_num = 0

    while not stop.is_set():
        poll_num += 1
        t0 = time.monotonic()

        # --- A) foreground window (fast) ---
        fg_title = _get_foreground_title()

        # --- B) ALL windows via EnumWindows ---
        all_titles = _enum_all_window_titles()

        # --- C) Process scan ---
        proc_plat, proc_name = _scan_processes()

        # Always log foreground title so we can see what's being read
        logger.info(
            f"[AI-MONITOR] Poll #{poll_num} | "
            f"fg='{fg_title[:70]}' | "
            f"windows={len(all_titles)} | "
            f"proc_match={proc_plat or 'none'}"
        )

        # --- Detection: window titles first, then process names ---
        detected_plat: str | None = None
        detected_source: str = ""

        for title in all_titles:
            plat = _detect_platform_in_text(title)
            if plat:
                detected_plat = plat
                detected_source = f"window='{title[:80]}'"
                break

        if detected_plat is None and proc_plat:
            detected_plat = proc_plat
            detected_source = f"process={proc_name}"

        # --- React to detection ---
        if detected_plat:
            now = time.monotonic()
            clip_recent = state.clipboard_flagged_recently(within_seconds=30.0)

            logger.info(
                f"[AI-MONITOR] AI platform ACTIVE: {detected_plat} | "
                f"source={detected_source} | "
                f"sensitive_clipboard={clip_recent}"
            )

            if clip_recent:
                # ── STEP 1: Clear clipboard immediately (5 s cooldown) ────────
                since_last_clear = now - last_clip_clear
                if since_last_clear >= _CLIP_CLEAR_COOLDOWN:
                    last_clip_clear = now
                    try:
                        pyperclip.copy("[BLOCKED BY DLP - Sensitive content detected]")
                        logger.success(
                            "[AI-MONITOR] *** CLIPBOARD CLEARED ***  "
                            f"platform={detected_plat}  "
                            "Paste is now BLOCKED"
                        )
                    except Exception as exc:
                        logger.error(f"[AI-MONITOR] Clipboard clear FAILED: {exc}")

                # ── STEP 2: Report incident to backend (60 s cooldown) ────────
                since_last_alert = now - last_alerted.get(detected_plat, 0.0)
                if since_last_alert > _ALERT_COOLDOWN:
                    last_alerted[detected_plat] = now
                    logger.critical(
                        f"[AI-MONITOR] !! DATA LEAK BLOCKED -- {detected_plat} "
                        f"| clipboard cleared | {detected_source}"
                    )
                    attempt = client.report_ai_leak_attempt(
                        agent_id=agent_id,
                        platform=detected_plat,
                        method="BROWSER",
                        content_sample=detected_source[:100],
                        risk_score=0.95,
                        blocked=True,
                    )
                    if attempt:
                        logger.success(
                            f"[AI-MONITOR] Incident REPORTED  id={attempt.get('id')}  "
                            "status=BLOCKED"
                        )
                    else:
                        logger.error("[AI-MONITOR] Failed to report incident to backend")

        elapsed = time.monotonic() - t0
        remaining = max(0.0, _POLL_INTERVAL - elapsed)
        stop.wait(remaining)


# ── Public entry point ────────────────────────────────────────────────────────

def start_ai_domain_monitor(
    client: DLPApiClient,
    agent_id: str,
    state: AgentState,
    stop: threading.Event,
) -> threading.Thread:
    if sys.platform != "win32":
        logger.warning("[AI-MONITOR] Non-Windows platform -- AI domain monitor disabled")
        return threading.Thread(target=lambda: None, daemon=True)

    t = threading.Thread(
        target=_ai_monitor_loop,
        args=(client, agent_id, state, stop),
        daemon=True,
        name="ai-domain-monitor",
    )
    t.start()
    logger.info("AI domain monitor started  (EnumWindows scan every 10s)")
    return t
