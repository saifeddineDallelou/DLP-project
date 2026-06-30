"""
AI domain monitor — 1-second window scan for open AI platforms.

Responsibilities:
  1. Expose AiBlocker: thread-safe class shared with clipboard_watcher so that
     a sensitive-clipboard detection can immediately trigger a window check and
     clipboard clear in the SAME event (sub-second detection-to-block).
  2. Run a background loop at 1 s to handle the DELAYED case — user copied
     sensitive content when no AI window was open, then opened one within 30 s.

AiBlocker is created by start_ai_domain_monitor() and returned alongside the
thread so clipboard_watcher can hold a reference to it.
"""

import sys
import time
import threading
import ctypes
import ctypes.wintypes
import psutil
import pyperclip
from loguru import logger

from api_client  import DLPApiClient
from agent_state import AgentState

# ── Tuning constants ──────────────────────────────────────────────────────────

_POLL_INTERVAL       = 1.0   # seconds between background scans (down from 10 s)
_ALERT_COOLDOWN      = 60.0  # min seconds between API reports per platform
_CLIP_CLEAR_COOLDOWN = 5.0   # min seconds between clipboard overwrites
_PROC_CACHE_TTL      = 2.0   # cache process-list scan for 2 s (called from 2 threads)
_LOG_STATUS_EVERY    = 10    # log AI status every N polls (= every 10 s)

# ── AI-platform keyword tables ────────────────────────────────────────────────

_WINDOW_KEYWORDS: list[tuple[str, str]] = [
    # OpenAI / ChatGPT
    ("chat.openai.com",        "OPENAI_CHATGPT"),
    ("chatgpt.com",            "OPENAI_CHATGPT"),
    ("chatgpt",                "OPENAI_CHATGPT"),
    ("openai",                 "OPENAI_CHATGPT"),
    # Anthropic / Claude
    ("claude.ai",              "ANTHROPIC_CLAUDE"),
    ("anthropic",              "ANTHROPIC_CLAUDE"),
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
]

_PROCESS_KEYWORDS: list[tuple[str, str]] = [
    ("chatgpt",    "OPENAI_CHATGPT"),
    ("claude",     "ANTHROPIC_CLAUDE"),
    ("gemini",     "GOOGLE_GEMINI"),
    ("copilot",    "MICROSOFT_COPILOT"),
    ("perplexity", "PERPLEXITY"),
    ("deepseek",   "DEEPSEEK"),
    ("mistral",    "MISTRAL"),
    ("grok",       "GROK"),
]

# ── Windows API helpers ───────────────────────────────────────────────────────

_WNDENUMPROC = ctypes.WINFUNCTYPE(
    ctypes.c_bool,
    ctypes.wintypes.HWND,
    ctypes.wintypes.LPARAM,
)


def _enum_all_window_titles() -> list[str]:
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


def _detect_platform_in_text(text: str) -> str | None:
    lower = text.lower()
    for keyword, plat in _WINDOW_KEYWORDS:
        if keyword in lower:
            return plat
    return None


def _scan_processes_raw() -> tuple[str | None, str]:
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


# ── AiBlocker — shared between ai_domain_monitor loop and clipboard_watcher ──

class AiBlocker:
    """
    Thread-safe detection + clipboard-clear engine.

    check_and_block() can be called from any thread:
      - clipboard_watcher calls it immediately on sensitive-content detection
        (IMMEDIATE path: detection-to-block in <500 ms)
      - ai_domain_monitor loop calls it every 1 s when clipboard is still flagged
        (DELAYED path: catches the "copy first, open AI window later" case)
    """

    def __init__(self, client: DLPApiClient, agent_id: str) -> None:
        self._client   = client
        self._agent_id = agent_id
        self._lock     = threading.Lock()

        # Cooldown state
        self._last_clip_clear: float         = 0.0
        self._last_alerted: dict[str, float] = {}

        # Process scan cache shared between the two threads
        self._proc_cache: tuple[str | None, str] = (None, "")
        self._proc_cache_time: float              = 0.0

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _detect_platform(self) -> tuple[str | None, str]:
        """Detect active AI platform. Window scan ~1 ms; process scan cached 2 s."""
        # Window titles (fast, thread-safe ctypes calls)
        for title in _enum_all_window_titles():
            plat = _detect_platform_in_text(title)
            if plat:
                return plat, f"window='{title[:80]}'"

        # Process scan (slower; cache for _PROC_CACHE_TTL seconds)
        now = time.monotonic()
        with self._lock:
            if now - self._proc_cache_time > _PROC_CACHE_TTL:
                self._proc_cache      = _scan_processes_raw()
                self._proc_cache_time = now
            cached = self._proc_cache

        plat, name = cached
        if plat:
            return plat, f"process={name}"
        return None, ""

    # ── Public interface ──────────────────────────────────────────────────────

    def check_and_block(
        self,
        t_detect: float,
        content_sample: str = "",
        risk_score: float   = 0.95,
        source_tag: str     = "CLIPBOARD",
    ) -> bool:
        """
        Detect active AI platform and block the clipboard if one is found.

        Args:
            t_detect:       time.monotonic() at the moment sensitive content
                            was first detected (used for timing log).
            content_sample: brief sanitised snippet for the backend report.
            risk_score:     forwarded to the leak-attempt report.
            source_tag:     "CLIPBOARD" (immediate) or "CLIPBOARD_DELAYED".

        Returns:
            True  — AI platform found; clipboard clear attempted.
            False — No AI platform active right now.
        """
        detected_plat, detected_source = self._detect_platform()
        if not detected_plat:
            return False

        now = time.monotonic()

        # ── STEP 1: clear clipboard (5 s cooldown) ────────────────────────────
        with self._lock:
            since_clear = now - self._last_clip_clear
            do_clear    = since_clear >= _CLIP_CLEAR_COOLDOWN
            if do_clear:
                self._last_clip_clear = now

        if do_clear:
            try:
                pyperclip.copy("[BLOCKED BY DLP - Sensitive content detected]")
                block_ms = (time.monotonic() - t_detect) * 1000
                logger.success(
                    f"[SPEED] Detection-to-block ({source_tag}): {block_ms:.0f} ms | "
                    f"platform={detected_plat}"
                )
                logger.success(
                    f"[AI-MONITOR] *** CLIPBOARD CLEARED ***  "
                    f"platform={detected_plat}  Paste is now BLOCKED"
                )
            except Exception as exc:
                logger.error(f"[AI-MONITOR] Clipboard clear FAILED: {exc}")

        # ── STEP 2: report to backend (60 s per-platform cooldown) ────────────
        with self._lock:
            since_alert = now - self._last_alerted.get(detected_plat, 0.0)
            do_alert    = since_alert >= _ALERT_COOLDOWN
            if do_alert:
                self._last_alerted[detected_plat] = now

        if do_alert:
            logger.critical(
                f"[AI-MONITOR] !! DATA LEAK BLOCKED -- {detected_plat} "
                f"| {detected_source} | via={source_tag}"
            )
            attempt = self._client.report_ai_leak_attempt(
                agent_id=self._agent_id,
                platform=detected_plat,
                method="BROWSER",
                content_sample=(content_sample or detected_source)[:100],
                risk_score=risk_score,
                blocked=True,
            )
            if attempt:
                logger.success(
                    f"[AI-MONITOR] Incident REPORTED  id={attempt.get('id')}  "
                    "status=BLOCKED"
                )
            else:
                logger.error("[AI-MONITOR] Failed to report incident to backend")

        return True


# ── Background poll loop (handles the DELAYED case) ──────────────────────────

def _ai_monitor_loop(
    agent_id: str,
    state: AgentState,
    stop: threading.Event,
    blocker: AiBlocker,
) -> None:
    poll_num = 0

    while not stop.is_set():
        poll_num += 1
        t0 = time.monotonic()

        # Periodic status log (every 10 s)
        if poll_num % _LOG_STATUS_EVERY == 0:
            fg = _get_foreground_title()
            logger.debug(
                f"[AI-MONITOR] Status | poll=#{poll_num} | fg='{fg[:70]}'"
            )

        # Only do expensive detection if clipboard was recently flagged
        if state.clipboard_flagged_recently(within_seconds=30.0):
            t_flagged = state.sensitive_clip_monotonic()
            blocked = blocker.check_and_block(
                t_detect=t_flagged,
                source_tag="CLIPBOARD_DELAYED",
            )
            if blocked:
                logger.info(
                    f"[AI-MONITOR] Delayed block applied "
                    f"({(time.monotonic() - t_flagged)*1000:.0f} ms after copy)"
                )

        elapsed   = time.monotonic() - t0
        stop.wait(max(0.0, _POLL_INTERVAL - elapsed))


# ── Public entry point ────────────────────────────────────────────────────────

def start_ai_domain_monitor(
    client: DLPApiClient,
    agent_id: str,
    state: AgentState,
    stop: threading.Event,
) -> tuple[threading.Thread, "AiBlocker"]:
    """
    Start the AI domain monitor background thread.

    Returns (thread, blocker) — pass *blocker* to start_clipboard_watcher()
    so the clipboard thread can call check_and_block() immediately on detection.
    """
    if sys.platform != "win32":
        logger.warning("[AI-MONITOR] Non-Windows -- AI domain monitor disabled")
        dummy_blocker = AiBlocker(client, agent_id)
        return threading.Thread(target=lambda: None, daemon=True), dummy_blocker

    blocker = AiBlocker(client, agent_id)

    t = threading.Thread(
        target=_ai_monitor_loop,
        args=(agent_id, state, stop, blocker),
        daemon=True,
        name="ai-domain-monitor",
    )
    t.start()
    logger.info("AI domain monitor started  (1 s poll | shared AiBlocker)")
    return t, blocker
