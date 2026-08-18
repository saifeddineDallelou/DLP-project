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
from pywinauto import Desktop

from api_client  import DLPApiClient
from agent_state import AgentState

# ── Tuning constants ──────────────────────────────────────────────────────────

_POLL_INTERVAL       = 1.0   # seconds between background scans (down from 10 s)
_ALERT_COOLDOWN      = 60.0  # min seconds between API reports per platform
_CLIP_CLEAR_COOLDOWN = 5.0   # min seconds between clipboard overwrites
_PROC_CACHE_TTL      = 2.0   # cache process-list scan for 2 s (called from 2 threads)
_URL_CACHE_TTL       = 2.0   # cache address-bar scan for 2 s -- UI Automation is slow
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
    ("claude",                 "ANTHROPIC_CLAUDE"),
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


def _enum_all_windows() -> list[tuple[int, str]]:
    """Return (hwnd, title) for every visible top-level window."""
    windows: list[tuple[int, str]] = []

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
                windows.append((hwnd, val))
        except Exception:
            pass
        return True

    try:
        ctypes.windll.user32.EnumWindows(_WNDENUMPROC(_cb), 0)
    except Exception as exc:
        logger.debug(f"[AI-MONITOR] EnumWindows error: {exc}")
    return windows


def _enum_all_window_titles() -> list[str]:
    return [title for _hwnd, title in _enum_all_windows()]


# Browsers append their own name to the tab title -- used to scope the
# (much slower) address-bar read to windows that are actually browsers.
_BROWSER_TITLE_MARKERS = (
    "Google Chrome", "Mozilla Firefox", "Microsoft​ Edge", "Microsoft Edge", "Brave", "Opera",
)


def _is_browser_window(title: str) -> bool:
    return any(marker in title for marker in _BROWSER_TITLE_MARKERS)


def _detect_platform_via_address_bar(hwnd: int) -> str | None:
    """
    Read a browser window's address bar via UI Automation and match the URL
    against the same platform keyword table used for titles.

    This exists because pages like ChatGPT rewrite document.title to the
    conversation topic once you start chatting (e.g. "Excel file request -
    Google Chrome"), so the tab title stops containing "chatgpt" at all --
    the URL doesn't change the same way, so it's a more reliable signal for
    an AI tab that's been open and in use for a while.
    """
    try:
        win = Desktop(backend="uia").window(handle=hwnd)
        checked = 0
        for edit in win.descendants(control_type="Edit"):
            checked += 1
            if checked > 20:  # bound the scan -- chat pages can have many Edit-role elements
                break
            text = edit.window_text()
            if not text:
                continue
            plat = _detect_platform_in_text(text)
            if plat:
                return plat
    except Exception as exc:
        logger.debug(f"[AI-MONITOR] Address-bar read failed hwnd={hwnd}: {exc}")
    return None


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

    def __init__(self, client: DLPApiClient, agent_id: str, policy_resolver=None) -> None:
        self._client          = client
        self._agent_id        = agent_id
        self._policy_resolver = policy_resolver
        self._lock            = threading.Lock()

        # Cooldown state
        self._last_clip_clear: float         = 0.0
        self._last_alerted: dict[str, float] = {}

        # Process scan cache shared between the two threads
        self._proc_cache: tuple[str | None, str] = (None, "")
        self._proc_cache_time: float              = 0.0

        # Browser address-bar scan cache (UI Automation is much slower than
        # the window-title/process checks, so this tier is cached separately)
        self._url_cache: tuple[str, str] | None = None
        self._url_cache_time: float             = 0.0

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _detect_platform(self) -> tuple[str | None, str]:
        """
        Detect active AI platform, cheapest signal first:
          1. Window title keyword match (~1 ms, always fresh) -- catches a
             fresh/idle AI tab or a desktop app.
          2. Browser address-bar URL via UI Automation (slower, cached 2 s)
             -- catches an AI tab whose page JS has renamed the title away
             from anything platform-shaped (e.g. ChatGPT retitling its tab
             to the conversation topic once you start chatting).
          3. Running-process name match (cached 2 s) -- catches a desktop
             app with no matching window title at all.
        """
        windows = _enum_all_windows()

        for _hwnd, title in windows:
            plat = _detect_platform_in_text(title)
            if plat:
                return plat, f"window='{title[:80]}'"

        now = time.monotonic()
        with self._lock:
            url_stale = now - self._url_cache_time > _URL_CACHE_TTL
        if url_stale:
            found: tuple[str, str] | None = None
            for hwnd, title in windows:
                if _is_browser_window(title):
                    plat = _detect_platform_via_address_bar(hwnd)
                    if plat:
                        found = (plat, title)
                        break
            with self._lock:
                self._url_cache      = found
                self._url_cache_time = now
        with self._lock:
            cached_url = self._url_cache
        if cached_url:
            plat, title = cached_url
            return plat, f"url-in-tab='{title[:80]}'"

        # Process scan (slower; cache for _PROC_CACHE_TTL seconds)
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
        detections: list | None = None,
    ) -> str | None:
        """
        Detect active AI platform and act on it according to the matching
        policy's action (resolved via the policy_resolver passed at
        construction; falls back to BLOCK if none was supplied or nothing
        matches):
          ALLOW              -- do nothing at all, not even a report.
          ALERT              -- report the attempt (blocked=False) but leave
                                the clipboard alone so the paste still goes
                                through.
          BLOCK / QUARANTINE -- current behavior: clear the clipboard and
                                report (blocked=True).

        Args:
            t_detect:       time.monotonic() at the moment sensitive content
                            was first detected (used for timing log).
            content_sample: brief sanitised snippet for the backend report.
            risk_score:     forwarded to the leak-attempt report.
            source_tag:     "CLIPBOARD" (immediate) or "CLIPBOARD_DELAYED".
            detections:     classifier detections for the content that
                            triggered this check -- used to resolve which
                            policy (and therefore which action) applies.

        Returns:
            The resolved action ("ALLOW" / "ALERT" / "BLOCK" / "QUARANTINE")
            if an AI platform was found and a decision was made -- callers
            should not retry and, for anything other than "ALLOW", can trust
            this call already reported the attempt internally.
            None if no AI platform is active right now -- caller may retry
            via the delayed path once one opens.
        """
        detected_plat, detected_source = self._detect_platform()
        if not detected_plat:
            return None

        policy = (
            self._policy_resolver.resolve(detections or [])
            if self._policy_resolver
            else {"id": None, "action": "BLOCK", "name": None}
        )
        action = policy["action"]

        if action == "ALLOW":
            logger.debug(
                f"[AI-MONITOR] Sensitive clipboard content near {detected_plat} but policy "
                f"'{policy.get('name') or 'default'}' is set to ALLOW -- not blocked, not reported"
            )
            return "ALLOW"

        now = time.monotonic()

        # ── STEP 1: clear clipboard (5 s cooldown) -- skipped for ALERT ───────
        do_clear = False
        if action != "ALERT":
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
                f"[AI-MONITOR] !! DATA LEAK {'BLOCKED' if do_clear else 'DETECTED (ALERT only)'} -- "
                f"{detected_plat} | {detected_source} | via={source_tag}"
            )
            attempt = self._client.report_ai_leak_attempt(
                agent_id=self._agent_id,
                platform=detected_plat,
                method="BROWSER",
                content_sample=(content_sample or detected_source)[:100],
                risk_score=risk_score,
                blocked=do_clear,
            )
            if attempt:
                logger.success(
                    f"[AI-MONITOR] Incident REPORTED  id={attempt.get('id')}  "
                    f"status={'BLOCKED' if do_clear else 'ALERTED'}"
                )
            else:
                logger.error("[AI-MONITOR] Failed to report incident to backend")

        return action


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
            # No detections available for the delayed path (the original
            # classify() result isn't carried in AgentState's flag) -- falls
            # back to the default policy's action.
            action_taken = blocker.check_and_block(
                t_detect=t_flagged,
                source_tag="CLIPBOARD_DELAYED",
            )
            if action_taken:
                logger.info(
                    f"[AI-MONITOR] Delayed {action_taken.lower()} applied "
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
    policy_resolver=None,
) -> tuple[threading.Thread, "AiBlocker"]:
    """
    Start the AI domain monitor background thread.

    Returns (thread, blocker) — pass *blocker* to start_clipboard_watcher()
    so the clipboard thread can call check_and_block() immediately on detection.
    """
    if sys.platform != "win32":
        logger.warning("[AI-MONITOR] Non-Windows -- AI domain monitor disabled")
        dummy_blocker = AiBlocker(client, agent_id, policy_resolver)
        return threading.Thread(target=lambda: None, daemon=True), dummy_blocker

    blocker = AiBlocker(client, agent_id, policy_resolver)

    t = threading.Thread(
        target=_ai_monitor_loop,
        args=(agent_id, state, stop, blocker),
        daemon=True,
        name="ai-domain-monitor",
    )
    t.start()
    logger.info("AI domain monitor started  (1 s poll | shared AiBlocker)")
    return t, blocker
