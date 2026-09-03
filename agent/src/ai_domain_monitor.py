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
from review_prompt import prompt_review_request
import browser_sensor

# ── Tuning constants ──────────────────────────────────────────────────────────

_POLL_INTERVAL       = 1.0   # seconds between background scans (down from 10 s)
# The exact text written over sensitive clipboard content. Defined HERE, in
# the module that writes it, and imported by clipboard_watcher, which skips
# any clipboard content starting with it. The two must match exactly or the
# watcher re-classifies the agent's own block message on every clear -- so it
# gets one definition, not a copy in each file.
_DLP_BLOCK_MSG = "[BLOCKED BY DLP - Sensitive content detected]"

_ALERT_COOLDOWN      = 60.0  # min seconds between API reports per platform
_CLIP_CLEAR_COOLDOWN = 5.0   # min seconds between clipboard overwrites
_PROC_CACHE_TTL      = 2.0   # cache process-list scan for 2 s (called from 2 threads)
_URL_CACHE_TTL       = 2.0   # cache address-bar scan for 2 s -- UI Automation is slow

# How long a browser window stays known as an AI platform after its title
# stopped saying so.
#
# ChatGPT rewrites document.title to the conversation topic the moment you
# send a message: "ChatGPT - Opera" becomes "Food advice - Opera". The
# address-bar reader exists to survive that, and on some browsers it does not
# work at all -- Opera exposes SEVEN accessibility nodes for its whole window
# and not one Edit control, so there is no address bar to read. Measured, not
# assumed: _detect_platform_via_address_bar returned None, descendants(
# control_type="Edit") returned zero.
#
# That left the agent able to see a ChatGPT tab only BEFORE anyone had talked
# to it -- the one state it is never in when a person actually pastes
# customer data into it.
#
# The window handle does not change when the title does. So a window that
# announced itself as an AI platform is remembered as one. The memory is
# dropped as soon as the window closes; this timer only bounds the other case,
# where the window is still open but has been navigated somewhere else
# entirely. Fifteen minutes is well past a paste and well short of a
# work session.
_AI_WINDOW_MEMORY_TTL = 900.0
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


def _get_foreground_window() -> tuple[int, str]:
    """Foreground window handle and title. The handle matters as well as the
    title: a browser tab whose page has renamed itself needs the address-bar
    check, and that needs an hwnd."""
    try:
        user32 = ctypes.windll.user32
        hwnd   = user32.GetForegroundWindow()
        if not hwnd:
            return 0, ""
        length = user32.GetWindowTextLengthW(hwnd)
        if length == 0:
            return hwnd, ""
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        return hwnd, buf.value
    except Exception:
        return 0, ""


def _get_foreground_title() -> str:
    return _get_foreground_window()[1]


def _detect_platform_in_text(text: str) -> str | None:
    lower = text.lower()
    for keyword, plat in _WINDOW_KEYWORDS:
        if keyword in lower:
            return plat
    return None


def _scan_processes_raw() -> list[tuple[int, str, str]]:
    """
    Return (pid, name, platform) for every RUNNING process whose name matches
    an AI-platform keyword. This alone is NOT enough to conclude that
    platform is actually in use -- a name match on a headless background/
    helper process (e.g. this very dev machine runs Claude Code's own
    subprocesses, all named "claude") is a false positive. _detect_platform()
    cross-references this against processes that actually own a visible
    window before treating a match as real.
    """
    matches: list[tuple[int, str, str]] = []
    try:
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = (proc.info.get("name") or "").lower().replace(".exe", "")
                for keyword, plat in _PROCESS_KEYWORDS:
                    if keyword in name:
                        matches.append((proc.info["pid"], name, plat))
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as exc:
        logger.debug(f"[AI-MONITOR] psutil error: {exc}")
    return matches


def _window_owner_pids(windows: list[tuple[int, str]]) -> set[int]:
    """PIDs that own at least one visible, titled top-level window (i.e. a
    real desktop app the user could actually be looking at), as opposed to a
    headless background/helper process."""
    pids: set[int] = set()
    for hwnd, _title in windows:
        pid = ctypes.wintypes.DWORD()
        try:
            ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value:
                pids.add(pid.value)
        except Exception:
            pass
    return pids


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

        # Cooldown state -- keyed per-platform (not a single shared timer) so
        # a block on one AI platform can't suppress a block on a different
        # one detected moments later (e.g. paste into Grok, then Gemini 3s
        # later -- each is its own leak attempt and must be independently
        # evaluated/cleared, not silently let through by an unrelated
        # platform's still-cooling-down clear timer).
        self._last_clip_clear: dict[str, float] = {}
        self._last_alerted: dict[str, float]    = {}
        # Separate from _last_alerted: the review prompt is throttled on its
        # own timer, so it stays quiet even as repeats keep being counted.
        self._last_prompted: dict[str, float]   = {}
        # platform -> id of the attempt row the current window is counting
        # onto. Cleared when a window closes, so a new burst opens a new row.
        self._open_attempt: dict[str, str]      = {}

        # Process scan cache shared between the two threads
        self._proc_cache: tuple[str | None, str] = (None, "")
        self._proc_cache_time: float              = 0.0

        # hwnd -> (platform, monotonic time last confirmed, title AT THAT TIME).
        #
        # A browser window that once identified itself as an AI platform stays
        # known as one after its title changes. See _AI_WINDOW_MEMORY_TTL for
        # why this is not optional on some browsers.
        #
        # The original title is kept because the CURRENT one is worthless as
        # evidence: a browser runs every tab in one window, so at block time
        # the title is whatever tab happens to be in front. Observed live --
        # a block correctly attributed to ChatGPT recorded its evidence as
        # "DLP Console - Opera", the dashboard tab. An incident naming the
        # wrong destination is worse than useless to whoever investigates it.
        self._ai_windows: dict[int, tuple[str, float, str]] = {}

        # Browser address-bar scan cache (UI Automation is much slower than
        # the window-title/process checks, so this tier is cached separately)
        self._url_cache: tuple[str, str] | None = None
        self._url_cache_time: float             = 0.0

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _remember_ai_window(self, hwnd: int, platform: str, title: str = "") -> None:
        """Record that this window IS an AI platform, however we found out.

        `title` is what it was called at the moment it identified itself --
        the only title that is evidence of anything later on.
        """
        if not hwnd:
            return
        with self._lock:
            previous = self._ai_windows.get(hwnd)
            # Keep the first title that identified it: "ChatGPT - Opera" says
            # where the data was going; a later refresh from a background scan
            # would overwrite it with whatever tab is in front now.
            seen_as = (previous[2] if previous and previous[0] == platform
                       else (title or "")) or title
            self._ai_windows[hwnd] = (platform, time.monotonic(), seen_as)

    def _recall_ai_window(self, windows: list[tuple[int, str]]) -> tuple[str, str] | None:
        """
        An open window we previously identified as an AI platform.

        Also prunes: an entry whose window has closed is dropped immediately
        rather than waiting out the TTL, so a handle Windows later reuses for
        something unrelated cannot inherit an AI identity.
        """
        live = {h: t for h, t in windows}
        now = time.monotonic()
        recalled: tuple[str, str] | None = None

        with self._lock:
            for hwnd in list(self._ai_windows):
                platform, seen, seen_as = self._ai_windows[hwnd]
                if hwnd not in live or now - seen > _AI_WINDOW_MEMORY_TTL:
                    del self._ai_windows[hwnd]
                elif recalled is None:
                    # Report the title it identified itself BY, and the one it
                    # wears now, so the incident says where the data was going
                    # without pretending the window still announces it.
                    current = live[hwnd]
                    evidence = (f"'{seen_as}' (now '{current}')"
                                if seen_as and seen_as != current
                                else f"'{current}'")
                    recalled = (platform, evidence)

        return recalled

    def observe_ai_windows(self) -> None:
        """
        Note which windows are AI platforms, from their titles alone.

        Called every poll, whether or not anything is being blocked. That is
        the whole point: _detect_platform only runs once the clipboard has
        already been flagged, so a memory populated only there would never see
        a ChatGPT tab during the minutes of ordinary browsing BEFORE it gets
        renamed -- it would learn the window's identity at the exact moment
        that knowledge stopped being available. Which is what happened, live:
        the fix looked correct and changed nothing.

        Costs a window enumeration -- 0.24 ms measured, against a 1 s poll. It
        deliberately does no UI Automation and no process scan; those are the
        expensive tiers the caller is right to gate.
        """
        windows = _enum_all_windows()
        for hwnd, title in windows:
            plat = _detect_platform_in_text(title)
            if plat:
                self._remember_ai_window(hwnd, plat, title)
        # Drops entries whose window has closed, so the memory cannot grow
        # unbounded across a long session.
        self._recall_ai_window(windows)

    def _detect_platform(self) -> tuple[str | None, str]:
        """
        Detect active AI platform, cheapest signal first:
          1. Window title keyword match (~1 ms, always fresh) -- catches a
             fresh/idle AI tab or a desktop app.
          2. Browser address-bar URL via UI Automation (slower, cached 2 s)
             -- catches an AI tab whose page JS has renamed the title away
             from anything platform-shaped (e.g. ChatGPT retitling its tab
             to the conversation topic once you start chatting).
          3. A window we ALREADY identified, whose title has since changed
             (dictionary lookup) -- catches ChatGPT renaming its tab to the
             conversation topic, which is the state the tab is in whenever
             someone actually pastes something into it.
          4. Running-process name match (cached 2 s) -- catches a desktop
             app with no matching window title at all.
        """
        # The browser extension, when it is installed and reporting.
        #
        # It sees TABS; every tier below sees only windows, and a browser puts
        # every tab in one window. That mismatch produced three separate
        # failures found by testing -- a renamed tab going invisible, an
        # accessibility tree that does not exist on Opera, and a remembered
        # window that kept blocking after its AI tab was closed. None are
        # solvable from outside the browser.
        #
        # A negative from the extension is as authoritative as a positive:
        # "no AI tab is open" is precisely the answer the window tiers get
        # wrong, so when the sensor is live its browser verdict stands and
        # the remembered-window tier is skipped entirely.
        sensor_live = browser_sensor.STATE.is_live()
        sensor_plat, sensor_detail = browser_sensor.STATE.current()
        if sensor_plat:
            return sensor_plat, f"extension='{sensor_detail}'"

        windows = _enum_all_windows()

        # The FOREGROUND window first, when it is itself an AI platform.
        #
        # Scanning every window (below) is deliberate -- an AI tab sitting in
        # the background is still a live paste target, so the block should
        # fire either way. But the platform NAME ends up on the incident, and
        # the loop below returns whichever matching window EnumWindows happens
        # to hand back first, which is not necessarily the one the user is
        # actually in. Observed live: a paste into a focused ChatGPT tab was
        # recorded as ANTHROPIC_CLAUDE, because an always-open Claude Code
        # terminal matched earlier in the enumeration.
        #
        # Blocking is unchanged. This only makes the attribution honest, and
        # an incident naming the wrong platform is worse than useless to
        # whoever investigates it.
        fg_hwnd, fg_title = _get_foreground_window()
        if fg_title:
            fg_plat = _detect_platform_in_text(fg_title)
            if fg_plat:
                self._remember_ai_window(fg_hwnd, fg_plat, fg_title)
                return fg_plat, f"foreground='{fg_title[:80]}'"

            # ChatGPT renames its tab to the conversation topic as soon as you
            # start chatting, so the focused tab's TITLE frequently matches
            # nothing -- which is what let a background Claude Code window win
            # the attribution. Check the focused browser's address bar before
            # falling back to other windows. Uncached on purpose: this is the
            # one window whose identity has to be correct right now, and it is
            # a single UIA call rather than a walk over every window.
            if _is_browser_window(fg_title):
                fg_url_plat = _detect_platform_via_address_bar(fg_hwnd)
                if fg_url_plat:
                    self._remember_ai_window(fg_hwnd, fg_url_plat, fg_title)
                    return fg_url_plat, f"foreground-url='{fg_title[:80]}'"

        for hwnd, title in windows:
            plat = _detect_platform_in_text(title)
            if plat:
                self._remember_ai_window(hwnd, plat, title)
                return plat, f"window='{title[:80]}'"

        # A window we identified earlier, whose title has since changed.
        #
        # Deliberately ahead of the address-bar and process tiers: it is a
        # dictionary lookup rather than a UI Automation walk, and it is the
        # case those tiers were supposed to cover and cannot on every browser.
        # Skipped when the extension is live: it already answered for
        # browsers, and this tier's whole failure mode is not knowing when a
        # tab was closed -- which the extension does know.
        remembered = None if sensor_live else self._recall_ai_window(windows)
        if remembered:
            # The evidence arrives already quoted -- it may name two titles,
            # the one that identified the window and the one it wears now.
            plat, evidence = remembered
            return plat, f"remembered={evidence[:120]}"

        now = time.monotonic()
        with self._lock:
            url_stale = now - self._url_cache_time > _URL_CACHE_TTL
        if url_stale:
            found: tuple[str, str] | None = None
            for hwnd, title in windows:
                if _is_browser_window(title):
                    plat = _detect_platform_via_address_bar(hwnd)
                    if plat:
                        self._remember_ai_window(hwnd, plat, title)
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

        if cached:
            # A name match alone isn't enough -- require the process to also
            # own a visible window, so a headless background/helper process
            # with a coincidentally matching name (e.g. Claude Code's own
            # subprocesses) can't be mistaken for the AI platform actually
            # in use. windows was already enumerated above (tier 1), so this
            # costs nothing extra.
            visible_pids = _window_owner_pids(windows)
            for pid, name, plat in cached:
                if pid in visible_pids:
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
            self._policy_resolver.resolve(detections or [], channel="CLIPBOARD")
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

        # ── STEP 1: clear the clipboard -- skipped only for ALERT ──────────────
        # The clear is UNCONDITIONAL. It used to be gated behind
        # _CLIP_CLEAR_COOLDOWN, which meant that for five seconds after any
        # block, sensitive content heading for an AI window was deliberately
        # left in place -- and because the "not cleared" message was written
        # inside the _ALERT_COOLDOWN branch below, it was left in place
        # SILENTLY. Get blocked once, copy again straight away, and the paste
        # went through with nothing in the log to say so.
        #
        # There is no situation in which the right answer is to leave a
        # customer record on the clipboard with ChatGPT in the foreground, so
        # the cooldown no longer gates the action -- it only damps log volume.
        # What prevents a runaway is not a timer but the check below: the
        # clipboard is only written when it does NOT already hold the block
        # message.
        do_clear = False
        # True when sensitive content was actually ON the clipboard for this
        # call -- i.e. a genuinely new attempt, as opposed to the delayed
        # loop looking at an already-clear clipboard again. Independent of
        # whether the clear then succeeded.
        fresh_attempt = False
        if action != "ALERT":
            with self._lock:
                since_clear = now - self._last_clip_clear.get(detected_plat, 0.0)
                announce = since_clear >= _CLIP_CLEAR_COOLDOWN
                self._last_clip_clear[detected_plat] = now

            # Gate the WRITE on what is actually on the clipboard, not on a
            # timer. The delayed path (_ai_monitor_loop) re-checks a STALE
            # FLAG once a second for the whole flag window rather than the
            # clipboard's current contents, so an unconditional write turned
            # one block into ~30 seconds of overwriting the clipboard every
            # second -- unusable for anything else, and logged as a fresh
            # block each time. Checking what is there keeps enforcement
            # immediate (anything sensitive is cleared at once, every time)
            # while an already-clear clipboard costs one read and nothing more.
            try:
                on_clipboard = pyperclip.paste()
            except Exception:
                on_clipboard = ""

            if on_clipboard.startswith(_DLP_BLOCK_MSG[:20]):
                # The sensitive content is already gone. Still blocked --
                # there is simply nothing left to overwrite, and nothing new
                # has happened, so this is not a fresh attempt.
                do_clear = True
                logger.debug(
                    f"[AI-MONITOR] Clipboard already cleared, nothing to "
                    f"overwrite | platform={detected_plat}"
                )
            else:
                # Sensitive content really is sitting on the clipboard right
                # now, so this is a genuine attempt whatever happens next --
                # set before the write, because a clear that FAILS is the most
                # important thing in this file to report: the data is going
                # through and nobody is stopping it.
                fresh_attempt = True
                do_clear = True
                try:
                    pyperclip.copy(_DLP_BLOCK_MSG)
                    block_ms = (time.monotonic() - t_detect) * 1000
                    if announce:
                        logger.success(
                            f"[SPEED] Detection-to-block ({source_tag}): {block_ms:.0f} ms | "
                            f"platform={detected_plat}"
                        )
                        logger.success(
                            f"[AI-MONITOR] *** CLIPBOARD CLEARED ***  "
                            f"platform={detected_plat}  Paste is now BLOCKED"
                        )
                    else:
                        # A genuine re-clear of freshly re-copied content --
                        # only the shouting is throttled, never the action.
                        logger.info(
                            f"[AI-MONITOR] Clipboard cleared again ({block_ms:.0f} ms) "
                            f"| platform={detected_plat}"
                        )
                except Exception as exc:
                    # Not blocked -- but still reported, and reported as NOT
                    # blocked, which is the honest record.
                    do_clear = False
                    logger.error(f"[AI-MONITOR] Clipboard clear FAILED: {exc}")

        # ── STEP 2: report to backend ─────────────────────────────────────────
        # EVERY attempt reaches the backend, but repeats inside a 60s window
        # increment a COUNTER on the existing row instead of filing a new one.
        #
        # The three ways to handle a burst, and why this is the one:
        #   * one row per 60s, extras dropped  -- what this used to do. Twenty
        #     blocked copies filed as a single incident reading "1", which is
        #     indistinguishable from one accidental paste. It hid the pattern.
        #   * one row per attempt -- honest, but twenty near-identical rows
        #     bury the queue and still make the reader count them by hand.
        #   * one row saying "23 attempts" -- same information, stated once.
        #
        # `fresh_attempt` is what makes any of it safe: the delayed loop
        # (_ai_monitor_loop) re-checks a stale flag once a second without
        # consulting the clipboard, so "was sensitive content actually ON the
        # clipboard for this call" separates the user copying again from the
        # loop merely looking again. ALERT never clears and so has no such
        # signal -- it keeps the plain timer, defensible for a policy whose
        # point is to notice rather than intervene.
        if action == "ALERT":
            with self._lock:
                since_alert = now - self._last_alerted.get(detected_plat, 0.0)
                do_alert    = since_alert >= _ALERT_COOLDOWN
                if do_alert:
                    self._last_alerted[detected_plat] = now
            repeat_of = None
        else:
            do_alert = fresh_attempt
            repeat_of = None
            if do_alert:
                with self._lock:
                    since_alert = now - self._last_alerted.get(detected_plat, 0.0)
                    if since_alert < _ALERT_COOLDOWN:
                        # Still inside the window: count against the row that
                        # opened it, if we still know which one that was.
                        repeat_of = self._open_attempt.get(detected_plat)
                    if repeat_of is None:
                        # Opening a new window -- the next row becomes the one
                        # repeats accumulate onto.
                        self._last_alerted[detected_plat] = now

        # The POPUP is throttled on the same window. One interruption a minute
        # is plenty -- being asked to justify yourself on every keystroke is
        # how a DLP agent gets switched off -- and a repeat never prompts,
        # because by definition its window already did.
        do_prompt = False
        if do_alert and repeat_of is None:
            with self._lock:
                since_prompt = now - self._last_prompted.get(detected_plat, 0.0)
                do_prompt    = since_prompt >= _ALERT_COOLDOWN
                if do_prompt:
                    self._last_prompted[detected_plat] = now

        if do_alert:
            if do_clear:
                status_word = "BLOCKED"
            elif action == "ALERT":
                status_word = "DETECTED (ALERT-only policy)"
            else:
                status_word = "DETECTED (clipboard clear FAILED)"
            logger.critical(
                f"[AI-MONITOR] !! DATA LEAK {status_word} -- "
                f"{detected_plat} | {detected_source} | via={source_tag}"
            )
            # STEP 1 already cleared the clipboard, so this attempt is
            # enforced no matter what happens here -- but the caller polls,
            # and blocking it blocks the NEXT detection. An unreachable
            # backend costs _MAX_RETRIES * timeout + backoff (~10s refused,
            # ~34s hung), and this is the flagship clipboard path: 34 seconds
            # of not watching the clipboard is 34 seconds of copy-paste into
            # ChatGPT going through untouched.
            def _report(pol=policy, plat=detected_plat, cleared=do_clear,
                        sample=(content_sample or detected_source)[:100],
                        risk=risk_score, prompt=do_prompt, repeat=repeat_of):
                if repeat:
                    updated = self._client.repeat_ai_leak_attempt(repeat)
                    if updated:
                        logger.info(
                            f"[AI-MONITOR] Repeat attempt counted  id={repeat}  "
                            f"attempts={updated.get('attempts')}  platform={plat}"
                        )
                        return
                    # The row is gone (deleted, or a backend that never got
                    # it). Fall through and open a new one rather than lose
                    # the attempt entirely -- an uncounted block is worse than
                    # a duplicate row.
                    logger.warning(
                        f"[AI-MONITOR] Could not count repeat onto {repeat} -- "
                        f"filing a new attempt instead"
                    )
                    with self._lock:
                        self._open_attempt.pop(plat, None)

                attempt = self._client.report_ai_leak_attempt(
                    agent_id=self._agent_id,
                    policy_id=pol.get("id"),
                    platform=plat,
                    method="BROWSER",
                    content_sample=sample,
                    risk_score=risk,
                    blocked=cleared,
                )
                if attempt:
                    logger.success(
                        f"[AI-MONITOR] Incident REPORTED  id={attempt.get('id')}  "
                        f"status={'BLOCKED' if cleared else 'ALERTED'}"
                    )
                    if attempt.get("id"):
                        # Repeats for the rest of this window count onto it.
                        with self._lock:
                            self._open_attempt[plat] = attempt["id"]
                    if cleared and prompt and attempt.get("id"):
                        self._offer_review_request(attempt["id"], pol, plat)
                else:
                    logger.error("[AI-MONITOR] Failed to report incident to backend")

            threading.Thread(target=_report, daemon=True,
                             name="ai-monitor-report").start()

        return action

    def _offer_review_request(self, attempt_id: str, policy: dict, detected_plat: str) -> None:
        """
        Show the block notification in its own thread -- never on the calling
        thread, so the clipboard clear/report above (already done by the time
        this is called) is never delayed by waiting on the user. This never
        restores or unblocks anything -- it only lets the user flag the block
        for an admin to review, with an optional note.
        """
        def _run() -> None:
            reason = (
                f"Policy '{policy.get('name') or 'default'}' blocked a paste "
                f"detected near {detected_plat}."
            )
            # Logged BEFORE the dialog blocks on the user. Without this,
            # "shown and dismissed" and "never rendered" are the same silence
            # -- and the second is a real failure mode, since this is a
            # tkinter window on someone else's desktop. An admin looking at a
            # blocked incident also has to be able to tell whether the worker
            # was ever offered the chance to explain themselves.
            logger.info(
                f"[AI-MONITOR] Review prompt shown  id={attempt_id}  "
                f"platform={detected_plat}"
            )
            note = prompt_review_request(reason)
            if note is None:
                # Dismissed, or timed out. Not an error -- most blocks are
                # accepted without comment -- but it is an outcome, and an
                # outcome that is never recorded may as well not have a
                # dialog behind it.
                logger.info(
                    f"[AI-MONITOR] Review prompt dismissed  id={attempt_id}"
                )
                return

            result = self._client.request_review_ai_leak_attempt(attempt_id, note or None)
            if result:
                logger.success(f"[AI-MONITOR] Review requested  id={attempt_id}")
            else:
                logger.error("[AI-MONITOR] Failed to record review request to backend")

        threading.Thread(target=_run, daemon=True, name="review-prompt").start()


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

        # Note any AI window that is currently ANNOUNCING itself, every poll.
        #
        # This has to happen unconditionally, not inside the gate below. A
        # ChatGPT tab is identifiable by title only until you send it a
        # message, and the gate opens only after something sensitive is
        # already on the clipboard -- by which time the tab has usually been
        # renamed and there is nothing left to learn from. Cheap on purpose:
        # a window enumeration, no UI Automation, no process scan.
        blocker.observe_ai_windows()

        # Only do expensive detection if clipboard was recently flagged
        if state.clipboard_flagged_recently(within_seconds=30.0):
            t_flagged = state.sensitive_clip_monotonic()
            ctx = state.sensitive_clip_context()
            action_taken = blocker.check_and_block(
                t_detect=t_flagged,
                content_sample=ctx.get("content_sample") or "",
                risk_score=ctx.get("risk_score") or 0.95,
                source_tag="CLIPBOARD_DELAYED",
                detections=ctx.get("detections"),
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
