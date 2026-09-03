/**
 * DLP Browser Sensor — reports which AI platform tab is active.
 *
 * WHAT IT SENDS
 * One platform name, or null, plus the hostname it came from. Nothing else.
 * Not the URL path, not the page, not what you typed. The agent decides what
 * to do about it; this only answers "is an AI tab in front right now".
 *
 * WHY IT EXISTS
 * The agent otherwise identifies AI platforms from WINDOW titles, and a
 * browser puts every tab in one window. That gap is not cosmetic:
 *   - ChatGPT renames its tab to the conversation topic once you start
 *     chatting, so the tab stops matching exactly when it starts mattering;
 *   - closing that tab leaves the window open, so anything that remembers
 *     the window keeps blocking pastes that are going nowhere.
 * Neither is solvable from outside the browser. Inside it, both are trivial.
 */

// Matched against the tab's HOSTNAME, so a page cannot spoof its way in or
// out of a match by putting text in its title. Mirrors the agent's platform
// vocabulary in agent/src/ai_domain_monitor.py.
const PLATFORMS = [
  [/(^|\.)chatgpt\.com$/, "OPENAI_CHATGPT"],
  [/(^|\.)chat\.openai\.com$/, "OPENAI_CHATGPT"],
  [/(^|\.)openai\.com$/, "OPENAI_CHATGPT"],
  [/(^|\.)claude\.ai$/, "ANTHROPIC_CLAUDE"],
  [/(^|\.)anthropic\.com$/, "ANTHROPIC_CLAUDE"],
  [/(^|\.)gemini\.google\.com$/, "GOOGLE_GEMINI"],
  [/(^|\.)bard\.google\.com$/, "GOOGLE_GEMINI"],
  [/(^|\.)copilot\.microsoft\.com$/, "MICROSOFT_COPILOT"],
  [/(^|\.)perplexity\.ai$/, "PERPLEXITY"],
  [/(^|\.)poe\.com$/, "POE"],
  [/(^|\.)character\.ai$/, "CHARACTER_AI"],
  [/(^|\.)chat\.mistral\.ai$/, "MISTRAL"],
  [/(^|\.)grok\.com$/, "GROK"],
  [/(^|\.)x\.ai$/, "GROK"],
  [/(^|\.)meta\.ai$/, "META_AI"],
  [/(^|\.)chat\.deepseek\.com$/, "DEEPSEEK"],
  [/(^|\.)huggingface\.co$/, "HUGGINGFACE"],
  [/(^|\.)you\.com$/, "YOU_COM"],
  [/(^|\.)pi\.ai$/, "PI_AI"],
  [/(^|\.)groq\.com$/, "GROQ"],
  [/(^|\.)cohere\.com$/, "COHERE"],
];

const ENDPOINT = "http://127.0.0.1:8765/tab";

// Re-sent even when nothing changed, so the agent can tell "no AI tab open"
// from "the extension is gone". Silence has to mean something.
const HEARTBEAT_MS = 5000;

function platformFor(url) {
  let host;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return null; // about:blank, chrome://, a file — not a platform
  }
  for (const [pattern, name] of PLATFORMS) {
    if (pattern.test(host)) return { platform: name, detail: host };
  }
  return null;
}

async function activeTab() {
  // lastFocusedWindow, not currentWindow: a service worker has no window of
  // its own, and what matters is the tab the user is actually looking at.
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    return tab || null;
  } catch {
    return null;
  }
}

let lastSent = null;

async function report(force = false) {
  const tab = await activeTab();
  const hit = tab && tab.url ? platformFor(tab.url) : null;
  const payload = {
    platform: hit ? hit.platform : null,
    detail: hit ? hit.detail : "",
  };

  const signature = `${payload.platform}|${payload.detail}`;
  if (!force && signature === lastSent) return; // nothing changed
  lastSent = signature;

  try {
    await fetch(ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    // The agent isn't running. Not an error worth surfacing — the extension
    // is a sensor, and a sensor with nobody listening just keeps sensing.
    lastSent = null; // resend once it comes back
  }
}

// Every way the active tab can change.
chrome.tabs.onActivated.addListener(() => report());
chrome.tabs.onUpdated.addListener((_id, info) => {
  // Navigation inside the same tab — the case a window title never reveals.
  if (info.url || info.status === "complete") report();
});
chrome.tabs.onRemoved.addListener(() => report(true));
chrome.windows.onFocusChanged.addListener(() => report());
chrome.runtime.onStartup.addListener(() => report(true));
chrome.runtime.onInstalled.addListener(() => report(true));

// MV3 service workers are evicted when idle; the alarm wakes this one so the
// heartbeat keeps the agent's picture fresh.
chrome.alarms.create("dlp-heartbeat", { periodInMinutes: 0.25 });
chrome.alarms.onAlarm.addListener(() => report(true));

setInterval(() => report(true), HEARTBEAT_MS);
report(true);
