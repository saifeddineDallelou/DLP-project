/**
 * Stops a sensitive file being attached, from inside the page.
 *
 * WHY THIS HAS TO LIVE HERE
 * Opera draws its own recent-files panel inside the browser window: click
 * attach in ChatGPT and a list of recent downloads appears, already in the
 * page. No Windows dialog is ever created, so the agent's file-dialog monitor
 * has nothing to find -- a sensitive CSV uploaded that way went straight up,
 * while the same file picked through Explorer was blocked.
 *
 * Nothing outside the browser can see that upload. Inside it, the file is an
 * ordinary <input type="file"> change event, and a capture-phase listener
 * sees it before the page's own handler does. That ordering is the whole
 * point: once ChatGPT's script has read the File, the data is in its hands
 * and clearing the input achieves nothing.
 *
 * WHAT IT SENDS
 * The filename and up to 5 KB of text, to 127.0.0.1 only, and only for a file
 * the user just chose to upload to an AI platform. Never page content, never
 * anything the user did not just hand to a third party themselves.
 */

const ENDPOINT = "http://127.0.0.1:8765/upload";

// Matches the agent's cap, so the two never disagree about what was checked.
const MAX_TEXT = 5000;

// Files worth reading as text. A JPEG's bytes are not going to classify, and
// decoding megabytes of binary to hand back nothing wastes the seconds the
// user is waiting.
const TEXT_LIKE = /\.(txt|csv|tsv|json|xml|ya?ml|md|log|htm|html|sql|ini|cfg|conf|env|py|js|ts|java|c|cpp|cs|go|rb|php|sh|ps1)$/i;

function platformFromHost() {
  const host = location.hostname.toLowerCase();
  if (/(^|\.)chatgpt\.com$|(^|\.)openai\.com$/.test(host)) return "OPENAI_CHATGPT";
  if (/(^|\.)claude\.ai$|(^|\.)anthropic\.com$/.test(host)) return "ANTHROPIC_CLAUDE";
  if (/(^|\.)gemini\.google\.com$|(^|\.)bard\.google\.com$/.test(host)) return "GOOGLE_GEMINI";
  if (/(^|\.)copilot\.microsoft\.com$/.test(host)) return "MICROSOFT_COPILOT";
  if (/(^|\.)perplexity\.ai$/.test(host)) return "PERPLEXITY";
  if (/(^|\.)grok\.com$|(^|\.)x\.ai$/.test(host)) return "GROK";
  if (/(^|\.)chat\.deepseek\.com$/.test(host)) return "DEEPSEEK";
  if (/(^|\.)chat\.mistral\.ai$/.test(host)) return "MISTRAL";
  if (/(^|\.)meta\.ai$/.test(host)) return "META_AI";
  if (/(^|\.)poe\.com$/.test(host)) return "POE";
  return null;
}

function readAsText(file) {
  return new Promise((resolve) => {
    if (!TEXT_LIKE.test(file.name)) return resolve("");
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || "").slice(0, MAX_TEXT));
    reader.onerror = () => resolve("");
    // Only the head of the file: enough for the classifier, and it keeps a
    // large file from stalling the page.
    reader.readAsText(file.slice(0, MAX_TEXT * 4));
  });
}

async function shouldBlock(file, platform) {
  const text = await readAsText(file);
  if (!text) return false;                 // nothing to judge on
  try {
    const res = await fetch(ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: file.name, text, platform }),
    });
    if (!res.ok) return false;
    const body = await res.json();
    return body.block === true;
  } catch (err) {
    // The agent is not running or not reachable. Failing open is deliberate:
    // this extension must not become a reason the browser cannot upload
    // anything, and the agent's other channels still cover the OS routes.
    console.warn("[DLP] could not reach the agent:", String(err));
    return false;
  }
}

function notify(name) {
  // The agent shows its own dialog, but that is a separate window on a
  // desktop the user may not be looking at. A line in the page, where their
  // attention already is, is what makes the block legible rather than
  // mysterious.
  const el = document.createElement("div");
  el.textContent = `Blocked by DLP: “${name}” contains sensitive data.`;
  el.style.cssText = [
    "position:fixed", "z-index:2147483647", "left:50%", "top:24px",
    "transform:translateX(-50%)", "background:#7f1d1d", "color:#fff",
    "padding:10px 16px", "border-radius:8px", "font:14px system-ui,sans-serif",
    "box-shadow:0 4px 16px rgba(0,0,0,.4)", "max-width:80vw",
  ].join(";");
  document.documentElement.appendChild(el);
  setTimeout(() => el.remove(), 6000);
}

// Inputs whose event we are re-dispatching after clearing them. Without this
// the re-dispatch below is caught by this very listener and the file is
// checked again, forever.
const passing = new WeakSet();

// Capture phase, on the document: this runs before any handler the page has
// registered on the input itself, which is the only moment at which clearing
// the selection still means anything.
document.addEventListener("change", async (event) => {
  const input = event.target;
  if (!(input instanceof HTMLInputElement) || input.type !== "file") return;
  if (!input.files || input.files.length === 0) return;
  if (passing.has(input)) {
    passing.delete(input);
    return;                               // our own re-dispatch, already cleared
  }

  const platform = platformFromHost();
  if (!platform) return;

  const files = Array.from(input.files);

  // Stop the page seeing this event until we know. Re-dispatched below if the
  // files turn out to be fine, so an allowed upload behaves exactly as it did
  // before the extension existed.
  event.stopImmediatePropagation();
  event.preventDefault();

  let blockedName = null;
  for (const file of files) {
    if (await shouldBlock(file, platform)) {
      blockedName = file.name;
      break;
    }
  }

  if (blockedName) {
    input.value = "";                     // drop the selection entirely
    notify(blockedName);
    return;
  }

  // Clean: hand the event back to the page. A fresh event is required --
  // the original has already been dispatched and cannot be re-run.
  passing.add(input);
  input.dispatchEvent(new Event("change", { bubbles: true }));
}, true);

console.log("[DLP] upload guard active on", location.hostname);
