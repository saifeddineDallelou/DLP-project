# DLP Browser Sensor

Tells the local DLP agent which AI platform tab is active — and nothing else.

## Why it exists

Every other way the agent identifies an AI platform reads **window titles**,
and a browser puts every tab in one window. That single mismatch caused three
failures, each found by testing rather than reading:

- ChatGPT rewrites its tab title to the conversation topic the moment you send
  a message, so a tab in active use — the only state it is in when someone
  actually pastes customer data into it — stopped matching.
- The address-bar fallback meant to cover that **cannot run on Opera**: the
  whole window exposes seven accessibility nodes and not one `Edit` control.
- Remembering a window that once identified itself patched the rename, but a
  window is not a tab. Close the ChatGPT tab and the window stays open, so the
  agent kept blocking pastes that were going nowhere.

None are solvable from outside the browser. Inside it, all three are trivial —
which is why Purview and Netskope ship an extension instead of guessing.

## Install (development)

`opera://extensions` — or `chrome://extensions`, `edge://extensions` — then:

1. Turn on **Developer mode**
2. **Load unpacked** — *Charger l'extension non empaquetée*
3. Select this folder (the one containing `manifest.json`)

**Do not use "Pack extension"** (*Empaqueter l'extension*). That builds a
`.crx` for distribution and generates a `.pem` private key you then have to
protect; it is not how you run the extension locally. Both are gitignored.

Loading unpacked is free in every Chromium browser. The $5 fee is only for
publishing to the Chrome Web Store, which a real deployment would not use
anyway — it would push the extension by group policy.

## Checking it works

The agent's listener reports its own state:

```bash
curl http://127.0.0.1:8765/health
```

```json
{"status":"ok","platform":"OPENAI_CHATGPT","detail":"chatgpt.com",
 "extensionConnected":true,"secondsSinceReport":1.2}
```

`extensionConnected` is the field that matters: `platform: null` means the
same thing whether no AI tab is open or nothing is reporting at all, and an
install that silently fails looks exactly like one that works.

If it is `false`, open the extension's **service worker** console — the
background script logs both its startup and any failure to reach the agent.

## What it sends

One platform name, or `null`, plus the hostname:

```json
{"platform": "OPENAI_CHATGPT", "detail": "chatgpt.com"}
```

No page content, no keystrokes, no browsing history, and **not the URL path** —
a path carries the conversation. Matching is on hostname, so a page cannot
talk its way in or out of a match through its title.

Enforcement does not live here. The extension replaces a guess with a fact;
the agent still decides what to do about it.

## Upload guard

The sensor reports which AI tab is active. The content script does something
different: it stops a sensitive file being attached at all.

That exists because some uploads never touch a Windows dialog. Opera draws its
own recent-files panel inside the browser window -- click attach in ChatGPT and
a list of recent downloads appears, already in the page -- so the agent's
file-dialog monitor has nothing to find. A sensitive CSV uploaded that way went
straight up while the same file picked through Explorer was blocked.

Nothing outside the browser can see that. Inside it, the file is an ordinary
`<input type="file">` change event, and a capture-phase listener sees it before
the page's own handler does. That ordering is the point: once ChatGPT's script
has read the File, the data is in its hands and clearing the input achieves
nothing.

**What it sends:** the filename and up to 5 KB of text, to `127.0.0.1:8765`
only, and only for a file the user just chose to upload to an AI platform.
Binary files are not read at all. Never page content, never browsing history.

**If the agent is not running** the upload proceeds. Failing open is
deliberate: this must not become the reason a browser cannot upload anything,
and the agent's other channels still cover the OS routes.

After editing the extension, reload it in `opera://extensions` -- a content
script change needs the page reloaded too.
