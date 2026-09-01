# Architecture

How the four components divide the problem, and why the boundaries sit where
they do. For setup and run commands, see the [root README](../README.md).

---

## 1. The separation of concerns

The system splits one question — *"should this data be allowed to leave?"* —
into four parts that can each change without touching the others.

```
   ┌──────────────────────────────────────────────────────────────────┐
   │  frontend/     React dashboard                                   │
   │                Humans configure rules and triage what happened    │
   └───────────────────────────────┬──────────────────────────────────┘
                                   │  REST + JWT
   ┌───────────────────────────────▼──────────────────────────────────┐
   │  backend/      Express + Prisma + PostgreSQL                     │
   │                Owns ALL persistent state and admin configuration  │
   └───────────▲───────────────────────────────────┬──────────────────┘
               │ policies, app rules               │ incidents, events
               │ (pulled every 3 s)                │ (pushed after the fact)
   ┌───────────┴───────────────────────────────────▼──────────────────┐
   │  agent/        Python, Windows endpoint                          │
   │                Watches 9 channels, decides, ENFORCES              │
   └───────────────────────────────┬──────────────────────────────────┘
                                   │  POST /classify
   ┌───────────────────────────────▼──────────────────────────────────┐
   │  classifier/   FastAPI, stateless                                │
   │                Answers only: "is this content sensitive?"         │
   └──────────────────────────────────────────────────────────────────┘
```

The rule that keeps this clean:

| Component | Knows about | Deliberately does *not* know about |
|---|---|---|
| `classifier` | Content patterns | Policies, users, agents, actions |
| `backend` | Policies, incidents, users, fleet | Windows, clipboards, enforcement |
| `agent` | Windows internals, enforcement | Database, other endpoints |
| `frontend` | The REST API | Everything else |

The classifier is stateless on purpose. It can be scaled, replaced or called
from anywhere, and it never needs a migration when the policy model changes.

---

## 2. Compliance tags: how detection reaches a policy

This is the seam that stops the same logic being written twice.

The classifier tags every detection with a compliance rule:

```json
{ "type": "credit_card", "value": "****-****-****-4242",
  "rule": "PCI-DSS", "confidence": 0.95 }
```

A policy in the database carries the *same* vocabulary in its `conditions`
JSON field:

```json
{ "complianceRule": "PCI-DSS", "minRiskScore": 0.7 }
```

So `agent/src/policy_resolver.py` resolves "which policy does this violate"
by matching one string against the other. It re-implements no detection logic,
and adding a new detector or a new policy requires no change on the other side.

```
classifier detection.rule ──── "PCI-DSS" ────► policy.conditions.complianceRule
                                                            │
                                                            ▼
                                              action: ALLOW │ ALERT │ BLOCK │ QUARANTINE
```

---

## 3. Request flow of a single leak attempt

Clipboard copy into ChatGPT, the most common path:

```
 t=0ms     clipboard_watcher.py polls, sees new text
              │
 t≈5ms        ├──► POST http://127.0.0.1:8000/classify
              │       { "text": "..." }
              │
 t≈40ms       ◄──   { "risk_score": 0.9,
              │       "detections": [{ "rule": "PCI-DSS", ... }],
              │       "evidence_excerpt": "..." }
              │
 t≈41ms    policy_resolver.py   PCI-DSS → "Cardholder data" policy → BLOCK
              │
 t≈42ms    ai_domain_monitor.py (AiBlocker) scans foreground windows
              │                  → ChatGPT tab is open
              │
 t≈45ms    ★ CLIPBOARD CLEARED — enforcement complete
              │
              ├──► POST /api/ai-policy/attempt        (backend, async)
              ├──► review_prompt.py shows the user a notice
              └──► quarantine.py, if the action was QUARANTINE
```

Two ordering decisions matter here:

**Enforcement precedes reporting.** The clipboard is cleared before the backend
is contacted. A slow, unreachable or overloaded backend can therefore never
delay or prevent a block. The incident record is written on a best-effort basis
afterwards.

**The classify call is synchronous and local.** It is the only thing standing
between detection and enforcement, so the agent talks to `127.0.0.1` rather than
`localhost` — resolving `localhost` on Windows can attempt IPv6 `::1` first and
cost roughly two seconds on first use, which is long enough to lose the race
against a fast double-click in the file-dialog monitor.

### The delayed case

If no AI window is open at the moment of the copy, there is nothing to block
yet — but the content is still in the clipboard. `agent_state.py` records the
detection (including the classify result, so the same policy resolves later),
and `ai_domain_monitor.py`'s 1-second loop clears the clipboard if the user
opens an AI platform within 30 seconds.

---

## 3a. Data at rest

Everything in §3 is triggered by *activity*. None of it can see sensitive data
that has been sitting on a share for two years — a separate DLP pillar
(Forcepoint calls it Discovery, Purview ships an on-prem scanner, and the
standalone category is sold as DSPM).

`agent/src/discovery.py` fills it without new detection logic: walk a tree,
call the same `classify()` the live watcher calls, report what is found. That
reuse is the point — nothing here decides what is sensitive, so there is no
second opinion to keep in sync with the classifier.

It is **read-only** by deliberate choice. A crawler with write authority over a
file share is a very different risk to sign off on, and remediating findings it
cannot see the context of would be reckless. Auto-remediation is a real feature
of commercial products and a stated non-goal here.

It also serves a second purpose that only became apparent once it existed:
running the classifier over a large corpus of *ordinary* text is the only way
to measure its false-positive rate. The live monitors classify small fragments
that are already suspicious, so a loose pattern never shows up. The first full
scan of this repository reported the README as cardholder data — see the
SWIFT/BIC fix in `classifier/src/engine.py`.

## 4. The agent's threading model

`main.py` starts every monitor as a daemon thread over one shared `AgentState`,
and a single `threading.Event` stops them all.

```
main()
  │
  ├── heartbeat            every 30 s   → PATCH /api/agents/:id/heartbeat
  ├── policy-refresh       every  3 s   → GET  /api/policies
  ├── app-rule-refresh     every  3 s   → GET  /api/app-rules
  │
  ├── file_watcher         watchdog, event-driven
  ├── clipboard_watcher    poll @ 0.3 s   ─┐ share AiBlocker for
  ├── ai_domain_monitor    poll @ 1 s     ─┘ same-cycle blocking
  ├── ueba_collector       flush @ 60 s
  ├── screenshot_monitor   clipboard-image poll
  ├── app_launch_monitor   psutil @ 15 s
  ├── file_dialog_monitor  window poll
  └── app_file_monitor     periodic re-check
        │
        └── all share ──► AgentState  (lock-guarded counters, flags,
                                       recently-flagged file list)
```

Policies and app rules are **pulled on a 3-second timer**, not pushed. A fleet
of endpoints cannot be asked to restart to pick up a policy edit, and pulling
avoids the agent needing an inbound listening port.

---

## 5. Why some monitors poll

Several monitors poll rather than hook, and each is a deliberate concession to
a Windows limitation rather than an oversight:

| Monitor | Why not an event hook |
|---|---|
| `screenshot_monitor` | Windows 10/11 handles `PrtScn` and `Win+Shift+S` in the Shell before any `SetWindowsHookEx` hook sees them. Confirmed unchanged with admin rights. Polling the clipboard for an image works regardless of *how* the screenshot was taken. |
| `file_dialog_monitor` | There is no global "a file was chosen in a dialog" event. It polls for window class `#32770` and reads the filename before the user confirms. |
| `app_file_monitor` | Catching a process that opens a file *after* the filesystem event already fired would need ETW or a kernel driver. A periodic re-check narrows the gap to one poll interval. |

Known gaps are documented in the module docstrings — notably OLE drag-and-drop
in `file_dialog_monitor.py`, which never touches the clipboard or a dialog.

---

## 5a. UEBA scoring

Two endpoints with distinct jobs, frequently confused:

| | `POST /baseline/:userId/recompute` | `GET /risk-score/:userId` |
|---|---|---|
| Reads | last 30 days | last 24 hours |
| Produces | the baseline | a score, and why |
| Judges | nothing | everything |

**Recompute builds the ruler.** It takes the user's recorded `BehaviorEvent`
history, buckets it per calendar day, and stores the **median across active
days** — files touched, volume moved, USB inserts — plus 10th/90th-percentile
working hours.

Two deliberate choices there. *Median, not mean*: one 8 GB afternoon would
otherwise shift the number every subsequent day is judged against. *Active days
only*: padding with weekends and leave drags every baseline toward zero and
makes an ordinary Monday look anomalous.

**Risk score does the measuring.** Each metric becomes a ratio of today against
that baseline, converted to a 0–1 signal that saturates at
`FULL_SIGNAL_RATIO` (5× normal), then weighted — volume 35%, files 25%, hours
20%, USB 20%.

Two properties are worth stating, because they are not what a plain weighted
mean would give you:

*A single fully anomalous metric is sufficient.* Exfiltration is
characteristically narrow and deep — one metric wildly abnormal, the rest
ordinary. A weighted mean demands *breadth* of anomaly, so a user moving 80×
their usual volume could not reach HIGH while their working hours stayed
normal. `DOMINANT_SIGNAL_FACTOR` sets the floor a single maxed metric scores on
its own (0.75, which clears HIGH unaided).

*A zero baseline is capped below full signal.* "Has not done this during the
window" is weaker evidence than a measured ratio, so novel behaviour raises the
score without deciding it — otherwise a new starter's first USB insert would
alone be a HIGH finding.

**Peer groups** are the defence against a poisoned baseline. Whoever controls
the baseline controls whether UEBA ever fires: a recompute over a deliberately
narrow window makes that day's behaviour the new normal, silently disabling
detection for one person with no trace anywhere else in the system — which is
why `RECOMPUTE_BEHAVIOR_BASELINE` records its `days` window in the audit trail.
Where a `department` is declared, each metric takes `max(self, peer)`, so a
corrupted self-baseline is still caught by a peer median that did not move.
Max rather than a blend precisely because blending lets the corrupted half drag
the result back down. A user with no department is scored self-relative only.

The known limit: peer groups are admin-declared, not discovered. The agent
reports a Windows username and has no idea what team that person is on.

**Priority content.** A deviation score says how *much* moved, never whether it
mattered — 500 MB of build artefacts and 500 MB of cardholder data deviate
identically. The classifier already tags every detection with a compliance rule
and the resolved `Policy` carries a severity, so incidents and AI leak attempts
raised on the endpoints a user was active on add a capped boost weighted by
severity. Capped, because sensitivity should sharpen a deviation score rather
than replace it.

Honest limitation: `BehaviorEvent` carries `userId` and `Incident` carries
`agentId`, with no direct link. A user is therefore associated with incidents on
the endpoints they were active on in the same window, which on a shared
workstation attributes an incident to whoever else was active there. Fixing it
properly means the agent stamping the OS user onto every incident it reports.

**Baselines refresh themselves.** A baseline that only changes when an admin
remembers to click Recompute is a snapshot of whenever that last happened, and
it drifts out of date exactly as someone's role changes — a developer moving
onto a data-heavy project keeps being scored against the job they used to do,
alerting daily until somebody notices. `lib/baseline-refresh.js` recomputes any
baseline older than `BASELINE_STALE_HOURS`, sharing `recomputeBaseline()` with
the manual endpoint so the two cannot drift apart.

A user with no events in the window is **skipped, not zeroed**: someone back
from three weeks' leave should return to the baseline they had, not to one
saying they normally do nothing, which would flag their first day back.

Scheduled refreshes are audited with a **null actor** and `source: SCHEDULED`.
The absent actor is the point — it separates an automatic refresh from an admin
reshaping a baseline by hand, which is what the trail exists to catch.

It is a plain `setInterval` started in `index.js`, not in `app.js`, so importing
the app in tests never starts a timer. If this ever runs multi-instance, that is
the piece to replace: every instance would refresh the same baselines at once.

## 6. Data model

```
User ──assigned──► Incident ◄──── Agent ────► BehaviorEvent
                      │                              │
                   Policy                   UserBehaviorBaseline
                      │
                AiLeakAttempt ◄──── Agent
                                            AppRule (standalone)
```

| Model | Holds |
|---|---|
| `User` | Dashboard accounts. Roles: `ADMIN`, `ANALYST`, `VIEWER` |
| `Policy` | `conditions` JSON, `action`, `severity`, `enabled`, `version` |
| `AppRule` | Restricted-app keyword + label. Standalone by design |
| `Agent` | Enrolled endpoint, `token`, `lastSeen` heartbeat |
| `Incident` | A violation: channel, severity, masked `evidence`, `riskScore` |
| `AiLeakAttempt` | An AI-platform leak: `platform`, `method`, `blocked` |
| `BehaviorEvent` | Raw UEBA signal from an endpoint |
| `UserBehaviorBaseline` | Per-user normal, plus an optional `department` peer group |
| `AuditLog` | Admin action trail |

Two design notes:

**`AppRule` intentionally has no relations.** Being on the restricted-apps list
is not itself a violation — the app runs normally. It is only an additional
risky-destination signal when sensitive content is about to touch it. This
mirrors Microsoft Purview Endpoint DLP's "Restricted apps" list, which likewise
never blocks an app from launching, only from touching a protected file.

**Blocks are silent, and users cannot self-unblock.** `Incident` and
`AiLeakAttempt` both carry `reviewRequested`, `justification` and `adminNote`.
A worker who is blocked may *request* a review with a short note
(`review_prompt.py`); only an `ADMIN` or `ANALYST` decides the outcome. There is
deliberately no self-service unblock path.

This is a considered divergence from commercial DLP, not a missing feature.
Microsoft Purview, Forcepoint and most enterprise suites ship *block with
override*: the user types a business justification and proceeds anyway, with
the override recorded. That design optimises for a real problem — false
positives creating friction at scale, in organisations where a blocked
executive escalates within minutes.

This project optimises for the opposite property. An override path is only as
strong as the user's incentive not to use it, and the single most likely person
to click through a block is precisely the person deliberately exfiltrating data.
The migration history records the change of mind explicitly: an `overridden`
column was added, then renamed to `review_requested`
(`20260831171700_rename_override_to_review_request`) once the block became
silent and final.

The cost is accepted openly: a false positive here blocks a legitimate worker
until an admin acts, where a commercial product would let them proceed. If this
were deployed at organisational scale, `Policy.allowOverride` — override enabled
per-policy rather than globally — is the natural way to reintroduce it without
weakening the high-severity rules.

---

## 7. Trust boundaries

Not every endpoint is authenticated the same way, and the split is intentional:

| Endpoint | Auth | Why |
|---|---|---|
| `POST /api/agents/enroll` | none | Bootstrap — this is how an agent gets its token |
| `PATCH /api/agents/:id/heartbeat` | `x-agent-token` | High frequency, low value |
| `POST /api/incidents` | `x-agent-token` or JWT | Agents must be able to report without a user session |
| `POST /api/ai-policy/attempt` | `x-agent-token` or JWT | Same |
| `POST /api/ueba/events` | `x-agent-token` or JWT | Same |
| `GET /api/policies`, `/api/app-rules` | none | Agents need these before any user logs in |
| everything else | JWT | Dashboard traffic |
| write operations | JWT + role | `ADMIN` / `ANALYST` only |

Sensitive values are masked by the classifier **before** they ever reach the
backend, so an incident record holds `****-****-****-4242`, never the card
number. Evidence is stored as `Bytes` with an encryption key configured
separately (`EVIDENCE_ENCRYPTION_KEY`).

That guarantee only holds because the agent reports *from the classifier's
masked detections*, never from the raw content it inspected — see
`agent/src/evidence.py`. This was not originally true. The clipboard paths
masked the raw copied text with a length heuristic that returned anything
30 characters or shorter unchanged, and sensitive values are short: a payment
card is 19 characters, a US SSN is 11. Live testing wrote
`" 4111 1111 1111 1111"` into `AiLeakAttempt.contentSample` verbatim — a DLP
tool retaining unmasked cardholder data, which is itself a PCI-DSS
Requirement 3 failure.

The lesson generalises beyond the one bug: **the agent should never be the
component deciding what is sensitive enough to redact.** The classifier already
made that determination and already returns a safe representation. Any second
redaction rule in the agent is a second place to get it wrong.
