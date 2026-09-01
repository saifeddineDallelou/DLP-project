# DLP Platform

An endpoint **Data Loss Prevention** system: it detects sensitive data (payment
cards, national IDs, health identifiers, credentials) leaving a Windows
workstation, and blocks the transfer before it completes — with a particular
focus on leaks into AI platforms such as ChatGPT, Claude and Gemini.

The system is built from four independent components:

| Component | Language / stack | Role |
|---|---|---|
| [`classifier/`](#classifier--detection-engine) | Python, FastAPI | Decides **what is sensitive**. Stateless content-scanning microservice. |
| [`backend/`](#backend--control-plane) | Node, Express, Prisma, PostgreSQL | Decides **what the rules are**. Stores policies, incidents, agents, behaviour data. |
| [`agent/`](#agent--windows-endpoint-monitor) | Python | Decides **when to act**. Runs on the endpoint, watches 9 leak channels, enforces the action. |
| [`frontend/`](#frontend--admin-dashboard) | React, Vite, Tailwind | Where a human **sees and configures** all of it. |

A full description of how they fit together — including the request flow of a
single leak attempt — is in [`docs/architecture.md`](docs/architecture.md).

---

## How a leak gets stopped

The short version of the flow. Each numbered step is a real network hop:

```
  User copies a customer list into ChatGPT
              │
              ▼
   [agent]  clipboard_watcher notices new clipboard text      (polls @ 0.3s)
              │
              │ 1. POST /classify  ─────────────────►  [classifier]
              │ ◄─────────  risk_score 0.9, PCI-DSS  ──────────┘
              ▼
   [agent]  policy_resolver maps PCI-DSS → policy → action = BLOCK
              │
              ▼
   [agent]  ai_domain_monitor confirms an AI window is focused
              │
              ▼
   [agent]  clipboard cleared — the paste never lands
              │
              │ 2. POST /api/ai-policy/attempt ─────►  [backend] ──► PostgreSQL
              ▼
   [frontend]  the attempt appears on the AI Policy page
```

Detection to block is **sub-second**, because the classify round trip and the
clipboard clear happen in the same event cycle. Reporting to the backend is
deliberately *after* the block, so a slow or offline backend can never delay
enforcement.

---

## Components

### `classifier/` — detection engine

A stateless FastAPI microservice. It receives text (or a base64 file) and
returns a risk score, plus the list of things it found.

- 13 regex pattern detectors: credit card (Luhn-validated), IBAN, SWIFT/BIC,
  US SSN, UK NIN, passport, French CIN, Tunisian CIN, email, Tunisian and
  international phone, private-key blocks, cloud API keys
- Keyword dictionary scoring on top of the patterns
- Every detection is tagged with a compliance rule — `PCI-DSS`, `HIPAA`,
  `GDPR`, `GDPR/loi-09-08`, `INTERNAL` — which is what lets the agent map a
  detection to a policy without duplicating any detection logic
- Values are **masked** in the response (`****-****-****-4242`), so sensitive
  data is never stored in an incident record

It holds no state and knows nothing about policies, users or agents.

```bash
cd classifier
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8000     # http://127.0.0.1:8000/health
python -m pytest -q                            # 25 tests
```

### `backend/` — control plane

Express API over PostgreSQL via Prisma. It owns all persistent state and all
admin configuration. JWT auth with three roles (`ADMIN`, `ANALYST`, `VIEWER`).

| Route module | Purpose |
|---|---|
| `auth.js` | Login, refresh token |
| `policies.js` | DLP policy CRUD — conditions, severity, action |
| `app-rules.js` | Admin-configured "restricted apps" list |
| `agents.js` | Endpoint enrollment, heartbeat, fleet listing |
| `incidents.js` | Incident intake from agents, triage, review requests |
| `ai-policy.js` | AI-platform leak attempts and their adjudication |
| `ueba.js` | Behaviour events, per-user baselines, risk scoring |
| `classify.js` | Authenticated proxy to the classifier |
| `reports.js` | Daily aggregate reporting |
| `audit.js` | Read-only audit trail — filter, paginate, per-object history |

```bash
cd backend
npm install
npx prisma migrate deploy && npm run seed
npm run dev                                    # http://localhost:3001
npm test                                       # 111 tests, 9 suites
```

### `agent/` — Windows endpoint monitor

The enforcement point. `src/main.py` enrolls the endpoint, then starts nine
monitor threads that each cover a distinct leak channel. Every module carries a
docstring explaining the vector it covers and its known gaps.

**Leak channel monitors**

| Module | Channel it covers |
|---|---|
| `file_watcher.py` | Files created/modified in watched folders |
| `clipboard_watcher.py` | Copied text, and copied *files* (`CF_HDROP`) |
| `ai_domain_monitor.py` | An AI platform window being open or focused |
| `file_dialog_monitor.py` | Native "Open File" pickers — a browser attach, which never touches the clipboard |
| `screenshot_monitor.py` | Screenshots, via clipboard-image polling |
| `app_launch_monitor.py` | Launches of watchlisted exfiltration tools |
| `app_file_monitor.py` | Restricted apps holding an already-flagged file |

**Decision and enforcement**

| Module | Responsibility |
|---|---|
| `policy_resolver.py` | Detection → policy → action (`ALLOW`/`ALERT`/`BLOCK`/`QUARANTINE`) |
| `app_rule_resolver.py` | Is the current destination a restricted app? |
| `quarantine.py` | Moves the source file out of reach — what makes QUARANTINE differ from BLOCK |
| `review_prompt.py` | Post-block dialog letting the user request an admin review |

**Support**

| Module | Responsibility |
|---|---|
| `api_client.py` | HTTP to backend and classifier, with a pooled session |
| `agent_state.py` | Thread-safe state shared across all monitors |
| `file_extractor.py` | Text extraction from PDF, DOCX, XLSX, PPTX and plain formats |
| `ueba_collector.py` | Periodic behaviour-event flush |

```bash
cd agent
pip install -r requirements.txt
cp .env.example .env                           # then edit WATCH_DIRS
python src/main.py
python -m pytest -q                            # 275 tests
```

> Windows-only. It depends on Win32 window APIs and clipboard formats.
> The screenshot monitor polls the clipboard rather than hooking the keyboard,
> because Windows 10/11 handles `PrtScn` and `Win+Shift+S` in the Shell before
> any user-mode hook sees them — admin rights do not change this.

### `frontend/` — admin dashboard

React + Vite + Tailwind, `recharts` for visualisation.

| Page | Purpose |
|---|---|
| `Dashboard.jsx` | Fleet and incident overview |
| `Incidents.jsx` | Incident queue and triage |
| `AiPolicy.jsx` | AI leak attempts, adjudication |
| `Policies.jsx` | Policy editor |
| `AppRules.jsx` | Restricted apps list |
| `UEBA.jsx` | Behaviour baselines and risk scores |
| `Agents.jsx` | Enrolled endpoints |
| `Reports.jsx` | Daily aggregates |
| `Audit.jsx` | Audit trail of privileged actions |

```bash
cd frontend
npm install
npm run dev                                    # http://localhost:5173
```

---

## Running the whole stack

Start in this order — the agent needs both services reachable at boot:

| # | Component | Command | Port |
|---|---|---|---|
| 1 | PostgreSQL | (your local instance) | 5432 |
| 2 | Classifier | `uvicorn src.main:app --port 8000` | 8000 |
| 3 | Backend | `npm run dev` | 3001 |
| 4 | Frontend | `npm run dev` | 5173 |
| 5 | Agent | `python src/main.py` | — |

Configuration lives in `.env` files per component; each has a committed
`.env.example` showing the required keys. Real `.env` files are gitignored.

## Tests

```bash
cd backend    && npm test            # 111
cd agent      && python -m pytest -q # 275
cd classifier && python -m pytest -q # 25
```

## Repository conventions

`main` is always green. Work happens on branches merged via pull request:

| Prefix | Used for |
|---|---|
| `feat/` | New capability |
| `fix/` | Bug fix |
| `docs/` | Documentation only |
| `chore/` | Tooling, dependencies, repo hygiene |
