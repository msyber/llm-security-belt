# LLM Security Belt Demo

**Purpose (TL;DR)**  
Show, in 2 minutes, how a tiny gateway + policies + CI **reduce LLM risk** *without changing models*.

**Who it’s for**  
Engineers, PMs, and Security teams who want a **minimal, copy-pasteable pattern** for safer LLM features.

**What you’ll see**  
- **Safe JSON** → **200 OK** 
- **Malicious link** (unknown domain) → **400 Blocked**
- **Rule bypass (jailbreak)** with **Expect JSON** → **400 Blocked**

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/msyber/llm-security-belt?quickstart=1)
![LLM Evals](https://github.com/msyber/llm-security-belt/actions/workflows/llm-evals.yml/badge.svg)

---

## Live demo

### Option A — Codespaces (1-click)
1. Click the badge above.  
2. Wait for port **8787** to open; set it **Public** to share.  
3. Open the URL (…`app.github.dev`) and use the demo page.

### Option B — Local
```bash
npm run demo       # starts the mock gateway
# open http://localhost:8787
```

**Try in the UI**
- “Safe JSON” → **200 OK**  
- “Non-allowlisted URL” → **400** (blocked: domain)  
- “Jailbreak” with **Expect JSON** → **400** (blocked: not_json/schema)

---

## Quick start (local)
Requirements: **Node 20+**
```bash
npm run demo   # run gateway on http://localhost:8787
npm run evals  # LLM01/LLM02 + JSON schema tests → PASS/FAIL
```

---

## How it works

**Flow**
```
UI → POST /chat → Gateway
        1) sanitize input
        2) block non-allowlisted URLs
        3) enforce tool allowlist
        4) (optional) validate output JSON schema
   ← 200 OK or 400 Blocked (with reason)
```

**Controls**
- `gateway/policies/domains.allowlist.txt` — URL allowlist (one per line)  
- `gateway/policies/tools.allowlist.json` — Allowed tools (deny-by-default)
- `gateway/policies/output.schema.json` — expected JSON when “Expect JSON” is on
- `gateway/server.js` — Rate limiting (express-rate-limit)
- `gateway/server.js` — Security headers (helmet)
- `/healthz` — Health check

**Endpoints**
- `POST /chat` — main call  
- `GET /metrics` — `{ total, allowed, blocked }`  
- `GET /events` — live events (SSE)  
- `POST /demo/policy` — `{ enforceUrlAllowlist: true|false }` (demo toggle)

---

## Configure / extend

- Add domains → `gateway/policies/domains.allowlist.txt`  
- Adjust output schema → `gateway/policies/output.schema.json`  
- Tighten tools → `gateway/policies/tools.allowlist.json`  
- Switch providers in `gateway/.env`:
  - `PROVIDER=mock` (default)
  - `PROVIDER=openai` + `OPENAI_API_KEY=…`
  - `PROVIDER=azure` + endpoint/key/deployment

---

## CI (LLM Evals)

Workflow: `.github/workflows/llm-evals.yml`
- Installs gateway deps  
- **Starts the mock gateway** in background, waits on `/metrics`  
- Runs `evals/run.mjs` against `http://localhost:8787`  
- Fails the build on any failed eval

---

## Project structure
```
gateway/
  server.js                # Express gateway
  public/index.html        # Live demo UI (accessible)
  policies/
    domains.allowlist.txt
    tools.allowlist.json
    output.schema.json
evals/
  run.mjs                  # Node eval runner
  tests.json               # LLM01/LLM02 + schema
.github/workflows/
  llm-evals.yml            # CI evals (local mock)
```

---

## Security notes

This is a **teaching/demo** gateway. For production you’ll likely:
- Add deeper content filtering & red-team evals
- Expand schemas, rate limits, and observability
- Run behind your API gateway/WAF