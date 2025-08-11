# LLM Security Belt — A 20-Minute Demo

Show, in minutes, how a tiny gateway + policies + CI **reduce LLM risk without changing models**.

**Who it’s for**  
Engineers, PMs, and Security teams who want a minimal, copy-pasteable pattern for safer LLM features.

**What you’ll see**
- Live UI: **safe → 200**, **attack → 400** (with reason)
- Policies that matter: **URL allowlist**, **deny-by-default tools**, **JSON schema on output**
- **Runtime controls**: tune **concurrency & prompt size** (LLM10) and **enable/disable tools** (LLM06)
- CI job that **fails** if protections don’t hold (LLM01/LLM02 evals)

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/msyber/llm-security-belt?quickstart=1)

---

## Live demo (2 options)

### A) Codespaces (1-click)
1. Click the badge above.  
2. Wait for the workspace to open; the gateway auto-starts and **port 8787** is forwarded.  
3. A new browser tab opens the demo UI (make sure to switch to public link).

### B) Local (Node only)
```bash
git clone https://github.com/msyber/llm-security-belt
cd llm-security-belt
npm run demo   # installs gateway deps and starts on :8787
# Open http://localhost:8787
```

**Requirements:** Node.js 20+

---

## What’s inside

- `gateway/` — Node/Express gateway + static UI  
  - Policies: `policies/domains.allowlist.txt`, `policies/tools.allowlist.json`, `policies/output.schema.json`
  - Endpoints: `/chat`, `/metrics`, `/events`, `/healthz`
  - Demo endpoints: `/demo/policy`, `/demo/limits`, `/demo/tools`, `/demo/reset`
- `evals/` — tiny tests for CI (LLM01/LLM02)

---

## OWASP 2025 mapping (implemented here)

- **LLM01 Prompt Injection** — *URL allowlist* + input sanitization block untrusted links **before** the model.  
- **LLM05 Improper Output Handling** — *JSON Schema* validation + *fail-closed*; UI renders with `textContent` (no HTML eval).  
- **LLM06 Excessive Agency** — *Tool allowlist* (deny-by-default) + runtime enable/disable in UI.  
- **LLM10 Unbounded Consumption** — rate limits, request timeout, prompt size caps, and a small concurrency guard (runtime-tunable).

> This demo focuses on the highest-impact controls you can ship fast.

---

## Using the UI

**Presets (with OWASP tags):**
- **Safe JSON [LLM05]** — requires strict JSON output (`answer`, `citations[]`).
- **Non-allowlisted link [LLM01]** — includes a URL outside the allowlist.
- **Tool misuse [LLM06]** — prompts an agent to call a (potentially) disabled tool.
- **Oversized prompt [LLM10]** — exceeds the configured prompt-size cap.

**Controls**
- **Enforce URL allowlist [LLM01]** — switch ON/OFF to compare behavior.
- **Max prompt chars [LLM10]** — change size cap at runtime.
- **Max concurrency [LLM10]** — limit simultaneous requests.
- **Tools policy [LLM06]** — enable/disable allowed tools live.

**Response panel**
- Badge shows **OK (200)** or **Blocked (4xx)** with the reason.
- “Show request body”, **Copy request JSON**, **Copy as cURL**, **Copy response**.

**Live metrics & events**
- Counters update every ~1s. Events stream via **SSE** (capped to 50 items).

---

## Runtime control APIs (for automation)

### URL allowlist (LLM01)
```bash
curl -sS -X POST http://localhost:8787/demo/policy   -H 'Content-Type: application/json'   -d '{"enforceUrlAllowlist": true}'
```

### Limits (LLM10)
```bash
# Read
curl -sS http://localhost:8787/demo/limits

# Update
curl -sS -X POST http://localhost:8787/demo/limits   -H 'Content-Type: application/json'   -d '{"maxConcurrency": 4, "maxPromptChars": 8000}'
```

### Tools (LLM06)
```bash
# List tools and status
curl -sS http://localhost:8787/demo/tools

# Enable/disable a tool
curl -sS -X POST http://localhost:8787/demo/tools   -H 'Content-Type: application/json'   -d '{"name":"web_search","enabled":false}'
```

### Reset metrics
```bash
curl -sS -X POST http://localhost:8787/demo/reset
```

---

## Policies

- **`policies/domains.allowlist.txt`** — one hostname per line.  
- **`policies/tools.allowlist.json`** — tools allowed for the agent; arguments are whitelisted per tool.  
- **`policies/output.schema.json`** — output schema validated when “Expect JSON” is checked.

---

## /chat contract

**Request**
```json
{
  "prompt": "Return a JSON object with fields: answer (string), citations (array of URLs).",
  "tools": [{ "name": "web_search", "args": {} }],
  "expect_json": true
}
```

**Response**
- `200` — `{ "output": <string or JSON> }`  
- `400` — blocked by a policy (`tool`, `schema`, `not_json`, `size`, etc.)  
- `413` — prompt too large (LLM10)  
- `429` — too many concurrent requests (LLM10)

---

## Configuration

| Variable | Default | Description |
|---|---:|---|
| `PORT` | 8787 | Gateway port |
| `RATE_LIMIT_WINDOW_MS` | 60000 | Global rate window (ms) |
| `RATE_LIMIT_MAX` | 60 | Requests/window |
| `MAX_CONCURRENCY` | 4 | Hard cap for concurrent `/chat` requests |
| `MAX_PROMPT_CHARS` | 8000 | Hard cap for prompt size |
| `PROVIDER` | `mock` | Use `mock` (default). OpenAI/Azure examples are scaffolded but off by default. |

> The **mock provider** returns deterministic text/JSON for a clean demo.  
> To test a real provider, wire credentials in `server.js` (OpenAI/Azure branches) and set `PROVIDER`.

---

## CI / Evals (basic)

- `evals/run.mjs` runs simple HTTP checks against a running gateway:
  - **LLM01** — prompt with a non-allowlisted URL must be **blocked**.
  - **LLM02 (refusal bypass)** — configurable test must **not** be mistakenly allowed.
- Wire these in GitHub Actions to fail PRs when protections regress.

---

## Security notes & limits

- Demo code favors **clarity**; treat it as a **pattern** to harden in prod (e.g., structured logging, authn/authz, rate limits per tenant, retries/backoff, audit trails).  
- Input sanitization is **minimal & targeted** (LLM01); combine with **output validation** (LLM05) and **tool policy** (LLM06).  
- Concurrency/size controls and rate limits mitigate **resource abuse** (LLM10) but don’t replace quota management.

