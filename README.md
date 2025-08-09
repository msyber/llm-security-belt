# LLM Security Belt — Node-only Demo

**Outcome**: Block 5/10 common LLM risks in ~20 minutes.  
**Playbook**: 1) Gateway 2) Policies (deny-by-default) 3) Evals in CI.  
**Mini-visual**: “Before/After” table is shown in the UI.  
**Derived number**: Residual Exposure (demo proxy) ≈ `1 − blocked/total` (illustrative).  
**References**: OWASP LLM Top‑10, NIST GAI Profile.

## Quickstart
```bash
npm run demo    # starts gateway on http://localhost:8787 (mock provider)
npm run evals   # runs Node evals (LLM01/02 + JSON schema)
```

## Files in this pack
- `gateway/public/index.html` — aligned wording (title, chips), Playbook (3 steps), Before/After table, accessible UI.
- `evals/tests.json` — test names aligned to OWASP (LLM01/02).
