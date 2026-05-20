# v2026.5.9 — Agentic Commerce Attack Coverage

> Google's UCP (Universal Commerce Protocol) launched 2026-01-11 with Shopify,
> Mastercard, Visa, Stripe, PayPal, Walmart, and Target. AP2 (Agent Payments
> Protocol) is the companion standard for signed payment mandates. AI agents
> will use these to spend money on users' behalf — and they ship with new
> attack surface.

## The headline

Three new dedicated scanners + 45 hand-tuned positive-pattern rules.

| | Scanner | Detects |
|---|---|---|
| 🛒 | **`UCPScanner`** | UCP discovery over plain HTTP, hardcoded UCP signing keys, unbounded agent mandates, missing fraud signals, malicious JSON-LD `@context`, PCI data in agent code |
| 💳 | **`AP2Scanner`** | Long-lived payment tokens, signature-verify bypass (`verify=False`), private keys from filesystem, algorithm downgrade (`HS256`, `none`), card-data-in-logs |
| 🎯 | **`PISCANCodeScanner`** | Prompt-injection-in-code: raw user input → `messages.append`, f-string prompt interpolation, untrusted HTTP tool output → `chat.completions.create` |

Every rule uses **positive detection** — they fire on attack-shape code, not
on the absence of defensive code. This is the lesson the project learned the
hard way: negative-lookahead "X without Y on the same line" patterns produced
3,623 hits on the audit corpus (mostly FPs). The new shape produces 2 hits on
the same corpus, both potentially actionable.

## Validation corpus

Each scanner was audited against **real-world UCP/AP2/MCP codebases** sourced
via MEDUSA's MinerHub research pipeline:

- 12 UCP/AP2 repos: agentic-commerce-skills-plugins, AP2 (Google official),
  fastucp, ucp-merchant-server, ai-shopping-agent-ucp, Retail-Agentic-Commerce,
  ap2java, ucpjava, ucp-samples, agentic-payments-bot, ucp-merchant,
  agent-payment-protocols
- 4 MCP servers: IMCP, hexstrike-ai, damn-vulnerable-MCP-server, MasterMCP
- Synthetic positives covering attack-shape code for each of 5 rule classes

Result: **2 hits across 12 reference implementations**. Both are
`MEDUSA-UCP-DISC-001` — UCP discovery served over plaintext HTTP — and both
are configurations a security reviewer would triage. No spammy FPs.

## What's detected (45 active rules across 5 files)

**UCP (10 rules)** — `MEDUSA-UCP-DISC-001`, `AGENT-005`, `CRED-001..003,005`,
`AP2-005..006`, `BRIDGE-003`, `PI-001`. CWE-319 (cleartext), CWE-798
(hardcoded creds), CWE-200 (PCI), CWE-345 (JSON-LD trust).

**AP2 (5 rules)** — `TOKEN-003`, `CRYPTO-001..003`, `PSP-003`. CWE-307
(no rate limit on auth), CWE-326 (weak crypto), CWE-321 (hardcoded
keys), CWE-117 (log injection).

**MCP-SCAN (11 rules)** — tool poisoning, reverse shells in tool handlers,
`eval`/`exec` on tool input, command injection, dynamic instruction loading,
tool output → `exec`, path traversal, infinite loops.

**PI-SCAN (9 rules)** — direct user input → LLM messages, f-string prompt
injection, raw HTTP tool output → LLM, role-field tampering (ChatInject),
system-prompt + user-input concatenation.

**TUA-SCAN (10 rules)** — hardcoded crypto keys, ECB mode, predictable PRNG
seeds, plaintext secret storage, AI-hallucinated package imports, deprecated
security APIs, LLM-guided fuzzing tools, untrusted tool chaining, embedding
inversion exposure.

## Bug fix

`parallel.py` was dropping `issue.rule_id` when converting `ScannerIssue` →
JSON findings dict. Meant `medusa scan --format json` output had no rule IDs
— broke per-rule filtering, analytics, and post-hoc auditing. Two-line fix.

## Try it

```bash
pip install -U medusa-security==2026.5.9
cd your-ucp-or-ap2-project
medusa scan .
```

## Documentation

- **[UCP + AP2 Scanner Guide](https://github.com/Pantheon-Security/medusa/blob/main/docs/UCP_AP2_SCANNERS.md)** — architecture, file gates, all 15 UCP/AP2 rules, FP audit results
- **[CHANGELOG](https://github.com/Pantheon-Security/medusa/blob/main/CHANGELOG.md)** — full release notes

## Quality

- `pytest tests/` → **419 passed, 10 skipped, 0 failed**
- Benchmark corpus regression → **5/5 passed** (with refreshed baseline)
- Security hardening → **55/55 passed**
- Self-scan on MEDUSA itself → 894 files, 0 crashes, 0 hits from new SHIP rules (correctly — we don't have the vulns these rules detect in our own code)

## Tier

**Free.** No license required.

---

**Previous release**: v2026.5.8 — `medusa secrets`: scan AI chat & shell histories for leaked credentials with interactive `[y/n/s/a/q]` purge.
