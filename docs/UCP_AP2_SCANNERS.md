# UCP + AP2 Scanners — Agentic-Commerce Attack Coverage

> Google's Universal Commerce Protocol (UCP) launched 2026-01-11 with Shopify,
> Mastercard, Visa, Stripe, PayPal, Walmart, and Target. AP2 (Agent Payments
> Protocol) is the companion standard from Cloud Security Alliance for
> signed payment mandates. AI agents will use these to spend money on
> users' behalf — and they ship with new attack surface.

## Why this exists

When an AI agent (Gemini, ChatGPT, Claude) initiates a checkout through UCP, the
traditional fraud signals — device fingerprint, IP geolocation, session
behaviour, browsing patterns — are absent. The transaction is signed by an AP2
mandate, but the mandate itself is only as trustworthy as the code that issues
and verifies it.

The new attack surface includes:

- **UCP discovery hijacking** — `/.well-known/ucp` served over plaintext HTTP
- **Mandate forgery** — signing keys exposed in source, signature verification
  disabled, expired/replayed mandates accepted
- **Agent identity spoofing** — UCP-Agent headers trusted without verification
- **JSON-LD `@context` poisoning** — semantic confusion attacks via untrusted
  context URLs
- **Product-data prompt injection** — merchant-supplied product descriptions
  containing instructions the agent obeys
- **Cross-protocol bridge bugs** — UCP code that calls into MCP, A2A, or AP2
  without isolating trust boundaries
- **PCI data leakage** — card numbers / CVVs flowing into logs because nobody
  scrubbed the agent path

`UCPScanner` and `AP2Scanner` are dedicated static-analysis scanners for these.

---

## What's detected

### UCP rules (10 active)

| Rule | Severity | Detects |
|---|---|---|
| `MEDUSA-UCP-DISC-001` | CRITICAL | UCP discovery endpoint served over insecure HTTP |
| `MEDUSA-UCP-AGENT-005` | HIGH | UCP consent without bounded delegation limits |
| `MEDUSA-UCP-CRED-001` | CRITICAL | Hardcoded UCP signing key in source |
| `MEDUSA-UCP-CRED-002` | CRITICAL | DID:key private material in source |
| `MEDUSA-UCP-CRED-003` | CRITICAL | PCI data (PAN/CVV) in agent code |
| `MEDUSA-UCP-CRED-005` | CRITICAL | VDC with weak algorithm (`none`, `HS256`) |
| `MEDUSA-UCP-AP2-005` | HIGH | Agent mandate with unbounded amount |
| `MEDUSA-UCP-AP2-006` | HIGH | Audit log delete/clear/truncate calls |
| `MEDUSA-UCP-BRIDGE-003` | HIGH | Untrusted JSON-LD `@context` URL |
| `MEDUSA-UCP-PI-001` | HIGH | Product catalog data with prompt-injection markers |

### AP2 rules (5 active)

| Rule | Severity | Detects |
|---|---|---|
| `MEDUSA-AP2-TOKEN-003` | HIGH | AP2 token with long-lived TTL / no expiry |
| `MEDUSA-AP2-CRYPTO-001` | CRITICAL | Algorithm downgrade (`alg: HS256`, `alg: none`) |
| `MEDUSA-AP2-CRYPTO-002` | CRITICAL | Private key loaded from filesystem |
| `MEDUSA-AP2-CRYPTO-003` | CRITICAL | Signature verify bypass (`verify=False`, `verify_signature: False`) |
| `MEDUSA-AP2-PSP-003` | HIGH | Card data (PAN/CVV/payment_token) in log calls |

---

## File gates — when each scanner fires

Each scanner has a content-based gate so its rules only apply to relevant
files — preventing FP noise on unrelated Python/JS/TS code.

**`UCPScanner.is_ucp_file()`** matches when the file contains any of:

- `from ucp` / `import ucp` / `require('ucp...')` / `from 'ucp...'`
- `@google/ucp`, `@ucp/(client|server|sdk|agent|merchant)`
- `.well-known/ucp` URL or `ucp_(endpoint|discovery|agent|merchant|catalog|mandate)` config keys
- `UCP-Agent: ...` HTTP header, `idempotency-key`, `x-ucp-(agent|merchant|signature)` headers
- Filename containing `ucp` or `agent-commerce`

**`AP2Scanner.is_ap2_file()`** matches on:

- `from ap2` / `import ap2` / `@google/ap2` / `@ap2/(client|server|sdk|mandate|wallet)`
- `payment_mandate`, `signed_mandate`, `cart_mandate`, `intent_mandate`
- `x-ap2-(signature|nonce|mandate|wallet)` headers
- VDC vocabulary: `vdc_issuer`, `verifiable_digital_credential`
- AP2 session shapes: `checkout.session`
- Filename containing `ap2`, `agent-payments`, or `agentic-payments`

If neither gate matches, the scanner short-circuits and applies no rules.
Java repos (without `import ucp` / `import ap2`) correctly produce 0 hits —
verified against `ap2java` and `ucpjava` test corpora.

---

## How well does it work in practice?

Audited against **12 real-world UCP/AP2 codebases** sourced via MEDUSA's
MinerHub research pipeline:

| Repo | Files | UCP hits | AP2 hits |
|---|---:|---:|---:|
| agentic-commerce-skills-plugins | 388 | 0 | 0 |
| AP2 (Google official) | 237 | 0 | 0 |
| Retail-Agentic-Commerce | 300 | 1 | 0 |
| fastucp | 117 | 0 | 0 |
| ucp-samples | 103 | 0 | 0 |
| ucp-merchant-server | 36 | 0 | 0 |
| ai-shopping-agent-ucp | 48 | 0 | 0 |
| agentic-payments-bot | 39 | 0 | 0 |
| ucp-merchant | 11 | 1 | 0 |
| ap2java | 6 | 0 | 0 |
| ucpjava | 3 | 0 | 0 |
| agent-payment-protocols | 2 | 0 | 0 |

**Total: 2 hits across 12 repos.** Both are `MEDUSA-UCP-DISC-001` (UCP
discovery over plaintext HTTP), both potentially actionable:

- `ucp-merchant/src/app.py:34` — `print("...http://localhost:5000/.well-known/ucp...")` — dev startup banner showing a localhost URL
- `Retail-Agentic-Commerce/docker-compose.yml:119` — `NEXT_PUBLIC_UCP_PLATFORM_PROFILE_URL=...http://merchant:8000/.well-known/ucp` — internal docker network env var

Neither is junk noise — both are configurations a security reviewer would want
to triage ("is localhost dev-only?", "does the docker URL ever leak past the
internal network?").

This is the design target: low FP rate (~2 hits across 12 reference
implementations is below 0.2 hits / 100 files), narrow positive patterns
that fire on actual attack-shape code.

---

## Architecture

```
medusa scan PROJECT_ROOT
       │
       ▼
  ParallelScanner walks all source files
       │
       ▼
  For each .py / .js / .ts / .json / .yaml:
       │
       ├── UCPScanner.is_ucp_file()? ─── no ──> skip
       │            │ yes
       │            ▼
       │   apply 10 UCP rules via RuleBasedScanner._scan_with_rules()
       │
       └── AP2Scanner.is_ap2_file()? ─── no ──> skip
                    │ yes
                    ▼
            apply 5 AP2 rules
```

Both scanners reuse the existing `RuleBasedScanner` machinery —
file-gate logic is the new part. Rules are loaded by ID prefix
(`MEDUSA-UCP-` / `MEDUSA-AP2-`) so each scanner owns its rule set
deterministically with no overlap.

### Source layout

| File | Purpose |
|---|---|
| `medusa/scanners/ucp_scanner.py` | `UCPScanner` class + import / usage patterns for the file gate |
| `medusa/scanners/ap2_scanner.py` | `AP2Scanner` class + mandate / VDC vocabulary patterns |
| `medusa/rules/agent_security/ucp_vulnerabilities.yaml` | 10 active UCP rules (+ 23 documented `# DROP:` for future AST work) |
| `medusa/rules/agent_security/ap2_vulnerabilities.yaml` | 5 active AP2 rules (+ 15 documented `# DROP:`) |
| `medusa/scanners/__init__.py` | Registers `UCPScanner()` and `AP2Scanner()` |

---

## Pattern design philosophy

All 15 active rules use **positive detection** — they match the
*presence* of a dangerous primitive, not the *absence* of a safe one.
Examples:

- ✅ `(?i)http://[^/\s"']+/\.well-known/ucp\b` — explicit plaintext UCP URL
- ✅ `(?i)\bverify_signature\s*=\s*False` — explicit signature-check disable
- ✅ `(?i)\b(?:card_number|pan|cvv|cvc)\s*[=:]\s*["']?\d{3,}` — PCI-shaped digit string
- ❌ ~~`(?i)checkout.*(?!.*agent_fraud)`~~ — "any line with `checkout` not also mentioning `agent_fraud`"

The negative-lookahead "absence-of-defensive-code" shape was tried and
abandoned: it produced 3,623 hits (mostly FPs) across the same 12 repos
because static analysis at single-line granularity can't know whether
defensive code lives in a different function or file.

42 rules from the original 87 had threat models that genuinely require
AST-level or call-graph analysis (e.g. "mandate processed but no
`verify_signature` call anywhere in the call graph"). Those are preserved
inline as `# DROP:` comments so a future AST-based detection engine can
revive them without re-researching the threat models.

---

## Roadmap

- AST-based detection layer to revive the 42 dropped rules
- ACP (Agent Communication Protocol) coverage
- A2A (Agent-to-Agent) protocol attack surface
- Live test corpus expansion as new UCP / AP2 implementations land
