# MEDUSA Issue Backlog

Generated: 2026-04-03 from Sentinel + Skeptic + Codex + Architect agent reviews.

### Architect Verdict
*"Functionally serviceable, but architecturally brittle."* Layering (rules → core → scanners → parallel → cli) is broadly correct. No God classes. Issues are fixable with small patches. Root patterns: hidden in-place mutation, broad exception swallowing, duplicated sources of truth, weak typing with permissive fallbacks.

### Codex Verdict
Confirmed issues 2, 3, 4, 5 as real. Issue 1 (severity MEDIUM) unconfirmed without `RuleSeverity` definition. **Architect confirmed it IS real** — two scanners already have independent workarounds (`yaml_rule_scanner.py:163`, `web_security_scanner.py:265`).

---

## 🔴 CRITICAL

### C1 — Stored XSS in HTML Report Generation
**File:** `medusa/core/reporter.py` ~line 1332  
**Source:** Sentinel review  
`_build_findings_html()` renders `finding['file']`, `finding['issue']`, `finding['code']` directly into HTML without `html.escape()`. Other rendering methods in the same file correctly use `html_lib.escape()`.  
**Attack:** Attacker creates repo with `<script>` in a filename or code comment → victim runs `medusa scan --git attacker/repo` → opens HTML report → JS executes.  
**Fix:** Apply `html_lib.escape()` to all finding fields in `_build_findings_html()` to match the other rendering methods.

---

### C2 — Rule Integrity Check Self-Defeating
**File:** `medusa/rules/__init__.py` lines 238–249  
**Source:** Skeptic review  
`_verify_rule_integrity()` raises `RuntimeError` on CRITICAL violations (tampered rule files). The outer `except Exception` on line 246 catches that same `RuntimeError`, prints a warning, sets `_integrity_verified = True`, and continues loading. Tampered rules are loaded regardless.  
**Attack:** Attacker embeds prompt-injection payload in a YAML rule file. Integrity check raises, except swallows it, poisoned rules load.  
**Fix:** Split the except: `except RuntimeError: raise` then `except Exception as e: print(warning); self._integrity_verified = True`. One-line change. **Architect confirmed** but rated LOW — intent was to not block on import errors, not to swallow tamper detection.

---

### C3 — `shell=True` with Dynamic Strings in Ecosystem Installer
**File:** `medusa/cli.py` lines 1098, 1113  
**Source:** Sentinel review  
`subprocess.run()` called with `shell=True` using `eco_cmd`/`manual_cmd` strings from `EcosystemDetector` and `TOOL_PACKAGES`. Currently safe only because `EcosystemDetector` is a deprecated stub returning `None`. Re-enabling ecosystem detection turns this into RCE.  
**Fix:** Remove `shell=True`. Parse strings with `shlex.split()` into list args.

---

## 🟠 HIGH

### H1 — Severity Always Downgraded to MEDIUM for YAML Rule Findings
**File:** `medusa/scanners/base.py` line 479  
**Source:** Skeptic review  
`_SEVERITY_MAP` maps string keys (`'CRITICAL'`, `'HIGH'` etc.) but `rule.severity` is a `RuleSeverity` enum member. `_SEVERITY_MAP.get(rule.severity, Severity.MEDIUM)` never matches — every YAML rule finding becomes MEDIUM. `--fail-on critical` never fires for rule-based findings.  
**Fix:** `_SEVERITY_MAP.get(rule.severity.value, Severity.MEDIUM)` in `base.py:479`. Then delete the workarounds in `yaml_rule_scanner.py:163` and `web_security_scanner.py:265`. **Architect confirmed** — two scanners already independently patched around this in concrete subclasses.

---

### H2 — FP Filter Double-Applies (filter_scan_results mutates then re-filters)
**File:** `medusa/core/fp_filter.py` lines 641–683  
**Source:** Skeptic review  
`filter_scan_results()` calls `filter_findings()` (mutates dicts in-place), then `get_stats()` which calls `filter_findings()` again on already-mutated data. Findings get severity-adjusted twice. Stats and findings list become inconsistent.  
**Fix (2 steps):** (1) Change `get_stats()` signature to accept `(filtered, fps)` instead of re-running filter. (2) Make `filter_findings()` build new dicts: `{**finding, 'fp_analysis': ...}` instead of mutating in-place. **Architect confirmed** — root cause is hidden mutation; double-pass is a symptom.

---

### H3 — Pattern Analyzer Recommends Non-Existent Scanners
**File:** `medusa/core/pattern_analyzer.py` lines 218, 235  
**Source:** Skeptic review  
`LANGUAGE_TO_SCANNER` maps `'csharp'` → `'CSharpScanner'` and `'yaml'` → `'YAMLScanner'`. Neither exists in the scanner registry. C# and YAML files get phantom scanner recommendations that resolve to nothing.  
**Fix:** Audit `LANGUAGE_TO_SCANNER` against registered scanner names. Remove or replace entries that don't exist.

---

### H4 — License HMAC Has No Secret Key (Fully Forgeable)
**File:** `medusa/core/licensing.py` line 257–260  
**Source:** Sentinel review  
`_compute_signature` hashes `tier:email:exp` with SHA-256, no secret. Anyone can forge a valid Enterprise license by computing the same hash. Truncated to 16 hex chars further weakens it.  
**Fix:** Use asymmetric signing (Ed25519). Embed public key in client, sign server-side. Or add server-side validation for online environments.  
**Note:** Licensing module is gitignored (paid tier) — not public, but still a real vulnerability.

---

### H5 — API Auth Bypass (`X-API-Key` Ignored)
**File:** `medusa/api/auth.py` lines 17–51  
**Source:** Sentinel review  
`verify_api_access()` reads the `X-API-Key` header but never validates it. Any request passes auth if a license is configured server-side.  
**Fix:** Validate `api_key` against a stored secret. Return 401 on missing/invalid key.

---

### H6 — API Scan Accepts Any Path (Arbitrary File Read)
**File:** `medusa/api/main.py` lines 204–209  
**Source:** Sentinel review  
No restriction on `target` path in scan endpoint. `/etc/`, `~/.ssh/`, `~/.aws/` all valid. Finding `code` snippets leak file contents into response.  
**Chain:** License bypass (H4) + API auth bypass (H5) + this = unauthenticated arbitrary file read over the network.  
**Fix:** Allowlist of scannable directories. Resolve symlinks, validate within allowed boundaries.

---

## 🟡 MEDIUM

### M1 — Cached Scans Show 0 Issues (Issues Disappear Between Runs)
**File:** `medusa/core/parallel.py` lines 580–591  
**Source:** Skeptic review  
Cached results return `issues=[]`. Report generator skips them. User sees 15 issues on first scan, 0 on second (nothing changed). Issues appear fixed when they aren't.  
**Fix:** Cache the issue list alongside the file hash. Return cached issues on cache hit instead of empty list.

---

### M2 — Dotfiles Walked but Not Analyzed (No Language Mapping)
**File:** `medusa/core/pattern_analyzer.py` lines 511–528  
**Source:** Skeptic review  
`.cursorrules`, `.clinerules`, `.windsurfrules` are now included in `_walk_repo` allowlist but have no extension → `EXTENSION_TO_LANGUAGE` lookup returns nothing → content never analyzed → AI scanner recommendations not triggered by these files.  
**Fix:** Add explicit handling for these filenames in `_analyze_file` (map to a pseudo-language or directly set `has_ai_context = True`).

---

### M3 — Inconsistent Dotfile Allowlists — No Shared Constants File
**File:** `medusa/core/parallel.py` line 453 vs `medusa/core/pattern_analyzer.py` line 499  
**Source:** Skeptic review  
`parallel.py` scans: `.cursorrules`, `cursorrules`, `.cursor-rules`, `CLAUDE.md` etc.  
`pattern_analyzer.py` analyzes: `.cursorrules`, `.clinerules`, `.windsurfrules`, `.env`, `.mcp.json`, `.continue`  
Files in one list but not the other are either scanned but not analyzed, or analyzed but never scanned.  
**Fix:** Create `medusa/core/constants.py` with `AI_CONTEXT_DOTDIRS` and `AI_CONTEXT_DOTFILES` frozensets. Import in both files. 3-file change. **Architect confirmed** — `.claude` and `.cursor` missing from pattern_analyzer; `.cursorrules`, `.clinerules` missing from parallel.py.

---

### M4 — Symlink Following in `--git` Scans Leaks Host Files
**File:** `medusa/core/parallel.py` line 485  
**Source:** Sentinel review  
Individual file symlinks within cloned repos are followed during scanning. Attacker commits `ln -s ~/.aws/credentials creds.py` → MEDUSA scans it → credential content appears in findings/report.  
**Fix:** Check `Path.is_symlink()` before scanning. Skip or verify target is within project root.

---

### M5 — FP Filter Mutates Input Dicts In-Place
**File:** `medusa/core/fp_filter.py` lines 252–270  
**Source:** Skeptic review  
`filter_findings()` adds `fp_analysis`, `original_severity`, modifies `severity` on the caller's original dicts. Non-idempotent. Dangerous to call multiple times (see H2).  
**Fix:** Deep-copy findings before mutating, or return new dicts.

---

### M6 — CORS Defaults Allow `localhost` Origins
**File:** `medusa/api/main.py` lines 90–97  
**Source:** Sentinel review  
Default CORS allows `http://localhost` and `http://localhost:3000`. Any webpage can hit a locally running MEDUSA API. Combined with H5 (auth bypass) = any site can initiate scans and read results.  
**Fix:** Default to no CORS origins. Require explicit `MEDUSA_CORS_ORIGINS` opt-in.

---

### M7 — Temp Directory Leaves Cloned Repos on SIGKILL
**File:** `medusa/cli.py` lines 1623–1627  
**Source:** Sentinel review  
`tempfile.mkdtemp(prefix="medusa-git-")` with `finally: shutil.rmtree()` doesn't clean up if process is killed with SIGKILL. Cloned repos with potentially sensitive scan targets left in `/tmp`.  
**Fix:** Use `tempfile.TemporaryDirectory` as context manager, or write to `~/.medusa/tmp/` with a startup-time cleanup pass.

---

## 🟢 LOW

### L1 — SBOM Version Was Hardcoded `2025.9.0.0` ✅ FIXED in v2026.5.1
**File:** `medusa/cli.py`  Now uses `__version__`.

---

### L2 — Bad Regex in Rule YAML Silently Reduces Pattern Count
**File:** `medusa/rules/__init__.py` lines 69–70  
Invalid regex prints to stdout, not logged, rule loads with fewer patterns than intended.  
**Fix:** Use structured logging. Surface regex errors in `medusa scan --debug` output.

---

### L3 — Docstring Detection via Triple-Quote Counting Is Fragile
**File:** `medusa/core/fp_filter.py` lines 401–405  
Counts `"""` and `'''` occurrences for odd/even parity. Strings containing triple quotes break the heuristic.  
**Fix:** Use `ast.parse()` for Python files to get accurate string/docstring boundaries.

---

### L4 — `tools/`/`scripts/` Dirs Classified as `EXAMPLE_FILE` FP Reason
**File:** `medusa/core/fp_filter.py` lines 580–587  
Utility code in `tools/`, `scripts/`, `utils/` treated as examples with 0.50 FP confidence adjustment. These can contain real security issues.  
**Fix:** Rename reason to `UTILITY_FILE`. Only apply to `examples/`, `samples/`, `fixtures/` directories.

---

### L5 — Git Clone Error Message Can Leak Auth Tokens in URLs
**File:** `medusa/cli.py` lines 1634–1637  
Raw git stderr printed on clone failure. If URL contains credentials (`https://token@github.com/...`) the token appears in terminal output.  
**Fix:** Strip credentials from URLs before displaying error messages.

---

### L6 — Parameterized Query Detection Patterns Too Broad
**File:** `medusa/core/pattern_analyzer.py` lines 586–591  
Patterns `%s`, `:\w+`, `\$\d+` match non-SQL contexts (Python string formatting, shell vars, templates), inflating `uses_parameterized_queries` and suppressing SQL injection confidence.  
**Fix:** Require SQL keyword context before counting as parameterized query evidence.

---

## Priority Order for Next Sprint

| # | Issue | Severity | Effort |
|---|-------|----------|--------|
| 1 | C1 — XSS in HTML reports | CRITICAL | Small — add html.escape() |
| 2 | H1 — Severity always MEDIUM | HIGH | Small — .value lookup fix |
| 3 | C2 — Integrity check swallowed | CRITICAL | Small — tighten except clause |
| 4 | H2 — FP double-filtering | HIGH | Medium — refactor filter_findings |
| 5 | M1 — Cached scans show 0 issues | MEDIUM | Medium — cache issue list |
| 6 | M2/M3 — Dotfile analysis gaps | MEDIUM | Small — shared constant + _analyze_file fix |
| 7 | H3 — Phantom scanner names | HIGH | Small — audit LANGUAGE_TO_SCANNER |
| 8 | M4 — Symlink escape via --git | MEDIUM | Small — is_symlink() check |
| 9 | C3 — shell=True latent RCE | CRITICAL | Small — shlex.split() |
| 10 | H4/H5/H6 — API security chain | HIGH | Medium — paid tier API work |
