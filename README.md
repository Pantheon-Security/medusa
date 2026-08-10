# MEDUSA - Vet before you install

[![PyPI](https://img.shields.io/pypi/v/medusa-security?label=PyPI&color=blue)](https://pypi.org/project/medusa-security/)
[![Downloads](https://img.shields.io/pypi/dm/medusa-security?label=Downloads&color=brightgreen)](https://pypi.org/project/medusa-security/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Tests](https://github.com/Pantheon-Security/medusa/actions/workflows/test.yml/badge.svg)](https://github.com/Pantheon-Security/medusa/actions/workflows/test.yml)
[![Windows](https://img.shields.io/badge/Windows-supported-brightgreen.svg)](https://github.com/Pantheon-Security/medusa)
[![macOS](https://img.shields.io/badge/macOS-supported-brightgreen.svg)](https://github.com/Pantheon-Security/medusa)
[![Linux](https://img.shields.io/badge/Linux-supported-brightgreen.svg)](https://github.com/Pantheon-Security/medusa)

**MEDUSA vets any repo, skill, or MCP server for supply-chain attacks *before* you install it — a plain SAFE / CAUTION / DO_NOT_INSTALL verdict in seconds, from your shell or straight inside your AI coding agent.**
It catches poisoned `.claude/` hooks, prompt injection, MCP tool poisoning, and leaked credentials at the moment you clone or install — the pre-install gap that runtime tools (NVIDIA Garak, NeMo Guardrails) only see *after* the code is already running.
Zero setup: `pip install`, and 42,684 built-in detection patterns work out of the box — no external tools, no server, no config.

---

## Quick start

```bash
pip install medusa-security                          # 1. install (Windows, macOS, Linux)
medusa vet https://github.com/org/repo               # 2. vet a repo / skill / URL before you touch it
medusa hooks install --all                           # 3. make the check automatic in your AI tools
```

That's it. `medusa vet` prints one verdict and one exit code. `medusa hooks install --all`
wires the same verdict into Claude Code, Cursor, and Codex so the check happens automatically,
at the moment of install — no extra step to remember.

---

## `medusa vet` — the install decision, in one command

> Catch a poisoned repo or skill *before* it lands on your machine.

The moment you `git clone` a repo, `pip install` a package, or add a Claude/Cursor skill, you
are running someone else's instructions. `medusa vet` is the single source of truth for the
install decision. Point it at a local path, a git URL, or a skill; it prints one plain
verdict — **SAFE**, **CAUTION**, or **DO_NOT_INSTALL** — with the findings that drove it.

```bash
medusa vet https://github.com/org/repo    # a remote repo (clones + vets)
medusa vet ./some-skill                    # a local path or SKILL.md
medusa vet org/repo                        # user/repo shorthand
medusa vet . --json                        # machine-readable verdict dict
```

```text
$ medusa vet https://github.com/acme/toolkit
VERDICT: DO_NOT_INSTALL  (risk score 250)
3 blocking · 168 detected (non-blocking)
Blocking findings:
  [CRITICAL] REPO_POISON_CLAUDE_HOOK — .claude/settings.json:12
  [CRITICAL] SECRET_EXFIL_CURL_BASH — install.sh:3
  [HIGH]     MCP_TOOL_POISONING — .cursor/mcp.json:8
168 more non-blocking findings — run `medusa scan` for the full report.
```

```text
$ medusa vet ./my-helper-skill
VERDICT: SAFE  (risk score 0)
0 blocking · 0 detected (non-blocking)
```

The headline leads with **blocking** findings — the signals that actually drove the verdict —
and keeps the full total as a secondary, non-blocking number so a narrow, precise verdict
never reads as a wall of alarms.

### Exit codes

A non-zero code fails an automated gate so a human decides:

| Exit code | Verdict | Meaning |
|-----------|---------|---------|
| `0` | **SAFE** | No blocking issues — install away. |
| `1` | **CAUTION** | A HIGH or several MEDIUM findings — review first. |
| `2` | **DO_NOT_INSTALL** | A CRITICAL or multiple HIGH findings — do not install. |
| `3` | **ERROR** | Could not vet the target (bad path / unclonable URL) — *not* a security verdict; fails closed so a gate still halts. |

```bash
# One-line CI gate before anything untrusted touches the machine
if ! medusa vet .; then echo "blocked by MEDUSA"; exit 1; fi
```

<details>
<summary><b>Tuning your own security-content repo (allowlist)</b></summary>

A repo that *documents* attack patterns (detection playbooks, agent rosters, skill
catalogues) legitimately quotes attack strings, so `vet` may rest at CAUTION on it. If you
own the repo and those files are benign, allowlist them so `vet` reaches SAFE — without
weakening detection elsewhere:

```bash
medusa vet . --allow 'skills/**' --allow 'agents/**'   # per-invocation, user-typed
```

Or persist it in a `.medusa.yml` that lives **outside** the repo you're vetting (a parent
dir or your global config), via `vet_allowlist: ["skills/**", "agents/**"]`.

> **Security:** a `vet_allowlist` inside the repo being vetted is **ignored** — an untrusted
> repo cannot ship its own allowlist to whitelist its malice. Only an allowlist from a config
> *outside* the target, or an explicit `--allow` flag, is honored. Allowlisting never
> suppresses a finding *outside* the listed paths.

</details>

<details>
<summary><b>vet vs. scan --git — which to use</b></summary>

| You want to… | Use | Returns |
|--------------|-----|---------|
| A direct install verdict on a repo/skill from your shell or CI | `medusa vet <target>` | SAFE / CAUTION / DO_NOT_INSTALL (exit 0/1/2) |
| A full report on a *remote* repo with your own severity threshold | `medusa scan --git <URL>` | Findings + `--fail-on` exit control (not the three-tier verdict) |
| Your AI assistant to vet a target before acting on it | MCP `scan_repo` tool (`medusa mcp`) | The same verdict, returned to the agent |

</details>

---

## Automatic vetting — MCP gatekeeper + native hooks

`medusa hooks install --all` wires vetting into the tools you already use, so the check
happens at the exact moment of install or commit.

```bash
medusa hooks install --all           # Claude + Cursor + Codex MCP + git pre-commit
medusa hooks install --all --global  # apply to every project on this machine
medusa hooks status                  # show what's wired up
```

**1. MCP gatekeeper — `medusa mcp`.** An MCP server that Claude Code, Cursor
(`.cursor/mcp.json`), and ChatGPT/Codex (`.codex/config.toml`) consume. It exposes three tools
that return a plain **SAFE / CAUTION / DO_NOT_INSTALL** verdict — the same engine `medusa vet`
uses — so your assistant vets a target before acting on it:

| MCP tool | What it vets |
|----------|--------------|
| `scan_repo` | A remote repo URL (wraps `medusa scan --git`) — repo poisoning, prompt injection, MCP tool poisoning |
| `scan_skill` | A Claude/Cursor skill or `SKILL.md` before you install it — dropper scripts, ToxicSkills |
| `secrets_scan` | A path or file for leaked API keys, tokens, and private keys |

**2. Native hooks — installed by `medusa hooks install`.**

- A real **Claude Code PreToolUse hook** that intercepts `git clone` / `gh repo clone` and
  **URL-based** fetch/install commands (`curl | sh`, `wget`, and `pip` / `npm` / `uv` /
  `poetry` / `cargo` / `go` installs **that reference a URL or git source**), runs the matching
  vet, and surfaces a verdict *before* the command executes. Bare-name installs
  (`pip install requests`) carry no URL to vet — registry-name resolution is on the roadmap.
- A git **pre-commit hook** that runs `medusa secrets scan` and **blocks the commit** if any
  credential is found — so a pasted token never reaches your history.

The win: a poisoned repo or skill is caught at clone/install time, and a leaked secret is
caught at commit time — automatically, by the tools you already use.

---

## `medusa secrets` — find leaked keys in your AI chat & shell history

> Your PyPI token might be in your Claude chat history right now.

Developers paste API keys, tokens, and credentials into AI assistants every day —
"deploy this with `pypi-AgEI...`", "use my `ghp_...` to push", "the AWS key is `AKIA...`".
The assistants keep those conversations in plaintext on disk. Anyone with read access to
`$HOME` — or any future malware with shell access — can `grep -r 'sk-\|ghp_\|AKIA' ~/`
and harvest production credentials in seconds.

`medusa secrets scan` finds them. `medusa secrets purge` cleans them up.

### 30-second tour

```bash
medusa secrets scan
```

```text
Scanning 118 file(s)...

── claude-code ──────────────────────────────────────────────
/home/ross/.claude/history.jsonl  (13 finding(s))
[CRITICAL] Anthropic API key (anthropic)
    /home/ross/.claude/history.jsonl:1005:13
    sk-ant-api03***...***
[CRITICAL] PyPI API token (pypi)
    /home/ross/.claude/history.jsonl:125:94
    pypi-AgEIc***...***
[CRITICAL] GitHub fine-grained PAT (github)
    /home/ross/.claude/history.jsonl:2306:13
    github_pat_11A***...***
[HIGH]     HuggingFace token (huggingface)
    /home/ross/.claude/history.jsonl:3387:13
    hf_JOi***...***
...

Total: 13 credentials across 1 file(s).
Report:  /home/ross/.medusa/secrets-scan/secrets-20260519-074452.json
```

```bash
medusa secrets purge
```

```text
[CRITICAL] PyPI API token  (pypi)
    /home/ross/.claude/history.jsonl:125:94
    pypi-AgEIc***...***
  redact?  [y/n/s/a/q/?]: y
...

/home/ross/.claude/history.jsonl  (13 redacted)
    backup → /home/ross/.medusa/secrets-scan/backups/20260519-074452/home/ross/.claude/history.jsonl
```

The original file is backed up byte-for-byte before any change. JSONL stays parseable after
redaction. The redaction marker (`[REDACTED-MEDUSA-...-<run-id>]`) is unique per run so you
can trace it back to the scan that produced it.

<details>
<summary><b>Commands, detected issuers, and safety properties</b></summary>

```bash
medusa secrets scan                       # everything (default — chat + shell)
medusa secrets scan --source ai-chats     # AI assistants only
medusa secrets scan --source shell        # ~/.bash_history, ~/.zsh_history, fish, psql, mysql, ...
medusa secrets scan --path FILE           # explicit file (e.g. a ChatGPT export)
medusa secrets scan --reveal              # show real values (requires 'I UNDERSTAND')

medusa secrets purge                      # interactive [y/n/s/a/q]
medusa secrets purge SCAN_ID              # purge a specific report
medusa secrets purge --all --yes-i-know   # batch mode for power users / CI
```

**What's detected (21 issuers):**

- **AI providers**: Anthropic, OpenAI, HuggingFace, Replicate, Cohere
- **Package registries**: PyPI, npm
- **Source forges**: GitHub PAT (classic + fine-grained + OAuth + App), GitLab PAT
- **Cloud**: AWS access keys, GCP service-account JSON
- **Payments / comms**: Stripe live/restricted keys, Slack bot/user tokens, SendGrid, Twilio, Discord webhooks
- **Cryptography**: PEM-encoded private keys (RSA, DSA, EC, OpenSSH, PGP)

**Safety properties:**

- **Local-only.** Reports under `~/.medusa/secrets-scan/` mode `0o600`. No network, no telemetry, never written to project trees.
- **Backup before write.** Every redaction is preceded by a byte-identical backup. `cp` restores it.
- **JSONL-safe.** The redaction marker contains no JSON-unsafe characters; affected lines are re-parsed after the write.
- **Refuse on drift.** If the source file changed between scan and purge, the purger refuses rather than risk clobbering an edit.
- **Atomic write.** Temp file + `os.replace` swap. Either the rewrite lands or the original stays.

[**Full secrets-scanner guide →**](docs/SECRETS_SCANNER.md)

</details>

---

## Network use & privacy

MEDUSA's pattern scanning is fully local — your source never leaves the machine. There is
**one** network call in the default scan: dependency CVE lookups query the public
**OSV.dev** database (`https://api.osv.dev`) with your **dependency names + versions only**
— never your code, never your secrets. The lookup **fails safe**: if the network is
unreachable it is skipped silently and the scan continues on the built-in CVE rules.

To keep every scan fully offline (no OSV call at all), pass `--offline`:

```bash
medusa scan . --offline      # never contacts api.osv.dev — built-in rules only
```

`medusa secrets scan` / `purge` are always local-only and never make network calls.

---

## What's new in v2026.8.0 — the trust release

This release makes the vet loop fast, precise, and honest end to end.

- **Precise verdicts.** SAFE on clean repos, DO_NOT_INSTALL on real malice. The
  research-harvested pattern tail that used to flood own-code scans is now scoped to
  screening/vet mode, so a scan of *your* code is not drowned in mentions of attack research.
- **Fast vet.** A parsed-rule cache means a repo or skill verdict returns in seconds, not the
  tens of seconds an earlier build spent re-parsing the corpus on every invocation.
- **Honest trust proof.** Dogfooding self-scan CRITICALs went from **214 → 4** — all 4 verified
  false positives (MEDUSA's own detector signatures + doc/config strings), 0 real
  vulnerabilities (see [Dogfooding](#dogfooding-results)). No "100%" hand-waving.
- **Real CI.** The test suite now runs on every pull request (previously an install-smoke check
  only), so changes to a 42,684-rule corpus get automated feedback.

<details>
<summary>Previous releases</summary>

**v2026.7.0** — Claude Code compromise detection, an always-on AI attack-signature scanner, native Rust & PHP security rules, and rule-level diagnostics (`--trace-rules`).

**v2026.5.12** — Biggest pattern release: 9,600 → 40,000+ detection patterns harvested from 8,466 AI-security research papers, false-positive-hardened; structural rule-integrity scanner.

**v2026.5.9** — Agentic-commerce coverage: UCPScanner + AP2Scanner + 45 hand-tuned positive-pattern rules.

**v2026.5.8** — `medusa secrets`: scan AI chat & shell histories for leaked credentials (21 issuer types) with interactive `[y/n/s/a/q]` purge.

**v2026.5.5** — Security hardening release (argv injection defenses, git SSRF, HMAC cache integrity, markdown XSS fix).

</details>

---

## What MEDUSA detects

MEDUSA ships **42,684 detection patterns**, in two tiers with different jobs:

| Tier | Count | When it runs | What it is |
|------|-------|--------------|------------|
| **Curated core** | **228** | Every scan | Hand-tuned, high-precision rules for AI/ML, MCP, agents, and traditional SAST — the rules that gate your own code. |
| **Research-harvested screening** | **~42,456** | `--screening` / `--git` / `medusa vet` | Broad patterns harvested from AI-security research, used for deep pre-install screening of *untrusted* targets, where a mention of an attack technique is signal, not noise. |

This split is deliberate: vetting a stranger's repo wants maximum recall (catch everything),
while scanning your own code wants precision (don't cry wolf). The `--git` / vet path turns on
the full corpus; a plain `medusa scan .` runs the curated core.

Plus **310 CVE detections** (Log4Shell, Spring4Shell, XZ Utils backdoor, LangChain RCE,
MCP-Remote RCE, React2Shell CVE-2025-55182, and more), and repo-poisoning coverage across
**28+ AI editor config file types**.

<details>
<summary><b>AI security coverage by category</b></summary>

Updated for **OWASP Top 10 for LLM Applications 2025** and **MITRE ATLAS**.

| Category | Rules | Detects |
|----------|------|---------|
| **Prompt Injection & Jailbreaks** | 10,400+ | Direct/indirect injection, jailbreaks, role manipulation, guardrail bypass, invisible-unicode / bidi (Trojan Source) |
| **Model Security** | 5,000+ | Insecure loading, checkpoint exposure, model poisoning, extraction, adversarial & fine-tuning attacks |
| **Other (SAST, secrets, configs, CVEs)** | 4,300+ | SQL injection, XSS, command injection, secrets, 310 CVEs, IaC/config, repo poisoning |
| **Agent Security** | 4,200+ | Excessive agency, memory poisoning, HITL bypass, agentic attack chains |
| **Privacy & Data Protection** | 3,400+ | Membership inference, data extraction, differential-privacy attacks |
| **MCP & Agent-Protocol Security** | 3,300+ | Tool poisoning, schema poisoning, ATPA, sampling injection, rug-pull |
| **Inference Infrastructure** | 3,100+ | Serving/endpoint exposure, resource abuse, configuration weaknesses |
| **Advanced & Emerging Threats** | 3,000+ | Watermarking bypass, federated-learning attacks, post-quantum, provenance |
| **RAG & Vector Security** | 2,900+ | Vector injection, document poisoning, tenant isolation, retrieval manipulation |
| **GenAI & Multimodal** | 2,000+ | Multimodal, voice/audio, and image attacks; GenAI-specific patterns |
| **Supply Chain** | 800+ | Dependency confusion, typosquatting, slopsquatting, lock-file backdoors |
| **Total** | **42,684** | Across 999 rule categories — verify with `medusa rules --count` |

</details>

<details>
<summary><b>AI editor config files detected (28+ known attack vectors)</b></summary>

```
# Critical - Known RCE vectors
.cursorrules              # Cursor AI (CVE-2025-54135)
.cursor/rules/*.mdc       # Cursor rules directory
.cursor/mcp.json          # Cursor MCP (CurXecute RCE)
.clinerules/*.md          # Cline (Clinejection)
.windsurfrules            # Windsurf (CVE-2025-36730)
.codex/config.toml        # Codex CLI (CVE-2025-61260)
.kiro/settings/mcp.json   # Kiro (CVE-2026-0830)
.vscode/settings.json     # VS Code (IDEsaster)
mcp.json / .mcp.json      # MCP server configs

# Critical - Claude Code compromise (structural .claude/ vetting)
.claude/settings.json     # Hooks, permissions (curl|bash, bypassPermissions)
.claude/agents/*          # Subagents (wildcard-tool access)
.claude/skills/*          # Skills (dropper scripts)

# High - AI instruction files
CLAUDE.md · GEMINI.md · AGENTS.md · AGENT.md · SKILL.md · CONVENTIONS.md
.github/copilot-instructions.md · .amazonq/rules/* · .augment/rules/*
.roo/rules/* · .tabnine/guidelines/* · .continue/config.yaml · .cody.yml
```

**Known attacks detected**: Clinejection, CurXecute (CVE-2025-54135), IDEsaster
(CVE-2025-64660), ToxicSkills, CamoLeak, RoguePilot, AIShellJack, Cacheract.

</details>

<details>
<summary><b>Language & tool coverage — 40+ built-in AI/ML analyzers + 44 optional linter integrations</b></summary>

MEDUSA's **40+ built-in AI/ML analyzers** work with zero setup. It also **auto-detects 44
optional external linters** if you already have them installed (bandit, eslint, shellcheck,
etc.) and folds their output in — but they are never required, and a zero-setup `pip install`
produces a full scan without any of them.

| Area | Languages (optional linter auto-detected if present) |
|------|------------------------------------------------------|
| **Backend** | Python (Bandit), JS/TS (ESLint), Go (golangci-lint), Ruby (RuboCop), PHP (native + PHPStan), Rust (native + Clippy), Java (Checkstyle), C/C++ (cppcheck), C# (Roslynator) |
| **JVM** | Kotlin (ktlint), Scala (Scalastyle), Groovy (CodeNarc) |
| **Functional** | Haskell (HLint), Elixir (Credo), Erlang (Elvis), F# (FSharpLint), Clojure (clj-kondo) |
| **Mobile** | Swift (SwiftLint), Objective-C (OCLint) |
| **Frontend** | CSS/SCSS/Less (Stylelint), HTML (HTMLHint), Vue (ESLint) |
| **IaC** | Terraform (tflint), Ansible (ansible-lint), Kubernetes (kubeval), CloudFormation (cfn-lint) |
| **Config** | JSON (built-in), TOML (taplo), XML (xmllint), Protobuf (buf) |
| **Shell/Scripts** | Bash (ShellCheck), PowerShell (PSScriptAnalyzer), Lua (luacheck), Perl (perlcritic) |
| **Docs** | Markdown (markdownlint), reStructuredText (rst-lint) |
| **Other** | SQL (SQLFluff), R (lintr), Dart (dart analyze), Solidity (solhint), Docker (hadolint) |

See the **[Optional Tools Guide](docs/OPTIONAL_TOOLS.md)** for how auto-detection works.

</details>

---

## Scan & report

AI/LLM detection is **always on** — a plain `medusa scan .` runs the curated core alongside
the traditional SAST rules. No special flag needed.

```bash
medusa scan .                    # scan the current directory
medusa scan . --quick            # quick scan (content-hash cache skips unchanged files)
medusa scan . --fail-on high     # exit non-zero on HIGH+ (CI gate)
medusa scan --git org/repo       # clone + scan a remote repo (full report, --fail-on control)
medusa scan . --format sarif     # json | html | markdown | sarif | all
```

<details>
<summary><b>Full command & options reference</b></summary>

### Scan options

| Option | Description |
|--------|-------------|
| `TARGET` | Directory or file to scan (default: `.`) |
| `-g, --git URL` | Clone and scan a remote git repo (GitHub URL or `user/repo` shorthand) |
| `-w, --workers N` | Number of parallel workers (default: auto-detect) |
| `--quick` | Quick scan (content-hash cache skips unchanged files) |
| `--force` | Force full scan (ignore cache) |
| `--no-cache` | Disable result caching |
| `--fail-on LEVEL` | Exit with error on severity: `critical`, `high`, `medium`, `low` |
| `-o, --output PATH` | Custom output directory for reports |
| `--format FORMAT` | Output format: `json`, `html`, `markdown`, `sarif`, `all` (repeatable) |
| `--no-report` | Skip generating HTML report |
| `--no-ai-safe` | Disable AI-safe output redaction (show raw matched payloads in the report) |
| `-y, --yes` / `--no-prompt` | Skip confirmation prompts / auto-continue optional-tool gates (CI) |
| `--trace-rules` | Rule diagnostics: per-rule firing log and timing (`rule-trace.jsonl`, `slow_rules.csv`); forces a serial scan |
| `--screening` | Target-vetting mode: surface attack/high-severity findings even in `tests/`, `examples/`, or dataset files (auto-enabled for `--git`) |
| `--allow-any-host` | Allow `--git` to clone from any host (default: github.com, gitlab.com, bitbucket.org, codeberg.org; private IPs still rejected) |
| `--baseline FILE` | Suppress findings whose fingerprint is in this baseline; surface only NEW findings |
| `--write-baseline FILE` | Write current findings' fingerprints to this baseline file |
| `--llm-triage` | Opt-in: semantically triage findings with an LLM (off by default; no network unless enabled and a backend is available) |
| `--llm-backend BACKEND` | Force the triage backend: `claude-cli`, `codex-cli`, `anthropic-api`, `openai-api` (with `--llm-triage`) |
| `--offline` | Fully offline scan — skip the OSV.dev dependency CVE lookup (built-in CVE rules still run) |
| `--include-user-mcp-configs` | Also scan user-home MCP config files (`~/.config/Claude`, `~/.cursor`) |

### Hooks & MCP

| Command | Description |
|---------|-------------|
| `medusa hooks install --all` | Claude + Cursor + Codex MCP + git pre-commit |
| `medusa hooks install --claude` | Claude Code PreToolUse hook only |
| `medusa hooks install --pre-commit` | git pre-commit secrets block only |
| `medusa hooks install --all --global` | apply to every project on this machine |
| `medusa hooks status` | show which hooks/configs are wired up |
| `medusa mcp` | run the MCP gatekeeper server |

### Other commands

```bash
medusa init                      # interactive setup wizard (--ide claude-code | gemini-cli | cursor | all)
medusa install --check           # check optional external-tool status
medusa install --ai-tools        # install modelscan for ML model scanning
medusa rules --count             # exact rule count (source of truth for the numbers here)
medusa config                    # show current configuration
```

</details>

### Suppressing false positives

Silence a single finding without disabling a rule project-wide with an inline comment on the
same line — `# medusa:ignore` in Python/shell, `// medusa:ignore` in Rust/PHP/JS/TS:

```python
api_key = "sk-test-not-a-real-key"  # medusa:ignore
```

For broader suppression, exclude paths in `.medusa.yml`. Full guidance:
**[Handling False Positives](docs/guides/handling-false-positives.md)**.

---

## Configuration — `.medusa.yml`

```yaml
version: 2026.8.0

scanners:
  enabled: []      # empty = all enabled
  disabled: []     # list scanners to disable

fail_on: high      # critical | high | medium | low

exclude:
  paths: [node_modules/, .venv/, .git/, dist/, build/]
  files: ["*.min.js", "*.min.css"]

# Owner allowlist for `medusa vet` — paths whose findings do NOT gate the verdict.
# ONLY honored when this config lives OUTSIDE the repo being vetted (a repo cannot
# ship its own allowlist to whitelist its malice); see `medusa vet`.
vet_allowlist: []

workers: null        # null = auto-detect usable CPUs (respects a container's
                     # cgroup CPU quota and CPU affinity, not just core count)
cache_enabled: true
```

Run `medusa init` to generate this with sensible defaults and auto-detect your IDE.

---

## IDE integration

MEDUSA integrates natively with **5 AI coding assistants**. Run `medusa init --ide all` or
select platforms.

| IDE | Context file | Integration |
|-----|-------------|-------------|
| **Claude Code** | `CLAUDE.md` | `/medusa-scan`, `/medusa-install` + PreToolUse vet hook + MCP |
| **Cursor** | `.cursor/mcp.json` | MCP gatekeeper |
| **OpenAI Codex** | `AGENTS.md` | `.codex/config.toml` MCP gatekeeper |
| **Gemini CLI** | `GEMINI.md` | `/scan`, `/install` |
| **GitHub Copilot** | `.github/copilot-instructions.md` | Security standards for suggestions |

Full setup: **[IDE Integration guide](docs/guides/ide-integration.md)**.

---

## CI/CD

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  medusa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install medusa-security
      - run: medusa scan . --fail-on high
```

No tool-installation step needed — MEDUSA's built-in rules work immediately. For GitHub Code
Scanning, add `--format sarif` and upload with `github/codeql-action/upload-sarif`.

---

## Dogfooding results

MEDUSA scans itself. Its own signature corpus (`medusa/rules/`) and detector source
(`medusa/scanners/`) are scoped out of the self-scan — those files literally *are* the attack
signatures the tool hunts for, so scanning them flags the signatures, not vulnerabilities (the
standard practice bandit/semgrep follow for their own rules).

```
Self-scan — MEDUSA application code (detector corpus scoped out):
  CRITICAL: 214 → 4 after FP-hardening — the residual 4 are all verified false
    positives, 0 real vulnerabilities (curated rules matching our own security
    identifiers: an OpenAI client init, the "prompt-injection" keyword in package
    metadata, a threat-describing comment, a docs line). Tracked for precision tuning.
  Harvested research rules run in screening/vet mode only (medusa vet / --git /
    --screening), so a self-scan of your own code is not flooded by them.
```

> Honesty note: an earlier README claimed "100% FP reduction / 0 CRITICALs." That was measured
> with the detector corpus in scope and is superseded by the scoped, reproducible number above.
> Run `medusa scan .` to reproduce.

Against the MEDUSA benchmark corpus, the FP-filter layer removes **99.2%** of would-be false
positives (350 of 353 native pre-filter findings filtered) — reproducible from the committed
baseline in `tests/benchmark_baseline.json` and guarded by `tests/test_regression.py`.

<details>
<summary><b>Performance & architecture</b></summary>

**Performance** — parallel, multi-core scanning:

| Project Size | Files | Time | Speed |
|--------------|-------|------|-------|
| Small (MEDUSA self-scan) | 473 | ~8s | 59 files/s |
| Medium | 1,000 | ~45s | 22 files/s |
| Large (OpenClaw) | 4,124 | ~3.3h | 0.34 files/s* |

*Large-project time is dominated by external tool subprocesses (Semgrep, Trivy, GitLeaks);
built-in pattern scanning is near-instant. Content-hash caching skips unchanged files on
rescan (typically 20x+ faster).

**Architecture** — every scanner follows one pattern (`get_tool_name`, `get_file_extensions`,
`scan_file → ScannerResult`) and auto-registers into a `ScannerRegistry`. Severity is unified
across all analyzers (CRITICAL / HIGH / MEDIUM / LOW / INFO). See
[`docs/development/`](docs/development/) for scanner internals.

</details>

---

## Roadmap

**Shipped:** `medusa vet` verdict engine · MCP gatekeeper + native hooks · `medusa scan --git`
repo vetting · `medusa secrets` scan/purge · 28+ AI editor config detection · 310 CVE
detections · agent-protocol security (UCP/AP2/ACP) · cross-platform (Linux/macOS/Windows).

**Planned:** registry-name resolution for bare `pip install <name>` vetting · MEDUSA
Professional (runtime proxy filters) · GitHub App (automatic PR scanning) · VS Code extension.

---

## Contributing

```bash
git clone https://github.com/Pantheon-Security/medusa.git && cd medusa
python -m venv .venv && source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest
medusa scan .                                        # dogfood your changes
```

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the FP-fix decision tree and rule-authoring
guidance, and [`docs/development/`](docs/development/) for scanner internals and adding language support.

---

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE). MEDUSA is free and open source: use, modify, and
distribute freely, but modifications and derivative works (including SaaS deployments) must
also be released under AGPL-3.0. Commercial licensing: support@pantheonsecurity.io.

---

## Support & docs

- **Guides**: [Quick Start](docs/guides/quick-start.md) · [AI Security Scanning](docs/AI_SECURITY.md) · [Handling False Positives](docs/guides/handling-false-positives.md) · [IDE Integration](docs/guides/ide-integration.md)
- **Issues**: https://github.com/Pantheon-Security/medusa/issues
- **Docs / contact**: https://pantheonsecurity.io · support@pantheonsecurity.io

---

**Version**: 2026.8.0 · 42,684 detection patterns (228 curated core + ~42,456 research-harvested
screening) · 40+ built-in AI/ML analyzers + 44 optional linter integrations · 310 CVE detections · Linux · macOS ·
Windows · Standards: OWASP Top 10 for LLM 2025, MITRE ATLAS.
