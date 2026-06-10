# medusa - MEDUSA Security Scanning

## CRITICAL: Release Gate — DO NOT SKIP

**Unit tests ALONE are not sufficient.** Before any `git push`, `git tag`, `gh release create`, or `twine upload` — all four commands below MUST run green AND their output MUST be pasted into the conversation for Ross to see:

```bash
# 1. Full unit test suite (must show: all pass except documented pre-existing failures)
python3 -m pytest tests/ -q

# 2. Benchmark corpus regression (must show: baseline matches)
python3 -m pytest tests/test_regression.py -v

# 3. Self-scan on MEDUSA itself (must show: no NEW findings vs prior scan)
medusa scan . --quick

# 4. Security hardening tests (must show: all pass)
python3 -m pytest tests/test_security_hardening.py -v
```

**If ANY of these fail or are skipped, DO NOT PROCEED.** Fix the failure or surface it to Ross. Do not bypass `git push --no-verify` — the pre-push hook at `.git/hooks/pre-push` exists specifically to block this.

**Why this exists:** Previous releases shipped without regression testing (v2026.5.5 tagged + GH-released before benchmark ran). "Day one dev stuff" that damages brand trust. This gate is the mechanism that prevents repeat. No willpower required.

Related: `feedback_release_gate.md` in memory has the full rule.

## CRITICAL: Bash Sandbox

Always use `dangerouslyDisableSandbox: true` on Bash tool calls that run `medusa scan` or invoke external linters. The default sandbox strips `~/.npm-global/bin`, `~/.local/bin`, and `/snap/bin` from PATH, causing installed tools (eslint, hadolint, rubocop, trivy, etc.) to appear missing and triggering the "Continue scan without these tools?" prompt which blocks non-interactive scans.

## Project Overview

This project uses **MEDUSA v2026.5.12** - AI Security Scanner with 40,000+ detection patterns for AI/ML, agents, and LLM applications. Works out of the box with no external tool installation required.

## MEDUSA Configuration

**Location**: `.medusa.yml`

### Quick Commands

```bash
# Run security scan (works immediately - no setup needed)
medusa scan .

# Quick scan (cached results)
medusa scan . --quick

# Exclude directories from scan
medusa scan . -e archive/ -e vendor/

# Check tool status
medusa install --check

# Install AI tools (modelscan for ML model scanning)
medusa install --ai-tools

# License management
medusa license info        # View license status
medusa license activate    # Activate license key
medusa license trial       # Start 14-day trial
medusa license deactivate  # Remove license
```

## Available Slash Commands

- `/medusa-scan` - Run security scan on project
- `/medusa-install` - Install missing security tools

## Integration Features

### Claude Code Integration

- **Auto-scan on save**: Automatically scans files when you save them
- **Inline annotations**: Security issues appear directly in your IDE
- **Smart detection**: Only scans relevant file types
- **Parallel processing**: Fast scanning with multi-core support

### AI-First Security

MEDUSA scans with 40,000+ built-in patterns for:
- AI/ML applications, LLM agents, MCP servers
- Prompt injection, RAG poisoning, agent security
- Traditional vulnerabilities (SQL injection, XSS, secrets)
- Configuration files (YAML, JSON, Terraform, Docker)

**Optional**: External linters (bandit, eslint, etc.) are auto-detected if installed.

## Security Scanning

### Scan Reports

Reports are generated in `.medusa/reports/`:
- HTML dashboard (visual report)
- JSON data (for CI/CD integration)
- SARIF output (GitHub integration)
- CLI output (terminal summary)

### Output Formats

```bash
# Default JSON output
medusa scan . --output json

# SARIF format (GitHub Code Scanning)
medusa scan . --output sarif

# HTML dashboard
medusa scan . --output html
```

### Severity Levels

- **CRITICAL**: Immediate security threats
- **HIGH**: Significant vulnerabilities
- **MEDIUM**: Moderate issues
- **LOW**: Minor concerns
- **INFO**: Best practice suggestions

### Fail Thresholds

Configure scan to fail CI/CD on certain severity:

```bash
medusa scan . --fail-on high
```

## Configuration

Edit `.medusa.yml` to customize:

```yaml
version: 2026.3.0
scanners:
  enabled: []     # Empty = all enabled
  disabled: []    # List scanners to disable
fail_on: high     # critical | high | medium | low
exclude:
  paths:
    - node_modules/
    - .venv/
    - dist/
workers: null     # null = auto-detect CPU cores
cache_enabled: true
output_format: sarif  # json | sarif | html
```

## CI/CD Integration

### GitHub Actions

```yaml
name: MEDUSA Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run MEDUSA Scan
        uses: pantheon-security/medusa-action@v2026
        with:
          fail-on: high
          output-format: sarif

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: .medusa/reports/results.sarif
```

### GitLab CI

```yaml
security_scan:
  script:
    - pip install medusa-security
    - medusa scan . --fail-on high --output sarif
  artifacts:
    reports:
      sast: .medusa/reports/results.sarif
```

## Licensing and Pricing

### Tier Comparison

| Feature | FREE | Professional | Enterprise |
|---------|------|--------------|------------|
| AI Security Patterns | 40,000+ | 40,000+ | 40,000+ |
| Runtime Filters | - | 1,100+ | 1,100+ |
| SARIF Output | Yes | Yes | Yes |
| CLI | Yes | Yes | Yes |
| GitHub Action | Yes | Yes | Yes |
| REST API | - | Yes | Yes |
| Webhooks | - | Yes | Yes |
| Custom Rules | - | - | Yes |
| SSO/SAML | - | - | Yes |
| Audit Logs | - | - | Yes |
| **Price** | Free | $99/dev/mo | $499/50 devs/mo |

### License Commands

```bash
# Check current license status
medusa license info

# Activate a license key
medusa license activate YOUR-LICENSE-KEY

# Start a 14-day Professional trial
medusa license trial

# Deactivate license (for transferring)
medusa license deactivate
```

### Runtime Filters (Professional/Enterprise)

Runtime filters provide 1,100+ additional rules for detecting:
- AI/ML model attacks and vulnerabilities
- Prompt injection patterns
- Training data poisoning
- Agent security issues
- RAG vulnerabilities

```bash
# Enable runtime filters (requires Professional license)
medusa scan . --runtime-filters
```

## Troubleshooting

### External Linters (Optional)

MEDUSA works out of the box with 40,000+ built-in patterns. External linters are optional and auto-detected if installed:

```bash
medusa install --check    # See tool status

# Install external linters via your package manager if desired:
pip install bandit ruff           # Python
npm install -g eslint             # JavaScript
apt install shellcheck            # Shell (or: brew install shellcheck)
```

### False Positives

Exclude files or directories in `.medusa.yml`:

```yaml
exclude:
  paths:
    - "tests/fixtures/"
    - "vendor/"
  files:
    - "*.min.js"
```

## MEDUSA 2026.3.0 Release

### What's New

**v2026.3.0** is the scanner precision + FP tuning release:

- **52% Faster Scans**: Single-pass file discovery, scanner pre-mapping cache, pre-compiled patterns
- **514 FP Filter Patterns**: 96.8% false positive reduction rate
- **133 Critical CVEs**: CVEMiner database for known vulnerability scanning
- **Structural Refactoring**: God methods split, dead code removed, data/logic separation
- **Large Project Support**: Live progress responsive on 40,000+ file codebases
- **40,000+ AI Security Patterns**: Works immediately with no tool installation

### Detection Pattern Categories

| Category | Patterns |
|----------|----------|
| Prompt Injection | 800+ |
| MCP Server Security | 400+ |
| RAG Security | 300+ |
| Agent Security | 500+ |
| Model Security | 400+ |
| Supply Chain | 350+ |
| Traditional SAST | 1,400+ |

### Specialized Agents (17 total)

MEDUSA has 17 custom agents. See `.claude/AGENTS_AND_SKILLS.md` for full details.

**Core Development:**
1. **python-expert** - Python & YAML processing
2. **ai-security-researcher** - AI/ML security expert
3. **code-reviewer** - Code quality & security review
4. **test-engineer** - pytest, coverage, CI testing

**Release & Distribution:**
5. **github-release-expert** - GitHub releases, Actions, marketplace
6. **pypi-expert** - Python packaging, PyPI publishing
7. **ci-cd-expert** - GitHub Actions, GitLab CI, Docker
8. **rule-migration-specialist** - Migrates rules to production

**Product Features:**
9. **rest-api-expert** - FastAPI for paid tier
10. **webhook-expert** - Event-driven integrations
11. **vscode-extension-expert** - VS Code extension
12. **licensing-expert** - Feature gating, tiers

**Proxy & JSON Rules:**
13. **json-rules-expert** - Proxy JSON rules, Hyperscan compatibility

**Documentation & Marketing:**
14. **docs-writer** - Technical documentation
15. **marketing-writer** - Pricing, landing pages
16. **data-analyst** - Rule stats, dashboards

**Meta Agents:**
17. **agent-improver** - Improves subagents from correction incidents

### Custom Skills

1. **validate-yaml-rules** - Validate rule syntax/schema
2. **extract-attack-patterns** - Extract patterns from research
3. **rule-stats-dashboard** - Show rule statistics
4. **batch-notebook-extraction** - Batch NotebookLM extraction

### Key Directories

- `/home/ross-churchill/Documents/medusa` - Production repo (here)
- `/home/ross-churchill/Documents/medusa-2026-dev` - Research & staging

## CRITICAL: Runtime Rules Are Paid Tier Only

**⚠️ NEVER COMMIT RUNTIME RULES TO GITHUB ⚠️**

Runtime rules (`*_runtime.yaml`) are **PAID TIER ONLY** and must never be published to the public GitHub repository.

The `.gitignore` excludes:
- `*_runtime.yaml` - All runtime rule files
- `medusa/rules/runtime/` - Runtime rules directory
- `medusa/api/` - REST API (paid tier)
- `medusa/core/licensing.py` - License management

Before any commit, verify runtime rules are excluded:
```bash
git status | grep runtime  # Should show nothing
```

## Learn More

- **Documentation**: https://docs.medusa-security.dev
- **GitHub**: https://github.com/Pantheon-Security/medusa
- **Report Issues**: https://github.com/Pantheon-Security/medusa/issues
- **Agents & Skills**: `.claude/AGENTS_AND_SKILLS.md`
- **Pricing**: https://medusa-security.dev/pricing

## Agent Continuous Improvement

When you (the main agent) delegate work to a subagent and then have to fix or correct its output:
1. Complete the fix first
2. Invoke the `agent-improver` agent, telling it:
   - Which subagent produced the work (e.g., `json-rules-expert`)
   - What was wrong or missing in the subagent's output
   - What you fixed and how
3. The agent-improver will update that subagent's `.claude/agents/<name>.md` so it handles the case correctly next time

This ensures agents get better with each use. Do not skip this step.

---

*This file provides context for Claude Code about MEDUSA integration*
