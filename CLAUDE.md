# medusa - MEDUSA Security Scanning

## Project Overview

This project uses **MEDUSA v2026.2.0** - AI Security Scanner with 4,152+ detection patterns for AI/ML, agents, and LLM applications. Works out of the box with no external tool installation required.

## MEDUSA Configuration

**Location**: `.medusa.yml`

### Quick Commands

```bash
# Run security scan (works immediately - no setup needed)
medusa scan .

# Quick scan (cached results)
medusa scan . --quick

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

MEDUSA scans with 4,152+ built-in patterns for:
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
version: 2026.2.0
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
| AI Security Patterns | 4,152+ | 4,152+ | 4,152+ |
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

MEDUSA works out of the box with 4,152+ built-in patterns. External linters are optional and auto-detected if installed:

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

## MEDUSA 2026.2.0 Release

### What's New

**v2026.2.0** is an AI rules-first release featuring:

- **4,152+ AI Security Patterns**: Works immediately with no tool installation
- **Simplified Installation**: Just `pip install medusa-security && medusa scan .`
- **modelscan Support**: `medusa install --ai-tools` for ML model scanning
- **External Linters Optional**: Auto-detected if present, not installed by MEDUSA
- **CLI Cleanup**: Removed 1,500+ lines of legacy installer code

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

### Specialized Agents (15 total)

MEDUSA has 15 custom agents. See `.claude/AGENTS_AND_SKILLS.md` for full details.

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

**Documentation & Marketing:**
13. **docs-writer** - Technical documentation
14. **marketing-writer** - Pricing, landing pages
15. **data-analyst** - Rule stats, dashboards

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

---

*This file provides context for Claude Code about MEDUSA integration*
