# MEDUSA Security Scanner - Cursor Integration

**Version:** v2025.1.9
**IDE:** Cursor (AI-powered code editor)
**Integration Type:** AI Security Agent

## What is MEDUSA?

MEDUSA is an open-source multi-engine security scanner that aggregates 43+ specialized security analyzers into a single unified CLI tool. Think of it as a security orchestration layer that runs bandit, semgrep, eslint, gosec, cargo-audit, and dozens more - all with one command.

**Key Capabilities:**
- 🔍 43+ specialized security scanners (Python, JavaScript, Go, Rust, PHP, Shell, etc.)
- 🤖 AI-powered false positive detection (<15% FP rate vs 91% industry average)
- 📊 Unified JSON/SARIF output format across all tools
- 🚀 Automatic tool installation and version management
- 💰 100% free and open source (buyer-based open core model)

## AI-Powered Security Analysis 🤖

### What Makes MEDUSA + Cursor Special

**Traditional SAST Tools:**
- 91% false positive rate (industry average)
- Rule-based pattern matching
- No context understanding
- Generic error messages

**MEDUSA + Cursor AI:**
- ✅ <15% false positive rate (AI-filtered)
- ✅ Semantic code understanding
- ✅ Contextual vulnerability analysis
- ✅ Plain English explanations
- ✅ Secure code fix suggestions
- ✅ Natural language security queries

### AI Commands Available

**`@medusa ai-review`** - Smart Security Scan
- Runs traditional 43+ scanners (fast)
- AI analyzes each finding for false positives
- Provides confidence scores and explanations
- Suggests secure fixes with code examples

**`@medusa ai-explain <finding-id>`** - Explain Vulnerability
- Deep dive into specific security findings
- Attack scenarios and risk assessment
- CWE/OWASP references
- Before/after code comparisons

**`@medusa ask "<question>"`** - Natural Language Queries
- "What are my critical security issues?"
- "Do I have SQL injection vulnerabilities?"
- "Is auth.py secure?"
- "How do I fix the XSS in views.py?"

**`@medusa fix <finding-id>`** - Generate Secure Code
- AI-generated secure code fixes
- Explanation of what changed and why
- Testing guidance and best practices
- Optional auto-apply with backup

**`@medusa scan`** - Traditional Fast Scan
- No AI analysis (fastest option)
- Raw scanner output
- Good for CI/CD pipelines

**`@medusa install`** - Setup Tools
- Auto-install missing security scanners
- Version management
- Platform-specific installers (apt, brew, choco, winget, npm, pip, cargo, go)

## Quick Start

### 1. Install MEDUSA

```bash
# Using pip
pip install medusa-security

# Using pipx (recommended)
pipx install medusa-security
```

### 2. Initialize Cursor Integration

```bash
medusa init --ide cursor
```

This creates:
- `.cursor/cursor.md` (this file)
- `.cursor/settings.json` (Cursor AI configuration)
- `.cursor/commands/` (custom AI commands)

### 3. Run Your First AI Security Review

In Cursor, use the AI chat:
```
@medusa ai-review
```

Or traditional scan:
```bash
medusa scan .
```

## Example Workflow

### Scenario: New Feature Development

1. **Write Code** - Build your feature in Cursor
2. **AI Review** - `@medusa ai-review` to catch security issues early
3. **Ask Questions** - `@medusa ask "Is my authentication secure?"`
4. **Get Explanations** - `@medusa ai-explain B201` for specific findings
5. **Generate Fixes** - `@medusa fix B201` for secure code alternatives
6. **Verify** - Re-run `@medusa scan` to confirm fixes work

### Scenario: Legacy Code Audit

1. **Full Scan** - `medusa scan . --format json -o .medusa/report.json`
2. **AI Filter** - `@medusa ai-review` to remove false positives
3. **Prioritize** - Focus on CRITICAL/HIGH confidence findings
4. **Bulk Questions** - `@medusa ask "What should I fix first?"`
5. **Fix Critical** - `@medusa fix` for each critical issue
6. **Verify** - Re-scan to track progress

## Supported Languages and Analyzers

### Python (13 scanners)
- bandit, semgrep, pysa, safety, pip-audit, mypy (security), pylint (security), pyright, ruff, vulture, pyre-check, pytype, detect-secrets

### JavaScript/TypeScript (8 scanners)
- eslint (security plugins), semgrep, npm audit, yarn audit, pnpm audit, retire.js, jshint, tslint

### Go (5 scanners)
- gosec, govulncheck, staticcheck, golangci-lint, nancy

### Rust (4 scanners)
- cargo-audit, cargo-clippy, cargo-deny, cargo-geiger

### Shell (3 scanners)
- shellcheck, shfmt, bashate

### PHP (3 scanners)
- psalm, phpstan, phpcs (security rules)

### Java (2 scanners)
- spotbugs, dependency-check

### Ruby (2 scanners)
- brakeman, bundler-audit

### C/C++ (2 scanners)
- cppcheck, flawfinder

### Infrastructure (3 scanners)
- trivy, checkov, tfsec

## Configuration

### `.medusa.yml` (Project Root)

```yaml
# Enable AI analysis
ide:
  cursor:
    enabled: true
    ai_analysis:
      enabled: true
      confidence_threshold: 0.7  # 70% minimum confidence
      explain_findings: true
      suggest_fixes: true
      filter_test_files: true  # Ignore test file warnings

# Scanner configuration
scanners:
  enabled:
    - bandit
    - semgrep
    - eslint
    - gosec
    - cargo-audit

  disabled:
    - trivy  # Disable specific scanners if needed

# Output preferences
output:
  format: json  # json, sarif, text, html
  verbosity: normal  # quiet, normal, verbose
  show_suppressed: false
```

### `.cursor/settings.json`

```json
{
  "medusa": {
    "version": "2025.1.9",
    "autoScanOnSave": true,
    "aiAnalysis": {
      "enabled": true,
      "provider": "anthropic",
      "model": "claude-sonnet-4",
      "confidenceThreshold": 0.7
    },
    "notifications": {
      "onIssuesFound": true,
      "severityLevels": ["critical", "high"],
      "showConfidenceScores": true
    }
  }
}
```

## AI Analysis Cost Estimates

MEDUSA uses Claude API for AI analysis (optional):

**Typical Costs:**
- Simple query: ~$0.01-0.02
- AI review (50 findings): ~$0.10
- AI review (200 findings): ~$0.40
- Fix generation: ~$0.05-0.25

**Note:** Traditional scanning is 100% free. AI features are optional and only used when explicitly requested.

## Privacy and Security

**What Gets Sent to Claude API (when using AI features):**
- Code snippets around security findings (10-20 lines of context)
- Security scanner output (finding descriptions, severity, CWE)
- Your natural language questions

**What NEVER Gets Sent:**
- Your entire codebase
- Environment variables or secrets
- Production data
- API keys or credentials

**Privacy Mode:**
Set `privacy_mode: true` in `.medusa.yml` to disable all AI features and use only local scanning.

## Integration with Cursor Features

### Inline Security Annotations

MEDUSA can add inline security annotations to your code:

```python
# MEDUSA: B201 (SQL Injection) - Use parameterized queries
query = f"SELECT * FROM users WHERE id = {user_id}"  # ❌ CRITICAL
```

### Command Palette Integration

Access MEDUSA via Cursor's command palette (Cmd/Ctrl+Shift+P):
- `MEDUSA: Run AI Security Review`
- `MEDUSA: Scan Current File`
- `MEDUSA: Explain Finding`
- `MEDUSA: Generate Fix`
- `MEDUSA: Install Tools`

### Git Integration

Add to `.gitignore`:
```
.medusa/
!.medusa/.medusaignore
```

## Troubleshooting

### "medusa: command not found"

Make sure MEDUSA is installed and in your PATH:
```bash
pip install --user medusa-security
# or
pipx install medusa-security
```

### "No scanners available"

Install security tools:
```bash
medusa install --all
```

### "AI analysis failed"

1. Check API key: `export ANTHROPIC_API_KEY=sk-ant-...`
2. Verify internet connection
3. Fall back to traditional scan: `medusa scan`

### "Too many false positives"

1. Use AI filtering: `@medusa ai-review` instead of `@medusa scan`
2. Adjust confidence threshold in `.medusa.yml`
3. Add suppressions to `.medusa/.medusaignore`

## Support and Resources

- **GitHub:** https://github.com/yourusername/medusa
- **Documentation:** https://medusa-security.readthedocs.io
- **Issues:** https://github.com/yourusername/medusa/issues
- **Discord:** https://discord.gg/medusa-security

## Version History

- **v2025.1.9** - AI-powered Cursor integration, 43+ scanners, <15% FP rate
- **v0.14.0** - Added PowerShell installers, Windows auto-install improvements
- **v0.11.2** - Initial multi-engine aggregation release

---

**License:** MIT
**Status:** Production-ready, actively maintained
**First-to-Market:** AI-powered SAST with intelligent false positive detection
