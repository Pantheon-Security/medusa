# MEDUSA Security Scan

Run MEDUSA security scanner on the project or specific files.

## Usage

```bash
@medusa scan [options]
```

In Cursor chat or terminal:
```
@medusa scan
medusa scan .
```

## Examples

### Quick scan (changed files only)
```bash
@medusa scan --quick
medusa scan . --quick
```

### Full project scan
```bash
@medusa scan
medusa scan .
```

### Scan specific directory
```bash
@medusa scan src/
medusa scan api/ --format json
```

### Scan with custom workers
```bash
medusa scan . --workers 8
```

### Fail on high severity
```bash
medusa scan . --fail-on high
```

### Output formats
```bash
medusa scan . --format json
medusa scan . --format sarif
medusa scan . --format html -o report.html
```

## What Gets Scanned

MEDUSA runs 43+ specialized security analyzers:

### Python (13 scanners)
bandit, semgrep, pysa, safety, pip-audit, mypy, pylint, pyright, ruff, vulture, pyre-check, pytype, detect-secrets

### JavaScript/TypeScript (8 scanners)
eslint, semgrep, npm audit, yarn audit, pnpm audit, retire.js, jshint, tslint

### Go (5 scanners)
gosec, govulncheck, staticcheck, golangci-lint, nancy

### Rust (4 scanners)
cargo-audit, cargo-clippy, cargo-deny, cargo-geiger

### Shell (3 scanners)
shellcheck, shfmt, bashate

### PHP (3 scanners)
psalm, phpstan, phpcs

### Java (2 scanners)
spotbugs, dependency-check

### Ruby (2 scanners)
brakeman, bundler-audit

### C/C++ (2 scanners)
cppcheck, flawfinder

### Infrastructure (3 scanners)
trivy, checkov, tfsec

## Integration

This command integrates with MEDUSA's parallel scanning engine:

- ✅ 43+ security analyzers
- ✅ Auto-detection of file types
- ✅ Parallel scanning for speed (10-40× faster)
- ✅ Beautiful HTML/JSON/SARIF reports
- ✅ Inline issue annotations in Cursor

## Configuration

Edit `.medusa.yml` to customize:

```yaml
version: 2025.1.9
scanners:
  enabled: []     # Empty = all enabled
  disabled:
    - trivy       # Disable specific scanners
fail_on: high     # critical | high | medium | low
exclude:
  paths:
    - node_modules/
    - .venv/
    - dist/
  files:
    - "*.min.js"
workers: null     # null = auto-detect (recommended)
cache_enabled: true
```

## AI-Powered Scanning

For intelligent false positive filtering, use:
```bash
@medusa ai-review
```

This runs the same 43+ scanners but adds AI analysis to:
- Filter false positives (<15% FP rate vs 91% industry)
- Explain vulnerabilities in plain English
- Suggest secure code fixes
- Provide confidence scores

## Learn More

- Documentation: https://medusa-security.readthedocs.io
- Report Issues: https://github.com/Pantheon-Security/medusa/issues
- Ask Questions: `@medusa ask "your question"`
