# medusa scan - Fast Security Scan

Run MEDUSA security scanner on the project or specific files.

## Usage

```bash
medusa scan [path] [options]
```

## Examples

### Quick scan (changed files only)
```bash
medusa scan . --quick
medusa scan --quick  # Same as above
```

### Full project scan
```bash
medusa scan .
medusa scan  # Same as above
```

### Scan specific directory
```bash
medusa scan src/
medusa scan api/
medusa scan tests/
```

### Scan specific file
```bash
medusa scan auth.py
medusa scan src/api/users.py
```

### Output formats
```bash
# JSON output
medusa scan --format json

# SARIF (for IDE integration)
medusa scan --format sarif -o results.sarif

# HTML report
medusa scan --format html -o report.html

# All formats
medusa scan --format all
```

### Custom workers
```bash
# Use 8 parallel workers
medusa scan --workers 8

# Single worker (no parallelism)
medusa scan --workers 1
```

### Fail on severity
```bash
# Fail on critical issues
medusa scan --fail-on critical

# Fail on high or above
medusa scan --fail-on high

# Fail on any issue
medusa scan --fail-on low
```

### Filtering
```bash
# Only specific scanners
medusa scan --scanners bandit,semgrep,eslint

# Disable specific scanners
medusa scan --disable trivy,checkov

# Only Python files
medusa scan --file-types py

# Exclude patterns
medusa scan --exclude "tests/*,*.min.js"
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

## Example Output

```bash
$ medusa scan .

🔍 MEDUSA Security Scanner v2025.1.9
Scanning 1,247 files with 43+ analyzers...

[████████████████████████] 100% | 6.3s

📊 Scan Results:

CRITICAL (3 issues):
  [B201] SQL Injection in api/users.py:156
  [B608] Hardcoded Password in config/db.py:22
  [CWE-79] XSS Vulnerability in views/profile.py:89

HIGH (7 issues):
  [B104] Weak Binding in server.py:45
  [B603] subprocess.call in utils/exec.py:23
  ...

MEDIUM (15 issues):
LOW (23 issues):

Total: 48 findings
Time: 6.3s
Scanners: 43

💡 Next Steps:
  - Review critical issues: medusa ai-explain B201
  - Get AI-powered review: medusa ai-review
  - Generate fixes: medusa fix B201
```

## Configuration

`.medusa.yml`:

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
workers: null     # null = auto-detect
cache_enabled: true
```

## AI-Powered Scanning

For intelligent false positive filtering:

```bash
medusa ai-review
```

**Differences:**
- **medusa scan**: Fast, high FP rate (91%), raw findings
- **medusa ai-review**: Slower, low FP rate (<15%), AI-filtered

## Performance Tips

```bash
# Use quick scan for frequent checks
medusa scan --quick

# Use cache for repeated scans
medusa scan --cache

# Disable slow scanners for rapid iteration
medusa scan --disable trivy,checkov,semgrep

# Scan only changed files
medusa scan $(git diff --name-only)
```

## Exit Codes

- `0` - No issues found (or below fail-on threshold)
- `1` - Issues found above fail-on threshold
- `2` - Scanner error or missing tools
- `3` - Configuration error

## Learn More

- Documentation: https://medusa-security.readthedocs.io
- Report Issues: https://github.com/Pantheon-Security/medusa/issues
- Ask Questions: `medusa ask "your question"`
