# medusa - MEDUSA Security Scanning

## Project Overview

This project uses **MEDUSA** - Multi-Language Security Scanner with 40+ specialized analyzers for automated security scanning.

## MEDUSA Configuration

**Location**: `.medusa.yml`

### Quick Commands

```bash
# Run security scan
medusa scan .

# Quick scan (cached results)
medusa scan . --quick

# Check installed scanners
medusa install --check

# Install missing tools
medusa install --all
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

### 42 Language Support

MEDUSA scans:
- Python, JavaScript, TypeScript, Go, Rust, Java, C/C++
- Shell scripts (bash, sh, zsh)
- Docker, Kubernetes, Terraform
- YAML, JSON, XML, TOML
- And 30+ more languages/formats

## Security Scanning

### Scan Reports

Reports are generated in `.medusa/reports/`:
- HTML dashboard (visual report)
- JSON data (for CI/CD integration)
- CLI output (terminal summary)

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
version: 0.8.0
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
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: MEDUSA Security Scan
  run: |
    pip install medusa-security
    medusa scan . --fail-on high --no-report
```

### GitLab CI

```yaml
security_scan:
  script:
    - pip install medusa-security
    - medusa scan . --fail-on high
```

## Troubleshooting

### Missing Scanners

If you see warnings about missing tools:

```bash
medusa install --check    # See what's missing
medusa install --all      # Install everything
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

## Learn More

- **Documentation**: https://docs.medusa-security.dev
- **GitHub**: https://github.com/Pantheon-Security/medusa
- **Report Issues**: https://github.com/Pantheon-Security/medusa/issues

---

*This file provides context for Claude Code about MEDUSA integration*
