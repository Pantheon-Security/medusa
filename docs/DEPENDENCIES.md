# MEDUSA Dependency Tracking

This document tracks all dependencies, their versions, and any blockers preventing updates.

**Last Updated:** 2025-12-11
**MEDUSA Version:** 2025.8.5.12

---

## Blocked Dependencies

These packages cannot be updated due to compatibility issues with other dependencies.

| Package | Current | Latest | Blocker | Blocking Package | Action Required |
|---------|---------|--------|---------|------------------|-----------------|
| magika | 0.6.3 | 1.0.1 | API breaking changes | markitdown ~=0.6.1 | Wait for markitdown to support magika 1.0 |

---

## Recently Updated (2025-12-11)

| Package | Previous | Updated To | Type |
|---------|----------|------------|------|
| semgrep | 1.144.0 | 1.145.0 | External Tool |
| trivy | 0.67.2 | 0.68.1 | External Tool |
| ruff | 0.14.5 | 0.14.8 | Python + External |
| black | 25.11.0 | 25.12.0 | Python + External |
| mypy | 1.18.2 | 1.19.0 | Python |
| pytest | 9.0.1 | 9.0.2 | Python |
| coverage | 7.11.3 | 7.13.0 | Python |
| beautifulsoup4 | 4.14.2 | 4.14.3 | Python |
| rpds-py | 0.29.0 | 0.30.0 | Python |
| cyclonedx-python-lib | 11.5.0 | 11.6.0 | Python |
| keyring | 25.6.0 | 25.7.0 | Python |
| markdownify | 1.2.0 | 1.2.2 | Python |
| markitdown | 0.1.3 | 0.1.4 | Python |
| numpy | 2.3.4 | 2.3.5 | Python |
| packageurl-python | 0.17.5 | 0.17.6 | Python |
| platformdirs | 4.5.0 | 4.5.1 | Python |
| protobuf | 6.33.1 | 6.33.2 | Python |
| SecretStorage | 3.4.1 | 3.5.0 | Python |

---

## Core Dependencies (pyproject.toml)

| Package | Minimum Version | Purpose |
|---------|-----------------|---------|
| click | >=8.0.0 | CLI framework |
| rich | >=13.0.0 | Terminal UI |
| bandit | >=1.7.0 | Python security scanner |
| yamllint | >=1.32.0 | YAML linting |
| tqdm | >=4.65.0 | Progress bars |
| requests | >=2.28.0 | HTTP client |
| urllib3 | >=2.0.0 | HTTP library |
| pyyaml | >=6.0 | YAML parsing |
| psutil | >=5.9.0 | System utilities |
| defusedxml | >=0.7.1 | Safe XML parsing |
| tomli-w | >=1.0.0 | TOML writing |
| toml | >=0.10.2 | TOML parsing |
| Blinter | >=0.2.3 | Lint utilities |

---

## External Security Tools (tool-versions.lock)

### Python Tools
| Tool | Locked Version | Purpose |
|------|----------------|---------|
| ansible-lint | 25.11.1 | Ansible linting |
| bandit | 1.9.2 | Python security |
| black | 25.12.0 | Python formatting |
| mccabe | 0.7.0 | Complexity checker |
| mypy | 1.19.0 | Type checking |
| prospector | 1.17.3 | Python analysis |
| pydocstyle | 6.3.0 | Docstring checker |
| pyflakes | 3.4.0 | Python error checker |
| pylint | 4.0.3 | Python linting |
| ruff | 0.14.8 | Fast Python linter |
| safety | 3.7.0 | Dependency security |
| sqlfluff | 3.5.0 | SQL linting |
| vulture | 2.14 | Dead code finder |
| yamllint | 1.37.1 | YAML linting |

### JavaScript Tools
| Tool | Locked Version | Purpose |
|------|----------------|---------|
| eslint | 9.39.1 | JS linting |
| htmlhint | 1.8.0 | HTML linting |
| jshint | 2.13.6 | JS quality |
| markdownlint-cli | 0.46.0 | Markdown linting |
| prettier | 3.7.2 | Code formatting |
| standard | 17.1.2 | JS style |
| stylelint | 16.26.1 | CSS linting |
| typescript | 5.9.3 | TS compiler |

### Go Tools
| Tool | Locked Version | Purpose |
|------|----------------|---------|
| golangci-lint | 2.6.2 | Go linting |
| staticcheck | 2025.1.1 | Go analysis |

### Rust Tools
| Tool | Locked Version | Purpose |
|------|----------------|---------|
| clippy | 0.0.302 | Rust linting |

### Shell Tools
| Tool | Locked Version | Purpose |
|------|----------------|---------|
| bashate | 2.1.1 | Bash style |
| shellcheck | 0.11.0 | Shell analysis |

### Container/IaC Tools
| Tool | Locked Version | Purpose |
|------|----------------|---------|
| hadolint | 2.14.0 | Dockerfile linting |
| checkov | 3.2.495 | IaC security |
| tflint | 0.60.0 | Terraform linting |
| tfsec | 1.28.14 | Terraform security |
| kube-linter | 0.7.6 | K8s linting |
| kubeval | 0.16.1 | K8s validation |

### AI Security Tools
| Tool | Locked Version | Purpose |
|------|----------------|---------|
| garak | 0.13.2 | LLM vulnerability scanner |
| llm-guard | 0.3.16 | LLM security |
| modelscan | 0.8.7 | ML model scanner |

### Misc Tools
| Tool | Locked Version | Purpose |
|------|----------------|---------|
| gitleaks | 8.30.0 | Secret detection |
| semgrep | 1.145.0 | Code analysis |
| trivy | 0.68.1 | Vulnerability scanner |

---

## Update Schedule

We aim to review dependencies weekly:
- **Thursdays**: Check `pip list --outdated` and external tool releases
- **Before releases**: Verify all safe updates are applied

### How to Check for Updates

```bash
# Check Python packages
.venv/bin/pip list --outdated

# Check if a specific package has updates
.venv/bin/pip index versions <package-name>

# Check external tools (manual review of GitHub releases)
```

---

## Dependency Conflict Resolution

When a dependency conflict occurs:

1. **Document the blocker** in the table above
2. **Create a GitHub issue** to track when the blocker is resolved
3. **Set a reminder** to check weekly
4. **Consider alternatives** if the blocker persists > 3 months

### Current Blockers

#### magika 0.6.3 → 1.0.1
- **Blocker:** markitdown 0.1.4 requires `magika~=0.6.1`
- **Impact:** Cannot use magika's new 200+ content type detection
- **Workaround:** None needed - magika 0.6.3 works fine
- **Monitor:** https://github.com/microsoft/markitdown/releases
- **Created:** 2025-12-11

---

## Notes

- External tool versions are pinned in `medusa/tool-versions.lock`
- Python dependencies use minimum versions in `pyproject.toml`
- Always run tests after updating dependencies
- Major version updates require manual review and testing
