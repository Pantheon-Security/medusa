# MEDUSA Examples

Example configuration files and vulnerable application demos to help you understand and integrate MEDUSA.

## Configuration Examples

| File | Description |
|------|-------------|
| `medusa.example.yml` | Example MEDUSA configuration file |
| `github-action.yml` | GitHub Actions workflow for CI/CD |
| `gitlab-ci.yml` | GitLab CI configuration |
| `pre-commit-config.yaml` | Pre-commit hooks configuration |

## Vulnerable Application Examples

Real-world vulnerable apps that demonstrate what MEDUSA detects. See [`vulnerable-apps/README.md`](vulnerable-apps/README.md) for details.

| Example | Language | Key Vulnerabilities |
|---------|----------|-------------------|
| [`vulnerable-apps/flask-llm-app/`](vulnerable-apps/flask-llm-app/) | Python | Prompt injection, RAG poisoning, secrets, pickle RCE |
| [`vulnerable-apps/mcp-server/`](vulnerable-apps/mcp-server/) | Python/JSON | Excessive agency, credential exposure, no sandboxing |
| [`vulnerable-apps/node-ai-agent/`](vulnerable-apps/node-ai-agent/) | Node.js | Unsafe eval, SSRF, unbounded agent loops, secrets |
| [`vulnerable-apps/docker-ml-pipeline/`](vulnerable-apps/docker-ml-pipeline/) | Docker | Privileged containers, host escape, insecure ML serving |

### Scan All Examples

```bash
# Scan all vulnerable apps to see MEDUSA in action
medusa scan examples/vulnerable-apps/

# Scan a specific example
medusa scan examples/vulnerable-apps/flask-llm-app/
```

## Quick Start

### 1. Add MEDUSA config to your project

```bash
cp examples/medusa.example.yml .medusa.yml
```

### 2. Set up CI/CD (choose one)

**GitHub Actions:**
```bash
mkdir -p .github/workflows
cp examples/github-action.yml .github/workflows/security.yml
```

**GitLab CI:**
```bash
cat examples/gitlab-ci.yml >> .gitlab-ci.yml
```

### 3. Set up pre-commit hooks (optional)

```bash
cp examples/pre-commit-config.yaml .pre-commit-config.yaml
pip install pre-commit
pre-commit install
```

## Learn More

- [Installation Guide](../docs/INSTALLATION.md)
- [Quick Start](../docs/QUICKSTART.md)
- [Full Documentation](https://github.com/Pantheon-Security/medusa)
