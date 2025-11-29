# MEDUSA Examples

Example configuration files to help you integrate MEDUSA into your projects.

## Files

| File | Description |
|------|-------------|
| `medusa.example.yml` | Example MEDUSA configuration file |
| `github-action.yml` | GitHub Actions workflow for CI/CD |
| `gitlab-ci.yml` | GitLab CI configuration |
| `pre-commit-config.yaml` | Pre-commit hooks configuration |

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
