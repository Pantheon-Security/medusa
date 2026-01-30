# Optional Security Tools Guide

MEDUSA v2026.2 works out of the box with **4,152+ AI security rules**. External linters are **optional** - they enhance coverage but aren't required.

> **Note:** MEDUSA detects and uses these tools automatically if installed. We don't install or manage them - please refer to each vendor's official documentation for installation support.

---

## Quick Reference

| Tool | Purpose | Official Docs |
|------|---------|---------------|
| [bandit](#bandit) | Python security linter | [github.com/PyCQA/bandit](https://github.com/PyCQA/bandit) |
| [semgrep](#semgrep) | Multi-language SAST | [semgrep.dev/docs](https://semgrep.dev/docs/getting-started/) |
| [shellcheck](#shellcheck) | Shell script analyzer | [github.com/koalaman/shellcheck](https://github.com/koalaman/shellcheck) |
| [hadolint](#hadolint) | Dockerfile linter | [github.com/hadolint/hadolint](https://github.com/hadolint/hadolint) |
| [yamllint](#yamllint) | YAML linter | [github.com/adrienverge/yamllint](https://github.com/adrienverge/yamllint) |
| [eslint](#eslint) | JavaScript linter | [eslint.org/docs](https://eslint.org/docs/latest/use/getting-started) |
| [trivy](#trivy) | Vulnerability scanner | [aquasecurity.github.io/trivy](https://aquasecurity.github.io/trivy/) |
| [gitleaks](#gitleaks) | Secrets scanner | [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| [tflint](#tflint) | Terraform linter | [github.com/terraform-linters/tflint](https://github.com/terraform-linters/tflint) |
| [golangci-lint](#golangci-lint) | Go linter | [golangci-lint.run](https://golangci-lint.run/usage/install/) |

---

## Check What's Installed

```bash
medusa install --check
```

This shows which tools MEDUSA detected on your system.

---

## Tool Installation Guides

### Bandit

Python security linter for finding common security issues.

**Official Documentation:** https://bandit.readthedocs.io/

<details>
<summary><b>Linux</b></summary>

```bash
# Via pip (recommended)
pip install bandit

# Via apt (Debian/Ubuntu)
sudo apt install bandit
```

For issues, see: https://github.com/PyCQA/bandit/issues
</details>

<details>
<summary><b>macOS</b></summary>

```bash
# Via pip (recommended)
pip install bandit

# Via Homebrew
brew install bandit
```

For issues, see: https://github.com/PyCQA/bandit/issues
</details>

<details>
<summary><b>Windows</b></summary>

```powershell
# Via pip
pip install bandit
```

For issues, see: https://github.com/PyCQA/bandit/issues
</details>

---

### Semgrep

Multi-language static analysis tool with 2,000+ rules.

**Official Documentation:** https://semgrep.dev/docs/getting-started/

<details>
<summary><b>Linux</b></summary>

```bash
# Via pip (recommended)
pip install semgrep

# Via apt (Debian/Ubuntu)
# See official docs for latest instructions
```

For issues, see: https://github.com/semgrep/semgrep/issues
</details>

<details>
<summary><b>macOS</b></summary>

```bash
# Via Homebrew (recommended)
brew install semgrep

# Via pip
pip install semgrep
```

For issues, see: https://github.com/semgrep/semgrep/issues
</details>

<details>
<summary><b>Windows</b></summary>

```powershell
# Via pip (WSL recommended)
pip install semgrep
```

**Note:** Semgrep has limited Windows support. See official docs for current status.

For issues, see: https://github.com/semgrep/semgrep/issues
</details>

---

### ShellCheck

Static analysis tool for shell scripts.

**Official Documentation:** https://github.com/koalaman/shellcheck#installing

<details>
<summary><b>Linux</b></summary>

```bash
# Debian/Ubuntu
sudo apt install shellcheck

# Fedora/RHEL
sudo dnf install ShellCheck

# Arch
sudo pacman -S shellcheck
```

For issues, see: https://github.com/koalaman/shellcheck/issues
</details>

<details>
<summary><b>macOS</b></summary>

```bash
brew install shellcheck
```

For issues, see: https://github.com/koalaman/shellcheck/issues
</details>

<details>
<summary><b>Windows</b></summary>

```powershell
# Via Chocolatey
choco install shellcheck

# Via Scoop
scoop install shellcheck
```

For issues, see: https://github.com/koalaman/shellcheck/issues
</details>

---

### Hadolint

Dockerfile linter that helps build best practice Docker images.

**Official Documentation:** https://github.com/hadolint/hadolint#install

<details>
<summary><b>Linux</b></summary>

```bash
# Download binary
wget -O hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
chmod +x hadolint
sudo mv hadolint /usr/local/bin/

# Via apt (if available)
sudo apt install hadolint
```

For issues, see: https://github.com/hadolint/hadolint/issues
</details>

<details>
<summary><b>macOS</b></summary>

```bash
brew install hadolint
```

For issues, see: https://github.com/hadolint/hadolint/issues
</details>

<details>
<summary><b>Windows</b></summary>

```powershell
# Via Chocolatey
choco install hadolint

# Via Scoop
scoop install hadolint
```

For issues, see: https://github.com/hadolint/hadolint/issues
</details>

---

### YAMLlint

Linter for YAML files.

**Official Documentation:** https://yamllint.readthedocs.io/

<details>
<summary><b>Linux</b></summary>

```bash
# Via pip (recommended)
pip install yamllint

# Via apt (Debian/Ubuntu)
sudo apt install yamllint
```

For issues, see: https://github.com/adrienverge/yamllint/issues
</details>

<details>
<summary><b>macOS</b></summary>

```bash
# Via pip
pip install yamllint

# Via Homebrew
brew install yamllint
```

For issues, see: https://github.com/adrienverge/yamllint/issues
</details>

<details>
<summary><b>Windows</b></summary>

```powershell
pip install yamllint
```

For issues, see: https://github.com/adrienverge/yamllint/issues
</details>

---

### ESLint

Pluggable JavaScript/TypeScript linter.

**Official Documentation:** https://eslint.org/docs/latest/use/getting-started

<details>
<summary><b>All Platforms</b></summary>

```bash
# Via npm (recommended)
npm install -g eslint

# Via yarn
yarn global add eslint
```

**Note:** ESLint requires Node.js. Install from https://nodejs.org/

For issues, see: https://github.com/eslint/eslint/issues
</details>

---

### Trivy

Comprehensive vulnerability scanner for containers, filesystems, and more.

**Official Documentation:** https://aquasecurity.github.io/trivy/

<details>
<summary><b>Linux</b></summary>

```bash
# Debian/Ubuntu
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Or download binary from GitHub releases
```

For issues, see: https://github.com/aquasecurity/trivy/issues
</details>

<details>
<summary><b>macOS</b></summary>

```bash
brew install trivy
```

For issues, see: https://github.com/aquasecurity/trivy/issues
</details>

<details>
<summary><b>Windows</b></summary>

```powershell
# Via Chocolatey
choco install trivy
```

For issues, see: https://github.com/aquasecurity/trivy/issues
</details>

---

### Gitleaks

Scan git repos for secrets and sensitive data.

**Official Documentation:** https://github.com/gitleaks/gitleaks#getting-started

<details>
<summary><b>Linux</b></summary>

```bash
# Download from GitHub releases
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_VERSION_linux_x64.tar.gz
tar -xzf gitleaks_*.tar.gz
sudo mv gitleaks /usr/local/bin/
```

For issues, see: https://github.com/gitleaks/gitleaks/issues
</details>

<details>
<summary><b>macOS</b></summary>

```bash
brew install gitleaks
```

For issues, see: https://github.com/gitleaks/gitleaks/issues
</details>

<details>
<summary><b>Windows</b></summary>

```powershell
# Via Chocolatey
choco install gitleaks

# Via Scoop
scoop install gitleaks
```

For issues, see: https://github.com/gitleaks/gitleaks/issues
</details>

---

### TFLint

Terraform linter focused on possible errors and best practices.

**Official Documentation:** https://github.com/terraform-linters/tflint#installation

<details>
<summary><b>Linux</b></summary>

```bash
# Via install script
curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash
```

For issues, see: https://github.com/terraform-linters/tflint/issues
</details>

<details>
<summary><b>macOS</b></summary>

```bash
brew install tflint
```

For issues, see: https://github.com/terraform-linters/tflint/issues
</details>

<details>
<summary><b>Windows</b></summary>

```powershell
# Via Chocolatey
choco install tflint
```

For issues, see: https://github.com/terraform-linters/tflint/issues
</details>

---

### golangci-lint

Fast Go linters runner with 100+ linters.

**Official Documentation:** https://golangci-lint.run/usage/install/

<details>
<summary><b>Linux</b></summary>

```bash
# Via install script (recommended)
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

# Via go install
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

For issues, see: https://github.com/golangci/golangci-lint/issues
</details>

<details>
<summary><b>macOS</b></summary>

```bash
# Via Homebrew (recommended)
brew install golangci-lint

# Via go install
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

For issues, see: https://github.com/golangci/golangci-lint/issues
</details>

<details>
<summary><b>Windows</b></summary>

```powershell
# Via go install
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Via Chocolatey
choco install golangci-lint
```

For issues, see: https://github.com/golangci/golangci-lint/issues
</details>

---

## Troubleshooting

### Tool Not Detected

If MEDUSA doesn't detect a tool you've installed:

1. **Check it's in your PATH:**
   ```bash
   which <tool-name>  # Linux/macOS
   where <tool-name>  # Windows
   ```

2. **Restart your terminal** after installation

3. **Verify it runs:**
   ```bash
   <tool-name> --version
   ```

### Installation Issues

For installation problems, please contact the tool vendor directly:

| Tool | Issue Tracker |
|------|---------------|
| bandit | https://github.com/PyCQA/bandit/issues |
| semgrep | https://github.com/semgrep/semgrep/issues |
| shellcheck | https://github.com/koalaman/shellcheck/issues |
| hadolint | https://github.com/hadolint/hadolint/issues |
| yamllint | https://github.com/adrienverge/yamllint/issues |
| eslint | https://github.com/eslint/eslint/issues |
| trivy | https://github.com/aquasecurity/trivy/issues |
| gitleaks | https://github.com/gitleaks/gitleaks/issues |
| tflint | https://github.com/terraform-linters/tflint/issues |
| golangci-lint | https://github.com/golangci/golangci-lint/issues |

---

## MEDUSA Support

MEDUSA-specific issues (detection not working, scan errors, etc.):
- GitHub Issues: https://github.com/Pantheon-Security/medusa/issues

**Note:** We cannot provide support for third-party tool installation issues. Please contact the respective tool vendors.

---

*Last updated: 2026-01-29 | MEDUSA v2026.2.0*
