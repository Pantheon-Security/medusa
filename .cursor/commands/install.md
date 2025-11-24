# MEDUSA Tool Installation

Install security analyzers needed for MEDUSA scanning.

## Usage

```bash
@medusa install [options]
```

Or in terminal:
```bash
medusa install --check
medusa install --all
```

## Examples

### Check what's installed
```bash
medusa install --check
```

Shows:
- ✅ Installed tools (version)
- ❌ Missing tools
- 🔄 Tools with updates available

### Install all missing tools
```bash
medusa install --all
```

Automatically installs via:
- **Linux**: apt, snap, npm, pip, cargo, go
- **macOS**: brew, npm, pip, cargo, go
- **Windows**: winget, choco, npm, pip, cargo, go

### Install specific tool
```bash
medusa install --tool shellcheck
medusa install --tool bandit
medusa install --tool eslint
```

### Dry run (preview only)
```bash
medusa install --all --dry-run
```

Shows what would be installed without actually installing.

## What Gets Installed

MEDUSA uses 43+ specialized security analyzers:

### Shell Security
- **shellcheck** - Shell script analysis
- **bashate** - Bash style checker
- **shfmt** - Shell formatter

### Python Security
- **bandit** - Python AST security scanner
- **safety** - Python dependency checker
- **pip-audit** - Audit Python packages for CVEs
- **pylint** - Python linter with security rules
- **mypy** - Static type checker
- **semgrep** - Multi-language pattern matcher

### JavaScript/TypeScript Security
- **eslint** - JavaScript linter
- **npm audit** - NPM dependency scanner
- **yarn audit** - Yarn dependency scanner
- **retire.js** - JS library vulnerability scanner

### Go Security
- **gosec** - Go security scanner
- **govulncheck** - Go vulnerability checker
- **staticcheck** - Go static analyzer

### Rust Security
- **cargo-audit** - Rust dependency auditor
- **cargo-clippy** - Rust linter

### Docker/Infrastructure
- **hadolint** - Dockerfile linter
- **trivy** - Container vulnerability scanner
- **checkov** - IaC security scanner

### And 20+ more...

## Auto-Installation Features

### Platform Detection
MEDUSA automatically detects:
- Operating system (Linux, macOS, Windows)
- Package managers (apt, brew, winget, choco, npm, pip)
- Architecture (x64, arm64)
- Distribution (Ubuntu, Debian, Fedora, etc.)

### Smart Installation
- Uses best package manager for each tool
- Falls back to alternatives if primary fails
- Handles PowerShell scripts on Windows
- Validates installations after completion

### Windows Support
Special PowerShell installers for:
- hadolint, shellcheck, shfmt, actionlint
- checkmake, gitleaks, trufflehog
- And more...

**Success Rate:** 86% (36/42 tools) on fresh Windows VMs

## Configuration

Edit `.medusa.yml` to control installation:

```yaml
installation:
  auto_install: true
  package_managers:
    - apt
    - brew
    - npm
    - pip
  confirm_before_install: false  # Set true for manual approval
```

## Troubleshooting

### Tool installation failed

1. **Check package manager availability:**
   ```bash
   medusa install --check-system
   ```

2. **Try manual installation:**
   ```bash
   # Linux/macOS
   sudo apt install shellcheck
   brew install hadolint
   npm install -g eslint
   pip install bandit

   # Windows
   winget install ShellCheck
   choco install hadolint
   ```

3. **Check installation logs:**
   ```bash
   cat .medusa/logs/install.log
   ```

### Permission denied

**Linux/macOS:**
```bash
sudo medusa install --all
```

**Windows:**
Run PowerShell as Administrator

### Tool not found after installation

Refresh your PATH:
```bash
# Linux/macOS
source ~/.bashrc
source ~/.zshrc

# Windows (restart terminal)
```

## Learn More

- **Installation Guide:** https://medusa-security.readthedocs.io/en/latest/installation/
- **Tool Manifest:** `tools-manifest.csv` (full tool list with versions)
- **Supported Platforms:** Linux, macOS, Windows (x64, arm64)
