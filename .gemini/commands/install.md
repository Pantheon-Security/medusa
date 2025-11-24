# medusa install - Install Security Tools

Install security analyzers needed for MEDUSA scanning.

## Usage

```bash
medusa install [options]
```

## Examples

### Check what's installed
```bash
medusa install --check
```

Shows:
- ✅ Installed tools (with version)
- ❌ Missing tools
- 🔄 Tools with updates available

Example output:
```bash
$ medusa install --check

Tool Installation Status:

Python Security:
  ✅ bandit (1.7.5)
  ✅ safety (2.3.5)
  ❌ semgrep (not installed)
  🔄 pylint (2.15.0 → 3.0.2 available)

JavaScript Security:
  ✅ eslint (8.52.0)
  ❌ retire.js (not installed)

Shell Security:
  ✅ shellcheck (0.9.0)
  ✅ shfmt (3.7.0)

Docker/Infrastructure:
  ❌ hadolint (not installed)
  ✅ trivy (0.46.0)

Summary:
- 36/43 tools installed (84%)
- 7 tools need installation
- 3 updates available

💡 Install missing tools: medusa install --all
💡 Update tools: medusa install --upgrade
```

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

### Update all tools
```bash
medusa install --upgrade
```

### Dry run (preview only)
```bash
medusa install --all --dry-run
```

Shows what would be installed without actually installing.

### Check system requirements
```bash
medusa install --check-system
```

Shows:
- Operating system and version
- Available package managers
- Architecture (x64, arm64)
- Python version
- Node.js version
- Go version
- Rust/Cargo version

## What Gets Installed

MEDUSA uses 43+ specialized security analyzers:

### Shell Security (3)
- shellcheck - Shell script analysis
- shfmt - Shell formatter
- bashate - Bash style checker

### Python Security (13)
- bandit - Python AST security scanner
- safety - Python dependency checker
- pip-audit - Audit Python packages
- pylint - Python linter
- mypy - Static type checker
- semgrep - Pattern matcher
- And 7 more...

### JavaScript/TypeScript (8)
- eslint - JavaScript linter
- npm audit - NPM dependency scanner
- yarn audit - Yarn dependency scanner
- retire.js - JS library vulnerability scanner
- And 4 more...

### Go Security (5)
- gosec - Go security scanner
- govulncheck - Go vulnerability checker
- staticcheck - Go static analyzer
- And 2 more...

### Rust Security (4)
- cargo-audit - Rust dependency auditor
- cargo-clippy - Rust linter
- And 2 more...

### Docker/Infrastructure (3)
- hadolint - Dockerfile linter
- trivy - Container vulnerability scanner
- checkov - IaC security scanner

### And 15+ more...

Full list: See `medusa install --check`

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

## Interactive Installation

```bash
$ medusa install --all

🔧 MEDUSA Tool Installer

Found 7 missing tools. Install them? [Y/n] y

Installing shellcheck...
  ✅ shellcheck 0.9.0 installed via apt

Installing hadolint...
  🔄 Downloading PowerShell installer...
  ✅ hadolint 2.12.0 installed

Installing semgrep...
  ✅ semgrep 1.45.0 installed via pip

...

Summary:
  ✅ 6 tools installed successfully
  ❌ 1 tool failed (retry: medusa install --tool retire.js)

💡 Verify: medusa install --check
```

## Configuration

`.medusa.yml`:

```yaml
installation:
  auto_install: true
  package_managers:
    - apt
    - brew
    - npm
    - pip
  confirm_before_install: false  # Set true for manual approval
  parallel_install: true
  max_retries: 3
```

`.gemini/config.yaml`:

```yaml
medusa:
  installation:
    auto_install: true
    package_managers:
      - apt
      - brew
      - npm
      - pip
    confirm_before_install: false
```

## Troubleshooting

### Tool installation failed

1. **Check package manager:**
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

3. **Check logs:**
   ```bash
   cat .medusa/logs/install.log
   ```

4. **Retry specific tool:**
   ```bash
   medusa install --tool shellcheck --verbose
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
hash -r

# Windows
refreshenv  # If using choco
# Or restart terminal
```

### "Package manager not available"

Install missing package manager:

**macOS:**
```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Linux:**
```bash
# Ubuntu/Debian
sudo apt update

# Fedora
sudo dnf update
```

**Windows:**
```powershell
# Install winget (usually pre-installed on Windows 11)
# Or install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

## Advanced Usage

### Install only Python tools
```bash
medusa install --category python
```

### Install only JavaScript tools
```bash
medusa install --category javascript
```

### Install from specific package manager
```bash
medusa install --all --pm brew
medusa install --all --pm npm
```

### Skip confirmation prompts
```bash
medusa install --all --yes
```

## Exit Codes

- `0` - All tools installed successfully
- `1` - Some tools failed to install
- `2` - No package manager available
- `3` - Configuration error

## Learn More

- **Installation Guide:** https://medusa-security.readthedocs.io/en/latest/installation/
- **Tool Manifest:** `tools-manifest.csv` (full tool list with versions)
- **Supported Platforms:** Linux, macOS, Windows (x64, arm64)
- **Package Managers:** apt, yum, dnf, pacman, snap, brew, winget, choco, npm, pip, cargo, go
