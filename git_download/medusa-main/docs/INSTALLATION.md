# 📦 MEDUSA Installation Guide

Complete installation guide for all supported platforms.

---

## Quick Install

### Prerequisites

- **Python**: 3.10 or higher
- **pip**: Python package manager
- **Internet connection**: For downloading tools

### One-Line Install

```bash
pip install medusa-security && medusa init && medusa install --all
```

This installs MEDUSA, initializes your project, and installs all security tools.

---

## Platform-Specific Installation

### Linux

#### Ubuntu / Debian

```bash
# 1. Install Python and pip (if not already installed)
sudo apt update
sudo apt install python3 python3-pip

# 2. Install MEDUSA
pip3 install medusa-security

# 3. Add to PATH (if needed)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# 4. Verify installation
medusa --version

# 5. Install security tools
cd your-project
medusa install --all --yes
```

**Tools auto-installed via apt**:
- shellcheck
- yamllint
- hadolint (Docker)
- cppcheck (C/C++)
- checkstyle (Java)

#### RHEL / CentOS / Fedora

```bash
# 1. Install Python and pip
sudo dnf install python3 python3-pip

# 2. Install MEDUSA
pip3 install medusa-security

# 3. Add to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# 4. Verify
medusa --version

# 5. Install tools
medusa install --all --yes
```

**Tools auto-installed via dnf/yum**:
- shellcheck
- yamllint
- cppcheck

#### Arch Linux

```bash
# 1. Install Python and pip
sudo pacman -S python python-pip

# 2. Install MEDUSA
pip install medusa-security

# 3. Verify
medusa --version

# 4. Install tools
medusa install --all --yes
```

**Tools auto-installed via pacman**:
- shellcheck
- yamllint
- hadolint

---

### macOS

#### Using Homebrew (Recommended)

```bash
# 1. Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Install Python
brew install python

# 3. Install MEDUSA
pip3 install medusa-security

# 4. Verify
medusa --version

# 5. Install security tools
cd your-project
medusa install --all --yes
```

**Tools auto-installed via Homebrew**:
- shellcheck
- yamllint
- hadolint
- tflint (Terraform)
- ktlint (Kotlin)
- swiftlint (Swift)
- golangci-lint (Go)

#### Using MacPorts

```bash
# 1. Install Python
sudo port install python310 py310-pip

# 2. Install MEDUSA
pip3 install medusa-security

# 3. Verify
medusa --version

# 4. Install tools
medusa install --all --yes
```

---

### Windows

#### Option 1: WSL2 (Recommended)

**Best Windows experience - full Linux compatibility**

```powershell
# 1. Install WSL2
wsl --install

# 2. Restart computer

# 3. Open Ubuntu (from Start menu)

# 4. Inside WSL Ubuntu:
sudo apt update
sudo apt install python3 python3-pip

pip3 install medusa-security

echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

medusa --version

# 5. Install tools
cd /mnt/c/Users/YourName/projects/your-project
medusa install --all --yes
```

**Advantages**:
- ✅ Full Linux tool support (95%+ coverage)
- ✅ Native performance
- ✅ All MEDUSA features work
- ✅ Easy file access (C: drive at `/mnt/c/`)

#### Option 2: Git Bash

**Good for Git users**

```bash
# 1. Install Git for Windows (includes Git Bash)
# Download from: https://git-scm.com/download/win

# 2. Install Python for Windows
# Download from: https://www.python.org/downloads/

# 3. Open Git Bash

# 4. Install MEDUSA
pip install medusa-security

# 5. Verify
medusa --version

# 6. Install tools (limited Windows support)
cd /c/Users/YourName/projects/your-project
medusa install --check  # See what's available
medusa install --all --yes
```

**Tool Support**:
- ✅ Python tools (pip)
- ✅ Node.js tools (npm)
- ⚠️ Limited system tools
- ❌ Some Unix-only tools unavailable

#### Option 3: PowerShell / CMD

**Native Windows experience**

```powershell
# 1. Install Python for Windows
# Download from: https://www.python.org/downloads/
# ✅ Check "Add Python to PATH" during installation

# 2. Open PowerShell or CMD

# 3. Install MEDUSA
pip install medusa-security

# 4. Verify
medusa --version

# 5. Install tools
cd C:\Users\YourName\projects\your-project
medusa install --check
medusa install --all --yes
```

**Tool Support**:
- ✅ Python tools (pip): bandit, sqlfluff, ansible-lint
- ✅ Node.js tools (npm): eslint, htmlhint, stylelint
- ⚠️ PowerShell-specific: PSScriptAnalyzer
- ❌ Unix tools (shellcheck, etc.) - use WSL2

#### Option 4: Scoop (Package Manager)

```powershell
# 1. Install Scoop
iwr -useb get.scoop.sh | iex

# 2. Install Python
scoop install python

# 3. Install MEDUSA
pip install medusa-security

# 4. Install some tools via Scoop
scoop install shellcheck  # Scoop has some Unix tools!

# 5. Install remaining tools
medusa install --all --yes
```

---

## Installing Security Tools

After installing MEDUSA, you need to install the actual security scanning tools.

### Automatic Installation (Recommended)

```bash
# Check which tools are available
medusa install --check

# Install all missing tools
medusa install --all

# Install without confirmation prompts
medusa install --all --yes
```

### Manual Installation

If auto-install fails or you prefer manual installation:

#### Python Tools (pip)

```bash
pip install bandit sqlfluff ansible-lint yamllint
```

#### Node.js Tools (npm)

```bash
npm install -g eslint htmlhint stylelint markdownlint-cli
npm install -g tslint  # For TypeScript
```

#### Ruby Tools (gem)

```bash
gem install rubocop
```

#### Go Tools

```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

#### Rust Tools

```bash
rustup component add clippy
```

#### PHP Tools (Composer)

```bash
composer global require phpstan/phpstan
```

#### System Tools (Linux)

**Ubuntu/Debian:**
```bash
sudo apt install shellcheck yamllint hadolint cppcheck checkstyle
```

**macOS:**
```bash
brew install shellcheck yamllint hadolint tflint ktlint swiftlint
```

### Tool Installation by Language

| Language | Tool | Command |
|----------|------|---------|
| Python | Bandit | `pip install bandit` |
| JavaScript | ESLint | `npm install -g eslint` |
| Go | golangci-lint | `brew install golangci-lint` |
| Ruby | RuboCop | `gem install rubocop` |
| PHP | PHPStan | `composer global require phpstan/phpstan` |
| Rust | Clippy | `rustup component add clippy` |
| Shell | ShellCheck | `apt install shellcheck` |
| YAML | yamllint | `pip install yamllint` |
| Docker | hadolint | `brew install hadolint` |
| Terraform | tflint | `brew install tflint` |

---

## Post-Installation

### Verify Installation

```bash
# Check MEDUSA version
medusa --version

# Check installed tools
medusa install --check

# Run a test scan
mkdir test-project
cd test-project
echo "print('Hello World')" > test.py
medusa scan .
```

Expected output:
```
🐍 MEDUSA v0.9.1.1 - Security Guardian
...
✅ Scan complete!
```

### Initialize Your Project

```bash
cd your-project
medusa init
```

This creates:
- `.medusa.yml` - Configuration file
- `.claude/agents/medusa/agent.json` - IDE integration (if using Claude Code)

### First Scan

```bash
medusa scan .
```

---

## Troubleshooting

### "Command not found: medusa"

**Linux/macOS:**

```bash
# Add pip install directory to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**Windows:**

Check if Python Scripts directory is in PATH:
- `C:\Users\YourName\AppData\Local\Programs\Python\Python3XX\Scripts`

### "Permission denied" during tool installation

**Linux:**

```bash
# Don't use sudo with pip
pip install --user medusa-security

# For system tools, use sudo
sudo apt install shellcheck
```

**macOS:**

```bash
# Use Homebrew for system tools
brew install shellcheck

# No sudo needed for pip
pip3 install medusa-security
```

### Tools not found after installation

**Check PATH:**

```bash
# Linux/macOS
echo $PATH

# Windows
echo %PATH%
```

**Verify tool location:**

```bash
# Linux/macOS
which bandit
which eslint

# Windows
where bandit
where eslint
```

### Python version issues

**Check Python version:**

```bash
python3 --version  # Should be 3.10+
```

**Install newer Python:**

```bash
# Ubuntu
sudo apt install python3.11

# macOS
brew install python@3.11

# Windows
# Download from python.org
```

### npm not found

**Install Node.js:**

```bash
# Ubuntu
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install nodejs

# macOS
brew install node

# Windows
# Download from nodejs.org
```

---

## Advanced Installation

### Install from Source

```bash
# Clone repository
git clone https://github.com/Pantheon-Security/medusa.git
cd medusa

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows

# Install in editable mode
pip install -e .

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Verify
medusa --version
```

### Docker Installation

```dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    shellcheck \
    yamllint \
    hadolint \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js for JavaScript tools
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs

# Install MEDUSA
RUN pip install medusa-security

# Install security tools
RUN medusa install --all --yes

WORKDIR /workspace
ENTRYPOINT ["medusa"]
CMD ["scan", "."]
```

**Usage:**

```bash
docker build -t medusa .
docker run -v $(pwd):/workspace medusa
```

### CI/CD Installation

#### GitHub Actions

```yaml
- name: Set up Python
  uses: actions/setup-python@v4
  with:
    python-version: '3.11'

- name: Install MEDUSA
  run: pip install medusa-security

- name: Install security tools
  run: medusa install --all --yes

- name: Run scan
  run: medusa scan . --fail-on high
```

#### GitLab CI

```yaml
security_scan:
  image: python:3.11
  before_script:
    - pip install medusa-security
    - medusa install --all --yes
  script:
    - medusa scan . --fail-on high
```

---

## System Requirements

### Minimum Requirements

- **CPU**: 2 cores
- **RAM**: 2GB
- **Disk**: 500MB for MEDUSA + tools
- **OS**: Linux, macOS 10.13+, Windows 10+
- **Python**: 3.10+

### Recommended Requirements

- **CPU**: 4+ cores (for parallel scanning)
- **RAM**: 4GB+
- **Disk**: 2GB (includes all 42 tools)
- **OS**: Ubuntu 20.04+, macOS 12+, Windows 11 (WSL2)
- **Python**: 3.11+

---

## Uninstallation

### Remove MEDUSA

```bash
pip uninstall medusa-security
```

### Remove Security Tools

```bash
# Python tools
pip uninstall bandit sqlfluff yamllint ansible-lint

# Node.js tools
npm uninstall -g eslint htmlhint stylelint

# System tools (Linux)
sudo apt remove shellcheck yamllint hadolint

# System tools (macOS)
brew uninstall shellcheck yamllint hadolint tflint
```

### Remove Configuration

```bash
# Remove project config
rm .medusa.yml
rm -rf .medusa/
rm -rf .claude/agents/medusa/

# Remove user cache
rm -rf ~/.medusa/
```

---

## Upgrading

### Upgrade MEDUSA

```bash
pip install --upgrade medusa-security
```

### Upgrade Security Tools

```bash
# Check for updates
medusa install --check

# Reinstall all tools (updates to latest)
medusa install --all --yes
```

---

## Next Steps

After installation:

1. Read [Quick Start Guide](QUICKSTART.md)
2. Run `medusa init` in your project
3. Install tools with `medusa install --all`
4. Run first scan with `medusa scan .`
5. Explore [Configuration Guide](CONFIGURATION.md)

---

**Installation Support**: [GitHub Issues](https://github.com/Pantheon-Security/medusa/issues)

**Last Updated**: 2025-11-15
**MEDUSA Version**: 0.9.1.1
