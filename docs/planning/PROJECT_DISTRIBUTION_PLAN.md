# MEDUSA Distribution Project Plan

**Version**: 7.0.0 (Public Release)
**Target Date**: Q1 2026
**Status**: 📋 PLANNING

---

## 🎯 Project Goals

### Primary Objectives
1. ✅ Package MEDUSA as pip-installable Python package
2. ✅ Support Linux, macOS, Windows (native + WSL)
3. ✅ Auto-install linters per platform
4. ✅ Auto-create IDE agent configurations (Claude Code, Cursor, Codex, Gemini CLI)
5. ✅ Provide beautiful CLI experience across all platforms
6. ✅ Maintain 42-headed scanner architecture

### Success Metrics
- **Installation time**: <5 minutes on any platform
- **Linter coverage**: ≥80% of heads working on all platforms
- **User satisfaction**: ≥4.5/5 stars on PyPI
- **Monthly downloads**: 1,000+ within 6 months
- **GitHub stars**: 500+ within 1 year

---

## 📦 Package Structure

### Python Package Layout

```
medusa-security/
├── pyproject.toml              # Modern Python packaging (PEP 621)
├── setup.py                    # Legacy support
├── README.md                   # PyPI landing page
├── LICENSE                     # MIT License
├── .github/
│   └── workflows/
│       ├── test.yml            # CI/CD tests
│       ├── publish.yml         # PyPI publishing
│       └── release.yml         # GitHub releases
├── docs/
│   ├── installation.md         # Installation guide
│   ├── quickstart.md           # Quick start tutorial
│   ├── configuration.md        # Configuration options
│   ├── ide-integration.md      # IDE setup guides
│   └── troubleshooting.md      # Common issues
├── medusa/
│   ├── __init__.py
│   ├── __main__.py             # Entry point (python -m medusa)
│   ├── cli.py                  # CLI commands
│   ├── core/
│   │   ├── __init__.py
│   │   ├── scanner.py          # Core scanning engine
│   │   ├── cache.py            # Caching system
│   │   ├── parallel.py         # Parallel execution
│   │   └── reporter.py         # Report generation
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── base.py             # Base scanner class
│   │   ├── python_scanner.py   # Python (Bandit)
│   │   ├── bash_scanner.py     # Bash (ShellCheck)
│   │   ├── go_scanner.py       # Go (golangci-lint)
│   │   └── [38 more scanners]
│   ├── platform/
│   │   ├── __init__.py
│   │   ├── detector.py         # OS detection
│   │   ├── installers/
│   │   │   ├── linux.py        # Linux linter installer
│   │   │   ├── macos.py        # macOS linter installer
│   │   │   └── windows.py      # Windows linter installer
│   │   └── paths.py            # Cross-platform path handling
│   ├── ide/
│   │   ├── __init__.py
│   │   ├── claude_code.py      # Claude Code integration
│   │   ├── cursor.py           # Cursor integration
│   │   ├── codex.py            # Codex integration
│   │   └── gemini_cli.py       # Gemini CLI integration
│   └── templates/
│       ├── medusa.sh           # Bash wrapper template
│       ├── medusa.ps1          # PowerShell wrapper template
│       └── agent_config.json   # IDE agent template
└── tests/
    ├── __init__.py
    ├── test_scanner.py
    ├── test_cache.py
    ├── test_parallel.py
    └── test_installers.py
```

---

## 🖥️ Platform-Specific Challenges & Solutions

### 1. Linux ✅ (Easiest)

**Challenges**: Minimal
- ✅ Native bash support
- ✅ Standard package managers (apt, yum, pacman)
- ✅ Python widely available

**Installation Strategy**:
```bash
# Detect distro
if command -v apt; then
    sudo apt install shellcheck bandit yamllint
elif command -v yum; then
    sudo yum install ShellCheck python3-bandit yamllint
elif command -v pacman; then
    sudo pacman -S shellcheck bandit yamllint
fi
```

**Linter Availability**: ✅ 95%+ (all major linters available)

---

### 2. macOS ✅ (Easy)

**Challenges**: Minor
- ✅ Native bash support
- ✅ Homebrew widely adopted
- ⚠️ Some tools need xcode-select

**Installation Strategy**:
```bash
# Install Homebrew if missing
if ! command -v brew; then
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install linters
brew install shellcheck bandit yamllint golangci-lint hadolint
```

**Linter Availability**: ✅ 90%+ (Homebrew has most linters)

---

### 3. Windows ⚠️ (Complex)

#### **Challenge 1: No Native Bash**

**Solutions**:
1. **Git Bash** (recommended) - Comes with Git for Windows (90%+ already have)
2. **WSL2** (preferred) - Full Linux environment, best compatibility
3. **PowerShell Native** - Rewrite scanners in PowerShell (most work)

**Strategy**:
- Detect environment during install
- Prioritize: WSL2 > Git Bash > PowerShell
- Provide PowerShell wrappers for all scanners

#### **Challenge 2: Package Management**

**Solutions**:
1. **Chocolatey** (most popular Windows package manager)
2. **Scoop** (developer-friendly, no admin required)
3. **winget** (official Microsoft, comes with Windows 11)

**Installation Strategy**:
```powershell
# Detect package manager
if (Get-Command choco -ErrorAction SilentlyContinue) {
    choco install shellcheck bandit yamllint
}
elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
    scoop install shellcheck python
    pip install bandit yamllint
}
elseif (Get-Command winget -ErrorAction SilentlyContinue) {
    winget install --id ShellCheck.ShellCheck
    winget install --id Python.Python.3.12
    pip install bandit yamllint
}
else {
    Write-Host "No package manager found. Install Chocolatey? (Y/n)"
    # Offer to install Chocolatey
}
```

#### **Challenge 3: Path Separators**

**Problem**: Windows uses `\`, Unix uses `/`

**Solution**: Use Python `pathlib.Path` everywhere
```python
from pathlib import Path

# ✅ Works on all platforms
file_path = Path("medusa") / "scanners" / "python.py"

# ❌ Don't do this
file_path = "medusa/scanners/python.py"  # Breaks on Windows
```

#### **Challenge 4: Shell Scripts Don't Run**

**Problem**: `.sh` files need bash interpreter

**Solutions**:
1. Detect Git Bash and use it: `"C:\Program Files\Git\bin\bash.exe" script.sh`
2. Provide `.ps1` PowerShell equivalents
3. Use WSL if available: `wsl bash script.sh`

**Strategy**: Pure Python implementation (platform-agnostic)
```python
# Instead of calling shellcheck via bash:
subprocess.run(["shellcheck", file])

# On Windows, use full path:
subprocess.run([shutil.which("shellcheck"), file])
```

#### **Challenge 5: Admin Permissions**

**Problem**: Many Windows installers need admin

**Solutions**:
1. Use Scoop (no admin required)
2. Prompt for admin elevation with UAC
3. Provide portable versions of linters

#### **Challenge 6: Line Endings (CRLF vs LF)**

**Problem**: Windows uses `\r\n`, Unix uses `\n`

**Solution**: Handle both in Python
```python
# Read with universal newlines
with open(file, 'r', newline=None) as f:
    content = f.read()
```

**Linter Availability**: ⚠️ 60-70% (many linters don't have Windows builds)

**Workaround**: Recommend WSL2 for full compatibility

---

## 📥 Installation Modes

### Mode 1: pip install (Recommended)

```bash
# Install from PyPI
pip install medusa-security

# Initialize in current directory
medusa init

# Run scan
medusa scan .
```

**Installs**:
- ✅ Core MEDUSA package
- ✅ Python dependencies (bandit, yamllint, etc.)
- ⚠️ Prompts to install native linters (platform-specific)

---

### Mode 2: pipx install (Isolated)

```bash
# Install in isolated environment
pipx install medusa-security

# Still works globally
medusa scan /path/to/project
```

**Benefits**:
- ✅ No conflicts with other packages
- ✅ Clean global installation
- ✅ Easy to upgrade/uninstall

---

### Mode 3: Docker (Universal)

```bash
# Pull Docker image
docker pull ghcr.io/chimera/medusa:latest

# Run scan
docker run -v $(pwd):/workspace medusa scan /workspace
```

**Benefits**:
- ✅ Works identically on all platforms
- ✅ All linters pre-installed
- ✅ No system pollution
- ❌ Slower (container startup overhead)

---

### Mode 4: GitHub Actions (CI/CD)

```yaml
# .github/workflows/security.yml
- uses: chimera/medusa-action@v1
  with:
    mode: quick
    fail-on: high
```

**Benefits**:
- ✅ Zero setup for CI/CD
- ✅ Cached between runs
- ✅ Auto-updates

---

## 🔧 Linter Installation Strategy

### Tier 1: Python Package (pip install)
**Auto-installed with MEDUSA**:
- ✅ Bandit (Python)
- ✅ yamllint (YAML)
- ✅ safety (Python dependencies)

### Tier 2: Easy Install (brew/choco/scoop)
**Prompted during `medusa init`**:
- ⚠️ ShellCheck (bash)
- ⚠️ hadolint (Dockerfile)
- ⚠️ eslint (JavaScript) - via npm

### Tier 3: Manual Install (complex)
**Documented in install guide**:
- ⚠️ golangci-lint (Go) - requires Go
- ⚠️ tflint (Terraform) - requires Terraform
- ⚠️ slither (Solidity) - requires Python + Solidity

### Tier 4: Optional (specialized)
**Advanced users only**:
- ⚠️ Semgrep (multi-language)
- ⚠️ CodeQL (GitHub-specific)
- ⚠️ Snyk (requires account)

---

## 🎮 IDE Integration

### Claude Code ✅

**Setup**:
```bash
medusa init --ide claude-code

# Creates:
# .claude/agents/medusa/
# ├── agent.json
# ├── README.md
# └── hooks/
#     ├── pre-commit.sh
#     └── pre-push.sh
```

**Agent Configuration**:
```json
{
  "name": "medusa",
  "description": "The 42-Headed Security Guardian",
  "version": "7.0.0",
  "commands": [
    {
      "name": "scan",
      "description": "Run security scan",
      "command": "medusa scan --quick ."
    },
    {
      "name": "full-scan",
      "description": "Full security audit",
      "command": "medusa scan --force ."
    }
  ],
  "hooks": {
    "pre-commit": "medusa scan --quick --fail-on high ."
  }
}
```

---

### Cursor ✅

**Setup**:
```bash
medusa init --ide cursor

# Creates:
# .cursor/
# └── commands/
#     └── medusa.json
```

**Configuration**:
```json
{
  "commands": {
    "medusa-scan": {
      "name": "Security Scan",
      "command": "medusa scan .",
      "keybinding": "ctrl+shift+s"
    }
  }
}
```

---

### VS Codex / VS Code ✅

**Setup**:
```bash
medusa init --ide vscode

# Creates:
# .vscode/
# ├── tasks.json
# └── extensions.json (recommend MEDUSA extension)
```

**Tasks Configuration**:
```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "MEDUSA Security Scan",
      "type": "shell",
      "command": "medusa scan .",
      "group": "test",
      "presentation": {
        "reveal": "always",
        "panel": "new"
      }
    }
  ]
}
```

---

### Gemini CLI ✅

**Setup**:
```bash
medusa init --ide gemini-cli

# Creates:
# .gemini/
# └── tools/
#     └── medusa.yaml
```

**Configuration**:
```yaml
tools:
  - name: medusa-scan
    description: Run security scan
    command: medusa scan --quick .
    output: json
```

---

## 📋 Installation Flow (User Experience)

### Step 1: Install MEDUSA

```bash
$ pip install medusa-security

Collecting medusa-security...
Installing collected packages: medusa-security
Successfully installed medusa-security-7.0.0

$ medusa --version
MEDUSA v7.0.0 - The 42-Headed Security Guardian
```

---

### Step 2: Initialize Project

```bash
$ cd my-project
$ medusa init

🐍 MEDUSA Initialization Wizard

📁 Detecting project type...
   ✅ Python project detected
   ✅ JavaScript project detected
   ✅ Docker files detected

🔧 Checking linter availability...
   ✅ bandit (Python) - installed
   ✅ yamllint (YAML) - installed
   ⚠️  shellcheck (bash) - not found
   ⚠️  eslint (JavaScript) - not found
   ⚠️  hadolint (Docker) - not found

📦 Install missing linters? (Y/n): y

🖥️  Detected platform: macOS (Homebrew)

📥 Installing linters...
   ⏳ brew install shellcheck hadolint...
   ✅ shellcheck installed
   ✅ hadolint installed
   ⏳ npm install -g eslint...
   ✅ eslint installed

🎮 IDE Integration:
   Which IDE/editor are you using?
   1) Claude Code
   2) Cursor
   3) VS Code
   4) Gemini CLI
   5) None (skip)

   Choice: 1

   ✅ Created .claude/agents/medusa/
   ✅ Configured security scanning commands
   ✅ Added pre-commit hooks

🎉 MEDUSA initialized successfully!

   Next steps:
   1. Run your first scan:    medusa scan .
   2. Set up Git hooks:       medusa install-hooks
   3. View configuration:     medusa config

   Documentation: https://medusa-security.dev
```

---

### Step 3: First Scan

```bash
$ medusa scan .

🐍 MEDUSA v7.0.0 - Security Scan

📂 Scanning 348 files (24 workers)...
   ⏳ Progress: [████████████████████] 100% (5.2s)

✅ Scan complete!

📊 Results:
   🎯 Security Score: 95/100 (EXCELLENT)
   📂 Files scanned: 348
   📝 Lines scanned: 175,580
   🔍 Issues found: 4

   Severity breakdown:
   ⚠️  MEDIUM: 1
   🔵 LOW: 3

📄 Reports generated:
   • HTML: .medusa/reports/medusa-scan-20251114-090000.html
   • JSON: .medusa/reports/medusa-scan-20251114-090000.json

🌐 Opening HTML report...
```

---

## 🧪 Testing Strategy

### Platform Testing Matrix

| Platform | Python | Linters | IDE | Priority |
|----------|--------|---------|-----|----------|
| **Ubuntu 22.04** | 3.10-3.12 | All | All | ✅ P0 |
| **Ubuntu 24.04** | 3.12-3.14 | All | All | ✅ P0 |
| **macOS 13 (Intel)** | 3.10-3.12 | Most | All | ✅ P0 |
| **macOS 14 (M1/M2)** | 3.11-3.12 | Most | All | ✅ P0 |
| **Windows 11 (WSL2)** | 3.10-3.12 | All | All | ✅ P0 |
| **Windows 11 (Git Bash)** | 3.10-3.12 | Some | All | ⚠️ P1 |
| **Windows 11 (Native)** | 3.10-3.12 | Limited | All | ⚠️ P2 |
| **Debian 11** | 3.9-3.11 | All | All | ⚠️ P1 |
| **Fedora 39** | 3.11-3.12 | All | All | ⚠️ P1 |
| **Arch Linux** | 3.12 | All | All | ⚠️ P2 |

### Continuous Integration

```yaml
# .github/workflows/test.yml
name: Cross-Platform Tests

on: [push, pull_request]

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-22.04, ubuntu-24.04, macos-13, macos-14, windows-2022]
        python: ['3.10', '3.11', '3.12']

    runs-on: ${{ matrix.os }}

    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python }}

      - name: Install MEDUSA
        run: pip install -e .

      - name: Run tests
        run: pytest tests/

      - name: Test installation
        run: |
          medusa --version
          medusa scan . --no-report
```

---

## 📦 Distribution Channels

### 1. PyPI (Primary)

```bash
pip install medusa-security
```

**URL**: https://pypi.org/project/medusa-security/
**Benefits**: Standard Python distribution

---

### 2. GitHub Releases (Source)

**URL**: https://github.com/chimera/medusa/releases
**Assets**:
- Source code (tar.gz, zip)
- Pre-built wheels (all platforms)
- Standalone executables (PyInstaller)
- Docker images

---

### 3. Docker Hub / GHCR

```bash
docker pull ghcr.io/chimera/medusa:latest
```

**Tags**:
- `latest` - Latest stable
- `7.0.0` - Specific version
- `develop` - Development branch

---

### 4. Homebrew (macOS)

```bash
brew install medusa-security
```

**Tap**: `chimera/medusa`

---

### 5. Chocolatey (Windows)

```powershell
choco install medusa-security
```

**URL**: https://community.chocolatey.org/packages/medusa-security

---

### 6. Snap Store (Linux)

```bash
snap install medusa-security
```

**Benefits**: Universal Linux binary

---

## 📚 Documentation Structure

### Website: medusa-security.dev

```
medusa-security.dev/
├── index.html                  # Landing page
├── docs/
│   ├── installation/
│   │   ├── linux.html
│   │   ├── macos.html
│   │   ├── windows.html
│   │   └── docker.html
│   ├── quickstart.html
│   ├── configuration.html
│   ├── ide-integration/
│   │   ├── claude-code.html
│   │   ├── cursor.html
│   │   ├── vscode.html
│   │   └── gemini-cli.html
│   ├── scanners/              # Docs for all 42 heads
│   ├── api-reference.html
│   └── troubleshooting.html
└── blog/
    ├── announcing-v7.html
    └── windows-support.html
```

---

## 🚀 Launch Checklist

### Pre-Launch (Phase 1)

- [ ] Convert current code to Python package structure
- [ ] Implement platform detection
- [ ] Create Linux installer
- [ ] Create macOS installer
- [ ] Create Windows installer (WSL2 + Git Bash + Native)
- [ ] Write comprehensive tests (80%+ coverage)
- [ ] Set up CI/CD (GitHub Actions)
- [ ] Create documentation website
- [ ] Write installation guides for all platforms
- [ ] Implement IDE integrations (Claude Code, Cursor, VS Code, Gemini CLI)

### Alpha Testing (Phase 2)

- [ ] Internal testing on all platforms
- [ ] Fix platform-specific bugs
- [ ] Gather feedback from 5-10 alpha testers
- [ ] Iterate on UX/CLI design
- [ ] Benchmark performance on different systems

### Beta Release (Phase 3)

- [ ] Publish to Test PyPI
- [ ] Create GitHub repository (public)
- [ ] Release beta version (v7.0.0-beta.1)
- [ ] Gather feedback from 50-100 beta testers
- [ ] Fix critical bugs
- [ ] Optimize performance
- [ ] Finalize documentation

### Public Release (Phase 4)

- [ ] Publish to PyPI (v7.0.0)
- [ ] Submit to Homebrew
- [ ] Submit to Chocolatey
- [ ] Create GitHub release with assets
- [ ] Publish Docker images
- [ ] Launch website (medusa-security.dev)
- [ ] Write launch blog post
- [ ] Social media announcement (Twitter, Reddit, HN)
- [ ] Submit to Product Hunt

### Post-Launch (Phase 5)

- [ ] Monitor bug reports
- [ ] Address user feedback
- [ ] Create video tutorials
- [ ] Write integration guides
- [ ] Build community (Discord/Slack)
- [ ] Plan v7.1.0 features

---

## 💰 Resource Requirements

### Development Time

| Task | Estimate | Owner |
|------|----------|-------|
| Package restructuring | 1-2 weeks | Dev Team |
| Platform installers | 2-3 weeks | Dev Team |
| IDE integrations | 1-2 weeks | Dev Team |
| Testing & QA | 2-3 weeks | QA Team |
| Documentation | 1-2 weeks | Docs Team |
| Website | 1 week | Design Team |
| Beta testing | 2-4 weeks | Community |
| **Total** | **10-17 weeks** | |

### Infrastructure Costs

| Service | Cost/Month | Purpose |
|---------|------------|---------|
| GitHub Actions | $0-50 | CI/CD |
| Documentation hosting | $0-10 | Read the Docs |
| Website hosting | $5-20 | Netlify/Vercel |
| Docker Hub | $0 | Free tier |
| **Total** | **$5-80** | |

---

## 🎯 Success Criteria

### Technical Metrics
- ✅ Installs in <5 minutes on all platforms
- ✅ 80%+ test coverage
- ✅ Zero critical bugs at launch
- ✅ <100ms CLI startup time
- ✅ Works with Python 3.10-3.12

### Adoption Metrics
- 🎯 1,000+ PyPI downloads in first month
- 🎯 100+ GitHub stars in first month
- 🎯 50+ community contributions in first year
- 🎯 4.5/5 star rating on PyPI

### Community Metrics
- 🎯 Active Discord community (100+ members)
- 🎯 10+ blog posts/tutorials by community
- 🎯 Integration with 5+ popular tools

---

## 🔮 Future Roadmap (v8.0+)

### Planned Features
- [ ] Web UI dashboard (React)
- [ ] VS Code extension (native)
- [ ] Cloud scanning service
- [ ] AI-powered vulnerability analysis
- [ ] Custom rule creation (YAML-based)
- [ ] Integration marketplace
- [ ] Enterprise features (SSO, audit logs)
- [ ] Mobile app (iOS/Android)

---

## 📞 Contact & Support

**GitHub**: https://github.com/chimera/medusa
**Docs**: https://medusa-security.dev
**Discord**: https://discord.gg/medusa-security
**Email**: support@medusa-security.dev

---

**Status**: 📋 PLANNING → 🚧 IN PROGRESS
**Target Launch**: Q1 2026
**Version**: 7.0.0 (Public Release)
