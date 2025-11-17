# 🐍 MEDUSA v0.9.2.2 - The 42-Headed Security Guardian

[![Version](https://img.shields.io/badge/version-0.9.2.2-blue.svg)](https://github.com/Pantheon-Security/medusa)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)]()

**Universal security scanner for all languages and platforms.**
*One look from Medusa stops vulnerabilities dead.*

---

## 🎯 What is MEDUSA?

MEDUSA is a comprehensive Static Application Security Testing (SAST) tool that scans your codebase for security vulnerabilities, code quality issues, and best practice violations across **42 different languages and file types**.

### ✨ Key Features

- 🔍 **42 Language Scanners** - Most comprehensive coverage available
- ⚡ **Parallel Processing** - Multi-core scanning (10-40× faster than sequential)
- 🎨 **Beautiful CLI** - Rich terminal output with progress bars
- 🤖 **IDE Integration** - Claude Code, Cursor, VS Code, Gemini CLI support
- 📦 **Auto-Installer** - One-command installation of all security tools
- 🔄 **Smart Caching** - Skip unchanged files for lightning-fast rescans
- ⚙️ **Configurable** - `.medusa.yml` for project-specific settings
- 🌍 **Cross-Platform** - Linux, macOS, Windows (WSL/Git Bash)
- 📊 **Multiple Reports** - JSON, HTML, and terminal output
- 🎯 **Zero Config** - Works out of the box with sensible defaults

---

## 🚀 Quick Start

### Installation

```bash
# Install MEDUSA
pip install medusa-security

# Or install from source
git clone https://github.com/Pantheon-Security/medusa.git
cd medusa
pip install -e .
```

**macOS Users:** If `medusa` command is not found after installation, run:
```bash
python3 -m medusa setup_path
```
This will automatically configure your PATH. Then open a new terminal or run `source ~/.zshrc`

### 5-Minute Setup

```bash
# 1. Initialize in your project
cd your-project
medusa init

# 2. Install security tools (auto-detected for your platform)
medusa install --all

# 3. Run your first scan
medusa scan .
```

### Example Output

```
🐍 MEDUSA v0.9.0.0 - Security Guardian

🎯 Target: .
🔧 Mode: Full

🐍 MEDUSA Parallel Scanner v6.1.0
   Workers: 6 cores
   Cache: enabled
   Mode: full

📁 Found 145 scannable files

📊 Scanning 145 files with 6 workers...
✅ Scanned 145 files

============================================================
🎯 PARALLEL SCAN COMPLETE
============================================================
📂 Files scanned: 145
⚡ Files cached: 0
🔍 Issues found: 114
⏱️  Total time: 47.28s
============================================================

✅ Scan complete!
```

---

## 📚 Language Support

MEDUSA supports **42 different scanner types** covering all major programming languages and file formats:

### Backend Languages (9)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Python | Bandit | `.py` |
| JavaScript/TypeScript | ESLint | `.js`, `.jsx`, `.ts`, `.tsx` |
| Go | golangci-lint | `.go` |
| Ruby | RuboCop | `.rb`, `.rake`, `.gemspec` |
| PHP | PHPStan | `.php` |
| Rust | Clippy | `.rs` |
| Java | Checkstyle | `.java` |
| C/C++ | cppcheck | `.c`, `.cpp`, `.cc`, `.cxx`, `.h`, `.hpp` |
| C# | Roslynator | `.cs` |

### JVM Languages (3)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Kotlin | ktlint | `.kt`, `.kts` |
| Scala | Scalastyle | `.scala` |
| Groovy | CodeNarc | `.groovy`, `.gradle` |

### Functional Languages (5)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Haskell | HLint | `.hs`, `.lhs` |
| Elixir | Credo | `.ex`, `.exs` |
| Erlang | Elvis | `.erl`, `.hrl` |
| F# | FSharpLint | `.fs`, `.fsx` |
| Clojure | clj-kondo | `.clj`, `.cljs`, `.cljc` |

### Mobile Development (2)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Swift | SwiftLint | `.swift` |
| Objective-C | OCLint | `.m`, `.mm` |

### Frontend & Styling (3)
| Language | Scanner | Extensions |
|----------|---------|------------|
| CSS/SCSS/Sass/Less | Stylelint | `.css`, `.scss`, `.sass`, `.less` |
| HTML | HTMLHint | `.html`, `.htm` |
| Vue.js | ESLint | `.vue` |

### Infrastructure as Code (4)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Terraform | tflint | `.tf`, `.tfvars` |
| Ansible | ansible-lint | `.yml` (playbooks) |
| Kubernetes | kubeval | `.yml`, `.yaml` (manifests) |
| CloudFormation | cfn-lint | `.yml`, `.yaml`, `.json` (templates) |

### Configuration Files (5)
| Language | Scanner | Extensions |
|----------|---------|------------|
| YAML | yamllint | `.yml`, `.yaml` |
| JSON | built-in | `.json` |
| TOML | taplo | `.toml` |
| XML | xmllint | `.xml` |
| Protobuf | buf lint | `.proto` |

### Shell & Scripts (4)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Bash/Shell | ShellCheck | `.sh`, `.bash` |
| PowerShell | PSScriptAnalyzer | `.ps1`, `.psm1` |
| Lua | luacheck | `.lua` |
| Perl | perlcritic | `.pl`, `.pm` |

### Documentation (2)
| Language | Scanner | Extensions |
|----------|---------|------------|
| Markdown | markdownlint | `.md` |
| reStructuredText | rst-lint | `.rst` |

### Other Languages (5)
| Language | Scanner | Extensions |
|----------|---------|------------|
| SQL | SQLFluff | `.sql` |
| R | lintr | `.r`, `.R` |
| Dart | dart analyze | `.dart` |
| Solidity | solhint | `.sol` |
| Docker | hadolint | `Dockerfile*` |

**Total: 42 scanner types covering 100+ file extensions**

---

## 🎮 Usage

### Basic Commands

```bash
# Initialize configuration
medusa init

# Scan current directory
medusa scan .

# Scan specific directory
medusa scan /path/to/project

# Quick scan (changed files only)
medusa scan . --quick

# Force full scan (ignore cache)
medusa scan . --force

# Use specific number of workers
medusa scan . --workers 4

# Fail on HIGH severity or above
medusa scan . --fail-on high

# Custom output directory
medusa scan . -o /tmp/reports
```

### Install Commands

```bash
# Check which tools are installed
medusa install --check

# Install all missing tools
medusa install --all

# Install specific tool
medusa install --tool bandit

# Skip confirmation prompts
medusa install --all --yes
```

### Init Commands

```bash
# Interactive initialization wizard
medusa init

# Initialize with specific IDE
medusa init --ide claude-code

# Initialize with multiple IDEs
medusa init --ide claude-code --ide gemini-cli --ide cursor

# Initialize with all supported IDEs
medusa init --ide all

# Force overwrite existing config
medusa init --force

# Initialize and install tools
medusa init --install
```

---

## ⚙️ Configuration

### `.medusa.yml`

MEDUSA uses a YAML configuration file for project-specific settings:

```yaml
# MEDUSA Configuration File
version: 0.9.0

# Scanner control
scanners:
  enabled: []      # Empty = all scanners enabled
  disabled: []     # List scanners to disable
  # Example: disabled: ['bandit', 'eslint']

# Build failure settings
fail_on: high      # critical | high | medium | low

# Exclusion patterns
exclude:
  paths:
    - node_modules/
    - venv/
    - .venv/
    - env/
    - .git/
    - .svn/
    - __pycache__/
    - "*.egg-info/"
    - dist/
    - build/
    - .tox/
    - .pytest_cache/
    - .mypy_cache/
  files:
    - "*.min.js"
    - "*.min.css"
    - "*.bundle.js"
    - "*.map"

# IDE integration
ide:
  claude_code:
    enabled: true
    auto_scan: true          # Scan on file save
    inline_annotations: true # Show issues inline
  cursor:
    enabled: false
  vscode:
    enabled: false
  gemini_cli:
    enabled: false

# Scan settings
workers: null        # null = auto-detect (cpu_count - 2)
cache_enabled: true  # Enable file caching for speed
```

### Generate Default Config

```bash
medusa init
```

This creates `.medusa.yml` with sensible defaults and auto-detects your IDE.

---

## 🤖 IDE Integration

MEDUSA supports **5 major AI coding assistants** with native integrations. Initialize with `medusa init --ide all` or select specific platforms.

### Supported Platforms

| IDE | Context File | Commands | Status |
|-----|-------------|----------|--------|
| **Claude Code** | `CLAUDE.md` | `/medusa-scan`, `/medusa-install` | ✅ Full Support |
| **Gemini CLI** | `GEMINI.md` | `/scan`, `/install` | ✅ Full Support |
| **OpenAI Codex** | `AGENTS.md` | Native slash commands | ✅ Full Support |
| **GitHub Copilot** | `.github/copilot-instructions.md` | Code suggestions | ✅ Full Support |
| **Cursor** | Reuses `CLAUDE.md` | MCP + Claude commands | ✅ Full Support |

### Quick Setup

```bash
# Setup for all IDEs (recommended)
medusa init --ide all

# Or select specific platforms
medusa init --ide claude-code --ide gemini-cli
```

### Claude Code

**What it creates:**
- `CLAUDE.md` - Project context file
- `.claude/agents/medusa/agent.json` - Agent configuration
- `.claude/commands/medusa-scan.md` - Scan slash command
- `.claude/commands/medusa-install.md` - Install slash command

**Usage:**
```
Type: /medusa-scan
Claude: *runs security scan*
Results: Displayed in terminal + chat
```

### Gemini CLI

**What it creates:**
- `GEMINI.md` - Project context file
- `.gemini/commands/scan.toml` - Scan command config
- `.gemini/commands/install.toml` - Install command config

**Usage:**
```bash
gemini /scan              # Full scan
gemini /scan --quick      # Quick scan
gemini /install --check   # Check tools
```

### OpenAI Codex

**What it creates:**
- `AGENTS.md` - Project context (root level)

**Usage:**
```
Ask: "Run a security scan"
Codex: *executes medusa scan .*
```

### GitHub Copilot

**What it creates:**
- `.github/copilot-instructions.md` - Security standards and best practices

**How it helps:**
- Knows project security standards
- Suggests secure code patterns
- Recommends running scans after changes
- Helps fix security issues

### Cursor

**What it creates:**
- `.cursor/mcp-config.json` - MCP server configuration
- Reuses `.claude/` structure (Cursor is VS Code fork)

**Usage:**
- Works like Claude Code integration
- MCP-native for future deeper integration

---

## 🔧 Advanced Features

### System Load Monitoring

MEDUSA automatically monitors system load and adjusts worker count:

```python
# Auto-detects optimal workers based on:
# - CPU usage
# - Memory usage
# - Load average
# - Available cores

# Warns when system is overloaded:
⚠️  High CPU usage: 85.3%
Using 2 workers (reduced due to system load)
```

### Smart Caching

Hash-based caching skips unchanged files:

```bash
# First scan
📂 Files scanned: 145
⏱️  Total time: 47.28s

# Second scan (no changes)
📂 Files scanned: 0
⚡ Files cached: 145
⏱️  Total time: 2.15s  # 22× faster!
```

### Parallel Processing

Multi-core scanning for massive speedups:

```
Single-threaded:  417.5 seconds
6 workers:         47.3 seconds  # 8.8× faster
24 workers:        ~18 seconds   # 23× faster
```

---

## 📊 Example Workflow

### New Project Setup

```bash
# 1. Initialize
cd my-awesome-project
medusa init

🐍 MEDUSA Initialization Wizard

✅ Step 1: Project Analysis
   Found 15 language types
   Primary: PythonScanner (44 files)

✅ Step 2: Scanner Availability
   Available: 6/42 scanners
   Missing: 36 tools

✅ Step 3: Configuration
   Created .medusa.yml
   Auto-detected IDE: Claude Code

✅ Step 4: IDE Integration
   Created .claude/agents/medusa/agent.json
   Created .claude/commands/medusa-scan.md

✅ MEDUSA Initialized Successfully!

# 2. Install tools
medusa install --all

📦 Installing 36 missing tools...
✅ bandit installed (pip)
✅ eslint installed (npm)
✅ shellcheck installed (apt)
...
✅ All tools installed!

# 3. First scan
medusa scan .

🔍 Issues found: 23
   CRITICAL: 0
   HIGH: 2
   MEDIUM: 18
   LOW: 3

# 4. Fix issues and rescan
medusa scan . --quick

⚡ Files cached: 142
🔍 Issues found: 12  # Progress!
```

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  medusa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install MEDUSA
        run: pip install medusa-security

      - name: Install security tools
        run: medusa install --all --yes

      - name: Run security scan
        run: medusa scan . --fail-on high
```

---

## 🏗️ Architecture

### Scanner Pattern

All scanners follow a consistent pattern:

```python
class PythonScanner(BaseScanner):
    """Scanner for Python files using Bandit"""

    def get_tool_name(self) -> str:
        return "bandit"

    def get_file_extensions(self) -> List[str]:
        return [".py"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        # Run bandit on file
        # Parse JSON output
        # Map severity levels
        # Return structured issues
        return ScannerResult(...)
```

### Auto-Registration

Scanners automatically register themselves:

```python
# medusa/scanners/__init__.py
registry = ScannerRegistry()
registry.register(PythonScanner())
registry.register(JavaScriptScanner())
# ... all 42 scanners
```

### Severity Mapping

Unified severity levels across all tools:

- **CRITICAL** - Security vulnerabilities, fatal errors
- **HIGH** - Errors, security warnings
- **MEDIUM** - Warnings, code quality issues
- **LOW** - Style issues, conventions
- **INFO** - Suggestions, refactoring opportunities

---

## 🧪 Testing & Quality

### Dogfooding Results

MEDUSA scans itself daily:

```
✅ Files scanned: 85
✅ CRITICAL issues: 0
✅ HIGH issues: 0
✅ MEDIUM issues: 113
✅ LOW issues: 1

Status: Production Ready ✅
```

### Performance Benchmarks

| Project Size | Files | Time (6 workers) | Speed |
|--------------|-------|------------------|-------|
| Small | 50 | ~15s | 3.3 files/s |
| Medium | 145 | ~47s | 3.1 files/s |
| Large | 500+ | ~3min | 2.8 files/s |

---

## 🗺️ Roadmap

### ✅ Completed Phases

- **Phase 1** ✅ - Package restructuring, CLI framework
- **Phase 2** ✅ - 42 scanners, auto-installer, platform support
- **Phase 3** ✅ - Configuration system, IDE integration (Claude Code)
- **Phase 4** ✅ - Testing & QA, dogfooding (0 HIGH/CRITICAL issues)
- **Phase 5** 🚧 - Documentation (current)

### 📋 Upcoming

- **Phase 6** - Alpha testing (private repo, Test PyPI)
- **Phase 7** - Beta release (public repo, community feedback)
- **Phase 8** - Public launch (PyPI v0.7.0.0, marketing)

### 🔮 Future Versions

**v0.8.0** - Enhanced Features
- Complete VS Code extension
- Full Cursor integration
- SARIF output format
- HTML report UI
- Baseline/ignore functionality

**v1.0.0** - Production Release
- GitHub Actions integration
- Pre-commit hooks
- Performance dashboard
- Web UI
- Multi-project support

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

```bash
# 1. Fork and clone
git clone https://github.com/yourusername/medusa.git
cd medusa

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows

# 3. Install in editable mode
pip install -e ".[dev]"

# 4. Run tests
pytest

# 5. Create feature branch
git checkout -b feature/my-awesome-feature

# 6. Make changes and test
medusa scan .  # Dogfood your changes!

# 7. Submit PR
git push origin feature/my-awesome-feature
```

### Adding New Scanners

See `docs/development/adding-scanners.md` for a guide on adding new language support.

---

## 📜 License

MIT License - See [LICENSE](LICENSE) file

---

## 🙏 Credits

**Development:**
- Pantheon Security
- Claude AI (Anthropic) - AI-assisted development

**Built With:**
- Python 3.10+
- Click - CLI framework
- Rich - Terminal formatting
- Bandit, ESLint, ShellCheck, and 39+ other open-source security tools

**Inspired By:**
- Bandit (Python security)
- SonarQube (multi-language analysis)
- Semgrep (pattern-based security)
- Mega-Linter (comprehensive linting)

---

## 📞 Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/Pantheon-Security/medusa/issues)
- **Email**: support@pantheonsecurity.io
- **Documentation**: https://docs.medusa-security.dev (coming soon)
- **Discord**: https://discord.gg/medusa (coming soon)

---

## 📈 Statistics

**Version**: 0.9.1.1
**Release Date**: 2025-11-15
**Total Scanners**: 42
**Language Coverage**: 16 major ecosystems
**Platform Support**: Linux, macOS, Windows
**Lines of Code**: ~6,700 (production)
**Development Time**: 4 phases, 4 sessions

---

## 🌟 Why MEDUSA?

### vs. Bandit
- ✅ Supports 42 languages (not just Python)
- ✅ Parallel processing (10-40× faster)
- ✅ Auto-installer for all tools
- ✅ IDE integration

### vs. SonarQube
- ✅ Simpler setup (one command)
- ✅ No server required
- ✅ Faster scans (local processing)
- ✅ Free and open source

### vs. Semgrep
- ✅ More language support (42 vs ~30)
- ✅ Uses established tools (Bandit, ESLint, etc.)
- ✅ Better IDE integration
- ✅ Easier configuration

### vs. Mega-Linter
- ✅ Faster (parallel processing)
- ✅ Smarter caching
- ✅ Better error handling
- ✅ More focused on security

---

**🐍🐍🐍 MEDUSA v0.9.1.1 - The 42-Headed Security Guardian 🐍🐍🐍**

*One look from Medusa stops vulnerabilities dead.*

**One Command. Complete Security.**

```bash
medusa init && medusa scan .
```

---

**Last Updated**: 2025-11-15
**Status**: Production Ready
**Current Phase**: Phase 5 - Documentation
