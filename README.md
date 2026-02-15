# 🐍 MEDUSA - AI Security Scanner

[![PyPI](https://img.shields.io/pypi/v/medusa-security?label=PyPI&color=blue)](https://pypi.org/project/medusa-security/)
[![Downloads](https://img.shields.io/pypi/dm/medusa-security?label=Downloads&color=brightgreen)](https://pypi.org/project/medusa-security/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Tests](https://github.com/Pantheon-Security/medusa/actions/workflows/test.yml/badge.svg)](https://github.com/Pantheon-Security/medusa/actions/workflows/test.yml)
[![Windows](https://img.shields.io/badge/Windows-✓-brightgreen.svg)](https://github.com/Pantheon-Security/medusa)
[![macOS](https://img.shields.io/badge/macOS-✓-brightgreen.svg)](https://github.com/Pantheon-Security/medusa)
[![Linux](https://img.shields.io/badge/Linux-✓-brightgreen.svg)](https://github.com/Pantheon-Security/medusa)

**AI-first security scanner with 3,000+ detection patterns for AI/ML, agents, and LLM applications.**
**🤖 Works out of the box - no tool installation required.**
**🚨 CVE Detection: React2Shell CVE-2025-55182, CVE-2025-6514 (mcp-remote RCE)**
**✨ NEW v2026.2.3: 52% faster scans, 430 FP filters, 133 CVEs, structural overhaul!**

---

## 🎯 What is MEDUSA?

MEDUSA is an AI-first security scanner with **3,000+ detection patterns** that works out of the box. Simply install and scan - no external tool installation required. MEDUSA's built-in rules detect vulnerabilities in AI/ML applications, LLM agents, MCP servers, RAG pipelines, and traditional code.

### ✨ Key Features

- 🤖 **3,000+ AI Security Patterns** - Industry-leading coverage for AI/ML, agents, and LLM applications
- 🚀 **Zero Setup Required** - Works immediately after `pip install` - no tool installation needed
- 🚨 **CVE Detection** - React2Shell (CVE-2025-55182), Next.js vulnerabilities, supply chain risks
- ⚡ **Parallel Processing** - Multi-core scanning (10-40x faster than sequential)
- 🎨 **Beautiful CLI** - Rich terminal output with progress bars
- 🧠 **IDE Integration** - Claude Code, Cursor, VS Code, Gemini CLI support
- 🔄 **Smart Caching** - Skip unchanged files for lightning-fast rescans
- ⚙️ **Configurable** - `.medusa.yml` for project-specific settings
- 🌍 **Cross-Platform** - Native Windows, macOS, and Linux support
- 📊 **Multiple Reports** - JSON, HTML, Markdown, SARIF exports for any workflow
- 🔧 **Optional Linter Support** - Auto-detects external linters if installed for enhanced coverage

### 🆕 What's New in v2026.2.3

**Performance Overhaul + Launch Ready** - 52% faster scans, 430 FP filters, and major structural improvements.

| Change | Description |
|--------|-------------|
| ⚡ **52% Faster Scans** | Single-pass file discovery, scanner pre-mapping cache, pre-compiled regex patterns |
| 🎯 **430 FP Filter Patterns** | 93.9% false positive reduction rate — industry-leading accuracy |
| 🏗️ **Structural Refactoring** | God methods split, 189 lines dead code removed, data/logic separation |
| 📊 **Large Project Support** | Live progress stays responsive on 4,000+ file codebases |
| 🛡️ **Agent Protocol Security** | 91 rules for UCP, AP2, and ACP vulnerability detection |
| 🔍 **Prompt Injection in Code** | Detects unsanitized user input in LLM API calls (f-string injection, ChatML tokens) |
| 🚨 **133 Critical CVEs** | CVEMiner database covering LangChain, PyTorch, MCP, Log4Shell, XZ Utils |
| 🤖 **3,000+ AI Patterns** | Built-in rules for AI/ML, agents, MCP, RAG, prompt injection |

**External Linters** (optional):
- MEDUSA auto-detects `bandit`, `eslint`, `shellcheck`, etc. if installed
- See **[Optional Tools Guide](docs/OPTIONAL_TOOLS.md)** for installation instructions

---

## 🚀 Quick Start

### Installation

```bash
# Install MEDUSA (works on Windows, macOS, Linux)
pip install medusa-security

# Run your first scan - that's it!
medusa scan .
```

**Virtual Environment (Recommended):**
```bash
# Create and activate virtual environment
python3 -m venv medusa-env
source medusa-env/bin/activate  # On Windows: medusa-env\Scripts\activate

# Install and scan
pip install medusa-security
medusa scan .
```

**Platform Notes:**
- **Windows**: Use `py -m medusa` if `medusa` command is not found
- **macOS/Linux**: Should work out of the box

### Optional: AI Model Scanning

```bash
# Install modelscan for ML model vulnerability detection
medusa install --ai-tools
```

### Optional: External Linters

MEDUSA auto-detects external linters if installed (bandit, eslint, shellcheck, etc.) and uses them automatically to enhance scan coverage.

**[See Installation Guide →](docs/OPTIONAL_TOOLS.md)** for platform-specific instructions.

> **Note:** External linters are optional. MEDUSA's 3,000+ built-in rules work without them. For installation support, please refer to each tool vendor's documentation.

### Screenshots

**Scan Startup** - Repository analysis, language detection, AI pattern recognition:

![MEDUSA Banner](media/medusa-banner.png)

**Live Progress** - Real-time scanner progress with issue counts:

![MEDUSA Scan Progress](media/medusa-scan-progress.png)

**Scan Complete** - Summary with stats and report paths:

![MEDUSA Scan Complete](media/medusa-scan-complete.png)

### 📊 Report Formats

MEDUSA generates beautiful reports in multiple formats:

**JSON** - Machine-readable for CI/CD integration
```bash
medusa scan . --format json
```

**HTML** - Stunning glassmorphism UI with interactive charts
```bash
medusa scan . --format html
```

**Markdown** - Documentation-friendly for GitHub/wikis
```bash
medusa scan . --format markdown
```

**All Formats** - Generate everything at once
```bash
medusa scan . --format all
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

## 🚨 React2Shell CVE Detection (NEW in v2025.8)

MEDUSA now detects **CVE-2025-55182 "React2Shell"** - a CVSS 10.0 RCE vulnerability affecting React Server Components and Next.js.

```bash
# Check if your project is vulnerable
medusa scan .

# Vulnerable versions detected:
# - React 19.0.0 - 19.2.0 (Server Components)
# - Next.js 15.0.0 - 15.0.4 (App Router)
# - Various canary/rc releases
```

**Scans**: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`

**Fix**: Upgrade to React 19.0.1+ and Next.js 15.0.5+

---

## 🤖 AI Agent Security

MEDUSA provides **industry-leading AI security scanning** with **3,000+ detection patterns** for the agentic AI era. Updated for **OWASP Top 10 for LLM Applications 2025** and includes detection for **CVE-2025-6514** (mcp-remote RCE).

**[Full AI Security Documentation](docs/AI_SECURITY.md)**

### AI Security Coverage

| Category | Patterns | Detects |
|----------|----------|---------|
| **Prompt Injection** | 800+ | Direct/indirect injection, jailbreaks, role manipulation |
| **MCP Server Security** | 400+ | Tool poisoning, CVE-2025-6514, confused deputy, command injection |
| **RAG Security** | 300+ | Vector injection, document poisoning, tenant isolation |
| **Agent Security** | 500+ | Excessive agency, memory poisoning, HITL bypass |
| **Model Security** | 400+ | Insecure loading, checkpoint exposure, adversarial attacks |
| **Supply Chain** | 350+ | Dependency confusion, typosquatting, malicious packages |
| **Traditional SAST** | 1,400+ | SQL injection, XSS, command injection, secrets |

### AI Attack Coverage

<table>
<tr><td>

**Context & Input Attacks**
- Prompt injection patterns
- Role/persona manipulation
- Hidden instructions
- Obfuscation tricks

**Memory & State Attacks**
- Memory poisoning
- Context manipulation
- Checkpoint tampering
- Cross-session exposure

**Tool & Action Attacks**
- Tool poisoning (CVE-2025-6514)
- Command injection
- Tool name spoofing
- Confused deputy patterns

</td><td>

**Workflow & Routing Attacks**
- Router manipulation
- Agent impersonation
- Workflow hijacking
- Delegation abuse

**RAG & Knowledge Attacks**
- Knowledge base poisoning
- Embedding pipeline attacks
- Source confusion
- Retrieval manipulation

**Advanced Attacks**
- HITL bypass techniques
- Semantic manipulation
- Evaluation poisoning
- Training data attacks

</td></tr>
</table>

### Supported AI Files

```
.cursorrules          # Cursor AI instructions
CLAUDE.md             # Claude Code context
.claude/              # Claude configuration directory
copilot-instructions.md  # GitHub Copilot
AGENTS.md             # Multi-agent definitions
mcp.json / mcp-config.json  # MCP server configs
*.mcp.ts / *.mcp.py   # MCP server code
rag.json / knowledge.json   # RAG configurations
memory.json           # Agent memory configs
```

### Quick AI Security Scan

```bash
# Scan AI configuration files
medusa scan . --ai-only

# Example output:
# 🔍 AI Security Scan Results
# ├── .cursorrules: 3 issues (1 CRITICAL, 2 HIGH)
# │   └── AIC001: Prompt injection - ignore previous instructions (line 15)
# │   └── AIC011: Tool shadowing - override default tools (line 23)
# ├── mcp-config.json: 2 issues (2 HIGH)
# │   └── MCP003: Dangerous path - home directory access (line 8)
# └── rag_config.json: 1 issue (1 CRITICAL)
#     └── AIR010: Knowledge base injection pattern detected (line 45)
```

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
# Check tool status
medusa install --check

# Install AI tools (modelscan for ML model scanning)
medusa install --ai-tools

# Show detailed output
medusa install --ai-tools --debug
```

> **Note**: MEDUSA v2026.2+ no longer installs external linters. Install them via your package manager (apt, brew, npm, pip) if needed. MEDUSA auto-detects and uses any installed linters.

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

### Additional Commands

```bash
# Uninstall modelscan
medusa uninstall modelscan

# Check for updates
medusa version --check-updates

# Show current configuration
medusa config

# Override scanner for specific file
medusa override path/to/file.yaml YAMLScanner

# List available scanners
medusa override --list

# Show current overrides
medusa override --show

# Remove override
medusa override path/to/file.yaml --remove
```

### Scan Options Reference

| Option | Description |
|--------|-------------|
| `TARGET` | Directory or file to scan (default: `.`) |
| `-w, --workers N` | Number of parallel workers (default: auto-detect) |
| `--quick` | Quick scan (changed files only, requires git) |
| `--force` | Force full scan (ignore cache) |
| `--no-cache` | Disable result caching |
| `--fail-on LEVEL` | Exit with error on severity: `critical`, `high`, `medium`, `low` |
| `-o, --output PATH` | Custom output directory for reports |
| `--format FORMAT` | Output format: `json`, `html`, `sarif`, `junit`, `text` (can specify multiple) |
| `--no-report` | Skip generating HTML report |
### Install Options Reference

| Option | Description |
|--------|-------------|
| `--check` | Check tool status |
| `--ai-tools` | Install AI security tools (modelscan) |
| `--debug` | Show detailed debug output |

> **v2026.2+ Change**: MEDUSA no longer manages external linter installation. The `--all` flag is deprecated. Install external linters via your system package manager if needed.

---

## ⚙️ Configuration

### `.medusa.yml`

MEDUSA uses a YAML configuration file for project-specific settings:

```yaml
# MEDUSA Configuration File
version: 2026.2.3

# Scanner control
scanners:
  enabled: []      # Empty = all scanners enabled
  disabled: []     # List scanners to disable

# Build failure settings
fail_on: high      # critical | high | medium | low

# Exclusion patterns
exclude:
  paths:
    - node_modules/
    - venv/
    - .venv/
    - .git/
    - __pycache__/
    - dist/
    - build/
  files:
    - "*.min.js"
    - "*.min.css"

# IDE integration
ide:
  claude_code:
    enabled: true
    auto_scan: true
  cursor:
    enabled: false
  vscode:
    enabled: false

# Scan settings
workers: null        # null = auto-detect CPU cores
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

# 2. First scan
medusa scan .

🔍 Issues found: 23
   CRITICAL: 0
   HIGH: 2
   MEDIUM: 18
   LOW: 3

# 3. Fix issues and rescan
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

      - name: Run security scan
        run: medusa scan . --fail-on high
```

> **Note**: No tool installation step needed - MEDUSA's 3,000+ built-in rules work immediately.

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

MEDUSA scans itself — and real-world projects:

```
Self-scan (473 files):
  ✅ Issues found: 115 (pre-filter) → 0 (post-filter)
  ✅ FP reduction: 100% on own codebase
  ⏱️  Time: 8.2s

OpenClaw benchmark (4,124 files, 751K LOC):
  🔍 Issues found: 825 (post-filter)
  ✅ FPs filtered: 11,436 (93.9% reduction)
  ⏱️  Time: 3.3 hours (42 scanners)
```

### Performance Benchmarks

| Project Size | Files | Time | Speed |
|--------------|-------|------|-------|
| Small (MEDUSA self-scan) | 473 | ~8s | 59 files/s |
| Medium | 1,000 | ~45s | 22 files/s |
| Large (OpenClaw) | 4,124 | ~3.3h | 0.34 files/s* |

*Large project time dominated by external tool subprocesses (Semgrep, Trivy, GitLeaks). Built-in pattern scanning is near-instant.

---

## 🗺️ Roadmap

### ✅ Completed (v2026.2.3)

- **3,000+ Detection Patterns** - Industry-leading AI security coverage
- **76 Specialized Analyzers** - Comprehensive language and platform coverage
- **133 Critical CVEs** - CVEMiner database for known vulnerability scanning
- **430 FP Filter Patterns** - 93.9% false positive reduction rate
- **52% Faster Scans** - Single-pass file discovery, pre-compiled patterns, scanner caching
- **Agent Protocol Security** - UCP, AP2, ACP vulnerability detection (91 rules)
- **Dataset Poisoning Detection** - CSV, JSON, JSONL injection scanning
- **Code-Level Prompt Injection** - F-string injection, ChatML tokens, role manipulation
- **Cross-Platform** - Native Windows, macOS, Linux support
- **IDE Integration** - Claude Code, Cursor, Gemini CLI, GitHub Copilot, OpenAI Codex

### 🔮 Upcoming

- **MEDUSA Professional** - Runtime proxy filters for production LLM protection
- **GitHub App** - Automatic PR scanning
- **VS Code Extension** - Native IDE integration
- **REST API** - CI/CD pipeline integration

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

AGPL-3.0-or-later - See [LICENSE](LICENSE) file

MEDUSA is free and open source software. You can use, modify, and distribute it freely, but any modifications or derivative works (including SaaS deployments) must also be released under AGPL-3.0.

For commercial licensing options, contact: support@pantheonsecurity.io

---

## Coming Soon

MEDUSA Professional adds **runtime protection** for production LLM applications - blocking prompt injection, jailbreaking, and data exfiltration attempts in real-time before they reach your models.

| Feature | Open Source | Professional | Enterprise |
|---------|-------------|--------------|------------|
| Static scanning (3,000+ patterns) | Yes | Yes | Yes |
| Runtime proxy filters (1,100+) | - | Yes | Yes |
| REST API & webhooks | - | Yes | Yes |
| Custom rules & SSO | - | - | Yes |
| **Price** | Free | $99/dev/mo | $499/50 devs/mo |

The runtime proxy is currently in private beta. If you're protecting production LLM applications and want early access, reach out to **support@pantheonsecurity.io**.

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

## 📖 Guides

- **[Quick Start](docs/guides/quick-start.md)** - Get running in 5 minutes
- **[AI Security Scanning](docs/AI_SECURITY.md)** - Complete guide to AI/LLM security (OWASP 2025, MCP, RAG)
- **[Handling False Positives](docs/guides/handling-false-positives.md)** - Reduce noise, find real issues
- **[IDE Integration](docs/guides/ide-integration.md)** - Setup Claude Code, Gemini, Copilot

---

## 📞 Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/Pantheon-Security/medusa/issues)
- **Email**: support@pantheonsecurity.io
- **Documentation**: https://docs.pantheonsecurity.io
- **Discord**: https://discord.gg/medusa (coming soon)

---

## 📈 Statistics

**Version**: 2026.2.3
**Release Date**: 2026-02-15
**Detection Patterns**: 3,000+ AI security rules
**Analyzers**: 76 specialized scanners
**FP Filter Patterns**: 430 intelligent filters (93.9% reduction rate)
**CVE Coverage**: 133 critical vulnerabilities
**Language Coverage**: 46+ file types
**Platform Support**: Linux, macOS, Windows
**AI Integration**: Claude Code, Gemini CLI, GitHub Copilot, Cursor, OpenAI Codex
**Standards**: OWASP Top 10 for LLM 2025, MITRE ATLAS
**Downloads**: 11,500+ on PyPI

---

## 🌟 Why MEDUSA?

### vs. Bandit
- ✅ 3,000+ patterns (not just Python security)
- ✅ AI/ML security coverage
- ✅ Zero setup required
- ✅ IDE integration

### vs. SonarQube
- ✅ Simpler setup (`pip install && scan`)
- ✅ No server required
- ✅ AI-first security focus
- ✅ Free and open source

### vs. Semgrep
- ✅ AI/ML-specific rules built-in
- ✅ MCP, RAG, agent security
- ✅ Better IDE integration
- ✅ No rule configuration needed

### vs. Traditional SAST
- ✅ Works immediately (no tool installation)
- ✅ AI security patterns included
- ✅ Parallel processing
- ✅ Smart caching

---

**🐍🐍🐍 MEDUSA - Multi-Language Security Scanner 🐍🐍🐍**

**One Command. Complete Security.**

```bash
medusa init && medusa scan .
```

---

**Last Updated**: 2026-02-15
**Status**: Production Ready
**Current Version**: v2026.2.3 - Performance Overhaul + Launch Ready
