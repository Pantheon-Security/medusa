# 🚀 MEDUSA Quick Start Guide

Get up and running with MEDUSA in 5 minutes.

---

## Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- Internet connection (for installing security tools)

---

## Step 1: Install MEDUSA (1 minute)

### Option A: From PyPI (Recommended)

```bash
pip install medusa-security
```

### Option B: From Source

```bash
git clone https://github.com/Pantheon-Security/medusa.git
cd medusa
pip install -e .
```

### Verify Installation

```bash
medusa --version
# Output: MEDUSA v0.7.0.0
```

---

## Step 2: Initialize Your Project (1 minute)

Navigate to your project directory and run the initialization wizard:

```bash
cd /path/to/your/project
medusa init
```

### What Happens:

```
🐍 MEDUSA Initialization Wizard

✅ Step 1: Project Analysis
   Scanning project for file types...
   Found 15 language types:
   - PythonScanner (44 files)
   - JavaScriptScanner (23 files)
   - ShellScanner (12 files)
   - YAMLScanner (8 files)
   ...

✅ Step 2: Scanner Availability
   Checking 42 security scanners...
   Available: 6/42 scanners
   Missing: 36 tools

   Available tools:
   ✅ bandit (Python)
   ✅ yamllint (YAML)
   ✅ shellcheck (Bash)
   ✅ markdownlint (Markdown)
   ✅ hadolint (Docker)
   ✅ tflint (Terraform)

✅ Step 3: Configuration
   Created .medusa.yml
   Auto-detected IDE: Claude Code

✅ Step 4: IDE Integration
   Created .claude/agents/medusa/agent.json
   Created .claude/commands/medusa-scan.md

✅ MEDUSA Initialized Successfully!

Next steps:
  1. Review configuration: .medusa.yml
  2. Install missing tools: medusa install --all
  3. Run your first scan: medusa scan .
```

### Files Created:

- `.medusa.yml` - Project configuration
- `.claude/agents/medusa/agent.json` - IDE agent (if using Claude Code)
- `.claude/commands/medusa-scan.md` - Slash command docs

---

## Step 3: Install Security Tools (2 minutes)

MEDUSA needs external security tools to scan different languages. Install them automatically:

```bash
medusa install --all
```

### What Happens:

```
📦 Installing missing security tools...

Platform: Linux (apt)
Installing 36 tools...

[1/36] Installing bandit...
  ✅ bandit installed successfully (pip install bandit)

[2/36] Installing eslint...
  ✅ eslint installed successfully (npm install -g eslint)

[3/36] Installing rubocop...
  ✅ rubocop installed successfully (gem install rubocop)

[4/36] Installing phpstan...
  ✅ phpstan installed successfully (composer global require phpstan/phpstan)

...

✅ Installation complete! 36/36 tools installed.
```

### Manual Installation (if needed)

If auto-install fails for specific tools, install manually:

```bash
# Python tools
pip install bandit sqlfluff

# Node.js tools
npm install -g eslint htmlhint stylelint

# System tools (Ubuntu/Debian)
sudo apt install shellcheck yamllint hadolint

# Ruby tools
gem install rubocop

# PHP tools
composer global require phpstan/phpstan
```

---

## Step 4: Run Your First Scan (1 minute)

```bash
medusa scan .
```

### What Happens:

```
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║          🐍🐍🐍 MEDUSA v0.7.0.0 - Security Guardian 🐍🐍🐍           ║
║                                                                    ║
║              The 42-Headed Universal Security Scanner             ║
║           One look from Medusa stops vulnerabilities dead          ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝

🎯 Target: .
🔧 Mode: Full

🐍 MEDUSA Parallel Scanner v6.1.0
   Workers: 6 cores
   Cache: enabled
   Mode: full

📁 Found 145 scannable files

📊 Scanning 145 files with 6 workers...
████████████████████████████████████████ 100%

✅ Scanned 145 files

============================================================
🎯 PARALLEL SCAN COMPLETE
============================================================
📂 Files scanned: 145
⚡ Files cached: 0
🔍 Issues found: 23
⏱️  Total time: 47.28s
============================================================

📊 Issue Summary:
   CRITICAL: 0
   HIGH: 2
   MEDIUM: 18
   LOW: 3

✅ Scan complete!
📁 Reports saved to: .medusa/reports/
```

---

## Step 5: Review Results

### Terminal Output

Scroll up to see all issues found during the scan.

### JSON Report

```bash
cat .medusa/reports/parallel_scan_temp.json
```

### Generate HTML Report (coming in v0.8.0)

```bash
medusa report .medusa/reports/
```

---

## Common Workflows

### Quick Scan (Changed Files Only)

Use caching to only scan modified files:

```bash
medusa scan . --quick
```

Output:
```
📂 Files scanned: 3
⚡ Files cached: 142  # Skipped unchanged files
⏱️  Total time: 3.2s  # Much faster!
```

### Force Full Scan

Ignore cache and scan everything:

```bash
medusa scan . --force
```

### Scan Specific Directory

```bash
medusa scan ./src
medusa scan /path/to/project
```

### Adjust Worker Count

```bash
# Use 4 workers (good for laptop)
medusa scan . --workers 4

# Use 24 workers (good for server)
medusa scan . --workers 24
```

### Fail Build on Issues

Exit with error code if HIGH or CRITICAL issues found:

```bash
medusa scan . --fail-on high
echo $?  # Non-zero if HIGH/CRITICAL found
```

Useful for CI/CD pipelines.

---

## Configuration Tips

### Edit `.medusa.yml`

```yaml
# Disable specific scanners
scanners:
  disabled: ['bandit', 'eslint']  # Don't use these

# Add exclusions
exclude:
  paths:
    - vendor/          # Exclude vendor directory
    - third_party/     # Exclude third-party code
  files:
    - "*.test.js"      # Skip test files
    - "*.spec.ts"      # Skip spec files

# Adjust workers
workers: 4             # Use 4 cores instead of auto-detect

# Change fail threshold
fail_on: critical      # Only fail on CRITICAL (more lenient)
```

### Exclude Vendor Code

Most projects have dependencies that shouldn't be scanned. Common exclusions are already in the default config:

- `node_modules/`
- `venv/`, `.venv/`, `env/`
- `vendor/`
- `.git/`
- `dist/`, `build/`

Add more as needed in `.medusa.yml`.

---

## IDE Integration

### Claude Code

If you initialized with `--ide claude-code`, you can:

**Auto-scan on save:**
- Edit any `.py`, `.js`, `.sh`, `.yml` file
- Save it
- MEDUSA automatically scans the file
- Issues appear inline in Claude Code

**Manual scan:**
- Type `/medusa-scan` in Claude Code
- Full project scan runs
- Results displayed in chat

**Configuration:**
```yaml
ide:
  claude_code:
    enabled: true
    auto_scan: true          # Scan on file save
    inline_annotations: true # Show issues in code
```

---

## Troubleshooting

### "Command not found: medusa"

**Solution**: Ensure pip install directory is in PATH:

```bash
# Check installation
pip show medusa-security

# Add to PATH (Linux/macOS)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify
medusa --version
```

### "Tool not found: bandit"

**Solution**: Install missing tools:

```bash
# Check which tools are missing
medusa install --check

# Install all missing tools
medusa install --all

# Or install specific tool
medusa install --tool bandit
```

### "Permission denied" during install

**Solution**: Some tools need sudo for system-wide installation:

```bash
# Ubuntu/Debian
sudo apt install shellcheck yamllint

# Or install in user directory
pip install --user bandit
npm install -g --prefix ~/.local eslint
```

### Scan is very slow

**Solution**: Reduce workers or enable quick mode:

```bash
# Reduce workers
medusa scan . --workers 2

# Quick scan (cache)
medusa scan . --quick

# Check system load
medusa install --check
```

### Too many false positives

**Solution**: Adjust severity threshold or disable specific scanners:

```yaml
# .medusa.yml
fail_on: critical  # Only care about CRITICAL issues

scanners:
  disabled: ['bandit']  # Disable noisy scanners
```

---

## Next Steps

### Learn More

- Read the full [README.md](../README.md)
- Check [CHANGELOG.md](../CHANGELOG.md) for version history
- Review [Configuration Guide](./CONFIGURATION.md)
- Explore [IDE Integration Guide](./IDE_INTEGRATION.md)

### Integrate with CI/CD

- See [GitHub Actions example](../README.md#cicd-integration)
- Configure pre-commit hooks
- Set up automated security scans

### Contribute

- Report issues on [GitHub](https://github.com/Pantheon-Security/medusa/issues)
- Submit feature requests
- Contribute new scanners
- Improve documentation

---

## Quick Reference

### Essential Commands

```bash
# Initialize
medusa init

# Install tools
medusa install --all

# Scan project
medusa scan .

# Quick scan (cache)
medusa scan . --quick

# Check installed tools
medusa install --check

# Help
medusa --help
medusa scan --help
```

### Essential Files

```
.medusa.yml                      # Project configuration
.medusa/reports/                 # Scan reports
.claude/agents/medusa/           # IDE integration
```

---

## Success Criteria

After completing this guide, you should have:

- ✅ MEDUSA installed and working
- ✅ Project initialized with `.medusa.yml`
- ✅ Security tools installed
- ✅ First scan completed successfully
- ✅ Understanding of basic commands
- ✅ IDE integration set up (optional)

---

**Congratulations! You're ready to scan for security issues with MEDUSA!** 🎉

**One command. Complete security.**

```bash
medusa init && medusa install --all && medusa scan .
```

---

**Questions?** Open an issue on [GitHub](https://github.com/Pantheon-Security/medusa/issues)

**Next:** Explore the [full documentation](../README.md) for advanced features.
