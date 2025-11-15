# 🔧 MEDUSA Troubleshooting Guide

Solutions to common problems and errors.

---

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Tool Installation Problems](#tool-installation-problems)
3. [Scanning Issues](#scanning-issues)
4. [Performance Problems](#performance-problems)
5. [Configuration Issues](#configuration-issues)
6. [IDE Integration Issues](#ide-integration-issues)
7. [Platform-Specific Issues](#platform-specific-issues)
8. [Error Messages](#error-messages)

---

## Installation Issues

### "Command not found: medusa"

**Symptoms:**
```bash
$ medusa --version
bash: medusa: command not found
```

**Solutions:**

**Linux/macOS:**
```bash
# Add pip install directory to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify
which medusa
medusa --version
```

**Windows:**
```powershell
# Check if Python Scripts directory is in PATH
echo %PATH%

# Add to PATH (replace XX with your Python version)
setx PATH "%PATH%;C:\Users\YourName\AppData\Local\Programs\Python\Python3XX\Scripts"

# Restart terminal and verify
medusa --version
```

---

### "No module named 'medusa'"

**Symptoms:**
```python
ModuleNotFoundError: No module named 'medusa'
```

**Solutions:**

```bash
# Check if installed
pip show medusa-security

# If not installed
pip install medusa-security

# If using virtual environment
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate      # Windows
pip install medusa-security
```

---

### "Permission denied" during installation

**Symptoms:**
```bash
ERROR: Could not install packages due to an EnvironmentError: [Errno 13] Permission denied
```

**Solutions:**

**Linux/macOS (Recommended):**
```bash
# Install for current user only (no sudo needed)
pip install --user medusa-security
```

**Alternative (Not Recommended):**
```bash
# System-wide install (requires sudo)
sudo pip install medusa-security
```

**Windows:**
```powershell
# Run PowerShell as Administrator
pip install medusa-security
```

---

## Tool Installation Problems

### "Tool not found: bandit"

**Symptoms:**
```
⚠️  bandit not found
Install with: pip install bandit
```

**Solutions:**

```bash
# Install specific tool
medusa install --tool bandit

# Or manually
pip install bandit

# Verify
which bandit  # Linux/macOS
where bandit  # Windows
bandit --version
```

---

### Auto-install fails

**Symptoms:**
```
❌ Failed to install eslint
Error: npm: command not found
```

**Solutions:**

**Missing npm:**
```bash
# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install nodejs

# macOS
brew install node

# Windows
# Download from nodejs.org
```

**Missing gem (Ruby):**
```bash
# Ubuntu/Debian
sudo apt install ruby-full

# macOS
brew install ruby

# Windows
# Download from rubyinstaller.org
```

**Missing composer (PHP):**
```bash
# Download and install
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer
```

---

### Tools install but aren't found

**Symptoms:**
```bash
medusa install --all --yes
# ✅ All tools installed

medusa scan .
# ⚠️  bandit not found
```

**Solutions:**

```bash
# Check PATH
echo $PATH

# Find where tool was installed
pip show bandit | grep Location
which bandit

# Add to PATH
export PATH="$HOME/.local/bin:$PATH"  # Linux/macOS

# Make permanent
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

---

## Scanning Issues

### Scan hangs or freezes

**Symptoms:**
- Scan starts but never completes
- Process uses 100% CPU
- No progress for > 5 minutes

**Solutions:**

**Reduce workers:**
```bash
# Use fewer workers
medusa scan . --workers 2

# Or set in config
# .medusa.yml
workers: 2
```

**Check system load:**
```bash
# Linux/macOS
top
htop
uptime

# Look for high load average or memory usage
```

**Kill hung scan:**
```bash
# Find process
ps aux | grep medusa

# Kill it
kill -9 <PID>

# Or
pkill -9 medusa
```

**Check for problematic files:**
```bash
# Scan in verbose mode
medusa scan . --verbose

# Look for file that scan hangs on
# Add it to exclusions in .medusa.yml
```

---

### "No files to scan"

**Symptoms:**
```
📁 Found 0 scannable files
✅ No files to scan
```

**Solutions:**

**Check file extensions:**
```bash
# See what files exist
find . -type f | head -20

# Check if extensions are supported
medusa install --check
```

**Check exclusions:**
```yaml
# .medusa.yml - might be excluding too much
exclude:
  paths:
    # - src/  # Don't exclude your code!
    - node_modules/
    - venv/
```

**Scan specific directory:**
```bash
medusa scan ./src
medusa scan ./backend
```

---

### Too many false positives

**Symptoms:**
- Scan reports issues in test files
- Vendor/library code flagged
- Acceptable patterns marked as issues

**Solutions:**

**Exclude test files:**
```yaml
# .medusa.yml
exclude:
  files:
    - "*.test.js"
    - "*.spec.ts"
    - "test_*.py"
    - "*_test.go"
```

**Exclude vendor code:**
```yaml
exclude:
  paths:
    - vendor/
    - third_party/
    - node_modules/
    - .venv/
```

**Adjust severity threshold:**
```yaml
fail_on: critical  # Only fail on CRITICAL issues
```

**Suppress specific issues:**
```python
# Python (bandit)
password = "test123"  # nosec B105

# JavaScript (ESLint)
eval(code);  // eslint-disable-line no-eval
```

---

## Performance Problems

### Scan is very slow

**Symptoms:**
- Small project takes > 5 minutes
- Scan slower than expected

**Solutions:**

**Enable caching:**
```bash
# Quick scan (uses cache)
medusa scan . --quick

# Check cache status
ls -lah ~/.medusa/cache/
```

**Reduce workers:**
```bash
# Too many workers can be slower
medusa scan . --workers 4
```

**Exclude large directories:**
```yaml
# .medusa.yml
exclude:
  paths:
    - node_modules/     # Can have 100,000+ files
    - dist/
    - build/
    - .git/
```

**Use specific scanners:**
```yaml
# Only scan for critical issues
scanners:
  enabled: [bandit, eslint]  # Only these two
```

**Check disk I/O:**
```bash
# Slow disk can cause issues
df -h        # Check free space
iostat -x 1  # Check I/O wait
```

---

### High memory usage

**Symptoms:**
- System slows during scan
- Out of memory errors
- Swap usage increases

**Solutions:**

**Reduce workers:**
```bash
medusa scan . --workers 2
```

**Disable cache:**
```bash
medusa scan . --no-cache
```

**Scan in batches:**
```bash
# Scan subdirectories separately
medusa scan ./backend
medusa scan ./frontend
medusa scan ./scripts
```

---

### CPU usage too high

**Symptoms:**
- System becomes unresponsive
- Other applications lag
- Fans run loudly

**Solutions:**

**MEDUSA auto-adjusts workers based on system load:**
```
⚠️  High CPU usage: 85.3%
Using 2 workers (reduced due to system load)
```

**Manual override:**
```bash
# Force fewer workers
medusa scan . --workers 1

# Set permanently
# .medusa.yml
workers: 2
```

**Run during idle time:**
```bash
# Schedule for off-hours (Linux/macOS)
crontab -e
# Add: 0 2 * * * cd /path/to/project && medusa scan .
```

---

## Configuration Issues

### Config file not loaded

**Symptoms:**
- Changes to `.medusa.yml` ignored
- Exclusions not working
- Scan uses default config

**Solutions:**

**Check file location:**
```bash
# Must be in project root
ls -la .medusa.yml

# Or in parent directories (MEDUSA walks up)
```

**Check YAML syntax:**
```bash
# Validate YAML
python3 -c "import yaml; yaml.safe_load(open('.medusa.yml'))"

# Common issues:
# - Tabs instead of spaces
# - Missing colons
# - Incorrect indentation
```

**Verify config loaded:**
```bash
# MEDUSA should show "Using config: .medusa.yml"
medusa scan . --verbose
```

---

### Exclusions not working

**Symptoms:**
- `node_modules/` still scanned
- Test files still checked
- Excluded paths showing in results

**Solutions:**

**Check exclusion syntax:**
```yaml
# CORRECT
exclude:
  paths:
    - node_modules/
    - .venv/

# WRONG
exclude:
  - node_modules/  # Missing "paths:" key
```

**Path must match:**
```yaml
# If your structure is:
# project/
#   frontend/node_modules/

# Use:
exclude:
  paths:
    - frontend/node_modules/  # Specific path
    # or
    - node_modules/            # Matches anywhere
```

**File patterns need wildcards:**
```yaml
exclude:
  files:
    - "*.min.js"    # CORRECT
    - "min.js"      # WRONG - won't match app.min.js
```

---

## IDE Integration Issues

### Claude Code auto-scan not working

**Symptoms:**
- Save file, no scan happens
- No MEDUSA output in Claude

**Solutions:**

**Check config:**
```yaml
# .medusa.yml
ide:
  claude_code:
    enabled: true      # Must be true
    auto_scan: true    # Must be true
```

**Check file pattern:**
```json
// .claude/agents/medusa/agent.json
{
  "triggers": {
    "file_save": {
      "patterns": [
        "*.py",   // Your file extension must be listed
        "*.js",
        // ...
      ]
    }
  }
}
```

**Restart Claude Code:**
```bash
# Close and reopen Claude Code
# Agent configurations are loaded on startup
```

---

### Slash command not found

**Symptoms:**
```
/medusa-scan
Unknown command: medusa-scan
```

**Solutions:**

**Check command file exists:**
```bash
ls .claude/commands/medusa-scan.md
```

**Recreate command:**
```bash
medusa init --ide claude-code --force
```

**Restart Claude Code:**
- Close Claude Code
- Reopen project
- Try `/medusa-scan` again

---

## Platform-Specific Issues

### Windows: "Access denied" errors

**Symptoms:**
```
PermissionError: [WinError 5] Access is denied
```

**Solutions:**

**Run as Administrator:**
- Right-click PowerShell
- "Run as Administrator"
- Run medusa commands

**Check antivirus:**
- Some antivirus software blocks Python scripts
- Add medusa to whitelist

**Use WSL2 instead:**
```powershell
# Install WSL2 (best Windows experience)
wsl --install
# Then use MEDUSA in WSL Ubuntu
```

---

### macOS: "Permission denied" for system tools

**Symptoms:**
```
sudo: a terminal is required to read the password
```

**Solutions:**

**Use Homebrew:**
```bash
# Don't use sudo
brew install shellcheck yamllint

# For Python tools
pip3 install --user bandit
```

**Grant terminal permissions:**
- System Preferences → Security & Privacy → Privacy
- Full Disk Access → Add Terminal.app

---

### Linux: Tools not in PATH

**Symptoms:**
```bash
medusa install --all --yes
# ✅ Tools installed

which eslint
# (nothing)
```

**Solutions:**

```bash
# Add npm global bin to PATH
export PATH="$PATH:$(npm config get prefix)/bin"

# Add gem bin to PATH
export PATH="$PATH:$(gem environment gemdir)/bin"

# Make permanent
echo 'export PATH="$PATH:$(npm config get prefix)/bin"' >> ~/.bashrc
source ~/.bashrc
```

---

## Error Messages

### "ModuleNotFoundError: No module named 'click'"

**Solution:**
```bash
pip install click rich bandit yamllint
# Or reinstall medusa
pip install --force-reinstall medusa-security
```

---

### "SyntaxError: invalid syntax"

**Symptoms:**
```python
SyntaxError: invalid syntax
  File "medusa/cli.py", line 50
    match severity:
          ^
```

**Solution:**
```bash
# MEDUSA requires Python 3.10+
python3 --version

# Upgrade Python
sudo apt install python3.11  # Ubuntu
brew install python@3.11     # macOS
```

---

### "subprocess.CalledProcessError"

**Symptoms:**
```
subprocess.CalledProcessError: Command '['bandit', ...]' returned non-zero exit status 1
```

**Solution:**

This is usually normal - it means the scanner found issues.

**If scan fails entirely:**
```bash
# Run scanner directly to see error
bandit -f json yourfile.py

# Check scanner installation
bandit --version
```

---

### "OSError: [Errno 24] Too many open files"

**Symptoms:**
```
OSError: [Errno 24] Too many open files
```

**Solutions:**

**Increase file limit (Linux/macOS):**
```bash
# Temporary
ulimit -n 4096

# Permanent (add to ~/.bashrc)
echo 'ulimit -n 4096' >> ~/.bashrc
```

**Reduce workers:**
```bash
medusa scan . --workers 2
```

---

## Getting Help

### Enable Verbose Mode

```bash
medusa scan . --verbose
```

Shows detailed information about what MEDUSA is doing.

### Check System Status

```bash
# Check MEDUSA version
medusa --version

# Check installed tools
medusa install --check

# Check Python version
python3 --version

# Check PATH
echo $PATH
```

### Collect Diagnostic Info

```bash
# Create diagnostic report
cat > medusa-diagnostics.txt <<EOF
MEDUSA Version: $(medusa --version)
Python Version: $(python3 --version)
OS: $(uname -a)
PATH: $PATH

Installed Tools:
$(medusa install --check)

Config File:
$(cat .medusa.yml 2>/dev/null || echo "No config file")
EOF

# Share medusa-diagnostics.txt when reporting issues
```

### Report Issues

1. Check [existing issues](https://github.com/chimera/medusa/issues)
2. Create new issue with:
   - MEDUSA version
   - Python version
   - Operating system
   - Complete error message
   - Steps to reproduce
   - Diagnostic info (above)

---

## Common Workarounds

### Scan won't complete

```bash
# Use sequential mode (slower but more stable)
medusa scan . --workers 1 --no-cache
```

### Can't install all tools

```bash
# Install what you can
medusa install --all --yes

# Scan with available tools only
medusa scan .  # Works with whatever is installed
```

### Config changes not applying

```bash
# Force config reload
rm -rf ~/.medusa/cache/
medusa scan . --force
```

---

## Performance Tuning

### Optimize for Speed

```yaml
# .medusa.yml
workers: 8              # Use more cores
cache_enabled: true     # Enable caching

exclude:
  paths:
    - node_modules/    # Exclude large directories
    - vendor/
    - dist/
```

```bash
# Use quick mode
medusa scan . --quick
```

### Optimize for Accuracy

```yaml
scanners:
  enabled: []  # Scan with all available tools
  disabled: []

fail_on: critical  # Show all issues
```

```bash
# Force full scan
medusa scan . --force
```

---

**Last Updated**: 2025-11-15
**MEDUSA Version**: 0.7.0.0

**Still having issues?** [Open a GitHub issue](https://github.com/chimera/medusa/issues)
