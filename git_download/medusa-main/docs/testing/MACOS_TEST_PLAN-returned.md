# MEDUSA macOS Testing Guide

**Purpose:** Validate MEDUSA works correctly on macOS before public launch

**Date:** 2025-11-17
**Tester:** Ross Churchill
**Platform:** macOS (Intel or Apple Silicon)

---

## Pre-Test System Info

Before starting, record your system details:

```bash
# macOS version
sw_vers

# Architecture (Intel or Apple Silicon)
uname -m
# x86_64 = Intel, arm64 = Apple Silicon

# Python version


# Pip version
pip3 --version
```

**Record:**
- macOS Version: 26.1 - 25878
- Architecture: arm64
- Python Version: 3.9.6

---

## Test 1: Clean Installation from PyPI

**Goal:** Test what a real user experiences

```bash
# Create fresh virtual environment
python3 -m venv ~/medusa-test
source ~/medusa-test/bin/activate

# Install from PyPI
pip install medusa-security

# Verify installation
medusa --version
# Expected: 0.9.1.0

# Check PATH


# Expected: ~/medusa-test/bin/medusa
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________
(medusa-test) rchurchill@MACLDN1-ROSCHU1 Documents % pip install medusa-security
ERROR: Could not find a version that satisfies the requirement medusa-security (from versions: none)
ERROR: No matching distribution found for medusa-security
WARNING: You are using pip version 21.2.4; however, version 25.3 is available.
You should consider upgrading via the '/Users/rchurchill/medusa-test/bin/python3 -m pip install --upgrade pip' command.
(medusa-test) rchurchill@MACLDN1-ROSCHU1 Documents % /Users/rchurchill/medusa-test/bin/python3 -m pip install --upgrade pip
Requirement already satisfied: pip in /Users/rchurchill/medusa-test/lib/python3.9/site-packages (21.2.4)
Collecting pip
  Using cached pip-25.3-py3-none-any.whl (1.8 MB)
Installing collected packages: pip
  Attempting uninstall: pip
    Found existing installation: pip 21.2.4
    Uninstalling pip-21.2.4:
      Successfully uninstalled pip-21.2.4
Successfully installed pip-25.3
(medusa-test) rchurchill@MACLDN1-ROSCHU1 Documents % pip install medusa-security
ERROR: Ignored the following versions that require a different python version: 0.9.0.0 Requires-Python >=3.10; 0.9.1.0 Requires-Python >=3.10
ERROR: Could not find a version that satisfies the requirement medusa-security (from versions: none)
ERROR: No matching distribution found for medusa-security
(medusa-test) rchurchill@MACLDN1-ROSCHU1 Documents %---

## Test 2: Tool Detection & Installation

**Goal:** Verify MEDUSA detects/installs security tools on macOS

```bash
# Check what's already installed
medusa install --check

# Try installing a few key tools
medusa install bandit
medusa install eslint
medusa install yamllint

# Verify they work
bandit --version
eslint --version
yamllint --version
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________
Run 'medusa install --all' to install all missing tools
(medusa-test) rchurchill@MACLDN1-ROSCHU1 ICS % medusa install eslint
Usage: medusa install [OPTIONS]
Try 'medusa install --help' for help.

Error: Got unexpected extra argument (eslint)
(medusa-test) rchurchill@MACLDN1-ROSCHU1 ICS %---

## Test 3: Basic Scanning

**Goal:** Run a simple scan to verify core functionality

```bash
# Create a test directory with vulnerable code
mkdir ~/medusa-scan-test
cd ~/medusa-scan-test

# Create test Python file with intentional issue
cat > test.py << 'EOF'
import os
password = "hardcoded123"  # Security issue
command = input("Enter command: ")
os.system(command)  # Command injection vulnerability
EOF

# Initialize MEDUSA
medusa init

# Run scan
medusa scan .

# Should find 2+ security issues
```

**Expected Output:**
- ✅ Finds hardcoded password
- ✅ Finds command injection
- ✅ No crashes or errors
- ✅ Clean terminal output

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________
(medusa-test) rchurchill@MACLDN1-ROSCHU1 Documents % # Create a test directory with vulnerable code
mkdir ~/medusa-scan-test
cd ~/medusa-scan-test

# Create test Python file with intentional issue
cat > test.py << 'EOF'
import os
password = "hardcoded123"  # Security issue
command = input("Enter command: ")
os.system(command)  # Command injection vulnerability
EOF

# Initialize MEDUSA
medusa init

# Run scan
medusa scan .
zsh: command not found: #
zsh: command not found: #
zsh: command not found: #

╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║          🐍🐍🐍 MEDUSA v0.9.1.0 - Security Guardian 🐍🐍🐍           ║
║                                                                    ║
║              The 42-Headed Universal Security Scanner             ║
║           One look from Medusa stops vulnerabilities dead          ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝


🔧 MEDUSA Initialization Wizard

Step 1/4: Detecting project languages...
✓ Found 1 language types:
  • PythonScanner        (1 files)

Step 2/4: Checking scanner availability...
✓ 5/42 scanners available
⚠️  37 tools missing: shellcheck, hadolint, markdownlint, eslint, tflint and 32 more

Install 37 missing tools? [y/N]: y
Installing missing tools...
Note: Run 'medusa install --all' to install missing tools

Step 3/4: Creating configuration...

Which IDE(s) are you using? (multiple selections allowed)
  1. Claude Code
  2. Cursor
  3. Gemini CLI
  4. OpenAI Codex
  5. GitHub Copilot
  6. All of the above
  7. None
Select IDE(s) (comma-separated, e.g., 1,2,3) [7]: 1
✓ Created /Users/rchurchill/medusa-scan-test/.medusa.yml

Step 4/4: Setting up IDE integration(s)...
✓ Claude Code integration configured
  • Created .claude/ directory with agents and commands
  • Created CLAUDE.md project context

✓ Configured 1/1 IDE integration(s)

✅ MEDUSA Initialized Successfully!

Next steps:
  1. Review configuration: .medusa.yml
  2. Install missing tools: medusa install --all
  3. Run your first scan: medusa scan .

zsh: command not found: #

╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║          🐍🐍🐍 MEDUSA v0.9.1.0 - Security Guardian 🐍🐍🐍           ║
║                                                                    ║
║              The 42-Headed Universal Security Scanner             ║
║           One look from Medusa stops vulnerabilities dead          ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝


🎯 Target: .
🔧 Mode: Full

🔍 Detecting project languages...
   Found 2 files across 2 file types

📊 Scanner Status:
   ✅ PythonScanner             (bandit         ) → .py
   ❌ MarkdownScanner           (markdownlint   ) → .md, .markdown

📦 Missing Tools (1):
   • markdownlint         (Markdown linter)

Install 1 missing tools? [Y/n]: y
Installing markdownlint... Traceback (most recent call last):
  File "/Users/rchurchill/medusa-test/bin/medusa", line 7, in <module>
    sys.exit(main())
  File "/Users/rchurchill/medusa-test/lib/python3.10/site-packages/click/core.py", line 1485, in __call__
    return self.main(*args, **kwargs)
  File "/Users/rchurchill/medusa-test/lib/python3.10/site-packages/click/core.py", line 1406, in main
    rv = self.invoke(ctx)
  File "/Users/rchurchill/medusa-test/lib/python3.10/site-packages/click/core.py", line 1873, in invoke
    return _process_result(sub_ctx.command.invoke(sub_ctx))
  File "/Users/rchurchill/medusa-test/lib/python3.10/site-packages/click/core.py", line 1269, in invoke
    return ctx.invoke(self.callback, **ctx.params)
  File "/Users/rchurchill/medusa-test/lib/python3.10/site-packages/click/core.py", line 824, in invoke
    return callback(*args, **kwargs)
  File "/Users/rchurchill/medusa-test/lib/python3.10/site-packages/medusa/cli.py", line 364, in scan
    _handle_batch_install(target, auto_install)
  File "/Users/rchurchill/medusa-test/lib/python3.10/site-packages/medusa/cli.py", line 185, in _handle_batch_install
    _install_tools(missing_tools)
  File "/Users/rchurchill/medusa-test/lib/python3.10/site-packages/medusa/cli.py", line 239, in _install_tools
    success = npm_installer.install(tool, use_latest=use_latest)
NameError: name 'use_latest' is not defined
(medusa-test) rchurchill@MACLDN1-ROSCHU1 medusa-scan-test %---

## Test 4: Comprehensive Scan on MEDUSA Source

**Goal:** Test scanning a real polyglot project

```bash
# Clone MEDUSA source
cd ~/
git clone https://github.com/Pantheon-Security/medusa.git medusa-source-test
cd medusa-source-test

# Ensure medusa is in PATH (from venv)
source ~/medusa-test/bin/activate

# Install tools
medusa install --all --yes

# Run full scan
time medusa scan . --mode full

# Should complete in < 2 minutes
# Should find 100+ issues across multiple file types
```

**Expected Results:**
- ✅ Scans Python files (.py)
- ✅ Scans YAML files (.yml, .yaml)
- ✅ Scans Markdown files (.md)
- ✅ Scans JSON files (.json)
- ✅ Completes without crashes
- ✅ Performance is reasonable (< 2 min)

**Result:** ☐ PASS ☐ FAIL

**Scan Time:** _________ seconds

**Issues Found:** _________

**Notes:**
_____________________________________________

---

## Test 5: macOS-Specific Issues

**Goal:** Check for common macOS pitfalls

### A. Permission Issues
```bash
# Try scanning system directories (should handle gracefully)
medusa scan /usr/local/bin
# Should skip inaccessible files, not crash
```

**Result:** ☐ PASS ☐ FAIL

### B. Path Issues
```bash
# Verify tools are in PATH
echo $PATH | grep medusa-test
```

**Result:** ☐ PASS ☐ FAIL

### C. Architecture Compatibility
```bash
# Check if any tools fail on Apple Silicon
file $(which medusa)
# Should show correct architecture
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 6: Version Pinning Feature

**Goal:** Test the new version pinning system (v0.9.1.0 feature)

```bash
cd ~/medusa-scan-test

# Show pinned versions
medusa versions

# Install with pinned versions (default)
medusa install bandit

# Install with latest (bypass pinning)
medusa install yamllint --use-latest

# Both should work
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 7: Uninstall & Cleanup

**Goal:** Verify clean removal

```bash
# Deactivate venv
deactivate

# Remove test environment
rm -rf ~/medusa-test
rm -rf ~/medusa-scan-test
rm -rf ~/medusa-source-test

# Verify removal
which medusa
# Should return nothing
```

**Result:** ☐ PASS ☐ FAIL

---

## Critical Issues Checklist

Mark any critical issues found:

- ☐ Installation fails
- ☐ Crashes during scan
- ☐ Cannot detect/install tools
- ☐ Permission errors
- ☐ Path issues
- ☐ Performance problems (> 5 min for full scan)
- ☐ Incorrect results
- ☐ Apple Silicon incompatibility

---

## Overall Test Result

**Status:** ☐ READY FOR LAUNCH ☐ NEEDS FIXES

**Summary:**
_____________________________________________
_____________________________________________
_____________________________________________

**Blocking Issues (must fix before launch):**
_____________________________________________
_____________________________________________

**Nice-to-have Improvements (can fix later):**
_____________________________________________
_____________________________________________

---

## Sign-off

**Tester:** Ross Churchill

**Date:** _____________

**Approved for Launch:** ☐ YES ☐ NO

**Notes for Public Release:**
_____________________________________________
_____________________________________________
