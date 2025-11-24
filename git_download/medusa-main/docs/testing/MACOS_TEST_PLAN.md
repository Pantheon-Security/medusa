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
python3 --version

# Pip version
pip3 --version
```

**Record:**
- macOS Version: _____________
- Architecture: _____________
- Python Version: _____________

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
which medusa
# Expected: ~/medusa-test/bin/medusa
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

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

---

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

---

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
