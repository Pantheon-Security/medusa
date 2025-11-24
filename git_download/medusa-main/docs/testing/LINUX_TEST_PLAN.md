# MEDUSA Linux Testing Guide

**Purpose:** Validate MEDUSA works correctly on Linux before public launch

**Date:** 2025-11-17
**Tester:** Ross Churchill
**Platform:** Linux (Ubuntu/Debian/Fedora/Arch)

---

## Pre-Test System Info

Before starting, record your system details:

```bash
# Distribution
cat /etc/os-release | grep PRETTY_NAME

# Kernel version
uname -r

# Architecture
uname -m

# Python version
python3 --version

# Pip version
pip3 --version
```

**Record:**
- Distribution: _____________
- Kernel: _____________
- Architecture: _____________
- Python Version: _____________

---

## Test 1: Clean Installation from PyPI

**Goal:** Test what a real user experiences

```bash
# Create fresh virtual environment
python3 -m venv ~/medusa-test
source ~/medusa-test/bin/activate

# Upgrade pip
pip install --upgrade pip

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

**Goal:** Verify MEDUSA detects/installs security tools on Linux

```bash
# Check what's already installed
medusa install --check

# Test installing Python tools (via pip)
medusa install bandit
medusa install yamllint

# Test installing Node.js tools (via npm)
medusa install eslint

# Verify they work
bandit --version
eslint --version
yamllint --version
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 3: Sudo/Permission Handling

**Goal:** Verify MEDUSA handles permissions correctly

```bash
# Try installing tools that might need system packages
medusa install semgrep

# Should either:
# - Install without sudo (to venv)
# - Prompt for sudo with clear message
# - Fail gracefully with helpful error

# Test scanning system directories
medusa scan /etc
# Should skip permission-denied files gracefully
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 4: Basic Scanning

**Goal:** Run a simple scan to verify core functionality

```bash
# Create test directory with vulnerable code
mkdir ~/medusa-scan-test
cd ~/medusa-scan-test

# Create test Python file
cat > test.py << 'EOF'
import pickle
import os

# Unsafe deserialization
data = pickle.loads(user_input)

# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "admin123"

# Command injection
command = input("Enter command: ")
os.system(command)

# SQL injection risk
query = f"SELECT * FROM users WHERE id = {user_id}"
EOF

# Create test JavaScript file
cat > test.js << 'EOF'
const password = "hardcoded123";
eval(userInput);  // Dangerous eval
document.write(userInput);  // XSS risk
EOF

# Initialize MEDUSA
medusa init

# Run scan
medusa scan .
```

**Expected Output:**
- ✅ Finds hardcoded credentials (3+)
- ✅ Finds command injection
- ✅ Finds unsafe deserialization
- ✅ Finds eval() usage
- ✅ Clean terminal output with colors
- ✅ No crashes

**Result:** ☐ PASS ☐ FAIL

**Issues Found:** _________

**Notes:**
_____________________________________________

---

## Test 5: Comprehensive Scan on MEDUSA Source

**Goal:** Test scanning a real polyglot project

```bash
# Clone MEDUSA source
cd ~/
git clone https://github.com/Pantheon-Security/medusa.git medusa-source-test
cd medusa-source-test

# Ensure medusa is in PATH
source ~/medusa-test/bin/activate

# Install all tools
medusa install --all --yes

# Run full scan with timing
time medusa scan . --mode full

# Should complete in < 90 seconds
# Should find 100+ issues
```

**Expected Results:**
- ✅ Scans Python files (.py)
- ✅ Scans YAML files (.yml, .yaml)
- ✅ Scans Markdown files (.md)
- ✅ Scans JSON files (.json)
- ✅ Scans Shell scripts (.sh)
- ✅ Parallel processing works (multiple cores)
- ✅ Progress bars display correctly
- ✅ No crashes or hangs

**Result:** ☐ PASS ☐ FAIL

**Scan Time:** _________ seconds

**Issues Found:** _________

**CPU Cores Used:** _________

**Notes:**
_____________________________________________

---

## Test 6: Linux-Specific Features

**Goal:** Test Linux-specific functionality

### A. Parallel Processing
```bash
# Check core detection
nproc
# MEDUSA should use available cores

# Scan with explicit worker count
medusa scan . --workers 4
```

**Result:** ☐ PASS ☐ FAIL

### B. File Permissions
```bash
# Create file with restricted permissions
echo "test" > restricted.py
chmod 000 restricted.py

# Scan should skip gracefully
medusa scan .

# Cleanup
chmod 644 restricted.py
rm restricted.py
```

**Result:** ☐ PASS ☐ FAIL

### C. Symlinks
```bash
# Create symlink
ln -s /etc/hosts test_link
medusa scan .
# Should handle symlinks correctly
rm test_link
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 7: Version Pinning Feature (v0.9.1.0)

**Goal:** Test new version pinning system

```bash
cd ~/medusa-scan-test

# Show pinned versions
medusa versions
# Should display 36+ pinned tool versions

# Verify version is used
medusa install bandit
bandit --version
# Should match pinned version (1.8.6)

# Test --use-latest flag
medusa install yamllint --use-latest
yamllint --version
# May be newer than pinned version
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 8: Different Python Versions

**Goal:** Test compatibility across Python versions

```bash
# Test with Python 3.10
python3.10 -m venv ~/test-py310
source ~/test-py310/bin/activate
pip install medusa-security
medusa --version
deactivate

# Test with Python 3.11 (if available)
python3.11 -m venv ~/test-py311
source ~/test-py311/bin/activate
pip install medusa-security
medusa --version
deactivate

# Test with Python 3.12 (if available)
python3.12 -m venv ~/test-py312
source ~/test-py312/bin/activate
pip install medusa-security
medusa --version
deactivate
```

**Supported Versions:** 3.10, 3.11, 3.12+

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 9: Package Manager Compatibility

**Goal:** Verify works with system package managers

### Ubuntu/Debian (apt)
```bash
# Verify npm is installed
npm --version || sudo apt install npm

# Install MEDUSA
pip install medusa-security

# Install Node tools
medusa install eslint
```

### Fedora/RHEL (yum/dnf)
```bash
# Verify npm is installed
npm --version || sudo dnf install npm

# Same test as above
```

### Arch (pacman)
```bash
# Verify npm is installed
npm --version || sudo pacman -S npm

# Same test as above
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 10: Uninstall & Cleanup

**Goal:** Verify clean removal

```bash
# Deactivate all venvs
deactivate

# Remove test environments
rm -rf ~/medusa-test
rm -rf ~/test-py310
rm -rf ~/test-py311
rm -rf ~/test-py312
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
- ☐ Parallel processing doesn't work
- ☐ Progress bars broken
- ☐ Incorrect results
- ☐ Python version incompatibility

---

## Distribution-Specific Issues

**Ubuntu/Debian:**
_____________________________________________

**Fedora/RHEL:**
_____________________________________________

**Arch Linux:**
_____________________________________________

**Other:**
_____________________________________________

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

**Distribution Tested:** _____________

**Approved for Launch:** ☐ YES ☐ NO

**Notes for Public Release:**
_____________________________________________
_____________________________________________
