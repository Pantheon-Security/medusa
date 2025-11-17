# MEDUSA Windows Testing Guide

**Purpose:** Validate MEDUSA works correctly on Windows before public launch

**Date:** 2025-11-17
**Tester:** Ross Churchill
**Platform:** Windows 10/11

---

## Pre-Test System Info

Before starting, record your system details in PowerShell:

```powershell
# Windows version
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion

# Python version
python --version

# Pip version
pip --version

# Node/npm version (if installed)
node --version
npm --version
```

**Record:**
- Windows Version: _____________
- Python Version: _____________
- Python Source: ☐ python.org ☐ Microsoft Store ☐ Anaconda
- Node.js Installed: ☐ YES ☐ NO

---

## Test Environment Options

**Choose ONE testing environment:**

- ☐ **PowerShell** (Recommended - native Windows)
- ☐ **Command Prompt (CMD)** (Legacy but still used)
- ☐ **Git Bash** (Unix-like on Windows)
- ☐ **WSL 2** (Windows Subsystem for Linux - use Linux test plan)

**Testing on:** _____________

---

## Test 1: Clean Installation from PyPI (PowerShell)

**Goal:** Test what a real Windows user experiences

```powershell
# Create fresh virtual environment
python -m venv $HOME\medusa-test

# Activate venv
$HOME\medusa-test\Scripts\Activate.ps1

# If execution policy error:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Upgrade pip
python -m pip install --upgrade pip

# Install from PyPI
pip install medusa-security

# Verify installation
medusa --version
# Expected: 0.9.1.0

# Check PATH
Get-Command medusa
# Expected: C:\Users\<username>\medusa-test\Scripts\medusa.exe
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 1b: Clean Installation (Command Prompt)

**Goal:** Test CMD compatibility

```batch
REM Create virtual environment
python -m venv %USERPROFILE%\medusa-test

REM Activate
%USERPROFILE%\medusa-test\Scripts\activate.bat

REM Install
pip install medusa-security

REM Verify
medusa --version
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 1c: Clean Installation (Git Bash)

**Goal:** Test Git Bash compatibility

```bash
# Create virtual environment
python -m venv ~/medusa-test

# Activate
source ~/medusa-test/Scripts/activate

# Install
pip install medusa-security

# Verify
medusa --version
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 2: Tool Detection & Installation

**Goal:** Verify MEDUSA detects/installs tools on Windows

```powershell
# Check what's already installed
medusa install --check

# Test Python tools (via pip)
medusa install bandit
medusa install yamllint

# Test Node.js tools (via npm - if Node is installed)
medusa install eslint

# Verify they work
bandit --version
yamllint --version
eslint --version  # If Node installed
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 3: Path Separator Handling

**Goal:** Verify Windows path handling (backslash vs forward slash)

```powershell
# Create test directory
New-Item -ItemType Directory -Path "$HOME\medusa-scan-test"
Set-Location "$HOME\medusa-scan-test"

# Create test file with path
@'
import os
file_path = r"C:\Users\test\data.txt"
os.system("dir C:\\Windows")
'@ | Out-File -FilePath test.py

# Scan with backslash path
medusa scan $HOME\medusa-scan-test

# Scan with forward slash path (Unix-style)
medusa scan $HOME/medusa-scan-test

# Both should work
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 4: Basic Scanning

**Goal:** Run a simple scan to verify core functionality

```powershell
# Navigate to test directory
Set-Location "$HOME\medusa-scan-test"

# Create test Python file
@'
import os
import pickle

# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "admin123"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Command injection
command = input("Enter command: ")
os.system(command)

# Unsafe deserialization
data = pickle.loads(user_input)

# SQL injection
query = f"SELECT * FROM users WHERE id = {user_id}"
'@ | Out-File -FilePath test.py -Encoding UTF8

# Create test JavaScript file
@'
const password = "hardcoded123";
const apiKey = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY";
eval(userInput);
document.write(userInput);
'@ | Out-File -FilePath test.js -Encoding UTF8

# Initialize MEDUSA
medusa init

# Run scan
medusa scan .
```

**Expected Output:**
- ✅ Finds hardcoded credentials (5+)
- ✅ Finds command injection
- ✅ Finds unsafe deserialization
- ✅ Finds eval() usage
- ✅ Clean output in PowerShell
- ✅ No crashes

**Result:** ☐ PASS ☐ FAIL

**Issues Found:** _________

**Notes:**
_____________________________________________

---

## Test 5: Windows-Specific Issues

**Goal:** Test Windows-specific edge cases

### A. Long Path Names (Windows MAX_PATH issue)
```powershell
# Create deeply nested directory
$longPath = "$HOME\medusa-scan-test\" + ("a\" * 50)
New-Item -ItemType Directory -Path $longPath -Force

# Try to scan
medusa scan $HOME\medusa-scan-test
# Should handle gracefully (skip or work with long paths)
```

**Result:** ☐ PASS ☐ FAIL

### B. Special Characters in Path
```powershell
# Create directory with spaces and special chars
New-Item -ItemType Directory -Path "$HOME\test (special) [chars]" -Force
Set-Location "$HOME\test (special) [chars]"

# Create test file
"print('test')" | Out-File -FilePath test.py

# Scan
medusa scan .
```

**Result:** ☐ PASS ☐ FAIL

### C. Windows Line Endings (CRLF vs LF)
```powershell
# Create file with Windows line endings
"line1`r`nline2`r`nline3" | Out-File -FilePath crlf_test.py -NoNewline

# Scan should handle both CRLF and LF
medusa scan .
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 6: Comprehensive Scan on MEDUSA Source

**Goal:** Test scanning a real polyglot project

```powershell
# Clone MEDUSA source
Set-Location $HOME
git clone https://github.com/Pantheon-Security/medusa.git medusa-source-test
Set-Location medusa-source-test

# Ensure medusa is in PATH (activate venv)
& "$HOME\medusa-test\Scripts\Activate.ps1"

# Install all tools
medusa install --all --yes

# Run full scan with timing
Measure-Command { medusa scan . --mode full }

# Should complete in < 3 minutes
# Should find 100+ issues
```

**Expected Results:**
- ✅ Scans Python files (.py)
- ✅ Scans YAML files (.yml, .yaml)
- ✅ Scans Markdown files (.md)
- ✅ Scans JSON files (.json)
- ✅ Handles Windows paths correctly
- ✅ Progress bars work in PowerShell
- ✅ No crashes

**Result:** ☐ PASS ☐ FAIL

**Scan Time:** _________ seconds

**Issues Found:** _________

**Notes:**
_____________________________________________

---

## Test 7: Version Pinning Feature (v0.9.1.0)

**Goal:** Test new version pinning system on Windows

```powershell
Set-Location "$HOME\medusa-scan-test"

# Show pinned versions
medusa versions
# Should display 36+ tools with versions

# Install with pinned version
medusa install bandit

# Check version matches
bandit --version
# Should be 1.8.6 (pinned)

# Test --use-latest flag
medusa install yamllint --use-latest
yamllint --version
# May be newer than pinned
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 8: Administrator Privileges

**Goal:** Test with/without admin rights

### As Regular User
```powershell
# Install and scan (no admin)
# Should work without requiring elevation
```

**Result:** ☐ PASS ☐ FAIL

### As Administrator (if needed)
```powershell
# Right-click PowerShell -> "Run as Administrator"
# Repeat installation test
# Should warn if admin isn't needed
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 9: Antivirus/Windows Defender

**Goal:** Ensure MEDUSA doesn't trigger false positives

```powershell
# Check Windows Defender status
Get-MpComputerStatus

# Install and run scan
# Monitor for any antivirus alerts
```

**Result:** ☐ PASS ☐ FAIL

**Antivirus Alerts:** ☐ NONE ☐ FLAGGED

**Notes:**
_____________________________________________

---

## Test 10: Different Python Installations

**Goal:** Test compatibility with different Python sources

### Python from python.org
```powershell
# Verify source
(Get-Command python).Source
# Should be: C:\Users\<user>\AppData\Local\Programs\Python\...
```

**Result:** ☐ PASS ☐ FAIL

### Python from Microsoft Store
```powershell
# Verify source
(Get-Command python).Source
# Should be: C:\Users\<user>\AppData\Local\Microsoft\WindowsApps\python.exe
```

**Result:** ☐ PASS ☐ FAIL

### Python from Anaconda/Miniconda
```powershell
# Activate conda
conda activate base
pip install medusa-security
medusa --version
```

**Result:** ☐ PASS ☐ FAIL

**Notes:**
_____________________________________________

---

## Test 11: Uninstall & Cleanup

**Goal:** Verify clean removal

```powershell
# Deactivate venv
deactivate

# Remove test directories
Remove-Item -Recurse -Force "$HOME\medusa-test"
Remove-Item -Recurse -Force "$HOME\medusa-scan-test"
Remove-Item -Recurse -Force "$HOME\medusa-source-test"
Remove-Item -Recurse -Force "$HOME\test (special) [chars]"

# Verify removal
Get-Command medusa
# Should error: "not recognized"
```

**Result:** ☐ PASS ☐ FAIL

---

## Critical Issues Checklist

Mark any critical issues found:

- ☐ Installation fails
- ☐ Crashes during scan
- ☐ Cannot detect/install tools
- ☐ Path separator issues
- ☐ Long path failures
- ☐ Permission errors
- ☐ Execution policy blocks
- ☐ Antivirus false positives
- ☐ PowerShell compatibility issues
- ☐ Git Bash compatibility issues
- ☐ Progress bars broken
- ☐ Incorrect results

---

## Environment-Specific Issues

**PowerShell:**
_____________________________________________

**Command Prompt:**
_____________________________________________

**Git Bash:**
_____________________________________________

**WSL:**
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

**Windows-Specific Notes:**
_____________________________________________
_____________________________________________

---

## Sign-off

**Tester:** Ross Churchill

**Date:** _____________

**Environment Tested:** _____________

**Approved for Launch:** ☐ YES ☐ NO

**Notes for Public Release:**
_____________________________________________
_____________________________________________
_____________________________________________

**Windows Compatibility Statement:**
☐ Fully compatible with Windows 10/11
☐ Requires specific setup (document in README)
☐ Not yet ready for Windows
