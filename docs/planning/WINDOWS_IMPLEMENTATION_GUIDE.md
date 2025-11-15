# MEDUSA Windows Implementation Guide

**Platform**: Windows 10, 11 (Native, WSL2, Git Bash)
**Complexity**: 🔴 HIGH
**Status**: 📋 PLANNING

---

## 🎯 Windows Challenges Summary

| Challenge | Severity | Solution | Status |
|-----------|----------|----------|--------|
| No native bash | 🔴 HIGH | WSL2 / Git Bash / PowerShell | 📋 Planned |
| Package management | 🟡 MEDIUM | Chocolatey / Scoop / winget | 📋 Planned |
| Path separators | 🟡 MEDIUM | Python `pathlib.Path` | ✅ Easy |
| Line endings (CRLF) | 🟢 LOW | Universal newlines | ✅ Easy |
| Linter availability | 🔴 HIGH | Prioritize Python linters | 📋 Planned |
| Admin permissions | 🟡 MEDIUM | Scoop (no admin) | 📋 Planned |
| Shell script execution | 🔴 HIGH | Pure Python | ✅ Easy |

---

## 🖥️ Windows Environment Detection

### Priority Order (Best to Worst)

1. **WSL2 (Windows Subsystem for Linux)** - ✅ BEST
   - Full Linux environment
   - All linters work
   - Native bash support
   - Best compatibility

2. **Git Bash (MINGW64)** - ✅ GOOD
   - Comes with Git for Windows (90%+ have it)
   - Most bash scripts work
   - Many linters available
   - No admin required

3. **PowerShell Native** - ⚠️ ACCEPTABLE
   - Built into Windows
   - Limited linter support
   - Requires PowerShell rewrites
   - Good for Python-only projects

4. **Command Prompt (cmd.exe)** - ❌ AVOID
   - Legacy
   - Minimal functionality
   - Not recommended

---

## 🔍 Environment Detection Code

```python
import os
import platform
import subprocess
import shutil
from pathlib import Path
from enum import Enum

class WindowsEnvironment(Enum):
    WSL2 = "wsl2"
    GIT_BASH = "git_bash"
    POWERSHELL = "powershell"
    CMD = "cmd"
    UNKNOWN = "unknown"

class WindowsDetector:
    """Detect Windows execution environment"""

    @staticmethod
    def is_windows() -> bool:
        """Check if running on Windows"""
        return platform.system() == "Windows"

    @staticmethod
    def is_wsl() -> bool:
        """Check if running in WSL (Windows Subsystem for Linux)"""
        # Check for /proc/version containing "microsoft" or "WSL"
        try:
            with open("/proc/version", "r") as f:
                version = f.read().lower()
                return "microsoft" in version or "wsl" in version
        except FileNotFoundError:
            return False

    @staticmethod
    def has_wsl2() -> bool:
        """Check if WSL2 is available on Windows"""
        if not WindowsDetector.is_windows():
            return False

        try:
            result = subprocess.run(
                ["wsl", "--status"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def has_git_bash() -> bool:
        """Check if Git Bash is available"""
        if not WindowsDetector.is_windows():
            return False

        # Common Git Bash locations
        git_bash_paths = [
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Git" / "bin" / "bash.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Git" / "bin" / "bash.exe",
            Path.home() / "AppData" / "Local" / "Programs" / "Git" / "bin" / "bash.exe",
        ]

        return any(path.exists() for path in git_bash_paths)

    @staticmethod
    def get_git_bash_path() -> Path:
        """Get path to Git Bash executable"""
        git_bash_paths = [
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Git" / "bin" / "bash.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Git" / "bin" / "bash.exe",
            Path.home() / "AppData" / "Local" / "Programs" / "Git" / "bin" / "bash.exe",
        ]

        for path in git_bash_paths:
            if path.exists():
                return path

        raise FileNotFoundError("Git Bash not found")

    @staticmethod
    def detect_environment() -> WindowsEnvironment:
        """Detect the Windows execution environment"""
        # Check if we're in WSL
        if WindowsDetector.is_wsl():
            return WindowsEnvironment.WSL2

        # Check if we're on Windows
        if not WindowsDetector.is_windows():
            return WindowsEnvironment.UNKNOWN

        # Check for Git Bash (MINGW environment)
        if os.environ.get("MSYSTEM"):  # Git Bash sets this
            return WindowsEnvironment.GIT_BASH

        # Check if running in PowerShell
        if os.environ.get("PSModulePath"):
            return WindowsEnvironment.POWERSHELL

        # Fallback to CMD
        return WindowsEnvironment.CMD

    @staticmethod
    def get_recommended_environment() -> WindowsEnvironment:
        """Get the best available environment"""
        # Priority: WSL2 > Git Bash > PowerShell
        if WindowsDetector.has_wsl2():
            return WindowsEnvironment.WSL2
        elif WindowsDetector.has_git_bash():
            return WindowsEnvironment.GIT_BASH
        else:
            return WindowsEnvironment.POWERSHELL
```

---

## 📦 Package Manager Detection

```python
class WindowsPackageManager(Enum):
    CHOCOLATEY = "choco"
    SCOOP = "scoop"
    WINGET = "winget"
    NONE = "none"

class PackageManagerDetector:
    """Detect available Windows package managers"""

    @staticmethod
    def has_chocolatey() -> bool:
        """Check if Chocolatey is installed"""
        return shutil.which("choco") is not None

    @staticmethod
    def has_scoop() -> bool:
        """Check if Scoop is installed"""
        return shutil.which("scoop") is not None

    @staticmethod
    def has_winget() -> bool:
        """Check if winget is installed"""
        return shutil.which("winget") is not None

    @staticmethod
    def detect_package_manager() -> WindowsPackageManager:
        """Detect available package manager (priority order)"""
        if PackageManagerDetector.has_scoop():
            return WindowsPackageManager.SCOOP  # Preferred (no admin)
        elif PackageManagerDetector.has_chocolatey():
            return WindowsPackageManager.CHOCOLATEY
        elif PackageManagerDetector.has_winget():
            return WindowsPackageManager.WINGET
        else:
            return WindowsPackageManager.NONE

    @staticmethod
    def install_linter(linter: str, package_manager: WindowsPackageManager) -> bool:
        """Install a linter using the detected package manager"""
        commands = {
            WindowsPackageManager.CHOCOLATEY: ["choco", "install", linter, "-y"],
            WindowsPackageManager.SCOOP: ["scoop", "install", linter],
            WindowsPackageManager.WINGET: ["winget", "install", linter, "--accept-source-agreements"],
        }

        if package_manager == WindowsPackageManager.NONE:
            print(f"❌ No package manager found. Install manually: {linter}")
            return False

        try:
            result = subprocess.run(
                commands[package_manager],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
```

---

## 🛠️ Linter Availability on Windows

### ✅ Tier 1: Python-Based (pip install) - ALWAYS WORKS

| Linter | Install Command | Coverage |
|--------|----------------|----------|
| **Bandit** | `pip install bandit` | Python security |
| **yamllint** | `pip install yamllint` | YAML validation |
| **safety** | `pip install safety` | Python deps |
| **pylint** | `pip install pylint` | Python quality |
| **flake8** | `pip install flake8` | Python linting |
| **mypy** | `pip install mypy` | Python types |

**Pros**: ✅ Always available, no dependencies
**Cons**: ❌ Python-only coverage

---

### ⚠️ Tier 2: Available via Package Managers

| Linter | Choco | Scoop | winget | Language |
|--------|-------|-------|--------|----------|
| **ShellCheck** | ✅ | ✅ | ✅ | Bash |
| **hadolint** | ✅ | ❌ | ❌ | Docker |
| **yamllint** | ✅ | ✅ | ❌ | YAML |
| **golangci-lint** | ❌ | ✅ | ❌ | Go |
| **Node.js** (for eslint) | ✅ | ✅ | ✅ | JavaScript |

**Installation Examples**:
```powershell
# Chocolatey (requires admin)
choco install shellcheck -y

# Scoop (no admin required) - RECOMMENDED
scoop install shellcheck
scoop install nodejs  # Then: npm install -g eslint

# winget (Windows 11 built-in)
winget install --id ShellCheck.ShellCheck
```

---

### ❌ Tier 3: Not Available Natively (Use WSL2)

| Linter | Reason | Workaround |
|--------|--------|------------|
| **tflint** | Linux-only binary | Use WSL2 |
| **ansible-lint** | Linux-only | Use WSL2 |
| **gixy** (Nginx) | Linux-only | Use WSL2 |
| **slither** (Solidity) | Linux-only | Use WSL2 |
| **detekt** (Kotlin) | Requires JVM | Install Java first |

**Recommendation**: Install WSL2 for full compatibility
```powershell
# Install WSL2 (requires admin, one-time setup)
wsl --install

# Then use Linux commands in WSL
wsl pip install slither-analyzer
wsl tflint
```

---

## 🚀 Installation Strategy by Environment

### Strategy 1: WSL2 (Recommended for Developers)

```python
def install_in_wsl2():
    """Install MEDUSA in WSL2 (best compatibility)"""
    print("🐧 Installing MEDUSA in WSL2...")

    # Install pip package in WSL
    subprocess.run([
        "wsl", "pip3", "install", "medusa-security"
    ], check=True)

    # Install all linters (Linux environment)
    subprocess.run([
        "wsl", "sudo", "apt", "update"
    ], check=True)

    subprocess.run([
        "wsl", "sudo", "apt", "install", "-y",
        "shellcheck", "yamllint", "nodejs", "npm"
    ], check=True)

    print("✅ MEDUSA installed in WSL2")
    print("   Run: wsl medusa scan .")
```

**Pros**:
- ✅ Full Linux compatibility
- ✅ All 42 linters available
- ✅ Best performance
- ✅ Native bash support

**Cons**:
- ⚠️ Requires Windows 10 build 19041+ or Windows 11
- ⚠️ One-time setup (5-10 minutes)
- ⚠️ File access slower across WSL boundary

---

### Strategy 2: Git Bash (Good Balance)

```python
def install_with_git_bash():
    """Install MEDUSA using Git Bash"""
    print("🦊 Installing MEDUSA with Git Bash support...")

    # Install Python package normally
    subprocess.run([
        "pip", "install", "medusa-security"
    ], check=True)

    # Install linters via Scoop (no admin)
    if shutil.which("scoop"):
        subprocess.run(["scoop", "install", "shellcheck"], check=True)
        subprocess.run(["scoop", "install", "nodejs"], check=True)
        subprocess.run(["npm", "install", "-g", "eslint"], check=True)

    # Configure to use Git Bash for shell scripts
    git_bash = WindowsDetector.get_git_bash_path()
    os.environ["MEDUSA_SHELL"] = str(git_bash)

    print("✅ MEDUSA installed with Git Bash")
    print(f"   Shell: {git_bash}")
```

**Pros**:
- ✅ No admin required (with Scoop)
- ✅ Most linters work
- ✅ Good compatibility
- ✅ Already have Git Bash (90%+ users)

**Cons**:
- ⚠️ Some Linux-only linters missing
- ⚠️ Slightly slower than native

---

### Strategy 3: Native PowerShell (Minimal)

```python
def install_native_powershell():
    """Install MEDUSA for PowerShell (Python linters only)"""
    print("⚡ Installing MEDUSA for PowerShell...")

    # Install Python package
    subprocess.run([
        "pip", "install", "medusa-security"
    ], check=True)

    # Install Python linters only (always work)
    subprocess.run([
        "pip", "install",
        "bandit", "yamllint", "safety", "pylint", "flake8"
    ], check=True)

    # Warn about limited coverage
    print("✅ MEDUSA installed (Python linters only)")
    print("⚠️  For full linter support, install WSL2 or Git Bash")
    print("   Run: medusa scan . --python-only")
```

**Pros**:
- ✅ No external dependencies
- ✅ Works immediately
- ✅ Good for Python-only projects

**Cons**:
- ❌ Limited to Python linters (~20% coverage)
- ❌ Missing bash, Docker, JavaScript linters

---

## 📋 Smart Installation Wizard

```python
def windows_installation_wizard():
    """Interactive installation wizard for Windows"""
    print("🐍 MEDUSA Windows Installation Wizard")
    print()

    # Detect environment
    env = WindowsDetector.detect_environment()
    recommended = WindowsDetector.get_recommended_environment()

    print(f"📍 Current environment: {env.value}")
    print(f"✨ Recommended environment: {recommended.value}")
    print()

    # Ask user preference
    print("Select installation method:")
    print("1) WSL2 (best compatibility, requires setup)")
    print("2) Git Bash (good balance, works for most)")
    print("3) Native PowerShell (Python linters only)")
    print()

    choice = input("Choice [1-3]: ").strip()

    if choice == "1":
        if WindowsDetector.has_wsl2():
            install_in_wsl2()
        else:
            print("❌ WSL2 not found")
            print("   Install with: wsl --install")
            print("   Then run this installer again")
            return False

    elif choice == "2":
        if WindowsDetector.has_git_bash():
            install_with_git_bash()
        else:
            print("❌ Git Bash not found")
            print("   Install Git for Windows:")
            print("   https://git-scm.com/download/win")
            return False

    elif choice == "3":
        install_native_powershell()

    else:
        print("❌ Invalid choice")
        return False

    # Test installation
    try:
        subprocess.run(["medusa", "--version"], check=True)
        print()
        print("🎉 Installation successful!")
        print("   Run: medusa scan .")
        return True
    except subprocess.CalledProcessError:
        print("❌ Installation failed")
        return False
```

---

## 🔧 PowerShell Wrappers for Shell Scripts

Since many linters use shell scripts, we need PowerShell wrappers:

```powershell
# medusa.ps1 - PowerShell wrapper

param(
    [Parameter(Position=0)]
    [string]$Command = "scan",

    [Parameter(Position=1)]
    [string]$Target = ".",

    [switch]$Quick,
    [switch]$Force,
    [int]$Workers = 0
)

# Detect Python executable
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command python3 -ErrorAction SilentlyContinue
}

if (-not $python) {
    Write-Error "Python not found. Install from python.org"
    exit 1
}

# Build command
$cmd = @($python.Source, "-m", "medusa", $Command, $Target)

if ($Quick) { $cmd += "--quick" }
if ($Force) { $cmd += "--force" }
if ($Workers -gt 0) { $cmd += "-w", $Workers }

# Execute
& $cmd
```

---

## 📦 Package Manager Installation Scripts

### Chocolatey Package

```xml
<!-- medusa-security.nuspec -->
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>medusa-security</id>
    <version>7.0.0</version>
    <title>MEDUSA Security Scanner</title>
    <authors>Chimera Trading Systems</authors>
    <description>The 42-Headed Security Guardian - Universal security scanner for all languages</description>
    <projectUrl>https://medusa-security.dev</projectUrl>
    <tags>security scanner linter python bash docker</tags>
    <dependencies>
      <dependency id="python" version="3.10" />
    </dependencies>
  </metadata>
  <files>
    <file src="tools\**" target="tools" />
  </files>
</package>
```

```powershell
# tools/chocolateyInstall.ps1
$ErrorActionPreference = 'Stop'

# Install via pip
python -m pip install --upgrade pip
python -m pip install medusa-security

# Add to PATH
$pythonScripts = [System.IO.Path]::Combine($env:APPDATA, "Python", "Scripts")
if ($env:PATH -notlike "*$pythonScripts*") {
    [Environment]::SetEnvironmentVariable(
        "PATH",
        "$env:PATH;$pythonScripts",
        "User"
    )
}

Write-Host "✅ MEDUSA installed successfully" -ForegroundColor Green
Write-Host "   Run: medusa --help"
```

---

### Scoop Manifest

```json
{
    "version": "7.0.0",
    "description": "The 42-Headed Security Guardian",
    "homepage": "https://medusa-security.dev",
    "license": "MIT",
    "depends": ["python"],
    "installer": {
        "script": [
            "python -m pip install --upgrade pip",
            "python -m pip install medusa-security"
        ]
    },
    "bin": [
        ["medusa.ps1", "medusa"]
    ],
    "checkver": {
        "url": "https://pypi.org/pypi/medusa-security/json",
        "jsonpath": "$.info.version"
    }
}
```

---

## 🧪 Windows Testing Strategy

### Test Matrix

| Environment | Python | Linters | Priority |
|-------------|--------|---------|----------|
| Win 11 WSL2 | 3.10-3.12 | All | ✅ P0 |
| Win 11 Git Bash | 3.10-3.12 | Most | ✅ P0 |
| Win 11 PowerShell | 3.10-3.12 | Python | ⚠️ P1 |
| Win 10 WSL2 | 3.10-3.12 | All | ⚠️ P1 |
| Win 10 Git Bash | 3.10-3.12 | Most | ⚠️ P1 |

### Automated Testing

```yaml
# .github/workflows/windows-test.yml
name: Windows Tests

on: [push, pull_request]

jobs:
  test-windows:
    runs-on: windows-2022
    strategy:
      matrix:
        python: ['3.10', '3.11', '3.12']
        environment: ['powershell', 'git-bash', 'wsl']

    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python }}

      - name: Setup WSL
        if: matrix.environment == 'wsl'
        run: wsl --install --no-launch

      - name: Setup Git Bash
        if: matrix.environment == 'git-bash'
        run: choco install git -y

      - name: Install MEDUSA
        run: pip install -e .

      - name: Run tests
        run: pytest tests/ -v

      - name: Test scan
        run: medusa scan . --no-report
```

---

## 📚 Windows-Specific Documentation

### Troubleshooting Guide

**Problem 1**: "Command not found: medusa"
```powershell
# Solution: Add Python Scripts to PATH
$pythonScripts = [System.IO.Path]::Combine($env:APPDATA, "Python", "Scripts")
$env:PATH += ";$pythonScripts"
```

**Problem 2**: "ShellCheck not found"
```powershell
# Solution: Install via Scoop (no admin)
scoop install shellcheck

# Or use WSL2
wsl sudo apt install shellcheck
medusa scan . --use-wsl
```

**Problem 3**: "Permission denied"
```powershell
# Solution: Run as Administrator OR use Scoop
Start-Process powershell -Verb RunAs -ArgumentList "medusa scan ."
```

**Problem 4**: "Line ending errors"
```bash
# Git auto-converts CRLF <-> LF
# Configure Git to preserve line endings:
git config --global core.autocrlf false
```

---

## 🎯 Windows Launch Checklist

- [ ] Implement Windows environment detection
- [ ] Create PowerShell wrapper scripts
- [ ] Build Chocolatey package
- [ ] Create Scoop manifest
- [ ] Test on Windows 10 (WSL2, Git Bash, PowerShell)
- [ ] Test on Windows 11 (WSL2, Git Bash, PowerShell)
- [ ] Write Windows-specific documentation
- [ ] Create Windows installation video
- [ ] Test all 3 installation paths
- [ ] Verify linter availability per environment

---

**Status**: 📋 PLANNING
**Target**: Q1 2026
**Complexity**: 🔴 HIGH
**Impact**: 🟢 HIGH (30-40% of users are on Windows)
