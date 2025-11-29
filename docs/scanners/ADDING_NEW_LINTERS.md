# Adding New Linters to MEDUSA

This guide documents the complete process for adding a new linter/scanner to MEDUSA, including platform-specific installation requirements.

## Overview

Adding a new linter requires updates to multiple files:

| File | Purpose |
|------|---------|
| `medusa/scanners/<name>_scanner.py` | Scanner wrapper implementation |
| `medusa/scanners/__init__.py` | Register the scanner |
| `medusa/platform/installers/base.py` | Package manager mappings |
| `medusa/tool-versions.lock` | Version pinning |

---

## Step 1: Create the Scanner Wrapper

Create a new file `medusa/scanners/<toolname>_scanner.py`:

```python
#!/usr/bin/env python3
"""
MEDUSA <ToolName> Scanner
<Brief description of what it scans>
"""

import shutil
import subprocess
import json
from typing import List
from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class <ToolName>Scanner(BaseScanner):
    """Scanner using <toolname> for <language/purpose>"""

    name = "<toolname>"
    tool_name = "<toolname>"  # CLI command name
    description = "<Brief description>"
    supported_languages = ["<language>"]

    # Rule ID to severity mapping
    SEVERITY_MAP = {
        "RULE001": Severity.HIGH,
        "RULE002": Severity.MEDIUM,
        # Add mappings...
    }

    def get_file_extensions(self) -> List[str]:
        """Return file extensions this scanner handles"""
        return [".ext1", ".ext2"]

    def is_available(self) -> bool:
        """Check if the tool is installed"""
        return shutil.which(self.tool_name) is not None

    def scan_file(self, file_path: str) -> ScannerResult:
        """Scan a single file"""
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=[],
                error=f"{self.tool_name} not installed"
            )

        try:
            result = subprocess.run(
                [self.tool_name, "--format", "json", file_path],
                capture_output=True,
                text=True,
                timeout=60
            )

            issues = self._parse_output(result.stdout, file_path)

            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=issues
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=[],
                error="Scan timed out"
            )
        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=[],
                error=str(e)
            )

    def _parse_output(self, output: str, file_path: str) -> List[ScannerIssue]:
        """Parse tool output into ScannerIssue objects"""
        issues = []

        if not output.strip():
            return issues

        try:
            data = json.loads(output)
            for finding in data.get("results", []):
                severity = self.SEVERITY_MAP.get(
                    finding.get("rule_id", ""),
                    Severity.MEDIUM
                )

                issues.append(ScannerIssue(
                    rule_id=finding.get("rule_id", "UNKNOWN"),
                    severity=severity,
                    message=finding.get("message", "No message"),
                    line=finding.get("line", 1),
                    column=finding.get("column", 1),
                    code=finding.get("code", ""),
                    cwe_id=finding.get("cwe_id")  # Optional
                ))
        except json.JSONDecodeError:
            pass

        return issues
```

### ScannerIssue Parameters

**Required:**
- `rule_id` - Unique rule identifier (e.g., "B101", "SEC001")
- `severity` - One of: `Severity.CRITICAL`, `Severity.HIGH`, `Severity.MEDIUM`, `Severity.LOW`, `Severity.INFO`
- `message` - Human-readable description

**Optional:**
- `line` - Line number (default: 1)
- `column` - Column number (default: 1)
- `code` - Code snippet
- `cwe_id` - CWE identifier (e.g., "CWE-79")

**DO NOT USE** (not in base class):
- ~~`file_path`~~ - Passed separately to ScannerResult
- ~~`snippet`~~ - Use `code` instead
- ~~`suggestion`~~ - Not supported
- ~~`cwe_url`~~ - Not supported

---

## Step 2: Register the Scanner

Edit `medusa/scanners/__init__.py`:

```python
# Add import at top with other imports
from medusa.scanners.<toolname>_scanner import <ToolName>Scanner

# Add to registry (in the registration section)
registry.register(<ToolName>Scanner())

# Add to __all__ list
__all__ = [
    # ... existing scanners ...
    "<ToolName>Scanner",
]
```

---

## Step 3: Add to Tool Mapper (base.py)

Edit `medusa/platform/installers/base.py`:

### 3a. Add to PYTHON_TOOLS or NPM_TOOLS (if applicable)

```python
# For pip-installable tools
PYTHON_TOOLS = {'ansible-lint', 'bandit', ..., '<toolname>'}

# For npm-installable tools
NPM_TOOLS = {'eslint', 'prettier', ..., '<toolname>'}
```

### 3b. Add to TOOL_PACKAGES dict

Add entry in alphabetical order:

```python
TOOL_PACKAGES = {
    # ... existing entries ...

    '<toolname>': {
        'pip': '<package-name>',      # PyPI package
        'npm': '<package-name>',      # npm package
        'apt': '<package-name>',      # Debian/Ubuntu
        'yum': '<package-name>',      # RHEL/CentOS
        'dnf': '<package-name>',      # Fedora
        'pacman': '<package-name>',   # Arch Linux
        'brew': '<package-name>',     # macOS Homebrew
        'winget': '<package-id>',     # Windows winget
        'choco': '<package-name>',    # Windows Chocolatey
        'manual': '<instructions>',   # Manual install instructions
    },

    # ... more entries ...
}
```

**Note:** Only include package managers where the tool is actually available.

---

## Step 4: Add Version Pin

Edit `medusa/tool-versions.lock`:

```toml
[tools.<category>]
# ... existing tools ...
<toolname> = "<version>"
```

Categories:
- `python` - Python/pip tools
- `javascript` - Node/npm tools
- `go` - Go tools
- `rust` - Rust/cargo tools
- `shell` - Shell script tools
- `docker` - Container tools
- `terraform` - IaC tools
- `kubernetes` - K8s tools
- `ai` - AI/LLM security tools
- `misc` - Other tools

To find the latest version:
```bash
# PyPI
pip index versions <package>

# npm
npm view <package> version

# GitHub
gh release list -R <owner>/<repo> -L 1
```

---

## Step 5: Test the Scanner

```bash
# Check scanner is registered
.venv/bin/medusa scanners | grep <toolname>

# Check tool availability
.venv/bin/medusa install --check | grep <toolname>

# Test scanning
.venv/bin/medusa scan /path/to/test/file.<ext> --scanner <toolname>
```

---

## Platform-Specific Notes

### Linux (Easy)

Most tools install cleanly via apt/yum/dnf/pacman or pip/npm.

```bash
# Debian/Ubuntu
sudo apt install <package>

# RHEL/CentOS
sudo yum install <package>

# Fedora
sudo dnf install <package>

# Arch
sudo pacman -S <package>

# pip (any distro)
pip install <package>
```

### macOS (Easy)

Homebrew handles most tools:

```bash
brew install <package>
```

For pip/npm tools, same as Linux.

### Windows (Complex)

Windows requires special handling. See [Windows Linter Guide](./WINDOWS_LINTER_GUIDE.md) for details.

**Quick summary:**
- Prefer `winget` over `choco` (built-in, no admin)
- pip/npm tools work but need PATH setup
- Some tools need PowerShell scripts
- Some tools simply don't work on Windows

---

## Checklist

Before submitting:

- [ ] Scanner wrapper created (`medusa/scanners/<name>_scanner.py`)
- [ ] Scanner registered in `__init__.py`
- [ ] Added to `PYTHON_TOOLS` or `NPM_TOOLS` if applicable
- [ ] Added to `TOOL_PACKAGES` with all available package managers
- [ ] Version pinned in `tool-versions.lock`
- [ ] Tested on Linux
- [ ] Tested `medusa scanners` shows the new scanner
- [ ] Tested `medusa install --check` shows install method

---

## Example: Adding a New AI Security Tool

Here's a real example adding `llm-guard`:

### 1. Create scanner
```python
# medusa/scanners/llm_guard_scanner.py
class LLMGuardScanner(BaseScanner):
    name = "llm-guard"
    tool_name = "llm-guard"
    # ... implementation
```

### 2. Register
```python
# medusa/scanners/__init__.py
from medusa.scanners.llm_guard_scanner import LLMGuardScanner
registry.register(LLMGuardScanner())
```

### 3. Add to base.py
```python
# PYTHON_TOOLS set
PYTHON_TOOLS = {..., 'llm-guard'}

# TOOL_PACKAGES dict
'llm-guard': {
    'pip': 'llm-guard',
},
```

### 4. Version pin
```toml
# tool-versions.lock
[tools.ai]
llm-guard = "0.3.16"
```

### 5. Test
```bash
medusa scanners --ai | grep llm-guard
medusa install --check | grep llm-guard
```
