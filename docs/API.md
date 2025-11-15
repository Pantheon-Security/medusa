# 📚 MEDUSA API Reference

Developer reference for extending MEDUSA and programmatic usage.

---

## Overview

MEDUSA provides a modular architecture that makes it easy to:
- Add new language scanners
- Integrate MEDUSA into your tools
- Extend functionality with custom scanners
- Build on top of the scanning engine

---

## Table of Contents

1. [Core Modules](#core-modules)
2. [Scanner Architecture](#scanner-architecture)
3. [Creating Custom Scanners](#creating-custom-scanners)
4. [Configuration API](#configuration-api)
5. [Platform Detection](#platform-detection)
6. [Programmatic Usage](#programmatic-usage)
7. [Testing](#testing)

---

## Core Modules

### `medusa.core.parallel`

Parallel scanning engine with caching and multi-core support.

**Classes:**

#### `MedusaParallelScanner`

Main scanner class for parallel file scanning.

```python
from pathlib import Path
from medusa.core.parallel import MedusaParallelScanner

scanner = MedusaParallelScanner(
    project_root=Path("."),
    workers=6,
    use_cache=True,
    quick_mode=False
)

files = scanner.find_scannable_files()
results = scanner.scan_parallel(files)
scanner.generate_report(results, Path(".medusa/reports"))
```

**Parameters:**
- `project_root` (Path): Root directory to scan
- `workers` (int, optional): Number of parallel workers (default: auto-detect)
- `use_cache` (bool): Enable file caching (default: True)
- `quick_mode` (bool): Only scan changed files (default: False)

**Methods:**

##### `find_scannable_files() -> List[Path]`

Finds all files that can be scanned based on supported extensions and exclusions.

```python
files = scanner.find_scannable_files()
# Returns: [Path('app.py'), Path('script.sh'), ...]
```

##### `scan_file(file_path: Path) -> ScanResult`

Scans a single file using the appropriate scanner.

```python
from pathlib import Path

result = scanner.scan_file(Path("app.py"))
# Returns: ScanResult(file='app.py', scanner='bandit', issues=[...])
```

##### `scan_parallel(files: List[Path]) -> List[ScanResult]`

Scans multiple files in parallel using worker processes.

```python
files = [Path("app.py"), Path("test.py")]
results = scanner.scan_parallel(files)
```

##### `generate_report(results: List[ScanResult], output_dir: Path)`

Generates JSON and HTML reports from scan results.

```python
scanner.generate_report(results, Path(".medusa/reports"))
```

---

#### `MedusaCacheManager`

Manages file caching for incremental scans.

```python
from medusa.core.parallel import MedusaCacheManager

cache = MedusaCacheManager()

# Check if file changed
if cache.is_file_changed(Path("app.py")):
    # Scan file
    ...
    # Update cache
    cache.update_cache(Path("app.py"), issues_found=5)

# Save cache to disk
cache.save()
```

**Methods:**

##### `is_file_changed(file_path: Path) -> bool`

Checks if a file has changed since last scan (using hash).

##### `update_cache(file_path: Path, issues_found: int)`

Updates cache entry for a scanned file.

##### `clear()`

Clears all cache entries.

---

### `medusa.scanners`

Scanner registry and base classes.

#### `BaseScanner`

Abstract base class for all scanners.

```python
from pathlib import Path
from typing import List
from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity

class MyScanner(BaseScanner):
    def get_tool_name(self) -> str:
        return "mytool"

    def get_file_extensions(self) -> List[str]:
        return [".myext"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        # Run your scanner
        issues = []
        # ... scanning logic ...

        return ScannerResult(
            scanner_name="MyScanner",
            file_path=file_path,
            issues=issues,
            scan_time=0.5
        )
```

**Required Methods:**

##### `get_tool_name() -> str`

Returns the name of the underlying security tool.

##### `get_file_extensions() -> List[str]`

Returns list of file extensions this scanner handles.

##### `scan_file(file_path: Path) -> ScannerResult`

Scans a single file and returns results.

**Optional Methods:**

##### `is_available() -> bool`

Checks if the scanner tool is installed (uses `shutil.which()`).

##### `get_install_command() -> str`

Returns installation command for the tool.

---

#### `ScannerResult`

Dataclass representing scan results for a file.

```python
from dataclasses import dataclass
from pathlib import Path
from typing import List

@dataclass
class ScannerResult:
    scanner_name: str
    file_path: Path
    issues: List[ScannerIssue]
    scan_time: float
```

---

#### `ScannerIssue`

Dataclass representing a single security issue.

```python
from dataclasses import dataclass
from medusa.scanners.base import Severity

@dataclass
class ScannerIssue:
    severity: Severity
    message: str
    line: int
    column: int = 0
    code: str = ""
    cwe_id: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "message": self.message,
            "line": self.line,
            "column": self.column,
            "code": self.code,
            "cwe_id": self.cwe_id
        }
```

---

#### `Severity`

Enum for issue severity levels.

```python
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
```

---

#### `ScannerRegistry`

Global registry for all scanners.

```python
from medusa.scanners import registry

# Get all registered scanners
all_scanners = registry.get_all_scanners()

# Get scanner for specific file
scanner = registry.get_scanner_for_file(Path("app.py"))

# Register new scanner
registry.register(MyScanner())
```

**Methods:**

##### `register(scanner: BaseScanner)`

Registers a scanner with the registry.

##### `get_all_scanners() -> List[BaseScanner]`

Returns all registered scanners.

##### `get_scanner_for_file(file_path: Path) -> Optional[BaseScanner]`

Returns appropriate scanner for a file based on extension.

---

## Scanner Architecture

### Creating Custom Scanners

**Step 1: Create Scanner Class**

Create `medusa/scanners/my_scanner.py`:

```python
#!/usr/bin/env python3
"""
MEDUSA MyLanguage Scanner
Security scanner for MyLanguage files
"""

import json
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class MyLanguageScanner(BaseScanner):
    """Scanner for MyLanguage files using mylinter"""

    def get_tool_name(self) -> str:
        return "mylinter"

    def get_file_extensions(self) -> List[str]:
        return [".mylang", ".ml"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan MyLanguage file for security issues"""
        import time
        start_time = time.time()

        if not self.is_available():
            return ScannerResult(
                scanner_name="MyLanguageScanner",
                file_path=file_path,
                issues=[],
                scan_time=0
            )

        try:
            # Run the scanner tool
            result = subprocess.run(
                ["mylinter", "--format=json", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )

            issues = []

            # Parse JSON output
            if result.stdout:
                data = json.loads(result.stdout)

                for item in data.get("issues", []):
                    # Map severity
                    severity_map = {
                        "error": Severity.HIGH,
                        "warning": Severity.MEDIUM,
                        "info": Severity.LOW
                    }
                    severity = severity_map.get(
                        item.get("severity", "warning"),
                        Severity.MEDIUM
                    )

                    issues.append(ScannerIssue(
                        severity=severity,
                        message=item.get("message", "Unknown issue"),
                        line=item.get("line", 0),
                        column=item.get("column", 0),
                        code=item.get("code", ""),
                        cwe_id=item.get("cwe", "")
                    ))

            return ScannerResult(
                scanner_name="MyLanguageScanner",
                file_path=file_path,
                issues=issues,
                scan_time=time.time() - start_time
            )

        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError) as e:
            print(f"⚠️  Error scanning {file_path}: {e}")
            return ScannerResult(
                scanner_name="MyLanguageScanner",
                file_path=file_path,
                issues=[],
                scan_time=time.time() - start_time
            )
```

**Step 2: Register Scanner**

Add to `medusa/scanners/__init__.py`:

```python
from medusa.scanners.my_scanner import MyLanguageScanner

# ...

registry.register(MyLanguageScanner())
```

**Step 3: Add Tool Mapping**

Add to `medusa/platform/installers/base.py`:

```python
TOOL_PACKAGES = {
    # ...
    'mylinter': {
        'apt': 'mylinter',
        'brew': 'mylinter',
        'npm': 'mylinter',
        'manual': 'npm install -g mylinter',
    },
}
```

**Step 4: Test**

```python
from pathlib import Path
from medusa.scanners.my_scanner import MyLanguageScanner

scanner = MyLanguageScanner()
result = scanner.scan_file(Path("test.mylang"))
print(f"Found {len(result.issues)} issues")
```

---

## Configuration API

### `medusa.config`

Configuration file management.

#### `MedusaConfig`

Dataclass representing `.medusa.yml` configuration.

```python
from medusa.config import MedusaConfig

config = MedusaConfig(
    version="0.7.0",
    fail_on="high",
    workers=4,
    cache_enabled=True,
    exclude_paths=["node_modules/", "venv/"],
    exclude_files=["*.min.js"]
)
```

**Fields:**
- `version` (str): Config version
- `scanners_enabled` (List[str]): Enabled scanners
- `scanners_disabled` (List[str]): Disabled scanners
- `fail_on` (str): Severity threshold
- `exclude_paths` (List[str]): Excluded path patterns
- `exclude_files` (List[str]): Excluded file patterns
- `workers` (Optional[int]): Number of workers
- `cache_enabled` (bool): Enable caching
- `ide_*` (bool): IDE integration settings

---

#### `ConfigManager`

Manages loading and saving configuration files.

```python
from pathlib import Path
from medusa.config import ConfigManager

# Find config file (walks up directory tree)
config_path = ConfigManager.find_config()

# Load config
config = ConfigManager.load_config()

# Save config
ConfigManager.save_config(config, Path(".medusa.yml"))

# Create default config
ConfigManager.create_default_config(Path("."))
```

**Methods:**

##### `find_config(start_path: Path = None) -> Optional[Path]`

Finds `.medusa.yml` by walking up directory tree.

##### `load_config(config_path: Path = None) -> MedusaConfig`

Loads configuration from file (or returns defaults).

##### `save_config(config: MedusaConfig, config_path: Path) -> bool`

Saves configuration to YAML file.

---

## Platform Detection

### `medusa.platform.detector`

Platform and package manager detection.

#### `PlatformDetector`

Detects operating system, package managers, and environment.

```python
from medusa.platform.detector import PlatformDetector

detector = PlatformDetector()
info = detector.detect()

print(f"OS: {info.os_type}")  # OSType.LINUX
print(f"Package Manager: {info.primary_package_manager}")  # PackageManager.APT
print(f"Platform: {info.os_name}")  # Linux
print(f"Architecture: {info.architecture}")  # x86_64
```

**Methods:**

##### `detect() -> PlatformInfo`

Detects all platform information.

##### `get_install_command(package: str, pm: Optional[PackageManager] = None) -> str`

Gets installation command for a package.

---

### `medusa.platform.installers`

Tool installation system.

#### `BaseInstaller`

Base class for platform-specific installers.

```python
from medusa.platform.installers import get_installer

# Get installer for current platform
installer = get_installer()

# Install tool
success = installer.install_tool("bandit")

# Check if tool is installed
if installer.is_tool_installed("bandit"):
    print("✅ bandit installed")
```

**Methods:**

##### `install_tool(tool_name: str, yes: bool = False) -> bool`

Installs a security tool.

##### `is_tool_installed(tool_name: str) -> bool`

Checks if a tool is installed.

##### `get_install_command(tool_name: str) -> str`

Gets the installation command for a tool.

---

## Programmatic Usage

### Basic Scanning

```python
from pathlib import Path
from medusa.core.parallel import MedusaParallelScanner

def scan_project(project_path: str):
    scanner = MedusaParallelScanner(
        project_root=Path(project_path),
        workers=4,
        use_cache=True
    )

    files = scanner.find_scannable_files()
    print(f"Found {len(files)} files to scan")

    results = scanner.scan_parallel(files)

    # Count issues by severity
    critical = sum(1 for r in results for i in r.issues if i.severity.value == "CRITICAL")
    high = sum(1 for r in results for i in r.issues if i.severity.value == "HIGH")

    print(f"CRITICAL: {critical}, HIGH: {high}")

    return results

# Usage
results = scan_project("./my-project")
```

---

### Custom Reporting

```python
from pathlib import Path
from medusa.core.parallel import MedusaParallelScanner
import json

scanner = MedusaParallelScanner(project_root=Path("."))
files = scanner.find_scannable_files()
results = scanner.scan_parallel(files)

# Custom JSON report
report = {
    "files_scanned": len(results),
    "total_issues": sum(len(r.issues) for r in results),
    "by_severity": {},
    "by_file": []
}

for result in results:
    if result.issues:
        report["by_file"].append({
            "file": str(result.file_path),
            "scanner": result.scanner_name,
            "issues": [i.to_dict() for i in result.issues]
        })

with open("custom_report.json", "w") as f:
    json.dump(report, f, indent=2)
```

---

### Integration with CI/CD

```python
import sys
from pathlib import Path
from medusa.core.parallel import MedusaParallelScanner
from medusa.scanners.base import Severity

def ci_scan(fail_on: str = "HIGH") -> int:
    """
    Scan for CI/CD pipeline
    Returns: 0 if no issues above threshold, 1 otherwise
    """
    scanner = MedusaParallelScanner(
        project_root=Path("."),
        workers=4
    )

    files = scanner.find_scannable_files()
    results = scanner.scan_parallel(files)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    fail_index = severity_order.index(fail_on.upper())

    for result in results:
        for issue in result.issues:
            issue_index = severity_order.index(issue.severity.value)
            if issue_index <= fail_index:
                print(f"❌ {result.file_path}:{issue.line} [{issue.severity.value}] {issue.message}")
                return 1  # Fail build

    print("✅ No issues found above threshold")
    return 0  # Pass build

if __name__ == "__main__":
    sys.exit(ci_scan(fail_on="HIGH"))
```

---

## Testing

### Testing Custom Scanners

```python
# tests/test_my_scanner.py
import pytest
from pathlib import Path
from medusa.scanners.my_scanner import MyLanguageScanner

def test_scanner_detects_issues(tmp_path):
    # Create test file
    test_file = tmp_path / "test.mylang"
    test_file.write_text("bad code here")

    scanner = MyLanguageScanner()
    result = scanner.scan_file(test_file)

    assert len(result.issues) > 0
    assert result.scanner_name == "MyLanguageScanner"

def test_scanner_file_extensions():
    scanner = MyLanguageScanner()
    assert ".mylang" in scanner.get_file_extensions()

def test_scanner_availability():
    scanner = MyLanguageScanner()
    # Will be False if tool not installed
    is_available = scanner.is_available()
    assert isinstance(is_available, bool)
```

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# With coverage
pytest --cov=medusa --cov-report=html

# Open coverage report
open htmlcov/index.html
```

---

## Examples

### Example 1: Custom Severity Mapping

```python
from medusa.scanners.base import BaseScanner, Severity

class CustomScanner(BaseScanner):
    def map_severity(self, tool_severity: str) -> Severity:
        mapping = {
            "fatal": Severity.CRITICAL,
            "error": Severity.HIGH,
            "warning": Severity.MEDIUM,
            "note": Severity.LOW,
            "hint": Severity.INFO
        }
        return mapping.get(tool_severity.lower(), Severity.MEDIUM)
```

### Example 2: Filtering Results

```python
from pathlib import Path
from medusa.core.parallel import MedusaParallelScanner

scanner = MedusaParallelScanner(project_root=Path("."))
results = scanner.scan_parallel(scanner.find_scannable_files())

# Only CRITICAL and HIGH issues
critical_results = [
    r for r in results
    if any(i.severity.value in ["CRITICAL", "HIGH"] for i in r.issues)
]

print(f"Files with critical issues: {len(critical_results)}")
```

### Example 3: Progress Callback

```python
from pathlib import Path
from medusa.core.parallel import MedusaParallelScanner

def progress_callback(completed, total):
    percent = (completed / total) * 100
    print(f"Progress: {completed}/{total} ({percent:.1f}%)")

scanner = MedusaParallelScanner(project_root=Path("."))
files = scanner.find_scannable_files()

# Manual scanning with progress
results = []
for i, file in enumerate(files):
    result = scanner.scan_file(file)
    results.append(result)
    progress_callback(i + 1, len(files))
```

---

## Best Practices

### 1. Always Check Tool Availability

```python
if scanner.is_available():
    result = scanner.scan_file(file_path)
else:
    print(f"⚠️  {scanner.get_tool_name()} not installed")
```

### 2. Handle Exceptions Gracefully

```python
try:
    results = scanner.scan_parallel(files)
except Exception as e:
    print(f"❌ Scan failed: {e}")
    # Log error, send notification, etc.
```

### 3. Use Type Hints

```python
from typing import List
from pathlib import Path
from medusa.scanners.base import ScannerResult

def scan_files(files: List[Path]) -> List[ScannerResult]:
    """Scan list of files and return results"""
    ...
```

### 4. Cache Scanner Results

```python
from medusa.core.parallel import MedusaCacheManager

cache = MedusaCacheManager()
# Use cache to skip unchanged files
```

---

## API Versioning

MEDUSA follows Semantic Versioning (SemVer):

- **Major**: Breaking API changes
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes, backward compatible

Current API Version: **0.7.0**

---

**Last Updated**: 2025-11-15
**MEDUSA Version**: 0.7.0.0
**API Status**: Stable (v0.7.0)
