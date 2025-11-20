#!/usr/bin/env python3
"""
MEDUSA Rust Scanner
Security scanner for Rust files using Clippy
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class RustScanner(BaseScanner):
    """Scanner for Rust files using Clippy"""

    def get_tool_name(self) -> str:
        return "cargo-clippy"

    def get_file_extensions(self) -> List[str]:
        return [".rs"]

    def is_available(self) -> bool:
        """Check if Clippy is installed"""
        # Clippy comes with rustup
        return shutil.which("cargo") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a Rust file with Clippy"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="Cargo/Clippy not installed. Install Rust from: https://rustup.rs"
            )

        # Clippy works on projects, not individual files
        # Try to find Cargo.toml in parent directories
        cargo_dir = self._find_cargo_project(file_path)
        if not cargo_dir:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="No Cargo.toml found - Clippy requires a Cargo project"
            )

        try:
            # Run Clippy with JSON output
            result = self._run_command([str(self.tool_path), "clippy",
                    "--message-format=json",
                    "--",
                    "-W", "clippy::all"
                ],
                cwd=cargo_dir, timeout=60
            )

            issues = []

            # Parse JSON output (one JSON object per line)
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue

                try:
                    data = json.loads(line)

                    # Only process compiler messages
                    if data.get("reason") != "compiler-message":
                        continue

                    message = data.get("message", {})
                    spans = message.get("spans", [])

                    if not spans:
                        continue

                    # Get the primary span
                    primary_span = spans[0]
                    span_file = Path(primary_span.get("file_name", ""))

                    # Only include issues for the file we're scanning
                    if span_file.resolve() != file_path.resolve():
                        continue

                    issues.append(ScannerIssue(
                        line=primary_span.get("line_start", 0),
                        column=primary_span.get("column_start", 0),
                        severity=self._map_severity(message.get("level", "warning")),
                        code=message.get("code", {}).get("code", "clippy"),
                        message=message.get("message", "Unknown issue"),
                        rule_url=f"https://rust-lang.github.io/rust-clippy/master/index.html"
                    ))

                except json.JSONDecodeError:
                    continue

            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=issues,
                scan_time=time.time() - start_time, success=True
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="Clippy timed out"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _find_cargo_project(self, file_path: Path) -> Path:
        """Find the Cargo.toml directory for this Rust file"""
        current = file_path.parent

        while current != current.parent:  # Stop at root
            if (current / "Cargo.toml").exists():
                return current
            current = current.parent

        return None

    def _map_severity(self, clippy_level: str) -> Severity:
        """Map Clippy severity to MEDUSA severity"""
        severity_map = {
            'error': Severity.CRITICAL,
            'warning': Severity.MEDIUM,
            'note': Severity.LOW,
            'help': Severity.INFO,
        }
        return severity_map.get(clippy_level.lower(), Severity.LOW)
