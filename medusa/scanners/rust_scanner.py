#!/usr/bin/env python3
"""
MEDUSA Rust Scanner

Native pattern-based Rust security scanning (works out-of-box, no toolchain
required) via the `rust_security` rule category, plus OPTIONAL `cargo clippy`
enrichment when a Rust toolchain is present. Clippy alone only surfaces style/
correctness lints — the native YAML rules are what detect security issues
(TLS-off, command injection, untrusted deserialization, raw SQL, unsafe memory
ops, weak crypto, SSRF).
"""

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class RustScanner(RuleBasedScanner):
    """Security scanner for Rust (.rs) files.

    Native rules (medusa/rules/rust_security/) always run. `cargo clippy` is
    layered on top only when cargo is installed and a Cargo project is found.
    """

    RULE_CATEGORIES = ['rust_security']
    RULE_ID_PREFIXES = ['MEDUSA-RUST-']

    def get_tool_name(self) -> str:
        # Used only for tool_path discovery by the optional clippy branch;
        # is_available() is inherited from RuleBasedScanner (always True), so the
        # native rules run regardless of whether cargo is installed.
        return "cargo"

    def get_file_extensions(self) -> List[str]:
        return [".rs"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan a Rust file: native security rules + optional clippy enrichment."""
        start_time = time.time()
        issues: List[ScannerIssue] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.split("\n")

            # (a) Native security rules — always, no external tool needed.
            issues.extend(self._scan_with_rules(lines, file_path))

            # (b) Optional clippy enrichment — only when cargo is available.
            if shutil.which("cargo"):
                issues.extend(self._run_clippy(file_path))

            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=issues,
                scan_time=time.time() - start_time,
                success=True,
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"Scan failed: {e}",
            )

    # ------------------------------------------------------------------
    # Optional clippy enrichment
    # ------------------------------------------------------------------

    def _run_clippy(self, file_path: Path) -> List[ScannerIssue]:
        """Run `cargo clippy` for the enclosing Cargo project and return issues.

        Returns [] (never raises) when there is no Cargo.toml or clippy fails —
        clippy is best-effort enrichment, not a hard dependency.
        """
        cargo_dir = self._find_cargo_project(file_path)
        if not cargo_dir:
            return []

        issues: List[ScannerIssue] = []
        try:
            result = self._run_command(
                ["cargo", "clippy", "--message-format=json", "--", "-W", "clippy::all"],
                cwd=cargo_dir, timeout=60,
            )
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if data.get("reason") != "compiler-message":
                    continue
                message = data.get("message", {})
                spans = message.get("spans", [])
                if not spans:
                    continue
                primary_span = spans[0]
                if Path(primary_span.get("file_name", "")).resolve() != file_path.resolve():
                    continue
                issues.append(ScannerIssue(
                    line=primary_span.get("line_start", 0),
                    column=primary_span.get("column_start", 0),
                    severity=self._map_severity(message.get("level", "warning")),
                    code=message.get("code", {}).get("code", "clippy"),
                    message=message.get("message", "Unknown issue"),
                    rule_url="https://rust-lang.github.io/rust-clippy/master/index.html",
                ))
        except (subprocess.TimeoutExpired, Exception):
            return issues
        return issues

    def _find_cargo_project(self, file_path: Path) -> Path:
        """Find the Cargo.toml directory for this Rust file (walk up to root)."""
        current = file_path.parent
        while current != current.parent:
            if (current / "Cargo.toml").exists():
                return current
            current = current.parent
        return None

    def _map_severity(self, clippy_level: str) -> Severity:
        """Map Clippy severity to MEDUSA severity."""
        severity_map = {
            'error': Severity.CRITICAL,
            'warning': Severity.MEDIUM,
            'note': Severity.LOW,
            'help': Severity.INFO,
        }
        return severity_map.get(clippy_level.lower(), Severity.LOW)
