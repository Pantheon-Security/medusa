#!/usr/bin/env python3
"""
MEDUSA PHP Scanner

Native pattern-based PHP security scanning (works out-of-box, no toolchain
required) via the `php_security` rule category, plus OPTIONAL PHPStan enrichment
when PHPStan is installed. PHPStan alone is a type/quality analyzer — the native
YAML rules are what detect security issues (SQLi, command injection, LFI/RFI,
unserialize, reflected XSS, SSRF, weak crypto, hardcoded secrets).
"""

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class PHPScanner(RuleBasedScanner):
    """Security scanner for PHP (.php) files.

    Native rules (medusa/rules/php_security/) always run. PHPStan is layered on
    top only when it is installed.
    """

    RULE_CATEGORIES = ['php_security']
    RULE_ID_PREFIXES = ['MEDUSA-PHP-']

    def get_tool_name(self) -> str:
        # Used only for the optional PHPStan branch; is_available() is inherited
        # from RuleBasedScanner (always True) so native rules run regardless.
        return "phpstan"

    def get_file_extensions(self) -> List[str]:
        return [".php"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan a PHP file: native security rules + optional PHPStan enrichment."""
        start_time = time.time()
        issues: List[ScannerIssue] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.split("\n")

            # (a) Native security rules — always, no external tool needed.
            issues.extend(self._scan_with_rules(lines, file_path))

            # (b) Optional PHPStan enrichment — only when phpstan is available.
            if shutil.which("phpstan"):
                issues.extend(self._run_phpstan(file_path))

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
    # Optional PHPStan enrichment
    # ------------------------------------------------------------------

    def _run_phpstan(self, file_path: Path) -> List[ScannerIssue]:
        """Run PHPStan and return issues. Returns [] (never raises) on any error —
        PHPStan is best-effort enrichment, not a hard dependency."""
        issues: List[ScannerIssue] = []
        try:
            result = self._run_command(
                ["phpstan", "analyse", "--error-format=json", "--no-progress",
                 "--level=max", str(file_path)],
                timeout=30,
            )
            if result.returncode not in (0, 1):
                return []
            data = json.loads(result.stdout)
            for file_data in data.get("files", {}).values():
                for message in file_data.get("messages", []):
                    issues.append(ScannerIssue(
                        line=message.get("line", 0),
                        column=0,
                        severity=self._determine_severity(message.get("message", "")),
                        code="phpstan",
                        message=message.get("message", "Unknown issue"),
                        rule_url="https://phpstan.org/user-guide/rule-levels",
                    ))
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            return issues
        return issues

    def _determine_severity(self, message: str) -> Severity:
        """Determine severity based on PHPStan message content."""
        m = message.lower()
        if any(w in m for w in ['sql injection', 'xss', 'csrf', 'security', 'unsafe']):
            return Severity.CRITICAL
        if any(w in m for w in ['undefined', 'null', 'type mismatch', 'incompatible']):
            return Severity.HIGH
        if any(w in m for w in ['unused', 'deprecated', 'unreachable']):
            return Severity.MEDIUM
        return Severity.LOW
