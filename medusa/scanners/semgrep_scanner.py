#!/usr/bin/env python3
"""
MEDUSA Semgrep Scanner
Advanced SAST using Semgrep with security-focused rulesets

Performance design: Semgrep has ~1.5s startup overhead per invocation. Running it
once per file inside the worker pool creates O(N) startups. Instead, scan_project()
runs a single batch invocation against the project root before the Pool forks, caches
results by file path, and scan_file() returns from cache — zero extra subprocess cost.
"""

import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class SemgrepScanner(BaseScanner):
    """
    Static Application Security Testing using Semgrep

    Semgrep detects:
    - SQL injection
    - XSS vulnerabilities
    - Command injection
    - Path traversal
    - Insecure deserialization
    - SSRF vulnerabilities
    - Authentication/Authorization issues
    - Cryptographic weaknesses
    - And thousands more patterns across 30+ languages

    Uses the 'p/security-audit' ruleset by default for comprehensive coverage.

    Reference: https://semgrep.dev/
    """

    # Languages Semgrep supports well
    SUPPORTED_EXTENSIONS = [
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
        '.cs', '.c', '.cpp', '.h', '.hpp', '.rs', '.swift', '.kt', '.scala',
        '.lua', '.bash', '.sh', '.yaml', '.yml', '.json', '.tf', '.hcl'
    ]

    def __init__(self):
        super().__init__()
        # Populated by scan_project() before the worker Pool forks.
        # Keyed by str(absolute_file_path) → list of ScannerIssue.
        self._results_cache: Dict[str, List[ScannerIssue]] = {}
        self._cache_populated: bool = False

    def get_tool_name(self) -> str:
        return "semgrep"

    def get_file_extensions(self) -> List[str]:
        return self.SUPPORTED_EXTENSIONS

    def get_confidence_score(self, file_path: Path, content_head: str = None) -> int:
        """Semgrep has comprehensive rules - use high confidence for supported files."""
        if file_path.suffix in self.SUPPORTED_EXTENSIONS:
            return 75
        return 0

    # ------------------------------------------------------------------
    # Batch mode (called once in main process before Pool fork)
    # ------------------------------------------------------------------

    def scan_project(self, project_root: Path) -> None:
        """
        Run one Semgrep invocation against the entire project root.

        Results are stored in _results_cache keyed by absolute file path string.
        Called in the main process before multiprocessing.Pool() forks workers.
        Workers inherit the populated cache via copy-on-write fork semantics,
        so scan_file() becomes a zero-cost cache lookup per file.

        Args:
            project_root: Directory to scan (typically the repo root).
        """
        if not self.is_available():
            self._cache_populated = True  # mark done so scan_file doesn't retry
            return

        start = time.time()
        try:
            cmd = [
                str(self.tool_path),
                'scan',
                '--config', 'p/security-audit',
                '--json',
                '--quiet',
                '--no-git-ignore',
                str(project_root),
            ]
            result = self._run_command(cmd, timeout=600)

            if result.stdout.strip():
                data = json.loads(result.stdout)
                for finding in data.get('results', []):
                    file_path_str = finding.get('path', '')
                    if not file_path_str:
                        continue
                    # Semgrep may return relative paths — resolve to absolute
                    p = Path(file_path_str)
                    if not p.is_absolute():
                        p = project_root / p
                    abs_key = str(p.resolve())

                    issue = self._parse_finding(finding)
                    self._results_cache.setdefault(abs_key, []).append(issue)

            elapsed = time.time() - start
            total = sum(len(v) for v in self._results_cache.values())
            print(f"  Semgrep batch scan: {len(self._results_cache)} files, "
                  f"{total} findings in {elapsed:.1f}s")

        except (json.JSONDecodeError, Exception):
            # On any failure, leave cache empty — scan_file() will fall back
            # to per-file mode for any uncached file.
            pass

        self._cache_populated = True

    # ------------------------------------------------------------------
    # Per-file entry point (called by worker pool)
    # ------------------------------------------------------------------

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Return Semgrep findings for a single file.

        If scan_project() was called before the Pool forked, results come from
        the in-memory cache (zero subprocess cost). Otherwise falls back to a
        per-file subprocess invocation.
        """
        start_time = time.time()

        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"{self.tool_name} not installed"
            )

        # Fast path: batch scan already ran
        if self._cache_populated:
            abs_key = str(file_path.resolve())
            issues = self._results_cache.get(abs_key, [])
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True,
            )

        # Slow path: no batch scan (e.g., single-file scan mode)
        return self._scan_file_subprocess(file_path, start_time)

    def _scan_file_subprocess(self, file_path: Path, start_time: float) -> ScannerResult:
        """Per-file subprocess fallback (used when scan_project() was not called)."""
        issues = []
        try:
            cmd = [
                str(self.tool_path),
                'scan',
                '--config', 'p/security-audit',
                '--json',
                '--quiet',
                '--no-git-ignore',
                str(file_path),
            ]
            result = self._run_command(cmd, timeout=120)

            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    for finding in data.get('results', []):
                        issues.append(self._parse_finding(finding))
                except json.JSONDecodeError:
                    pass

            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True,
            )

        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"Scan failed: {e}",
            )

    # ------------------------------------------------------------------
    # Shared parsing helpers
    # ------------------------------------------------------------------

    def _parse_finding(self, finding: dict) -> ScannerIssue:
        """Parse a single Semgrep JSON finding into a ScannerIssue."""
        extra = finding.get('extra', {})
        check_id = finding.get('check_id', 'unknown')
        message = extra.get('message', 'Security issue detected')

        start_info = finding.get('start', {})
        line = start_info.get('line')
        col = start_info.get('col')

        code_lines = extra.get('lines', '')

        metadata = extra.get('metadata', {})
        cwe = metadata.get('cwe', [])
        cwe_id: Optional[int] = None
        cwe_link: Optional[str] = None
        if cwe and isinstance(cwe, list):
            cwe_str = cwe[0] if isinstance(cwe[0], str) else str(cwe[0])
            if 'CWE-' in cwe_str:
                try:
                    cwe_num = cwe_str.split('CWE-')[1].split(':')[0].split(' ')[0]
                    cwe_id = int(cwe_num)
                    cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                except (ValueError, IndexError):
                    pass

        return ScannerIssue(
            severity=self._map_severity(finding),
            message=message,
            line=line,
            column=col,
            code=code_lines[:200] if code_lines else None,
            rule_id=check_id,
            cwe_id=cwe_id,
            cwe_link=cwe_link,
        )

    def _map_severity(self, finding: dict) -> Severity:
        """Map Semgrep severity to MEDUSA severity."""
        extra = finding.get('extra', {})
        semgrep_severity = extra.get('severity', 'WARNING').upper()
        metadata = extra.get('metadata', {})
        owasp = metadata.get('owasp', [])

        severity_map = {
            'ERROR': Severity.CRITICAL,
            'WARNING': Severity.HIGH,
            'INFO': Severity.MEDIUM,
        }
        base_severity = severity_map.get(semgrep_severity, Severity.MEDIUM)

        # Boost to CRITICAL for top OWASP categories
        critical_owasp = ('A01', 'A02', 'A03')
        if any(isinstance(o, str) and o.startswith(critical_owasp) for o in owasp):
            if base_severity != Severity.CRITICAL:
                return Severity.CRITICAL

        return base_severity

    def get_install_instructions(self) -> str:
        return (
            "Install Semgrep:\n"
            "  pip install semgrep\n"
            "  OR brew install semgrep (macOS)\n"
            "  OR docker pull returntocorp/semgrep"
        )
