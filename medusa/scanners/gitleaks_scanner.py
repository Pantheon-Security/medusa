#!/usr/bin/env python3
"""
MEDUSA GitLeaks Scanner
Detects secrets, API keys, and credentials in code using GitLeaks

Performance design: GitLeaks has ~20ms startup overhead per invocation. Running it
once per file creates O(N) startups. scan_project() runs a single batch invocation
against the project root, caches results by file path, and scan_file() returns from
cache — zero extra subprocess cost.
"""

import json
import time
from pathlib import Path
from typing import Dict, List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class GitLeaksScanner(BaseScanner):
    """
    Secret detection scanner using GitLeaks

    GitLeaks finds:
    - API keys (AWS, GCP, Azure, GitHub, etc.)
    - Private keys (SSH, PGP, etc.)
    - Database credentials
    - OAuth tokens
    - JWT secrets
    - Generic passwords and secrets
    - And 100+ more secret patterns

    Reference: https://github.com/gitleaks/gitleaks
    """

    # File extensions that commonly contain secrets
    SECRET_EXTENSIONS = [
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
        '.cs', '.cpp', '.c', '.h', '.rs', '.swift', '.kt', '.scala',
        '.yml', '.yaml', '.json', '.toml', '.xml', '.ini', '.cfg', '.conf',
        '.env', '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
        '.tf', '.hcl', '.dockerfile', '.sql', '.md', '.txt'
    ]

    def __init__(self):
        super().__init__()
        # Populated by scan_project() before the worker Pool forks.
        # Keyed by str(absolute_file_path) → list of ScannerIssue.
        self._results_cache: Dict[str, List[ScannerIssue]] = {}
        self._cache_populated: bool = False

    def get_tool_name(self) -> str:
        return "gitleaks"

    def get_file_extensions(self) -> List[str]:
        return self.SECRET_EXTENSIONS

    def get_confidence_score(self, file_path: Path, content_head: str = None) -> int:
        """
        GitLeaks should scan most files but with medium confidence
        to allow language-specific scanners to take priority for their specialty.
        """
        if file_path.suffix in self.SECRET_EXTENSIONS:
            return 30
        return 0

    # ------------------------------------------------------------------
    # Batch mode (called once in main process before Pool fork)
    # ------------------------------------------------------------------

    def scan_project(self, project_root: Path) -> None:
        """
        Run one GitLeaks invocation against the entire project root.

        Results are stored in _results_cache keyed by absolute file path string.
        Called in the main process before multiprocessing.Pool() forks workers.
        Workers inherit the populated cache via copy-on-write fork semantics,
        so scan_file() becomes a zero-cost cache lookup per file.
        """
        if not self.is_available():
            self._cache_populated = True
            return

        start = time.time()
        try:
            cmd = [
                str(self.tool_path),
                'detect',
                '--source', str(project_root),
                '--report-format', 'json',
                '--report-path', '/dev/stdout',
                '--no-git',
                '--exit-code', '0',
            ]
            result = self._run_command(cmd, timeout=300)

            if result.stdout.strip():
                try:
                    findings = json.loads(result.stdout)
                    if isinstance(findings, list):
                        for finding in findings:
                            # GitLeaks returns relative paths from the source dir
                            file_rel = finding.get('File', '')
                            if not file_rel:
                                continue
                            p = Path(file_rel)
                            if not p.is_absolute():
                                p = project_root / p
                            abs_key = str(p.resolve())

                            issue = self._parse_finding(finding)
                            self._results_cache.setdefault(abs_key, []).append(issue)
                except json.JSONDecodeError:
                    pass

            elapsed = time.time() - start
            total = sum(len(v) for v in self._results_cache.values())
            print(f"  GitLeaks batch scan: {len(self._results_cache)} files, "
                  f"{total} findings in {elapsed:.1f}s")

        except Exception:
            pass

        self._cache_populated = True

    # ------------------------------------------------------------------
    # Per-file entry point (called by worker pool)
    # ------------------------------------------------------------------

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Return GitLeaks findings for a single file.

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
        # Defense-in-depth: refuse dash-prefixed filenames (argv injection).
        # GitLeaks uses '--source <value>' form (no trailing positional), so it
        # is safe-by-construction from the '--config=...' filename attack, but
        # a value like '-' or '--version' passed to --source would still be
        # interpreted as a flag by some versions. Rejecting is cheap insurance.
        rejected = self._reject_if_dash_prefixed(file_path, start_time)
        if rejected is not None:
            return rejected
        issues = []
        try:
            cmd = [
                str(self.tool_path),
                'detect',
                '--source', str(file_path),
                '--report-format', 'json',
                '--report-path', '/dev/stdout',
                '--no-git',
                '--exit-code', '0'
            ]
            result = self._run_command(cmd, timeout=60)

            if result.stdout.strip():
                try:
                    findings = json.loads(result.stdout)
                    if isinstance(findings, list):
                        for finding in findings:
                            issues.append(self._parse_finding(finding))
                except json.JSONDecodeError:
                    pass

            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True
            )

        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"Scan failed: {e}"
            )

    # ------------------------------------------------------------------
    # Shared parsing helpers
    # ------------------------------------------------------------------

    def _parse_finding(self, finding: dict) -> ScannerIssue:
        """Parse a single GitLeaks finding into a ScannerIssue."""
        rule_id = finding.get('RuleID', 'unknown')
        description = finding.get('Description', 'Secret detected')
        match = finding.get('Match', '')[:50]

        return ScannerIssue(
            severity=self._map_severity(finding),
            message=f"{description}: {rule_id}",
            line=finding.get('StartLine'),
            code=f"...{match}..." if match else None,
            rule_id=f"GL-{rule_id}",
            cwe_id=798,
            cwe_link="https://cwe.mitre.org/data/definitions/798.html"
        )

    def _map_severity(self, finding: dict) -> Severity:
        """
        Map GitLeaks finding to MEDUSA severity.
        All secret leaks are considered at least HIGH severity.
        """
        rule_id = finding.get('RuleID', '').lower()

        critical_patterns = [
            'aws', 'gcp', 'azure', 'private-key', 'ssh-key',
            'pgp', 'rsa', 'stripe', 'twilio', 'sendgrid'
        ]
        for pattern in critical_patterns:
            if pattern in rule_id:
                return Severity.CRITICAL

        high_patterns = [
            'api-key', 'token', 'password', 'secret', 'credential',
            'github', 'gitlab', 'npm', 'pypi', 'docker'
        ]
        for pattern in high_patterns:
            if pattern in rule_id:
                return Severity.HIGH

        return Severity.HIGH

    def get_install_instructions(self) -> str:
        return (
            "Install GitLeaks:\n"
            "  macOS: brew install gitleaks\n"
            "  Linux: Download from https://github.com/gitleaks/gitleaks/releases\n"
            "  Windows: choco install gitleaks OR scoop install gitleaks"
        )
