#!/usr/bin/env python3
"""
MEDUSA GitLeaks Scanner
Detects secrets, API keys, and credentials in code using GitLeaks
"""

import json
import tempfile
import time
from pathlib import Path
from typing import List

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
        '.tf', '.hcl', '.dockerfile', '.sql', '.md', '.txt',
        # Template and example files that often contain secrets
        '.template', '.tpl', '.example', '.sample', '.dist',
    ]

    # Filename patterns to scan (regardless of extension)
    SECRET_FILENAMES = [
        '.env', '.env.example', '.env.sample', '.env.local', '.env.development',
        '.env.production', '.env.test', 'env.template', '.envrc',
    ]

    def get_tool_name(self) -> str:
        return "gitleaks"

    def get_file_extensions(self) -> List[str]:
        return self.SECRET_EXTENSIONS

    def get_confidence_score(self, file_path: Path) -> int:
        """
        GitLeaks should scan most files but with medium confidence
        to allow language-specific scanners to take priority for their specialty.
        """
        # Check file extension
        if file_path.suffix in self.SECRET_EXTENSIONS:
            return 30
        # Check filename patterns (e.g., .env.example has no real extension)
        if file_path.name in self.SECRET_FILENAMES:
            return 40  # Higher confidence for env files
        # Check if filename contains common patterns
        name_lower = file_path.name.lower()
        if any(pattern in name_lower for pattern in ['.env', 'secret', 'credential', 'password']):
            return 35
        return 0

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Scan a single file for secrets using GitLeaks

        Args:
            file_path: Path to file to scan

        Returns:
            ScannerResult with secrets found
        """
        start_time = time.time()
        issues = []

        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"{self.tool_name} not installed"
            )

        try:
            # Use a temp file for JSON output (gitleaks can't write to /dev/stdout)
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                report_path = tmp.name

            try:
                # Run GitLeaks on single file with JSON output to temp file
                cmd = [
                    str(self.tool_path),
                    'detect',
                    '--source', str(file_path),
                    '--report-format', 'json',
                    '--report-path', report_path,
                    '--no-git',  # Don't require git repo
                    '--exit-code', '0'  # Don't fail on findings
                ]

                self._run_command(cmd, timeout=60)

                # Parse JSON output from temp file
                report_file = Path(report_path)
                if report_file.exists():
                    content = report_file.read_text().strip()
                    if content:
                        try:
                            findings = json.loads(content)
                            if isinstance(findings, list):
                                for finding in findings:
                                    severity = self._map_severity(finding)

                                    # Build descriptive message
                                    rule_id = finding.get('RuleID', 'unknown')
                                    description = finding.get('Description', 'Secret detected')
                                    match = finding.get('Match', '')[:50]  # Truncate match

                                    scanner_issue = ScannerIssue(
                                        severity=severity,
                                        message=f"{description}: {rule_id}",
                                        line=finding.get('StartLine'),
                                        code=f"...{match}..." if match else None,
                                        rule_id=f"GL-{rule_id}",
                                        cwe_id=798,  # CWE-798: Use of Hard-coded Credentials
                                        cwe_link="https://cwe.mitre.org/data/definitions/798.html"
                                    )
                                    issues.append(scanner_issue)
                        except json.JSONDecodeError:
                            # No findings or invalid JSON
                            pass
            finally:
                # Clean up temp file
                Path(report_path).unlink(missing_ok=True)

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

    def _map_severity(self, finding: dict) -> Severity:
        """
        Map GitLeaks finding to MEDUSA severity

        All secret leaks are considered at least HIGH severity.
        Certain patterns (AWS keys, private keys) are CRITICAL.
        """
        rule_id = finding.get('RuleID', '').lower()

        # Critical: Cloud provider keys, private keys
        critical_patterns = [
            'aws', 'gcp', 'azure', 'private-key', 'ssh-key',
            'pgp', 'rsa', 'stripe', 'twilio', 'sendgrid'
        ]
        for pattern in critical_patterns:
            if pattern in rule_id:
                return Severity.CRITICAL

        # High: API keys, tokens, passwords
        high_patterns = [
            'api-key', 'token', 'password', 'secret', 'credential',
            'github', 'gitlab', 'npm', 'pypi', 'docker'
        ]
        for pattern in high_patterns:
            if pattern in rule_id:
                return Severity.HIGH

        # Default to HIGH for any secret detection
        return Severity.HIGH

    def get_install_instructions(self) -> str:
        return (
            "Install GitLeaks:\n"
            "  macOS: brew install gitleaks\n"
            "  Linux: Download from https://github.com/gitleaks/gitleaks/releases\n"
            "  Windows: choco install gitleaks OR scoop install gitleaks"
        )
