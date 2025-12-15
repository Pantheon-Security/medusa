#!/usr/bin/env python3
"""
MEDUSA Trivy Scanner
Container, IaC, and dependency vulnerability scanning using Trivy
"""

import json
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class TrivyScanner(BaseScanner):
    """
    Comprehensive vulnerability scanner using Trivy

    Trivy detects:
    - Container image vulnerabilities
    - Dockerfile misconfigurations
    - Kubernetes manifest issues
    - Terraform misconfigurations
    - CloudFormation issues
    - Dependency vulnerabilities (package-lock.json, requirements.txt, etc.)
    - License compliance issues
    - Secret detection

    Reference: https://github.com/aquasecurity/trivy
    """

    # Files Trivy can scan for vulnerabilities and misconfigurations
    SUPPORTED_FILES = {
        # Dockerfiles
        '.dockerfile': 'config',
        'dockerfile': 'config',
        # Kubernetes
        '.yaml': 'config',
        '.yml': 'config',
        # Terraform
        '.tf': 'config',
        '.hcl': 'config',
        # CloudFormation
        '.template': 'config',
        # Package manifests (dependency scanning)
        '.json': 'fs',  # package-lock.json, composer.json
        '.lock': 'fs',  # Gemfile.lock, poetry.lock
        '.txt': 'fs',   # requirements.txt
        '.toml': 'fs',  # pyproject.toml, Cargo.toml
        '.mod': 'fs',   # go.mod
        '.sum': 'fs',   # go.sum
    }

    def get_tool_name(self) -> str:
        return "trivy"

    def get_file_extensions(self) -> List[str]:
        return list(self.SUPPORTED_FILES.keys())

    def get_confidence_score(self, file_path: Path) -> int:
        """
        Trivy has high confidence for Dockerfiles, K8s manifests, and Terraform.
        Medium confidence for package manifests.
        """
        name_lower = file_path.name.lower()

        # High confidence for specific files
        if name_lower in ['dockerfile', 'docker-compose.yml', 'docker-compose.yaml']:
            return 85
        if name_lower.endswith('.tf') or name_lower.endswith('.hcl'):
            return 85

        # Medium confidence for package manifests
        if name_lower in [
            'package-lock.json', 'package.json', 'yarn.lock',
            'requirements.txt', 'poetry.lock', 'pyproject.toml',
            'gemfile.lock', 'cargo.toml', 'cargo.lock',
            'go.mod', 'go.sum', 'composer.lock', 'composer.json'
        ]:
            return 70

        # Low confidence for generic YAML (could be K8s or not)
        if file_path.suffix in ['.yaml', '.yml']:
            return 40

        return 20

    def can_scan(self, file_path: Path) -> bool:
        """Check if Trivy can scan this file"""
        name_lower = file_path.name.lower()

        # Explicit matches
        if name_lower == 'dockerfile':
            return True
        if name_lower in [
            'package-lock.json', 'package.json', 'yarn.lock',
            'requirements.txt', 'poetry.lock', 'pyproject.toml',
            'gemfile.lock', 'cargo.toml', 'cargo.lock',
            'go.mod', 'go.sum', 'composer.lock', 'composer.json',
            'docker-compose.yml', 'docker-compose.yaml'
        ]:
            return True

        # Extension matches
        return file_path.suffix.lower() in self.SUPPORTED_FILES

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Scan a file using Trivy

        Args:
            file_path: Path to file to scan

        Returns:
            ScannerResult with vulnerabilities found
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
            # Determine scan type based on file
            scan_type = self._get_scan_type(file_path)

            # Build command based on scan type
            if scan_type == 'config':
                # Configuration scanning (Dockerfile, K8s, Terraform)
                cmd = [
                    str(self.tool_path),
                    'config',
                    '--format', 'json',
                    '--quiet',
                    str(file_path)
                ]
            else:
                # Filesystem scanning (dependencies)
                cmd = [
                    str(self.tool_path),
                    'fs',
                    '--format', 'json',
                    '--quiet',
                    '--scanners', 'vuln,secret,misconfig',
                    str(file_path.parent)  # Scan directory for fs mode
                ]

            result = self._run_command(cmd, timeout=180)

            # Parse JSON output
            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    issues.extend(self._parse_results(data, file_path))
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

    def _get_scan_type(self, file_path: Path) -> str:
        """Determine Trivy scan type based on file"""
        name_lower = file_path.name.lower()

        # Config scanning for IaC files
        if name_lower == 'dockerfile':
            return 'config'
        if file_path.suffix in ['.tf', '.hcl']:
            return 'config'
        if name_lower in ['docker-compose.yml', 'docker-compose.yaml']:
            return 'config'

        # Check YAML content for K8s markers
        if file_path.suffix in ['.yaml', '.yml']:
            try:
                content = file_path.read_text(errors='ignore')[:2000]
                if 'apiVersion:' in content and 'kind:' in content:
                    return 'config'
            except (OSError, IOError):
                pass

        return 'fs'

    def _parse_results(self, data: dict, file_path: Path) -> List[ScannerIssue]:
        """Parse Trivy JSON output into ScannerIssues"""
        issues = []

        # Handle 'Results' array (from fs/config scan)
        results = data.get('Results', [])
        for result in results:
            # Vulnerabilities
            for vuln in result.get('Vulnerabilities', []):
                severity = self._map_severity(vuln.get('Severity', 'UNKNOWN'))

                vuln_id = vuln.get('VulnerabilityID', 'Unknown')
                pkg_name = vuln.get('PkgName', '')
                installed = vuln.get('InstalledVersion', '')
                fixed = vuln.get('FixedVersion', '')
                title = vuln.get('Title', vuln.get('Description', 'Vulnerability detected'))

                message = f"{vuln_id}: {title}"
                if pkg_name:
                    message = f"{pkg_name}@{installed} - {message}"
                if fixed:
                    message += f" (fix: {fixed})"

                # Extract CWE
                cwe_ids = vuln.get('CweIDs', [])
                cwe_id = None
                cwe_link = None
                if cwe_ids:
                    try:
                        cwe_str = cwe_ids[0].replace('CWE-', '')
                        cwe_id = int(cwe_str)
                        cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                    except (ValueError, IndexError):
                        pass

                issues.append(ScannerIssue(
                    severity=severity,
                    message=message[:500],  # Truncate long messages
                    rule_id=vuln_id,
                    cwe_id=cwe_id,
                    cwe_link=cwe_link
                ))

            # Misconfigurations
            for misconfig in result.get('Misconfigurations', []):
                severity = self._map_severity(misconfig.get('Severity', 'UNKNOWN'))

                avd_id = misconfig.get('AVDID', misconfig.get('ID', 'Unknown'))
                title = misconfig.get('Title', 'Misconfiguration detected')
                description = misconfig.get('Description', '')
                resolution = misconfig.get('Resolution', '')

                message = f"{avd_id}: {title}"
                if resolution:
                    message += f" - Fix: {resolution}"

                # Get line numbers if available
                cause = misconfig.get('CauseMetadata', {})
                start_line = cause.get('StartLine')
                end_line = cause.get('EndLine')
                code = cause.get('Code', {}).get('Lines', [])
                code_snippet = '\n'.join([l.get('Content', '') for l in code[:3]]) if code else None

                issues.append(ScannerIssue(
                    severity=severity,
                    message=message[:500],
                    line=start_line,
                    code=code_snippet[:200] if code_snippet else None,
                    rule_id=avd_id
                ))

            # Secrets
            for secret in result.get('Secrets', []):
                severity = Severity.CRITICAL  # Secrets are always critical

                rule_id = secret.get('RuleID', 'SECRET')
                title = secret.get('Title', 'Secret detected')
                match = secret.get('Match', '')[:50]  # Truncate

                issues.append(ScannerIssue(
                    severity=severity,
                    message=f"{title}: {rule_id}",
                    line=secret.get('StartLine'),
                    code=f"...{match}..." if match else None,
                    rule_id=f"TRIVY-{rule_id}",
                    cwe_id=798,
                    cwe_link="https://cwe.mitre.org/data/definitions/798.html"
                ))

        return issues

    def _map_severity(self, trivy_severity: str) -> Severity:
        """Map Trivy severity to MEDUSA severity"""
        severity_map = {
            'CRITICAL': Severity.CRITICAL,
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW,
            'UNKNOWN': Severity.INFO,
        }
        return severity_map.get(trivy_severity.upper(), Severity.MEDIUM)

    def get_install_instructions(self) -> str:
        return (
            "Install Trivy:\n"
            "  macOS: brew install trivy\n"
            "  Linux: See https://aquasecurity.github.io/trivy/latest/getting-started/installation/\n"
            "  Windows: choco install trivy OR scoop install trivy\n"
            "  Docker: docker pull aquasec/trivy"
        )
