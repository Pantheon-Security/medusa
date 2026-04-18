#!/usr/bin/env python3
"""
MEDUSA Trivy Scanner
Container, IaC, and dependency vulnerability scanning using Trivy

Performance design: Trivy has significant startup overhead per invocation. Running it
once per file creates O(N) startups. scan_project() runs two batch invocations against
the project root (trivy fs + trivy config), caches results by file path, and scan_file()
returns from cache — zero extra subprocess cost.
"""

import json
import time
from pathlib import Path
from typing import Dict, List

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

    # Known package manifest filenames — only these get Trivy's fs scan.
    # Arbitrary .json data files are excluded to avoid wasted trivy invocations.
    KNOWN_MANIFESTS = frozenset([
        'package-lock.json', 'package.json', 'yarn.lock',
        'requirements.txt', 'poetry.lock', 'pyproject.toml',
        'gemfile.lock', 'cargo.toml', 'cargo.lock',
        'go.mod', 'go.sum', 'composer.lock', 'composer.json',
        'pnpm-lock.yaml', 'npm-shrinkwrap.json', 'bun.lockb',
        'pipfile', 'pipfile.lock', 'setup.cfg', 'setup.py',
    ])

    def __init__(self):
        super().__init__()
        # Populated by scan_project() before the worker Pool forks.
        # Keyed by str(absolute_file_path) → list of ScannerIssue.
        self._results_cache: Dict[str, List[ScannerIssue]] = {}
        self._cache_populated: bool = False

    def get_tool_name(self) -> str:
        return "trivy"

    def get_file_extensions(self) -> List[str]:
        return list(self.SUPPORTED_FILES.keys())

    def get_confidence_score(self, file_path: Path, content_head: str = None) -> int:
        """
        Trivy has high confidence for Dockerfiles, K8s manifests, and Terraform.
        Medium confidence for known package manifests.
        Returns 0 for generic JSON/text data files that aren't package manifests.
        """
        name_lower = file_path.name.lower()

        # High confidence for specific config files
        if name_lower in ['dockerfile', 'docker-compose.yml', 'docker-compose.yaml']:
            return 85
        if file_path.suffix in ['.tf', '.hcl']:
            return 85

        # Medium confidence for known package manifests only
        if name_lower in self.KNOWN_MANIFESTS:
            return 70

        # YAML: check for K8s/IaC markers in content
        if file_path.suffix in ['.yaml', '.yml']:
            if content_head and ('apiVersion:' in content_head or 'AWSTemplateFormatVersion' in content_head):
                return 65
            return 40

        # Generic .json, .txt, .toml: skip unless it's a known manifest
        # This prevents scanning large data files (enterprise-attack.json, etc.)
        if file_path.suffix in ['.json', '.txt', '.toml', '.lock', '.mod', '.sum']:
            return 0

        return 0

    def can_scan(self, file_path: Path) -> bool:
        """Check if Trivy can scan this file"""
        name_lower = file_path.name.lower()

        # Explicit matches
        if name_lower == 'dockerfile':
            return True
        if name_lower in self.KNOWN_MANIFESTS:
            return True
        if name_lower in ['docker-compose.yml', 'docker-compose.yaml']:
            return True

        # Extension matches for config files (IaC)
        if file_path.suffix.lower() in ['.tf', '.hcl', '.yaml', '.yml', '.template']:
            return True

        return False

    # ------------------------------------------------------------------
    # Batch mode (called once in main process before Pool fork)
    # ------------------------------------------------------------------

    def scan_project(self, project_root: Path) -> None:
        """
        Run Trivy batch scans against the entire project root.

        Runs two passes:
        - trivy fs: dependency/secret scanning (package manifests)
        - trivy config: IaC misconfiguration scanning (Dockerfile, K8s, Terraform)

        Results are stored in _results_cache keyed by absolute file path string.
        Called in the main process before multiprocessing.Pool() forks workers.
        Workers inherit the populated cache via copy-on-write fork semantics.
        """
        if not self.is_available():
            self._cache_populated = True
            return

        start = time.time()
        try:
            # Pass 1: filesystem scan (package manifests, secrets)
            cmd_fs = [
                str(self.tool_path), 'fs',
                '--format', 'json',
                '--quiet',
                '--scanners', 'vuln,secret,misconfig',
                str(project_root),
            ]
            result = self._run_command(cmd_fs, timeout=600)
            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    self._cache_trivy_results(data, project_root)
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

        try:
            # Pass 2: config/IaC scan (Dockerfile, K8s, Terraform)
            cmd_cfg = [
                str(self.tool_path), 'config',
                '--format', 'json',
                '--quiet',
                str(project_root),
            ]
            result = self._run_command(cmd_cfg, timeout=600)
            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    self._cache_trivy_results(data, project_root)
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

        elapsed = time.time() - start
        total = sum(len(v) for v in self._results_cache.values())
        print(f"  Trivy batch scan: {len(self._results_cache)} files, "
              f"{total} findings in {elapsed:.1f}s")

        self._cache_populated = True

    def _cache_trivy_results(self, data: dict, project_root: Path) -> None:
        """Parse Trivy JSON output and cache issues by absolute file path."""
        for result_block in data.get('Results', []):
            target = result_block.get('Target', '')
            if not target:
                continue
            # Trivy returns paths relative to the project root
            p = Path(target)
            if not p.is_absolute():
                p = project_root / p
            abs_key = str(p.resolve())

            issues = self._parse_results({'Results': [result_block]}, p)
            if issues:
                self._results_cache.setdefault(abs_key, []).extend(issues)

    # ------------------------------------------------------------------
    # Per-file entry point (called by worker pool)
    # ------------------------------------------------------------------

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Return Trivy findings for a single file.

        If scan_project() was called before the Pool forked, results come from
        the in-memory cache (zero subprocess cost). Otherwise falls back to a
        per-file/per-directory subprocess invocation.
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
        rejected = self._reject_if_dash_prefixed(file_path, start_time)
        if rejected is not None:
            return rejected
        issues = []
        try:
            scan_type = self._get_scan_type(file_path)

            if scan_type == 'config':
                cmd = [
                    str(self.tool_path), 'config',
                    '--format', 'json', '--quiet',
                    '--',
                    str(file_path)
                ]
            else:
                cmd = [
                    str(self.tool_path), 'fs',
                    '--format', 'json', '--quiet',
                    '--scanners', 'vuln,secret,misconfig',
                    '--',
                    str(file_path.parent)
                ]

            result = self._run_command(cmd, timeout=180)
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
                    message=message[:500],
                    rule_id=vuln_id,
                    cwe_id=cwe_id,
                    cwe_link=cwe_link
                ))

            # Misconfigurations
            for misconfig in result.get('Misconfigurations', []):
                severity = self._map_severity(misconfig.get('Severity', 'UNKNOWN'))

                avd_id = misconfig.get('AVDID', misconfig.get('ID', 'Unknown'))
                title = misconfig.get('Title', 'Misconfiguration detected')
                resolution = misconfig.get('Resolution', '')

                message = f"{avd_id}: {title}"
                if resolution:
                    message += f" - Fix: {resolution}"

                cause = misconfig.get('CauseMetadata', {})
                start_line = cause.get('StartLine')
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
                rule_id = secret.get('RuleID', 'SECRET')
                title = secret.get('Title', 'Secret detected')
                match = secret.get('Match', '')[:50]

                issues.append(ScannerIssue(
                    severity=Severity.CRITICAL,
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
