#!/usr/bin/env python3
"""
MEDUSA React2Shell Scanner (CVE-2025-55182 / CVE-2025-66478)

Detects vulnerable React Server Components and Next.js versions affected by
the critical React2Shell RCE vulnerability (CVSS 10.0).

References:
- https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
- https://nextjs.org/blog/CVE-2025-66478
- https://github.com/advisories/GHSA-x8fr-w8mr-r8g8
"""

import json
import re
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class React2ShellScanner(BaseScanner):
    """
    Scanner for CVE-2025-55182 (React2Shell) - Critical RCE in React Server Components

    This vulnerability allows unauthenticated remote code execution through
    insecure deserialization in the RSC "Flight" protocol.

    Checks:
    - package.json for vulnerable React/Next.js versions
    - package-lock.json, yarn.lock, pnpm-lock.yaml for transitive dependencies
    - Source files for React Server Components usage ("use server" directive)
    """

    # Vulnerable React versions (react-server-dom-* packages)
    VULNERABLE_REACT_VERSIONS = {
        "19.0.0", "19.1.0", "19.1.1", "19.2.0"
    }

    # Fixed React versions
    FIXED_REACT_VERSIONS = {
        "19.0.0": "19.0.1",
        "19.1.0": "19.1.2",
        "19.1.1": "19.1.2",
        "19.2.0": "19.2.1",
    }

    # Vulnerable Next.js version ranges
    VULNERABLE_NEXTJS_RANGES = [
        # (min_version, max_version, fixed_version)
        ("14.3.0-canary.77", "14.3.0-canary.87", "14.3.0-canary.88"),
        ("15.0.0", "15.0.4", "15.0.5"),
        ("15.1.0", "15.1.8", "15.1.9"),
        ("15.2.0", "15.2.5", "15.2.6"),
        ("15.3.0", "15.3.5", "15.3.6"),
        ("15.4.0", "15.4.7", "15.4.8"),
        ("15.5.0", "15.5.6", "15.5.7"),
        ("16.0.0", "16.0.6", "16.0.7"),
    ]

    # React Server Components packages to check
    RSC_PACKAGES = [
        "react-server-dom-webpack",
        "react-server-dom-parcel",
        "react-server-dom-turbopack",
    ]

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return ['.json', '.lock', '.yaml']

    def get_target_files(self) -> List[str]:
        return [
            'package.json',
            'package-lock.json',
            'yarn.lock',
            'pnpm-lock.yaml',
        ]

    def is_available(self) -> bool:
        return True

    def get_confidence_score(self, file_path: Path) -> int:
        """
        Return high confidence for package manifest files.
        This scanner specifically targets React/Next.js CVE detection.
        """
        if not self.can_scan(file_path):
            return 0

        name_lower = file_path.name.lower()

        # High confidence for package manifest files
        if name_lower == 'package.json':
            # Check if it contains React/Next.js dependencies
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if '"next"' in content or '"react"' in content:
                        return 95  # Very high - this is what we're looking for
                    if any(pkg in content for pkg in self.RSC_PACKAGES):
                        return 95
            except (OSError, IOError, UnicodeDecodeError):
                pass  # File read failed - return medium confidence below
            return 30  # Medium - it's a package.json but no React/Next

        # High confidence for lockfiles
        if name_lower in ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']:
            return 85

        return 0  # Not a target file

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan for React2Shell vulnerability (CVE-2025-55182)"""
        start_time = time.time()
        issues = []

        try:
            filename = file_path.name.lower()

            if filename == 'package.json':
                issues.extend(self._scan_package_json(file_path))
            elif filename == 'package-lock.json':
                issues.extend(self._scan_package_lock(file_path))
            elif filename == 'yarn.lock':
                issues.extend(self._scan_yarn_lock(file_path))
            elif filename == 'pnpm-lock.yaml':
                issues.extend(self._scan_pnpm_lock(file_path))

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

    def _scan_package_json(self, file_path: Path) -> List[ScannerIssue]:
        """Scan package.json for vulnerable dependencies"""
        issues = []

        with open(file_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return issues

        # Check all dependency sections
        dep_sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']

        for section in dep_sections:
            deps = data.get(section, {})

            # Check for Next.js
            if 'next' in deps:
                version = self._extract_version(deps['next'])
                if version and self._is_nextjs_vulnerable(version):
                    fixed = self._get_nextjs_fixed_version(version)
                    issues.append(ScannerIssue(
                        severity=Severity.CRITICAL,
                        message=f"CVE-2025-55182 (React2Shell): Next.js {version} is vulnerable to RCE. Upgrade to {fixed}. See: https://nextjs.org/blog/CVE-2025-66478",
                        line=None,
                        rule_id="react2shell-nextjs",
                    ))

            # Check for React
            if 'react' in deps:
                version = self._extract_version(deps['react'])
                if version and version in self.VULNERABLE_REACT_VERSIONS:
                    fixed = self.FIXED_REACT_VERSIONS.get(version, "19.2.1")
                    issues.append(ScannerIssue(
                        severity=Severity.CRITICAL,
                        message=f"CVE-2025-55182 (React2Shell): React {version} may be vulnerable if using Server Components. Upgrade to {fixed}. See: https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",
                        line=None,
                        rule_id="react2shell-react",
                    ))

            # Check for RSC packages directly
            for pkg in self.RSC_PACKAGES:
                if pkg in deps:
                    version = self._extract_version(deps[pkg])
                    if version and version in self.VULNERABLE_REACT_VERSIONS:
                        fixed = self.FIXED_REACT_VERSIONS.get(version, "19.2.1")
                        issues.append(ScannerIssue(
                            severity=Severity.CRITICAL,
                            message=f"CVE-2025-55182 (React2Shell): {pkg}@{version} is vulnerable to RCE. Upgrade to {fixed}",
                            line=None,
                            rule_id="react2shell-rsc",
                        ))

        return issues

    def _scan_package_lock(self, file_path: Path) -> List[ScannerIssue]:
        """Scan package-lock.json for vulnerable transitive dependencies"""
        issues = []

        with open(file_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return issues

        # Handle both lockfile v2/v3 format
        packages = data.get('packages', {})
        if not packages:
            # Fallback to v1 format
            packages = data.get('dependencies', {})

        for pkg_path, pkg_info in packages.items():
            pkg_name = pkg_path.split('node_modules/')[-1] if 'node_modules/' in pkg_path else pkg_path
            version = pkg_info.get('version', '')

            # Check Next.js
            if pkg_name == 'next' and self._is_nextjs_vulnerable(version):
                fixed = self._get_nextjs_fixed_version(version)
                issues.append(ScannerIssue(
                    severity=Severity.CRITICAL,
                    message=f"CVE-2025-55182 (React2Shell): Locked next@{version} is vulnerable. Upgrade to {fixed}",
                    line=None,
                    rule_id="react2shell-nextjs-lock",
                ))

            # Check RSC packages
            if pkg_name in self.RSC_PACKAGES and version in self.VULNERABLE_REACT_VERSIONS:
                fixed = self.FIXED_REACT_VERSIONS.get(version, "19.2.1")
                issues.append(ScannerIssue(
                    severity=Severity.CRITICAL,
                    message=f"CVE-2025-55182 (React2Shell): Locked {pkg_name}@{version} is vulnerable. Upgrade to {fixed}",
                    line=None,
                    rule_id="react2shell-rsc-lock",
                ))

        return issues

    def _scan_yarn_lock(self, file_path: Path) -> List[ScannerIssue]:
        """Scan yarn.lock for vulnerable dependencies"""
        issues = []

        with open(file_path, 'r') as f:
            content = f.read()

        # Parse yarn.lock format (simplified)
        # Look for patterns like: next@^15.0.0, next@15.0.4:
        #   version "15.0.4"

        # Next.js pattern
        nextjs_pattern = r'next@[^:]+:\s*\n\s*version\s+"([^"]+)"'
        for match in re.finditer(nextjs_pattern, content):
            version = match.group(1)
            if self._is_nextjs_vulnerable(version):
                fixed = self._get_nextjs_fixed_version(version)
                issues.append(ScannerIssue(
                    severity=Severity.CRITICAL,
                    message=f"CVE-2025-55182 (React2Shell): Locked next@{version} is vulnerable. Upgrade to {fixed}",
                    line=None,
                    rule_id="react2shell-nextjs-yarn",
                ))

        # RSC packages pattern
        for pkg in self.RSC_PACKAGES:
            pkg_pattern = rf'{re.escape(pkg)}@[^:]+:\s*\n\s*version\s+"([^"]+)"'
            for match in re.finditer(pkg_pattern, content):
                version = match.group(1)
                if version in self.VULNERABLE_REACT_VERSIONS:
                    fixed = self.FIXED_REACT_VERSIONS.get(version, "19.2.1")
                    issues.append(ScannerIssue(
                        severity=Severity.CRITICAL,
                        message=f"CVE-2025-55182 (React2Shell): Locked {pkg}@{version} is vulnerable. Upgrade to {fixed}",
                        line=None,
                        rule_id="react2shell-rsc-yarn",
                    ))

        return issues

    def _scan_pnpm_lock(self, file_path: Path) -> List[ScannerIssue]:
        """Scan pnpm-lock.yaml for vulnerable dependencies"""
        issues = []

        try:
            import yaml
        except ImportError:
            # Fall back to regex parsing if PyYAML not available
            return self._scan_pnpm_lock_regex(file_path)

        with open(file_path, 'r') as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError:
                return issues

        packages = data.get('packages', {})

        for pkg_spec, pkg_info in packages.items():
            # pnpm format: /next@15.0.4 or next@15.0.4
            if '/next@' in pkg_spec or pkg_spec.startswith('next@'):
                version = pkg_spec.split('@')[-1]
                if self._is_nextjs_vulnerable(version):
                    fixed = self._get_nextjs_fixed_version(version)
                    issues.append(ScannerIssue(
                        severity=Severity.CRITICAL,
                        message=f"CVE-2025-55182 (React2Shell): Locked next@{version} is vulnerable. Upgrade to {fixed}",
                        line=None,
                        rule_id="react2shell-nextjs-pnpm",
                    ))

            for pkg in self.RSC_PACKAGES:
                if f'/{pkg}@' in pkg_spec or pkg_spec.startswith(f'{pkg}@'):
                    version = pkg_spec.split('@')[-1]
                    if version in self.VULNERABLE_REACT_VERSIONS:
                        fixed = self.FIXED_REACT_VERSIONS.get(version, "19.2.1")
                        issues.append(ScannerIssue(
                            severity=Severity.CRITICAL,
                            message=f"CVE-2025-55182 (React2Shell): Locked {pkg}@{version} is vulnerable. Upgrade to {fixed}",
                            line=None,
                            rule_id="react2shell-rsc-pnpm",
                        ))

        return issues

    def _scan_pnpm_lock_regex(self, file_path: Path) -> List[ScannerIssue]:
        """Fallback regex-based pnpm-lock.yaml scanner"""
        issues = []

        with open(file_path, 'r') as f:
            content = f.read()

        # Next.js pattern
        nextjs_pattern = r'/next@(\d+\.\d+\.\d+(?:-[a-z0-9.]+)?)'
        for match in re.finditer(nextjs_pattern, content):
            version = match.group(1)
            if self._is_nextjs_vulnerable(version):
                fixed = self._get_nextjs_fixed_version(version)
                issues.append(ScannerIssue(
                    severity=Severity.CRITICAL,
                    message=f"CVE-2025-55182 (React2Shell): Locked next@{version} is vulnerable. Upgrade to {fixed}",
                    line=None,
                    rule_id="react2shell-nextjs-pnpm",
                ))

        return issues

    def _extract_version(self, version_spec: str) -> Optional[str]:
        """Extract concrete version from npm version specifier"""
        if not version_spec:
            return None

        # Remove common prefixes
        version = version_spec.strip()
        for prefix in ['^', '~', '>=', '>', '<=', '<', '=', 'v']:
            if version.startswith(prefix):
                version = version[len(prefix):]

        # Handle ranges - take the first version
        if ' ' in version:
            version = version.split()[0]

        # Validate it looks like a version
        if re.match(r'^\d+\.\d+\.\d+', version):
            return version

        return None

    def _is_nextjs_vulnerable(self, version: str) -> bool:
        """Check if Next.js version is vulnerable"""
        if not version:
            return False

        for min_ver, max_ver, _ in self.VULNERABLE_NEXTJS_RANGES:
            if self._version_in_range(version, min_ver, max_ver):
                return True

        return False

    def _get_nextjs_fixed_version(self, version: str) -> str:
        """Get the fixed version for a vulnerable Next.js version"""
        for min_ver, max_ver, fixed in self.VULNERABLE_NEXTJS_RANGES:
            if self._version_in_range(version, min_ver, max_ver):
                return fixed
        return "16.0.7"

    def _version_in_range(self, version: str, min_ver: str, max_ver: str) -> bool:
        """Check if version is within range (inclusive)"""
        try:
            v = self._parse_version(version)
            v_min = self._parse_version(min_ver)
            v_max = self._parse_version(max_ver)

            return v_min <= v <= v_max
        except (ValueError, TypeError):
            return False

    def _parse_version(self, version: str) -> Tuple:
        """Parse version string into comparable tuple"""
        # Handle canary versions: 14.3.0-canary.77
        if '-' in version:
            main, prerelease = version.split('-', 1)
            main_parts = [int(x) for x in main.split('.')]

            # Extract number from prerelease if present
            pre_match = re.search(r'(\d+)$', prerelease)
            pre_num = int(pre_match.group(1)) if pre_match else 0

            # Prerelease versions sort before release
            return (*main_parts, 0, pre_num)
        else:
            parts = [int(x) for x in version.split('.')]
            # Release versions sort after prereleases
            return (*parts, 1, 0)

    def get_install_instructions(self) -> str:
        return "React2Shell scanning is built-in (no additional tools required)"
