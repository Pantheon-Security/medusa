#!/usr/bin/env python3
"""
MEDUSA Critical CVE Scanner

Detects known critical (CVSS 9.0+) vulnerabilities in dependency manifests
across major ecosystems: pip, npm, Maven, Go, Cargo, Ruby, PHP/Composer.

This scanner targets Tier 1 vulnerabilities - framework-level RCEs, auth
bypasses, and supply chain attacks that give external attackers shell access.

Includes React2Shell (CVE-2025-55182) and Next.js (CVE-2025-66478) detection
via the curated CVE database.

References:
- https://nvd.nist.gov/
- https://github.com/advisories
- https://osv.dev/
"""

import json
import re
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple

import yaml

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


# Ecosystem name mapping: YAML file uses these → scanner uses these
_ECOSYSTEM_MAP = {
    'pypi': 'pip',
    'npm': 'npm',
    'maven': 'maven',
    'go': 'go',
    'cargo': 'cargo',
    'gem': 'gem',
    'composer': 'composer',
    # 'system' entries are skipped (not detectable via dependency manifests)
}


def _load_cve_database() -> List[Dict]:
    """
    Load CVE database from rules/cve/*.yaml (v2.0 format).

    Also accepts v1.0 format files during transition — detected by presence
    of 'vulnerable_range' instead of 'affected[]'.

    v2.0: affected[].ranges[].introduced / fixed (fixed is exclusive, i.e. < fixed)
    v1.0: vulnerable_range.min / max (max is inclusive — legacy only)
    """
    rules_dir = Path(__file__).parent.parent / 'rules' / 'cve'

    yaml_files = sorted(rules_dir.glob('*.yaml')) + sorted(rules_dir.glob('*.yml'))
    if not yaml_files:
        return []

    # id → entry, so daily update files can overwrite full-export entries
    seen: Dict[str, Dict] = {}

    for yaml_path in yaml_files:
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except Exception:
            continue

        if not data or 'rules' not in data:
            continue

        schema_version = str(data.get('version', '1.0'))

        for rule in data['rules']:
            # Detect format by presence of v2.0 'affected' field
            if 'affected' in rule:
                entries = _parse_v2_rule(rule)
            else:
                entries = _parse_v1_rule(rule)

            for entry in entries:
                rule_id = entry['cve']
                # Empty affected signals retraction — remove from active set
                if entry.get('retracted'):
                    seen.pop(rule_id, None)
                else:
                    seen[rule_id] = entry

    return list(seen.values())


def _parse_v2_rule(rule: Dict) -> List[Dict]:
    """Parse a v2.0 rule (affected[].ranges[].introduced/fixed) into scanner entries."""
    entries = []

    cve_id = rule.get('id', '')
    name = rule.get('name', '')
    cvss = float(rule.get('cvss', 0))
    description = rule.get('description', '')
    cwe = rule.get('cwe', '')
    severity = rule.get('severity', 'HIGH')

    # Pick first ADVISORY reference URL, fall back to NVD
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    for ref in rule.get('references', []):
        if isinstance(ref, dict) and ref.get('type') == 'ADVISORY':
            url = ref.get('url', url)
            break

    affected = rule.get('affected', [])
    if not affected:
        # Retraction signal
        return [{'cve': cve_id, 'retracted': True}]

    for affected_entry in affected:
        ecosystem_raw = affected_entry.get('ecosystem', '')
        ecosystem = _ECOSYSTEM_MAP.get(ecosystem_raw)
        if not ecosystem:
            continue

        package_raw = affected_entry.get('package', '')
        ranges = affected_entry.get('ranges', [])
        if not ranges:
            continue

        # Normalise package name for Maven (group:artifact)
        group_id = ''
        if ecosystem == 'maven' and ':' in package_raw:
            parts = package_raw.split(':', 1)
            group_id = parts[0]
            package = parts[1]
        else:
            package = package_raw

        # One entry per range (handles multi-range vulns)
        for vrange in ranges:
            introduced_str = str(vrange.get('introduced', '0.0.0'))
            fixed_str = vrange.get('fixed')  # May be absent for unpatched

            introduced_v = _str_to_version_tuple(introduced_str)
            fixed_v = _str_to_version_tuple(str(fixed_str)) if fixed_str else None

            if not introduced_v:
                continue

            entry = {
                'cve': cve_id,
                'name': name,
                'cvss': cvss,
                'ecosystem': ecosystem,
                'packages': [package],
                'introduced_version': introduced_v,
                'fixed_version': fixed_v,  # None = unpatched
                'fixed': str(fixed_str) if fixed_str else 'No fix available',
                'description': description,
                'url': url,
                'cwe': cwe,
                'severity': severity,
                'format': 'v2',
            }
            if group_id:
                entry['group_id'] = group_id

            entries.append(entry)

    return entries


def _parse_v1_rule(rule: Dict) -> List[Dict]:
    """Parse a v1.0 rule (vulnerable_range.min/max, inclusive) into scanner entries."""
    ecosystem_raw = rule.get('ecosystem', '')
    ecosystem = _ECOSYSTEM_MAP.get(ecosystem_raw)
    if not ecosystem:
        return []

    packages_raw = rule.get('packages', [])
    vrange = rule.get('vulnerable_range', {})
    min_str = str(vrange.get('min', '0.0.0'))
    max_str = str(vrange.get('max', '0.0.0'))

    min_v = _str_to_version_tuple(min_str)
    max_v = _str_to_version_tuple(max_str)
    if not min_v or not max_v:
        return []

    group_id = ''
    packages = []
    if ecosystem == 'maven':
        for pkg in packages_raw:
            if ':' in str(pkg):
                parts = str(pkg).split(':', 1)
                group_id = parts[0]
                packages.append(parts[1])
            else:
                packages.append(str(pkg))
    else:
        packages = [str(p) for p in packages_raw]

    cve_id = rule.get('cve', rule.get('id', ''))
    url = rule.get('url', f"https://nvd.nist.gov/vuln/detail/{cve_id}")

    entry = {
        'cve': cve_id,
        'name': rule.get('name', ''),
        'cvss': float(rule.get('cvss', 0)),
        'ecosystem': ecosystem,
        'packages': packages,
        'introduced_version': min_v,
        'fixed_version': None,       # v1.0 max is inclusive, handled in _is_in_range
        'max_version_inclusive': max_v,  # v1.0 legacy field
        'fixed': str(rule.get('fixed', '')),
        'description': rule.get('description', ''),
        'url': url,
        'cwe': rule.get('cwe', ''),
        'severity': rule.get('severity', 'HIGH'),
        'format': 'v1',
    }
    if group_id:
        entry['group_id'] = group_id

    return [entry]


def _str_to_version_tuple(version_str: str) -> Optional[Tuple[int, ...]]:
    """Convert a version string like '2.14.1' to a tuple like (2, 14, 1)."""
    if not version_str:
        return None
    # Strip common prefixes
    version = str(version_str).strip()
    for prefix in ['v', '=']:
        if version.startswith(prefix):
            version = version[len(prefix):]
    # Strip pre-release suffixes for comparison
    version = re.sub(r'[-+].*$', '', version)
    # Handle special Maven versions like "2.0-beta9"
    version = re.sub(r'-[a-zA-Z].*$', '', version)
    parts = re.findall(r'\d+', version)
    if not parts:
        return (0, 0, 0)
    try:
        return tuple(int(p) for p in parts[:4])
    except (ValueError, TypeError):
        return None


class CriticalCVEScanner(BaseScanner):
    """
    Scanner for CVEs in dependency manifests (lockfile-based SCA).

    Loads CVE rules from medusa/rules/cve/*.yaml (v2.0 format).
    Also accepts v1.0 format files during migration.

    Supported ecosystems and lockfiles:
    - Python (pip): requirements.txt, pyproject.toml, Pipfile, Pipfile.lock,
                    poetry.lock, setup.py, setup.cfg
    - Java (Maven): pom.xml, build.gradle, build.gradle.kts
    - Go: go.mod, go.sum
    - Rust (Cargo): Cargo.toml, Cargo.lock
    - Ruby (gem): Gemfile, Gemfile.lock
    - PHP (Composer): composer.json, composer.lock
    - npm: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml

    Data source: CVEMiner v2.0 rules (rules/cve/*.yaml)
    """

    # Load CVE database from YAML at class level (once)
    CVE_DATABASE = _load_cve_database()

    # Dependency manifest files and their ecosystems
    MANIFEST_FILES = {
        # Python
        'requirements.txt': 'pip',
        'setup.py': 'pip',
        'setup.cfg': 'pip',
        'pyproject.toml': 'pip',
        'Pipfile': 'pip',
        'Pipfile.lock': 'pip',
        'poetry.lock': 'pip',
        # Java/Maven
        'pom.xml': 'maven',
        'build.gradle': 'maven',
        'build.gradle.kts': 'maven',
        # Go
        'go.mod': 'go',
        'go.sum': 'go',
        # Rust
        'Cargo.toml': 'cargo',
        'Cargo.lock': 'cargo',
        # Ruby
        'Gemfile': 'gem',
        'Gemfile.lock': 'gem',
        # PHP
        'composer.json': 'composer',
        'composer.lock': 'composer',
        # npm (includes React2Shell CVE-2025-55182 and Next.js CVE-2025-66478)
        'package.json': 'npm',
        'package-lock.json': 'npm',
        'yarn.lock': 'npm',
        'pnpm-lock.yaml': 'npm',
    }

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return [
            '.txt', '.py', '.cfg', '.toml', '.lock',
            '.xml', '.gradle', '.kts',
            '.mod', '.sum',
            '.json', '.yaml',
        ]

    def is_available(self) -> bool:
        return True

    def can_scan(self, file_path: Path) -> bool:
        return file_path.name in self.MANIFEST_FILES

    def get_confidence_score(self, file_path: Path, content_head: str = None) -> int:
        if file_path.name in self.MANIFEST_FILES:
            return 90
        return 0

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan dependency manifest for critical CVEs."""
        start_time = time.time()
        issues = []

        try:
            filename = file_path.name
            ecosystem = self.MANIFEST_FILES.get(filename)

            if not ecosystem:
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Get CVEs for this ecosystem
            ecosystem_cves = [c for c in self.CVE_DATABASE if c['ecosystem'] == ecosystem]
            if not ecosystem_cves:
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Parse dependencies from manifest
            deps = self._parse_dependencies(file_path, filename, ecosystem)

            # Check each dependency against CVE database
            for dep_name, dep_version in deps.items():
                for cve in ecosystem_cves:
                    if self._matches_package(dep_name, cve):
                        parsed = self._parse_version(dep_version)
                        if parsed and self._is_vulnerable(parsed, cve):
                            cwe_id = None
                            cwe_link = None
                            if cve.get('cwe'):
                                cwe_match = re.search(r'CWE-(\d+)', cve['cwe'])
                                if cwe_match:
                                    cwe_id = int(cwe_match.group(1))
                                    cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"

                            severity_str = cve.get('severity', 'CRITICAL')
                            severity = {
                                'CRITICAL': Severity.CRITICAL,
                                'HIGH': Severity.HIGH,
                                'MEDIUM': Severity.MEDIUM,
                                'LOW': Severity.LOW,
                            }.get(severity_str, Severity.HIGH)

                            fix_note = (
                                f"Upgrade to {cve['fixed']}+"
                                if cve['fixed'] and cve['fixed'] != 'No fix available'
                                else "No fix available — consider alternative package"
                            )

                            issues.append(ScannerIssue(
                                severity=severity,
                                message=(
                                    f"{cve['cve']} ({cve['name']}): {dep_name}@{dep_version} is vulnerable "
                                    f"(CVSS {cve['cvss']}). {cve['description']}. "
                                    f"{fix_note}. See: {cve['url']}"
                                ),
                                line=None,
                                rule_id=f"cve-{cve['cve'].lower()}",
                                cwe_id=cwe_id,
                                cwe_link=cwe_link,
                            ))

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

    # =================================================================
    # Dependency Parsing
    # =================================================================

    def _parse_dependencies(self, file_path: Path, filename: str, ecosystem: str) -> Dict[str, str]:
        """Parse dependency file and return {package_name: version} mapping."""
        parsers = {
            'requirements.txt': self._parse_requirements_txt,
            'setup.py': self._parse_setup_py,
            'setup.cfg': self._parse_setup_cfg,
            'pyproject.toml': self._parse_pyproject_toml,
            'Pipfile': self._parse_pipfile,
            'Pipfile.lock': self._parse_pipfile_lock,
            'poetry.lock': self._parse_poetry_lock,
            'pom.xml': self._parse_pom_xml,
            'build.gradle': self._parse_gradle,
            'build.gradle.kts': self._parse_gradle,
            'go.mod': self._parse_go_mod,
            'go.sum': self._parse_go_sum,
            'Cargo.toml': self._parse_cargo_toml,
            'Cargo.lock': self._parse_cargo_lock,
            'Gemfile': self._parse_gemfile,
            'Gemfile.lock': self._parse_gemfile_lock,
            'composer.json': self._parse_composer_json,
            'composer.lock': self._parse_composer_lock,
            'package.json': self._parse_package_json,
            'package-lock.json': self._parse_package_lock_json,
            'yarn.lock': self._parse_yarn_lock,
            'pnpm-lock.yaml': self._parse_pnpm_lock_yaml,
        }

        parser = parsers.get(filename)
        if parser:
            try:
                return parser(file_path)
            except Exception:
                return {}
        return {}

    def _parse_requirements_txt(self, file_path: Path) -> Dict[str, str]:
        """Parse requirements.txt: package==1.2.3 or package>=1.2.3"""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                # Match: package==1.2.3 or package>=1.2.3 or package~=1.2.3
                match = re.match(r'^([a-zA-Z0-9_.-]+)\s*[=~<>!]+\s*([0-9][0-9a-zA-Z.*-]*)', line)
                if match:
                    deps[match.group(1).lower()] = match.group(2)
        return deps

    def _parse_setup_py(self, file_path: Path) -> Dict[str, str]:
        """Parse setup.py install_requires via regex (no exec)."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # Find install_requires list
        requires_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if requires_match:
            for match in re.finditer(r'["\']([a-zA-Z0-9_.-]+)\s*[=~<>!]+\s*([0-9][0-9a-zA-Z.*-]*)', requires_match.group(1)):
                deps[match.group(1).lower()] = match.group(2)
        return deps

    def _parse_setup_cfg(self, file_path: Path) -> Dict[str, str]:
        """Parse setup.cfg [options] install_requires."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # Find install_requires section
        requires_match = re.search(r'install_requires\s*=\s*\n((?:\s+.+\n)*)', content)
        if requires_match:
            for line in requires_match.group(1).split('\n'):
                line = line.strip()
                match = re.match(r'([a-zA-Z0-9_.-]+)\s*[=~<>!]+\s*([0-9][0-9a-zA-Z.*-]*)', line)
                if match:
                    deps[match.group(1).lower()] = match.group(2)
        return deps

    def _parse_pyproject_toml(self, file_path: Path) -> Dict[str, str]:
        """Parse pyproject.toml dependencies via regex."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # PEP 621 [project] dependencies
        dep_section = re.search(r'\[project\].*?dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if dep_section:
            for match in re.finditer(r'["\']([a-zA-Z0-9_.-]+)\s*[=~<>!]+\s*([0-9][0-9a-zA-Z.*-]*)', dep_section.group(1)):
                deps[match.group(1).lower()] = match.group(2)
        # Poetry [tool.poetry.dependencies]
        poetry_section = re.search(r'\[tool\.poetry\.dependencies\](.*?)(?:\[|\Z)', content, re.DOTALL)
        if poetry_section:
            for match in re.finditer(r'^([a-zA-Z0-9_.-]+)\s*=\s*["\']([^"\']+)', poetry_section.group(1), re.MULTILINE):
                name = match.group(1).lower()
                if name != 'python':
                    version = re.sub(r'[\^~>=<]', '', match.group(2))
                    deps[name] = version
        return deps

    def _parse_pipfile(self, file_path: Path) -> Dict[str, str]:
        """Parse Pipfile [packages] section."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        packages_section = re.search(r'\[packages\](.*?)(?:\[|\Z)', content, re.DOTALL)
        if packages_section:
            for match in re.finditer(r'^([a-zA-Z0-9_.-]+)\s*=\s*["\']([^"\']+)', packages_section.group(1), re.MULTILINE):
                name = match.group(1).lower()
                version = re.sub(r'[=~<>!*]', '', match.group(2))
                if version:
                    deps[name] = version
        return deps

    def _parse_pipfile_lock(self, file_path: Path) -> Dict[str, str]:
        """Parse Pipfile.lock JSON."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        for section in ['default', 'develop']:
            for pkg, info in data.get(section, {}).items():
                version = info.get('version', '')
                if version.startswith('=='):
                    version = version[2:]
                deps[pkg.lower()] = version
        return deps

    def _parse_poetry_lock(self, file_path: Path) -> Dict[str, str]:
        """Parse poetry.lock via regex (TOML-like)."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # [[package]] blocks with name and version
        for block in re.finditer(r'\[\[package\]\](.*?)(?=\[\[package\]\]|\Z)', content, re.DOTALL):
            name_match = re.search(r'name\s*=\s*"([^"]+)"', block.group(1))
            version_match = re.search(r'version\s*=\s*"([^"]+)"', block.group(1))
            if name_match and version_match:
                deps[name_match.group(1).lower()] = version_match.group(1)
        return deps

    def _parse_pom_xml(self, file_path: Path) -> Dict[str, str]:
        """Parse pom.xml <dependency> elements via regex."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # Match <dependency> blocks
        dep_pattern = re.compile(
            r'<dependency>\s*'
            r'<groupId>([^<]+)</groupId>\s*'
            r'<artifactId>([^<]+)</artifactId>\s*'
            r'(?:<version>([^<]+)</version>)?',
            re.DOTALL,
        )
        for match in dep_pattern.finditer(content):
            group_id = match.group(1).strip()
            artifact_id = match.group(2).strip()
            version = match.group(3).strip() if match.group(3) else ''
            if version and not version.startswith('${'):
                # Store as "group:artifact" -> version
                deps[f"{group_id}:{artifact_id}"] = version
        return deps

    def _parse_gradle(self, file_path: Path) -> Dict[str, str]:
        """Parse build.gradle dependency declarations via regex."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # Match: implementation 'group:artifact:version'
        # or: implementation "group:artifact:version"
        for match in re.finditer(r"(?:implementation|api|compile|runtime|classpath)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]", content):
            group_id = match.group(1).strip()
            artifact_id = match.group(2).strip()
            version = match.group(3).strip()
            deps[f"{group_id}:{artifact_id}"] = version
        # Kotlin DSL: implementation("group:artifact:version")
        for match in re.finditer(r'(?:implementation|api|compile|runtime|classpath)\("([^:]+):([^:]+):([^")]+)"\)', content):
            group_id = match.group(1).strip()
            artifact_id = match.group(2).strip()
            version = match.group(3).strip()
            deps[f"{group_id}:{artifact_id}"] = version
        return deps

    def _parse_go_mod(self, file_path: Path) -> Dict[str, str]:
        """Parse go.mod require directives."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # Check go version directive for stdlib CVEs
        go_version_match = re.search(r'^go\s+(\d+\.\d+(?:\.\d+)?)', content, re.MULTILINE)
        if go_version_match:
            deps['stdlib'] = go_version_match.group(1)
        # Parse require block
        require_block = re.search(r'require\s*\((.*?)\)', content, re.DOTALL)
        if require_block:
            for match in re.finditer(r'(\S+)\s+v(\S+)', require_block.group(1)):
                module = match.group(1)
                version = match.group(2)
                deps[module] = version
        # Single-line requires
        for match in re.finditer(r'^require\s+(\S+)\s+v(\S+)', content, re.MULTILINE):
            deps[match.group(1)] = match.group(2)
        return deps

    def _parse_go_sum(self, file_path: Path) -> Dict[str, str]:
        """Parse go.sum entries."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    module = parts[0]
                    version = parts[1].lstrip('v').split('/')[0]
                    deps[module] = version
        return deps

    def _parse_cargo_toml(self, file_path: Path) -> Dict[str, str]:
        """Parse Cargo.toml [dependencies] section."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        dep_section = re.search(r'\[dependencies\](.*?)(?:\[|\Z)', content, re.DOTALL)
        if dep_section:
            for match in re.finditer(r'^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', dep_section.group(1), re.MULTILINE):
                deps[match.group(1)] = re.sub(r'[\^~>=<]', '', match.group(2))
            # Extended form: name = { version = "1.2.3" }
            for match in re.finditer(r'^([a-zA-Z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"', dep_section.group(1), re.MULTILINE):
                deps[match.group(1)] = re.sub(r'[\^~>=<]', '', match.group(2))
        return deps

    def _parse_cargo_lock(self, file_path: Path) -> Dict[str, str]:
        """Parse Cargo.lock [[package]] entries."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        for block in re.finditer(r'\[\[package\]\](.*?)(?=\[\[package\]\]|\Z)', content, re.DOTALL):
            name_match = re.search(r'name\s*=\s*"([^"]+)"', block.group(1))
            version_match = re.search(r'version\s*=\s*"([^"]+)"', block.group(1))
            if name_match and version_match:
                deps[name_match.group(1)] = version_match.group(1)
        return deps

    def _parse_gemfile(self, file_path: Path) -> Dict[str, str]:
        """Parse Gemfile gem declarations."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # gem 'name', '~> 1.0' or gem 'name', '>= 1.0'
                match = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", line)
                if match:
                    name = match.group(1)
                    version = match.group(2) or ''
                    version = re.sub(r'[~>=<]', '', version).strip()
                    if version:
                        deps[name] = version
        return deps

    def _parse_gemfile_lock(self, file_path: Path) -> Dict[str, str]:
        """Parse Gemfile.lock specs section."""
        deps = {}
        in_specs = False
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.strip() == 'specs:':
                    in_specs = True
                    continue
                if in_specs:
                    if line.strip() == '' or not line.startswith(' '):
                        in_specs = False
                        continue
                    # Match: "    name (version)"
                    match = re.match(r'^\s{4}(\S+)\s+\(([^)]+)\)', line)
                    if match:
                        deps[match.group(1)] = match.group(2)
        return deps

    def _parse_composer_json(self, file_path: Path) -> Dict[str, str]:
        """Parse composer.json require section."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        for section in ['require', 'require-dev']:
            for pkg, version in data.get(section, {}).items():
                version = re.sub(r'[\^~>=<|*]', '', version).strip()
                if version:
                    deps[pkg] = version
        return deps

    def _parse_composer_lock(self, file_path: Path) -> Dict[str, str]:
        """Parse composer.lock packages."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        for section in ['packages', 'packages-dev']:
            for pkg_info in data.get(section, []):
                name = pkg_info.get('name', '')
                version = pkg_info.get('version', '').lstrip('v')
                if name and version:
                    deps[name] = version
        return deps

    def _parse_package_json(self, file_path: Path) -> Dict[str, str]:
        """Parse package.json dependencies."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        for section in ['dependencies', 'devDependencies']:
            for pkg, version in data.get(section, {}).items():
                version = re.sub(r'[\^~>=<|*]', '', str(version)).strip()
                if version:
                    deps[pkg] = version
        return deps

    def _parse_package_lock_json(self, file_path: Path) -> Dict[str, str]:
        """Parse package-lock.json packages."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        # v2/v3 lockfile format
        for pkg_path, info in data.get('packages', {}).items():
            if not pkg_path:
                continue
            name = pkg_path.split('node_modules/')[-1]
            version = info.get('version', '')
            if name and version:
                deps[name] = version
        # v1 lockfile format
        for pkg, info in data.get('dependencies', {}).items():
            version = info.get('version', '')
            if version:
                deps[pkg] = version
        return deps

    def _parse_yarn_lock(self, file_path: Path) -> Dict[str, str]:
        """Parse yarn.lock entries."""
        deps = {}
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # Match: "package@^version": \n  version "1.2.3"
        # or: package@^version: \n  version "1.2.3"
        for match in re.finditer(
            r'^["\']?(@?[^@\s"\']+)@[^:\n]+["\']?:\s*\n\s+version\s+"([^"]+)"',
            content, re.MULTILINE
        ):
            deps[match.group(1)] = match.group(2)
        return deps

    def _parse_pnpm_lock_yaml(self, file_path: Path) -> Dict[str, str]:
        """Parse pnpm-lock.yaml packages."""
        deps = {}
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = yaml.safe_load(f)
            if not data or not isinstance(data, dict):
                return deps
            packages = data.get('packages', {})
            for pkg_spec in packages:
                # pnpm format: /package@version or package@version
                spec = str(pkg_spec).lstrip('/')
                if '@' in spec:
                    # Handle scoped packages: @scope/name@version
                    if spec.startswith('@'):
                        # @scope/name@version -> split on last @
                        at_idx = spec.rfind('@')
                        if at_idx > 0:
                            name = spec[:at_idx]
                            version = spec[at_idx + 1:]
                            deps[name] = version
                    else:
                        name, version = spec.split('@', 1)
                        deps[name] = version
        except Exception:
            pass
        return deps

    # =================================================================
    # Version Matching
    # =================================================================

    def _matches_package(self, dep_name: str, cve: Dict) -> bool:
        """Check if a dependency name matches a CVE entry."""
        dep_lower = dep_name.lower().replace('-', '_')

        # For Maven: match "group:artifact" against cve group_id + packages
        if cve['ecosystem'] == 'maven' and ':' in dep_name:
            group, artifact = dep_name.split(':', 1)
            group_match = cve.get('group_id', '') == group
            artifact_match = artifact in cve['packages']
            return group_match and artifact_match

        # For other ecosystems: match package name (normalized)
        for pkg in cve['packages']:
            if dep_lower == pkg.lower().replace('-', '_'):
                return True
        return False

    def _parse_version(self, version_str: str) -> Optional[Tuple[int, ...]]:
        """Parse a version string into a comparable tuple of ints."""
        return _str_to_version_tuple(version_str)

    def _is_vulnerable(self, version: Tuple[int, ...], cve: Dict) -> bool:
        """
        Check if an installed version is in a vulnerable range.

        v2.0: introduced (inclusive) <= version < fixed (exclusive)
              If fixed is absent, any version >= introduced is vulnerable.

        v1.0 legacy: min (inclusive) <= version <= max (inclusive)
        """
        if cve.get('format') == 'v1':
            return self._in_range_inclusive(
                version, cve['introduced_version'], cve['max_version_inclusive']
            )

        # v2.0
        introduced = cve['introduced_version']
        fixed = cve.get('fixed_version')  # None = unpatched

        max_len = max(len(version), len(introduced), len(fixed) if fixed else 0)
        v = version + (0,) * (max_len - len(version))
        v_intro = introduced + (0,) * (max_len - len(introduced))

        if v < v_intro:
            return False
        if fixed is None:
            return True  # No fix — all versions >= introduced are vulnerable
        v_fixed = fixed + (0,) * (max_len - len(fixed))
        return v < v_fixed  # Exclusive upper bound

    def _in_range_inclusive(
        self,
        version: Tuple[int, ...],
        min_version: Tuple[int, ...],
        max_version: Tuple[int, ...],
    ) -> bool:
        """v1.0 legacy: inclusive range [min, max]."""
        max_len = max(len(version), len(min_version), len(max_version))
        v = version + (0,) * (max_len - len(version))
        v_min = min_version + (0,) * (max_len - len(min_version))
        v_max = max_version + (0,) * (max_len - len(max_version))
        return v_min <= v <= v_max

    def get_install_instructions(self) -> str:
        return f"CVE scanning is built-in ({len(self.CVE_DATABASE)} rules loaded from rules/cve/, no additional tools required)"
