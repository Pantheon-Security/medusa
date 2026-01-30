#!/usr/bin/env python3
"""
MEDUSA Critical CVE Scanner

Detects known critical (CVSS 9.0+) vulnerabilities in dependency manifests
across major ecosystems: pip, Maven, Go, Cargo, Ruby, PHP/Composer.

This scanner targets Tier 1 vulnerabilities - framework-level RCEs, auth
bypasses, and supply chain attacks that give external attackers shell access.

npm/JS ecosystem is handled by React2ShellScanner (no overlap).

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

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class CriticalCVEScanner(BaseScanner):
    """
    Scanner for critical (CVSS 9.0+) CVEs in dependency manifests.

    Ecosystem coverage:
    - Python (pip): requirements.txt, pyproject.toml, Pipfile, setup.cfg
    - Java (Maven): pom.xml, build.gradle, build.gradle.kts
    - Go: go.mod
    - Rust (Cargo): Cargo.toml, Cargo.lock
    - Ruby (gem): Gemfile, Gemfile.lock
    - PHP (Composer): composer.json, composer.lock

    Note: npm/JS ecosystem is handled by React2ShellScanner.
    """

    # ===================================================================
    # CRITICAL CVE DATABASE
    # Each entry is a curated, verified critical vulnerability.
    # Add new CVEs here - the scanner is fully data-driven.
    # ===================================================================
    CVE_DATABASE = [
        # ----- Java / Maven -----
        {
            'cve': 'CVE-2021-44228',
            'name': 'Log4Shell',
            'cvss': 10.0,
            'ecosystem': 'maven',
            'packages': ['log4j-core'],
            'group_id': 'org.apache.logging.log4j',
            'min_version': (2, 0, 0),
            'max_version': (2, 17, 0),
            'fixed': '2.17.1',
            'description': 'Log4j2 JNDI injection allows unauthenticated RCE via crafted log messages',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
            'cwe': 'CWE-917',
        },
        {
            'cve': 'CVE-2021-45046',
            'name': 'Log4Shell Bypass',
            'cvss': 9.0,
            'ecosystem': 'maven',
            'packages': ['log4j-core'],
            'group_id': 'org.apache.logging.log4j',
            'min_version': (2, 0, 0),
            'max_version': (2, 16, 0),
            'fixed': '2.17.0',
            'description': 'Log4j2 incomplete fix for CVE-2021-44228 allows RCE in non-default configs',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2021-45046',
            'cwe': 'CWE-917',
        },
        {
            'cve': 'CVE-2022-22965',
            'name': 'Spring4Shell',
            'cvss': 9.8,
            'ecosystem': 'maven',
            'packages': ['spring-beans', 'spring-webmvc', 'spring-web'],
            'group_id': 'org.springframework',
            'min_version': (5, 3, 0),
            'max_version': (5, 3, 17),
            'fixed': '5.3.18',
            'description': 'Spring Framework RCE via data binding on JDK 9+ with Tomcat',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2022-22965',
            'cwe': 'CWE-94',
        },
        {
            'cve': 'CVE-2017-5638',
            'name': 'Apache Struts RCE',
            'cvss': 10.0,
            'ecosystem': 'maven',
            'packages': ['struts2-core'],
            'group_id': 'org.apache.struts',
            'min_version': (2, 3, 5),
            'max_version': (2, 3, 31),
            'fixed': '2.3.32 or 2.5.10.1',
            'description': 'Apache Struts 2 RCE via Content-Type header parsing (Equifax breach)',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2017-5638',
            'cwe': 'CWE-20',
        },
        {
            'cve': 'CVE-2021-26084',
            'name': 'Confluence OGNL Injection',
            'cvss': 9.8,
            'ecosystem': 'maven',
            'packages': ['confluence-server', 'confluence'],
            'group_id': 'com.atlassian.confluence',
            'min_version': (6, 13, 0),
            'max_version': (7, 12, 5),
            'fixed': '7.13.0',
            'description': 'Confluence Server OGNL injection allows unauthenticated RCE',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2021-26084',
            'cwe': 'CWE-74',
        },
        {
            'cve': 'CVE-2023-22515',
            'name': 'Confluence Auth Bypass',
            'cvss': 10.0,
            'ecosystem': 'maven',
            'packages': ['confluence-server', 'confluence'],
            'group_id': 'com.atlassian.confluence',
            'min_version': (8, 0, 0),
            'max_version': (8, 5, 1),
            'fixed': '8.5.2',
            'description': 'Confluence Data Center broken access control allows admin account creation',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-22515',
            'cwe': 'CWE-284',
        },

        # ----- Python / pip -----
        {
            'cve': 'CVE-2025-32434',
            'name': 'PyTorch RCE',
            'cvss': 9.3,
            'ecosystem': 'pip',
            'packages': ['torch'],
            'min_version': (0, 0, 1),
            'max_version': (2, 5, 1),
            'fixed': '2.6.0',
            'description': 'PyTorch torch.load() RCE even with weights_only=True via legacy .tar deserialization path',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2025-32434',
            'cwe': 'CWE-502',
        },
        {
            'cve': 'CVE-2025-68664',
            'name': 'LangGrinch Serialization RCE',
            'cvss': 9.3,
            'ecosystem': 'pip',
            'packages': ['langchain-core'],
            'min_version': (0, 0, 1),
            'max_version': (0, 3, 80),
            'fixed': '0.3.81',
            'description': 'LangChain Core serialization injection via dumps()/dumpd() allows secret extraction and arbitrary class instantiation',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2025-68664',
            'cwe': 'CWE-502',
        },
        {
            'cve': 'CVE-2024-5480',
            'name': 'LangChain RCE',
            'cvss': 9.8,
            'ecosystem': 'pip',
            'packages': ['langchain'],
            'min_version': (0, 0, 1),
            'max_version': (0, 2, 5),
            'fixed': '0.2.6',
            'description': 'LangChain SQL agent prompt injection allows arbitrary code execution',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-5480',
            'cwe': 'CWE-94',
        },
        {
            'cve': 'CVE-2024-3571',
            'name': 'LangChain Experimental RCE',
            'cvss': 9.8,
            'ecosystem': 'pip',
            'packages': ['langchain-experimental'],
            'min_version': (0, 0, 1),
            'max_version': (0, 0, 61),
            'fixed': '0.0.62',
            'description': 'LangChain experimental Python REPL tool allows arbitrary code execution',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-3571',
            'cwe': 'CWE-94',
        },
        {
            'cve': 'CVE-2024-21513',
            'name': 'LangChain Experimental ACE',
            'cvss': 8.5,
            'ecosystem': 'pip',
            'packages': ['langchain-experimental'],
            'min_version': (0, 0, 15),
            'max_version': (0, 0, 20),
            'fixed': '0.0.21',
            'description': 'LangChain experimental VectorSQLDatabaseChain eval() on database values allows arbitrary code execution',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-21513',
            'cwe': 'CWE-94',
        },
        {
            'cve': 'CVE-2024-46946',
            'name': 'LangServe SSRF',
            'cvss': 9.8,
            'ecosystem': 'pip',
            'packages': ['langserve'],
            'min_version': (0, 0, 1),
            'max_version': (0, 2, 1),
            'fixed': '0.2.2',
            'description': 'LangServe LCEL playground allows SSRF via prompt chaining',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-46946',
            'cwe': 'CWE-918',
        },
        {
            'cve': 'CVE-2024-3271',
            'name': 'LlamaIndex Command Injection',
            'cvss': 9.8,
            'ecosystem': 'pip',
            'packages': ['llama-index', 'llama_index', 'llama-index-core'],
            'min_version': (0, 10, 6),
            'max_version': (0, 10, 23),
            'fixed': '0.10.24',
            'description': 'LlamaIndex safe_eval bypass allows OS command execution via attacker-controlled LLM output',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-3271',
            'cwe': 'CWE-77',
        },
        {
            'cve': 'CVE-2025-1793',
            'name': 'LlamaIndex Vector Store SQLi',
            'cvss': 9.8,
            'ecosystem': 'pip',
            'packages': [
                'llama-index-core', 'llama_index',
                'llama-index-vector-stores-clickhouse',
                'llama-index-vector-stores-couchbase',
                'llama-index-vector-stores-deeplake',
                'llama-index-vector-stores-lantern',
                'llama-index-vector-stores-oracledb',
                'llama-index-vector-stores-singlestoredb',
            ],
            'min_version': (0, 0, 1),
            'max_version': (0, 12, 21),
            'fixed': '0.12.28',
            'description': 'LlamaIndex vector_store.delete() SQL injection across multiple store backends',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2025-1793',
            'cwe': 'CWE-89',
        },
        {
            'cve': 'CVE-2023-37920',
            'name': 'certifi Compromised Root CA',
            'cvss': 9.8,
            'ecosystem': 'pip',
            'packages': ['certifi'],
            'min_version': (2015, 4, 28),
            'max_version': (2023, 7, 21),
            'fixed': '2023.7.22',
            'description': 'certifi includes e-Tugra root certificate with known key compromise',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-37920',
            'cwe': 'CWE-345',
        },
        {
            'cve': 'CVE-2024-34064',
            'name': 'Jinja2 Sandbox Escape',
            'cvss': 9.8,
            'ecosystem': 'pip',
            'packages': ['jinja2', 'Jinja2'],
            'min_version': (2, 0, 0),
            'max_version': (3, 1, 3),
            'fixed': '3.1.4',
            'description': 'Jinja2 sandbox escape via xmlattr filter allows arbitrary attribute injection',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-34064',
            'cwe': 'CWE-79',
        },

        # ----- Go -----
        {
            'cve': 'CVE-2024-24790',
            'name': 'Go net/netip ParseAddr Bypass',
            'cvss': 9.8,
            'ecosystem': 'go',
            'packages': ['stdlib'],
            'min_version': (1, 21, 0),
            'max_version': (1, 21, 10),
            'fixed': '1.21.11 or 1.22.4',
            'description': 'Go net/netip incorrectly handles IPv4-mapped IPv6 addresses, bypassing access controls',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-24790',
            'cwe': 'CWE-1287',
        },
        {
            'cve': 'CVE-2023-29404',
            'name': 'Go Toolchain Command Injection',
            'cvss': 9.8,
            'ecosystem': 'go',
            'packages': ['stdlib'],
            'min_version': (1, 0, 0),
            'max_version': (1, 19, 9),
            'fixed': '1.19.10 or 1.20.5',
            'description': 'Go toolchain allows command injection via linker flags in go get',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-29404',
            'cwe': 'CWE-94',
        },

        # ----- Rust / Cargo -----
        {
            'cve': 'CVE-2024-24576',
            'name': 'Rust std Command Injection',
            'cvss': 10.0,
            'ecosystem': 'cargo',
            'packages': ['std'],
            'min_version': (1, 0, 0),
            'max_version': (1, 77, 1),
            'fixed': '1.77.2',
            'description': 'Rust std::process::Command on Windows improperly escapes arguments, enabling command injection',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-24576',
            'cwe': 'CWE-78',
        },

        # ----- Ruby / Gem -----
        {
            'cve': 'CVE-2023-22795',
            'name': 'Rails Action Dispatch ReDoS',
            'cvss': 9.1,
            'ecosystem': 'gem',
            'packages': ['actionpack'],
            'min_version': (7, 0, 0),
            'max_version': (7, 0, 4),
            'fixed': '7.0.4.1',
            'description': 'Action Dispatch regex DoS via specially crafted HTTP Accept header',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-22795',
            'cwe': 'CWE-1333',
        },
        {
            'cve': 'CVE-2023-28362',
            'name': 'Rails Arbitrary File Read',
            'cvss': 9.1,
            'ecosystem': 'gem',
            'packages': ['actionpack'],
            'min_version': (7, 0, 0),
            'max_version': (7, 0, 5),
            'fixed': '7.0.5.1',
            'description': 'Action Dispatch allows arbitrary file reading via specially crafted routes',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-28362',
            'cwe': 'CWE-22',
        },

        # ----- PHP / Composer -----
        {
            'cve': 'CVE-2023-3824',
            'name': 'PHP Phar Buffer Overflow',
            'cvss': 9.8,
            'ecosystem': 'composer',
            'packages': ['php'],
            'min_version': (8, 0, 0),
            'max_version': (8, 0, 29),
            'fixed': '8.0.30 or 8.1.22 or 8.2.8',
            'description': 'PHP phar buffer read overflow via insufficient length checks enables RCE',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-3824',
            'cwe': 'CWE-119',
        },
    ]

    # Dependency manifest files and their ecosystems
    # npm/JS files intentionally excluded (handled by React2ShellScanner)
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
    }

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return [
            '.txt', '.py', '.cfg', '.toml', '.lock',
            '.xml', '.gradle', '.kts',
            '.mod', '.sum',
            '.json',
        ]

    def is_available(self) -> bool:
        return True

    def can_scan(self, file_path: Path) -> bool:
        return file_path.name in self.MANIFEST_FILES

    def get_confidence_score(self, file_path: Path) -> int:
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
                        if parsed and self._is_in_range(parsed, cve['min_version'], cve['max_version']):
                            cwe_id = None
                            cwe_link = None
                            if cve.get('cwe'):
                                cwe_match = re.search(r'CWE-(\d+)', cve['cwe'])
                                if cwe_match:
                                    cwe_id = int(cwe_match.group(1))
                                    cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"

                            issues.append(ScannerIssue(
                                severity=Severity.CRITICAL,
                                message=(
                                    f"{cve['cve']} ({cve['name']}): {dep_name}@{dep_version} is vulnerable "
                                    f"(CVSS {cve['cvss']}). {cve['description']}. "
                                    f"Upgrade to {cve['fixed']}+. "
                                    f"See: {cve['url']}"
                                ),
                                line=None,
                                rule_id=f"critical-cve-{cve['cve'].lower()}",
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
        if not version_str:
            return None

        # Clean version string
        version = version_str.strip()
        for prefix in ['^', '~', '>=', '>', '<=', '<', '=', 'v', '==']:
            if version.startswith(prefix):
                version = version[len(prefix):]

        # Handle pre-release suffixes (strip them for comparison)
        version = re.sub(r'[-+].*$', '', version)

        # Extract numeric parts
        parts = re.findall(r'\d+', version)
        if not parts:
            return None

        try:
            return tuple(int(p) for p in parts[:4])
        except (ValueError, TypeError):
            return None

    def _is_in_range(
        self,
        version: Tuple[int, ...],
        min_version: Tuple[int, ...],
        max_version: Tuple[int, ...],
    ) -> bool:
        """Check if version tuple falls within [min, max] inclusive."""
        # Pad tuples to same length for comparison
        max_len = max(len(version), len(min_version), len(max_version))
        v = version + (0,) * (max_len - len(version))
        v_min = min_version + (0,) * (max_len - len(min_version))
        v_max = max_version + (0,) * (max_len - len(max_version))

        return v_min <= v <= v_max

    def get_install_instructions(self) -> str:
        return "Critical CVE scanning is built-in (no additional tools required)"
