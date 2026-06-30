#!/usr/bin/env python3
"""
MEDUSA Dependency CVE Scanner

Performs a LIVE software-composition lookup of pinned dependencies against the
OSV.dev vulnerability database (https://osv.dev). For each dependency manifest
(requirements.txt, pyproject.toml, package.json, lockfiles, ...) it extracts the
PINNED (name + exact version) dependencies, maps each to its OSV ecosystem
(PyPI / npm), and queries OSV for known vulnerabilities. A vulnerable pin yields
a single MEDUSA-OSV-001 finding naming the package, version, and CVE/OSV IDs.

Design notes:
- OFFLINE-SAFE BY CONSTRUCTION: every network call uses a short timeout and any
  failure (no network, timeout, non-200, malformed JSON) is swallowed and yields
  NO findings for that dependency. The scanner never raises or hangs because of
  the network; run fully offline and it simply reports nothing.
- Only PINNED dependencies are checked. Ranges, carets, tildes, and unpinned
  specs are skipped (OSV needs a concrete version, and an unpinned spec is not a
  reproducible finding).
- Uses STDLIB urllib.request only — no new third-party dependency.
- Results are cached per-run by (name, version, ecosystem) so a manifest and its
  lockfile naming the same pin only hit the network once.
"""

import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


# OSV.dev single-package query endpoint.
_OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# Network timeout (seconds). Kept short so an unreachable network degrades
# gracefully to "no findings" rather than stalling a scan.
_OSV_TIMEOUT = 5

# Manifest filenames this scanner understands, mapped to a parser key.
# Matched by basename (case-insensitive), not just extension, because several
# manifests share an extension (e.g. *.json) or have none distinguishing them.
_REQUIREMENTS_RE = re.compile(r"^requirements.*\.txt$", re.IGNORECASE)

_PYPI = "PyPI"
_NPM = "npm"

# OSV severity strings -> MEDUSA Severity. OSV ranks via CVSS; we map the
# database_specific/severity hints when present, else default to HIGH (a known
# CVE in a pinned dep is, by default, a real and actionable finding).
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class DependencyCVEScanner(BaseScanner):
    """Live OSV.dev CVE lookup for pinned dependencies in manifest files."""

    display_name = "Dependency CVE (OSV)"
    description = (
        "Queries OSV.dev for known CVEs affecting pinned dependencies in "
        "requirements.txt, pyproject.toml, package.json, and lockfiles. "
        "Offline-safe: yields nothing when the network is unavailable."
    )

    def __init__(self):
        super().__init__()
        # Per-run cache: (name, version, ecosystem) -> list of vuln-id strings.
        self._osv_cache: Dict[Tuple[str, str, str], List[str]] = {}

    def get_tool_name(self) -> str:
        return "python"  # stdlib-only HTTP; no external tool

    def get_file_extensions(self) -> List[str]:
        # Used for fast extension pre-filtering by the registry. can_scan()
        # does the authoritative basename match below.
        return [".txt", ".toml", ".json", ".lock"]

    def is_available(self) -> bool:
        return True

    def can_scan(self, file_path: Path) -> bool:
        """Match dependency manifests by basename (not just extension)."""
        return self._manifest_kind(file_path) is not None

    def _manifest_kind(self, file_path: Path) -> Optional[str]:
        """Return a parser key for the manifest, or None if unsupported."""
        name = file_path.name.lower()
        if _REQUIREMENTS_RE.match(name):
            return "requirements"
        if name == "pyproject.toml":
            return "pyproject"
        if name in ("pipfile", "pipfile.lock"):
            return "pipfile" if name == "pipfile" else "pipfile_lock"
        if name == "poetry.lock":
            return "poetry_lock"
        if name in ("package.json",):
            return "package_json"
        if name == "package-lock.json":
            return "package_lock"
        if name == "yarn.lock":
            return "yarn_lock"
        return None

    def scan_file(self, file_path: Path) -> ScannerResult:
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            kind = self._manifest_kind(file_path)
            if kind is None:
                return self._ok(file_path, [], start_time)

            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            deps = self._parse(kind, content)

            for name, version, ecosystem, line in deps:
                vuln_ids = self._lookup(name, version, ecosystem)
                if vuln_ids:
                    issues.append(self._make_issue(name, version, ecosystem, vuln_ids, line))

            return self._ok(file_path, issues, start_time)

        except Exception as e:  # noqa: BLE001 - any parse/read failure is a scan failure
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )

    def _ok(self, file_path: Path, issues: List[ScannerIssue], start_time: float) -> ScannerResult:
        return ScannerResult(
            scanner_name=self.name,
            file_path=str(file_path),
            issues=issues,
            scan_time=time.time() - start_time,
            success=True,
        )

    # ------------------------------------------------------------------
    # Parsing: extract (name, version, ecosystem, line) for PINNED deps only.
    # ------------------------------------------------------------------

    def _parse(self, kind: str, content: str) -> List[Tuple[str, str, str, int]]:
        if kind == "requirements":
            return self._parse_requirements(content)
        if kind == "pyproject":
            return self._parse_pyproject(content)
        if kind in ("pipfile_lock", "poetry_lock"):
            return self._parse_lock_toml_or_json(kind, content)
        if kind == "pipfile":
            return self._parse_pipfile(content)
        if kind == "package_json":
            return self._parse_package_json(content)
        if kind == "package_lock":
            return self._parse_package_lock(content)
        if kind == "yarn_lock":
            return self._parse_yarn_lock(content)
        return []

    # requirements*.txt -> PyPI, only `pkg==1.2.3` pins.
    _REQ_PIN_RE = re.compile(
        r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.\-+!]*)"
    )

    def _parse_requirements(self, content: str) -> List[Tuple[str, str, str, int]]:
        deps: List[Tuple[str, str, str, int]] = []
        for i, raw in enumerate(content.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Drop inline comments / environment markers / hashes.
            line = line.split(";", 1)[0]
            line = line.split(" #", 1)[0]
            m = self._REQ_PIN_RE.match(line)
            if m:
                deps.append((self._norm(m.group(1)), m.group(2).strip(), _PYPI, i))
        return deps

    # pyproject.toml [project].dependencies pins: "pkg==1.2.3"
    _PYPROJECT_DEP_RE = re.compile(
        r'["\']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.\-+!]*)["\']'
    )

    def _parse_pyproject(self, content: str) -> List[Tuple[str, str, str, int]]:
        deps: List[Tuple[str, str, str, int]] = []
        for i, line in enumerate(content.splitlines(), 1):
            for m in self._PYPROJECT_DEP_RE.finditer(line):
                deps.append((self._norm(m.group(1)), m.group(2), _PYPI, i))
        return deps

    def _parse_lock_toml_or_json(self, kind: str, content: str) -> List[Tuple[str, str, str, int]]:
        # poetry.lock is TOML with [[package]] tables; Pipfile.lock is JSON.
        if kind == "poetry_lock":
            return self._parse_poetry_lock(content)
        return self._parse_pipfile_lock(content)

    def _parse_poetry_lock(self, content: str) -> List[Tuple[str, str, str, int]]:
        deps: List[Tuple[str, str, str, int]] = []
        cur_name: Optional[str] = None
        name_line = 0
        in_package = False
        name_re = re.compile(r'^\s*name\s*=\s*"([^"]+)"')
        ver_re = re.compile(r'^\s*version\s*=\s*"([^"]+)"')
        for i, line in enumerate(content.splitlines(), 1):
            if line.strip() == "[[package]]":
                in_package = True
                cur_name = None
                continue
            if not in_package:
                continue
            nm = name_re.match(line)
            if nm:
                cur_name = self._norm(nm.group(1))
                name_line = i
                continue
            vm = ver_re.match(line)
            if vm and cur_name:
                deps.append((cur_name, vm.group(1), _PYPI, name_line))
                cur_name = None
        return deps

    def _parse_pipfile_lock(self, content: str) -> List[Tuple[str, str, str, int]]:
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return []
        deps: List[Tuple[str, str, str, int]] = []
        for section in ("default", "develop"):
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for name, meta in block.items():
                if not isinstance(meta, dict):
                    continue
                ver = meta.get("version")
                if isinstance(ver, str) and ver.startswith("=="):
                    deps.append((self._norm(name), ver[2:].strip(), _PYPI, 1))
        return deps

    def _parse_pipfile(self, content: str) -> List[Tuple[str, str, str, int]]:
        # Pipfile is TOML: lines like  requests = "==2.19.1"
        deps: List[Tuple[str, str, str, int]] = []
        pin_re = re.compile(
            r'^\s*"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=\s*"==\s*([A-Za-z0-9][A-Za-z0-9.\-+!]*)"'
        )
        for i, line in enumerate(content.splitlines(), 1):
            m = pin_re.match(line)
            if m:
                deps.append((self._norm(m.group(1)), m.group(2), _PYPI, i))
        return deps

    def _parse_package_json(self, content: str) -> List[Tuple[str, str, str, int]]:
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return []
        deps: List[Tuple[str, str, str, int]] = []
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for name, spec in block.items():
                if not isinstance(spec, str):
                    continue
                # Only exact pins: "1.2.3" (no ^, ~, >=, ranges, urls, *).
                if _EXACT_NPM_VERSION_RE.match(spec.strip()):
                    deps.append((name, spec.strip(), _NPM, self._json_line(content, name, spec)))
        return deps

    def _parse_package_lock(self, content: str) -> List[Tuple[str, str, str, int]]:
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return []
        deps: List[Tuple[str, str, str, int]] = []
        seen: set = set()

        # lockfile v2/v3: "packages": {"node_modules/pkg": {"version": "1.2.3"}}
        packages = data.get("packages")
        if isinstance(packages, dict):
            for path, meta in packages.items():
                if not path or not isinstance(meta, dict):
                    continue  # "" is the root project
                ver = meta.get("version")
                name = path.split("node_modules/")[-1]
                if name and isinstance(ver, str) and _EXACT_NPM_VERSION_RE.match(ver):
                    key = (name, ver)
                    if key not in seen:
                        seen.add(key)
                        deps.append((name, ver, _NPM, 1))

        # lockfile v1: "dependencies": {"pkg": {"version": "1.2.3"}}
        legacy = data.get("dependencies")
        if isinstance(legacy, dict):
            for name, meta in legacy.items():
                if not isinstance(meta, dict):
                    continue
                ver = meta.get("version")
                if isinstance(ver, str) and _EXACT_NPM_VERSION_RE.match(ver):
                    key = (name, ver)
                    if key not in seen:
                        seen.add(key)
                        deps.append((name, ver, _NPM, 1))
        return deps

    # yarn.lock blocks:  pkg@^1.0.0:\n  version "1.2.3"
    _YARN_HEADER_RE = re.compile(r'^"?(@?[^@\s"]+)@')
    _YARN_VER_RE = re.compile(r'^\s+version\s+"([^"]+)"')

    def _parse_yarn_lock(self, content: str) -> List[Tuple[str, str, str, int]]:
        deps: List[Tuple[str, str, str, int]] = []
        cur_name: Optional[str] = None
        header_line = 0
        for i, line in enumerate(content.splitlines(), 1):
            if line and not line.startswith(" ") and not line.startswith("#"):
                hm = self._YARN_HEADER_RE.match(line)
                cur_name = hm.group(1) if hm else None
                header_line = i
                continue
            vm = self._YARN_VER_RE.match(line)
            if vm and cur_name:
                deps.append((cur_name, vm.group(1), _NPM, header_line))
                cur_name = None
        return deps

    @staticmethod
    def _norm(name: str) -> str:
        """Normalize a PyPI project name (PEP 503): lowercase, runs of -_. -> -."""
        return re.sub(r"[-_.]+", "-", name).lower()

    @staticmethod
    def _json_line(content: str, name: str, spec: str) -> int:
        """Best-effort manifest line for a JSON dep entry (for the finding)."""
        needle = f'"{name}"'
        for i, line in enumerate(content.splitlines(), 1):
            if needle in line and spec in line:
                return i
        return 1

    # ------------------------------------------------------------------
    # OSV lookup (offline-safe).
    # ------------------------------------------------------------------

    def _lookup(self, name: str, version: str, ecosystem: str) -> List[str]:
        """Return vuln IDs for a pin, using the per-run cache. Never raises."""
        key = (name, version, ecosystem)
        if key in self._osv_cache:
            return self._osv_cache[key]
        result = self._query_osv(name, version, ecosystem)
        self._osv_cache[key] = result
        return result

    def _query_osv(self, name: str, version: str, ecosystem: str) -> List[str]:
        """
        Query OSV.dev for a single (name, version, ecosystem).

        Returns a list of vuln-id strings (CVE/GHSA/OSV ids) on success, or an
        EMPTY list on ANY failure. This method is the offline-safety boundary:
        no network, timeout, non-200, or bad JSON ever propagates out of here.
        """
        try:
            payload = json.dumps(
                {
                    "package": {"name": name, "ecosystem": ecosystem},
                    "version": version,
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                _OSV_QUERY_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=_OSV_TIMEOUT) as resp:
                if resp.status != 200:
                    return []
                body = resp.read()
            data = json.loads(body)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError,
                ValueError, json.JSONDecodeError, TimeoutError):
            return []
        except Exception:  # noqa: BLE001 - defensive: never let the network break a scan
            return []

        return self._extract_vuln_ids(data)

    @staticmethod
    def _extract_vuln_ids(data: object) -> List[str]:
        """Pull CVE/OSV ids out of an OSV /v1/query response, CVEs preferred."""
        if not isinstance(data, dict):
            return []
        vulns = data.get("vulns")
        if not isinstance(vulns, list):
            return []
        ids: List[str] = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            vid = v.get("id")
            aliases = v.get("aliases") if isinstance(v.get("aliases"), list) else []
            # Prefer a CVE alias for the headline id; fall back to the OSV id.
            cve = next((a for a in aliases if isinstance(a, str) and a.startswith("CVE-")), None)
            chosen = cve or vid
            if isinstance(chosen, str):
                ids.append(chosen)
        # De-dup, preserve order.
        seen: set = set()
        out: List[str] = []
        for i in ids:
            if i not in seen:
                seen.add(i)
                out.append(i)
        return out

    def _make_issue(
        self,
        name: str,
        version: str,
        ecosystem: str,
        vuln_ids: List[str],
        line: int,
    ) -> ScannerIssue:
        id_str = ", ".join(vuln_ids)
        return ScannerIssue(
            rule_id="MEDUSA-OSV-001",
            severity=Severity.HIGH,
            message=(
                f"Known vulnerability in {ecosystem} package '{name}=={version}': "
                f"{id_str} (source: OSV.dev). Upgrade to a patched version."
            ),
            line=line,
            column=1,
        )


# Exact npm version: a bare semver with no range operators.
_EXACT_NPM_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
