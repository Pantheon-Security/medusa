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
  failure (no network, timeout, malformed JSON) is swallowed and yields NO
  findings for that manifest. The scanner never raises or hangs because of the
  network; run fully offline and it simply reports nothing. The FIRST transport
  failure in a run flips the scanner offline so remaining manifests short-circuit
  with no further per-manifest stalls (CR-013).
- BATCHED: dependencies are resolved through OSV's /v1/querybatch endpoint — one
  HTTP POST per manifest (chunked to OSV's 1000-queries/request limit) instead of
  one request per dependency, so a large lockfile no longer times out and drops
  all of its CVE findings (CR-014).
- DISTINGUISHES FAILURE FROM CLEAN: a rate-limit/5xx that survives one backoff
  retry sets a per-run "incomplete" flag and emits an INFO MEDUSA-OSV-INCOMPLETE
  finding, so an empty result is never mistaken for a clean bill of health (CR-015).
- Only PINNED dependencies are checked. Ranges, carets, tildes, and unpinned
  specs are skipped (OSV needs a concrete version, and an unpinned spec is not a
  reproducible finding).
- Uses STDLIB urllib.request only — no new third-party dependency.
- Results are cached per-run by (name, version, ecosystem) so a manifest and its
  lockfile naming the same pin only hit the network once (CR-016). Only
  {name, version, ecosystem} is ever sent to OSV.dev.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


# OSV.dev batched-query endpoint. One POST resolves up to 1000 (name, version,
# ecosystem) queries at once, mapping results back to the request by index.
_OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"

# OSV caps querybatch at 1000 queries per request; chunk anything larger.
_OSV_BATCH_MAX = 1000

# CR-028: cross-file circuit breaker. After this many consecutive network
# failures in a run (transport OR reachable-but-erroring), the scanner opens the
# breaker (flips offline) so the remaining lookups short-circuit to no findings
# — bounded degradation, no per-manifest stalls behind a flaky/blocking network.
_OSV_CIRCUIT_BREAKER_K = 3

# Exact npm version: a bare version pin with no range operators. Accepts 1-2
# component pins ("1", "1.2") as well as full semver ("1.2.3") plus an optional
# prerelease/build suffix. Ranges, carets, tildes, and wildcards are NOT pins.
# Defined here (not at module foot) so it precedes the lockfile parsers below.
_EXACT_NPM_VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.\-]+)?$")

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
        # Per-run cache: (name, version, ecosystem) -> (vuln-id list, OSV severity).
        # Severity is best-effort (querybatch omits it) and is None when absent;
        # _make_issue then defaults to HIGH.
        self._osv_cache: Dict[Tuple[str, str, str], Tuple[List[str], Optional[str]]] = {}
        # Set on the first transport failure so the rest of the run short-circuits
        # (no per-manifest network stalls when offline / behind a drop-firewall).
        # PR-011: `medusa scan --offline` sets MEDUSA_OFFLINE=1 so no dependency
        # names/versions ever leave the machine — the existing circuit-breaker
        # already short-circuits all OSV network when _offline is True.
        self._offline = os.environ.get("MEDUSA_OFFLINE") == "1"
        # Set when a reachable OSV returns 429/5xx even after one retry — results
        # may be partial, so an empty finding list must not be read as "clean".
        self._network_incomplete = False
        # CR-028 circuit breaker: count consecutive failed batch calls; on the
        # Kth in a row the run flips offline so the rest short-circuits. Reset to
        # zero on any successful batch.
        self._consecutive_failures = 0
        # Marks the cache as pre-populated by a project-wide prefetch (CR-016) so
        # spawn-mode Pool workers can rehydrate it via the batch-cache snapshot.
        self._cache_populated = False

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

            # Resolve every pin through ONE batched querybatch call (per-run cache
            # dedups pins already looked up in this run / by the prefetch).
            self._resolve([(n, v, e) for n, v, e, _ in deps])

            for name, version, ecosystem, line in deps:
                vuln_ids, severity = self._osv_cache.get(
                    (name, version, ecosystem), ([], None)
                )
                if vuln_ids:
                    issues.append(
                        self._make_issue(name, version, ecosystem, vuln_ids, line, severity)
                    )

            # CR-015: a reachable-but-erroring OSV means the results above may be
            # partial. Emit one INFO finding so absence of CVEs is not read as a
            # clean bill of health. (Offline runs do not set this flag.)
            if self._network_incomplete and deps:
                issues.append(self._incomplete_issue())

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

    # Poetry table headers whose entries are `pkg = "<spec>"` install deps.
    _POETRY_DEP_HEADER_RE = re.compile(
        r'^\[tool\.poetry(?:\.group\.[^.\]]+)?\.dependencies\]$|^\[tool\.poetry\.dev-dependencies\]$'
    )
    _POETRY_PIN_RE = re.compile(
        r'^\s*"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=\s*"(?:==)?\s*([0-9][0-9A-Za-z.\-+!]*)"\s*$'
    )
    _TOML_HEADER_RE = re.compile(r'^(\[\[?[^\]]+\]\]?)\s*$')

    def _parse_pyproject(self, content: str) -> List[Tuple[str, str, str, int]]:
        """Extract exact `==` pins from *install* dependency tables only.

        Scopes to PEP 621 [project] ``dependencies`` / [project.optional-
        dependencies] and Poetry dependency tables. Test/tool blocks such as
        [tool.tox] command lists, example lockfiles, and [dependency-groups] are
        NOT install dependencies, so pins inside them are ignored — reading them
        was the source of phantom CVEs for projects like flask.
        """
        deps: List[Tuple[str, str, str, int]] = []
        section = ''
        in_project_deps = False  # inside [project] dependencies = [ ... ]
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            hdr = self._TOML_HEADER_RE.match(stripped)
            if hdr:
                section = hdr.group(1).lower()
                in_project_deps = False
                continue

            if section == '[project]':
                if not in_project_deps:
                    m = re.match(r'^dependencies\s*=\s*\[(.*)$', stripped)
                    if m:
                        in_project_deps = True
                        self._collect_pyproject_line(m.group(1), i, deps)
                        if ']' in m.group(1):
                            in_project_deps = False
                else:
                    self._collect_pyproject_line(stripped, i, deps)
                    if ']' in stripped:
                        in_project_deps = False
            elif section == '[project.optional-dependencies]':
                self._collect_pyproject_line(stripped, i, deps)
            elif self._POETRY_DEP_HEADER_RE.match(section):
                pm = self._POETRY_PIN_RE.match(stripped)
                if pm and pm.group(1).lower() != 'python':
                    deps.append((self._norm(pm.group(1)), pm.group(2), _PYPI, i))
        return deps

    def _collect_pyproject_line(
        self, text: str, line_no: int, deps: List[Tuple[str, str, str, int]]
    ) -> None:
        """Append every exact `==` pin found in a PEP 621 dependency-array line."""
        for m in self._PYPROJECT_DEP_RE.finditer(text):
            deps.append((self._norm(m.group(1)), m.group(2), _PYPI, line_no))

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
                    pinned = ver[2:].strip()
                    deps.append((
                        self._norm(name), pinned, _PYPI,
                        self._lockfile_line(content, name, pinned),
                    ))
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
                        deps.append((name, ver, _NPM, self._lockfile_line(content, name, ver)))

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
                        deps.append((name, ver, _NPM, self._lockfile_line(content, name, ver)))
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

    @staticmethod
    def _lockfile_line(content: str, name: str, version: str) -> int:
        """Best-effort line for a JSON/TOML-lockfile dependency (name and version
        usually live on different lines). Prefer the package's own key line
        (``"pkg":`` or ``node_modules/pkg``); fall back to the version's line,
        then to 1."""
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            if f'"{name}"' in line or f'/{name}"' in line:
                return i
        for i, line in enumerate(lines, 1):
            if f'"{version}"' in line or f'=={version}"' in line:
                return i
        return 1

    # ------------------------------------------------------------------
    # OSV lookup (offline-safe).
    # ------------------------------------------------------------------

    def collect_manifest_deps(
        self, files: List[Path]
    ) -> List[Tuple[str, str, str]]:
        """Parse every manifest in `files` and return their unique pins.

        Used by the project-wide prefetch (CR-016): the caller resolves the whole
        set with one batched query before Pool workers fork, so no worker performs
        a redundant per-file lookup. Parse failures are skipped, never raised.
        """
        pins: List[Tuple[str, str, str]] = []
        for f in files:
            path = Path(f)
            kind = self._manifest_kind(path)
            if kind is None:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                deps = self._parse(kind, content)
            except Exception:  # noqa: BLE001 - a bad manifest must not abort prefetch
                continue
            pins.extend((n, v, e) for n, v, e, _ in deps)
        return pins

    def _resolve(self, pins: List[Tuple[str, str, str]]) -> None:
        """Populate self._osv_cache for every pin, using ONE batched query.

        Pins already in the cache (from this run or the prefetch) are skipped, and
        when the run has gone offline no network is touched at all.
        """
        pending: List[Tuple[str, str, str]] = []
        seen: set = set()
        for key in pins:
            if key in self._osv_cache or key in seen:
                continue
            seen.add(key)
            pending.append(key)
        if not pending:
            return
        if self._offline:
            for key in pending:
                self._osv_cache.setdefault(key, ([], None))
            return
        self._query_batch(pending)

    def _query_batch(self, keys: List[Tuple[str, str, str]]) -> None:
        """Resolve `keys` via /v1/querybatch (chunked) into self._osv_cache.

        Offline-safe: a transport failure flips the run offline and swallows;
        a 429/503 surviving one retry sets self._network_incomplete. Either way
        the affected keys are cached empty so they are never re-queried.
        """
        for start in range(0, len(keys), _OSV_BATCH_MAX):
            chunk = keys[start:start + _OSV_BATCH_MAX]
            results = self._post_querybatch(chunk)
            if results is None:
                # Failure already recorded (_offline / _network_incomplete).
                # CR-028: after K consecutive failures in this run, open the
                # circuit breaker (flip offline) so the remaining lookups
                # short-circuit — bounded degradation, no further stalls.
                self._consecutive_failures += 1
                if self._consecutive_failures >= _OSV_CIRCUIT_BREAKER_K:
                    self._offline = True
                # Cache-empty this chunk, and if we are now offline cache-empty
                # the remainder too and stop (bounded, no further stalls).
                for key in chunk:
                    self._osv_cache.setdefault(key, ([], None))
                if self._offline:
                    for key in keys[start + _OSV_BATCH_MAX:]:
                        self._osv_cache.setdefault(key, ([], None))
                    return
                continue
            # A successful batch clears the consecutive-failure streak.
            self._consecutive_failures = 0
            for key, res in zip(chunk, results):
                # _extract_batch_ids yields (ids, severity) tuples; a mocked
                # _post_querybatch may return bare id-lists — normalise both.
                if isinstance(res, tuple):
                    ids, severity = res
                else:
                    ids, severity = res, None
                self._osv_cache[key] = (ids, severity)

    def _post_querybatch(
        self, chunk: List[Tuple[str, str, str]]
    ) -> Optional[List[List[str]]]:
        """POST one querybatch chunk; return per-query vuln-id lists, or None.

        This is the offline-safety boundary: no network, timeout, or bad JSON
        propagates out. Only {name, version, ecosystem} is transmitted.
        Returns None on failure (with _offline / _network_incomplete set), else
        a list aligned with `chunk`.
        """
        payload = json.dumps(
            {
                "queries": [
                    {"package": {"name": n, "ecosystem": e}, "version": v}
                    for (n, v, e) in chunk
                ]
            }
        ).encode("utf-8")
        try:
            data = self._http_post(payload)
        except urllib.error.HTTPError as e:
            # Reachable server, transient error: one backoff + retry, then give up
            # but mark the run incomplete so empty != clean.
            if getattr(e, "code", None) in (429, 503):
                time.sleep(1)
                try:
                    data = self._http_post(payload)
                except Exception:  # noqa: BLE001 - retry failed; degrade gracefully
                    self._network_incomplete = True
                    self._offline = True  # stop hammering a rate-limited endpoint
                    return None
            else:
                # Other HTTP status (4xx/other 5xx): treat as no data, not a lie.
                return None
        except (urllib.error.URLError, OSError, TimeoutError):
            # Transport failure = offline. Flip the run so the rest short-circuits.
            self._offline = True
            return None
        except Exception:  # noqa: BLE001 - defensive: never let the network break a scan
            self._offline = True
            return None

        return self._extract_batch_ids(data, len(chunk))

    def _http_post(self, payload: bytes) -> object:
        """Single POST to the querybatch endpoint; raises on any transport/HTTP error."""
        req = urllib.request.Request(
            _OSV_QUERYBATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_OSV_TIMEOUT) as resp:
            return json.loads(resp.read())

    @staticmethod
    def _extract_batch_ids(
        data: object, expected: int
    ) -> List[Tuple[List[str], Optional[str]]]:
        """Map a /v1/querybatch response to per-query (vuln-id list, severity)
        tuples, by index. Severity is best-effort and usually None (querybatch
        omits it); callers default to HIGH when it is absent."""
        out: List[Tuple[List[str], Optional[str]]] = [([], None) for _ in range(expected)]
        if not isinstance(data, dict):
            return out
        results = data.get("results")
        if not isinstance(results, list):
            return out
        for i, res in enumerate(results):
            if i >= expected:
                break
            if isinstance(res, dict):
                out[i] = (
                    DependencyCVEScanner._extract_vuln_ids(res),
                    DependencyCVEScanner._extract_severity(res),
                )
        return out

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

    # OSV severity rank for picking the worst across a package's vulns.
    _SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}

    @staticmethod
    def _extract_severity(data: object) -> Optional[str]:
        """Best-effort OSV severity string for a query result, taking the most
        severe across its vulns via database_specific.severity. querybatch
        responses omit this, so it typically returns None (callers default HIGH)."""
        if not isinstance(data, dict):
            return None
        vulns = data.get("vulns")
        if not isinstance(vulns, list):
            return None
        best: Optional[str] = None
        best_rank = 0
        for v in vulns:
            if not isinstance(v, dict):
                continue
            ds = v.get("database_specific")
            sev = ds.get("severity") if isinstance(ds, dict) else None
            if isinstance(sev, str):
                up = sev.upper()
                rank = DependencyCVEScanner._SEVERITY_RANK.get(up, 0)
                if rank > best_rank:
                    best, best_rank = up, rank
        return best

    def _make_issue(
        self,
        name: str,
        version: str,
        ecosystem: str,
        vuln_ids: List[str],
        line: int,
        severity: Optional[str] = None,
    ) -> ScannerIssue:
        id_str = ", ".join(vuln_ids)
        # Map the OSV-reported severity through _SEVERITY_MAP; default to HIGH when
        # absent (querybatch omits severity — a known CVE in a pin is actionable).
        mapped = _SEVERITY_MAP.get((severity or "").upper(), Severity.HIGH)
        return ScannerIssue(
            rule_id="MEDUSA-OSV-001",
            severity=mapped,
            message=(
                f"Known vulnerability in {ecosystem} package '{name}=={version}': "
                f"{id_str} (source: OSV.dev). Upgrade to a patched version."
            ),
            line=line,
            column=1,
        )

    def _incomplete_issue(self) -> ScannerIssue:
        """INFO finding emitted when the OSV lookup was reachable but errored,
        so an empty CVE list is not mistaken for a clean bill of health."""
        return ScannerIssue(
            rule_id="MEDUSA-OSV-INCOMPLETE",
            severity=Severity.INFO,
            message=(
                "OSV lookup incomplete — network error querying OSV.dev; CVE "
                "results for this manifest may be partial."
            ),
            line=1,
            column=1,
        )
