#!/usr/bin/env python3
"""
MEDUSA Parallel Scanner v1.1.0
High-performance parallel security scanning with caching and incremental modes

Features:
- Parallel execution (auto-detect CPU cores)
- File-level caching (skip unchanged files)
- Quick scan mode (changed files only)
- Progress tracking with tqdm
- JSON/HTML reporting via medusa-report.py
- Pluggable scanner architecture with registry
"""

import fnmatch
import hmac
import os
import re
import secrets
import sys
import json
import hashlib
import signal
import time
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from multiprocessing import Pool, cpu_count
from dataclasses import dataclass, asdict, field
from datetime import datetime
# Import new scanner architecture
from medusa.scanners import registry as scanner_registry

# Max length for code snippets stored in findings — prevents full secret values
# (API keys, tokens, passwords) from being written verbatim into report artifacts.
_CODE_SNIPPET_MAX = 200

def _truncate_code(code: str) -> str:
    """Truncate a code snippet to _CODE_SNIPPET_MAX chars to avoid leaking full secret values."""
    if not code:
        return code
    code = code.strip()
    if len(code) > _CODE_SNIPPET_MAX:
        return code[:_CODE_SNIPPET_MAX] + ' …[truncated]'
    return code

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    from rich.live import Live
    from rich.table import Table
    from rich.text import Text
    from rich.console import Console as RichConsole
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# Maximum file size for content/regex scanners (2MB).
# Files larger than this are almost always data files (datasets, logs,
# vendor bundles) rather than source code.  Scanning a 73MB JSON dataset
# line-by-line with regex patterns can hang for minutes.
MAX_SCAN_FILE_SIZE = 2 * 1024 * 1024  # 2 MB

# Per-scanner timeout in seconds.  If a single scanner takes longer than
# this on a single file it is killed and scanning moves on.
# Set high enough for external tools (semgrep ~3s/file, gitleaks, etc.)
# but low enough to catch runaway regex scans on large files.
PER_SCANNER_TIMEOUT = 60  # seconds


@dataclass
class FileMetadata:
    """Metadata for cached file scanning"""
    path: str
    size: int
    mtime: float
    hash: str
    last_scan: str
    issues_found: int
    rule_version: str = ""
    cached_issues: list = field(default_factory=list)  # Serialized issue dicts for cache hits


@dataclass
class ScanResult:
    """Result from scanning a single file"""
    file: str
    scanner: str
    issues: List[Dict]
    scan_time: float
    cached: bool = False
    scanner_stats: Optional[Dict[str, int]] = None  # {scanner_name: issue_count}
    line_count: int = 0


class MedusaCacheManager:
    """Manage file scanning cache for incremental scans"""

    def __init__(self, cache_dir: Path = None):
        self.cache_dir = cache_dir or Path.home() / ".medusa" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.cache_file = self.cache_dir / "file_cache.json"
        self.hmac_key_file = self.cache_dir / ".hmac_key"
        self._hmac_key = self._load_or_create_hmac_key()
        self.rule_version = self._compute_rule_fingerprint()
        self.cache: Dict[str, FileMetadata] = self._load_cache()

    def _load_or_create_hmac_key(self) -> bytes:
        """
        Load the machine-local HMAC key for cache integrity, creating it on
        first run. The key lives at ``<cache_dir>/.hmac_key`` with mode 0600.

        Cache integrity: an attacker with write access to the cache file
        (compromised dev workstation, malicious postinstall, shared CI runner)
        could otherwise forge cache entries marking vulnerable files as clean,
        silently suppressing scan findings. The HMAC makes such tampering
        detectable. Key rotation simply deletes this file — next scan
        regenerates and invalidates every stale cache entry.
        """
        if self.hmac_key_file.exists():
            try:
                key = self.hmac_key_file.read_bytes().strip()
                if len(key) >= 32:
                    return key
            except OSError:
                pass
        # Generate fresh key (256-bit).
        key = secrets.token_hex(32).encode()
        try:
            # Write with restrictive mode (POSIX; best-effort on Windows).
            fd = os.open(
                self.hmac_key_file,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            try:
                os.write(fd, key)
            finally:
                os.close(fd)
        except OSError:
            # If we can't persist the key, still return it; this run works but
            # the next run will regenerate and effectively invalidate the cache.
            pass
        return key

    def _compute_hmac(self, serialized: str) -> str:
        """Compute HMAC-SHA256 over a canonical serialization string."""
        return hmac.new(
            self._hmac_key,
            serialized.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _compute_rule_fingerprint(self) -> str:
        """Compute a fingerprint of the rules directory for cache invalidation."""
        rules_dir = Path(__file__).parent.parent / "rules"
        if not rules_dir.exists():
            return ""
        yaml_files = sorted(rules_dir.rglob("*.yaml"))
        hasher = hashlib.sha256()
        hasher.update(str(len(yaml_files)).encode())
        for yf in yaml_files:
            try:
                hasher.update(str(yf.stat().st_mtime).encode())
            except OSError:
                pass
        return hasher.hexdigest()[:16]

    def _load_cache(self) -> Dict[str, FileMetadata]:
        """
        Load cache from disk, verifying the HMAC envelope.

        Silent discard on:
          - Missing file (first run)
          - Missing HMAC envelope (upgrade from pre-HMAC MEDUSA versions)
          - HMAC mismatch (tampering)
          - JSON parse error
          - Unexpected schema

        Silent-vs-warn: a warning flood on every scan after an upgrade or a
        single tampered entry would train users to ignore cache messages.
        Discard is the correct UX — the next scan simply rebuilds the cache
        from a fresh pass.
        """
        if not self.cache_file.exists():
            return {}

        try:
            with open(self.cache_file, encoding="utf-8") as f:
                envelope = json.load(f)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return {}

        # Schema: {"hmac": "<hex>", "entries": {<path>: <meta>, ...}}
        if not isinstance(envelope, dict):
            return {}
        stored_hmac = envelope.get("hmac")
        entries = envelope.get("entries")
        if not isinstance(stored_hmac, str) or not isinstance(entries, dict):
            return {}

        # Verify HMAC over a canonical serialization of entries.
        canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"))
        expected_hmac = self._compute_hmac(canonical)
        if not hmac.compare_digest(stored_hmac, expected_hmac):
            return {}

        try:
            return {
                path: FileMetadata(**meta)
                for path, meta in entries.items()
                if isinstance(meta, dict)
            }
        except TypeError:
            # Schema drift between versions — discard rather than crash.
            return {}

    def _save_cache(self):
        """Save cache to disk wrapped in an HMAC-signed envelope."""
        try:
            entries = {
                path: asdict(meta)
                for path, meta in self.cache.items()
            }
            canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"))
            envelope = {
                "hmac": self._compute_hmac(canonical),
                "entries": entries,
            }
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(envelope, f, indent=2)
        except Exception as e:
            print(f"⚠️  Cache save error: {e}")

    def _get_file_hash(self, file_path: Path) -> str:
        """Calculate file hash (first 8KB for speed)"""
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                # Hash first 8KB for speed (detects most changes)
                chunk = f.read(8192)
                hasher.update(chunk)
            return hasher.hexdigest()[:16]
        except Exception:
            return ""

    def is_file_changed(self, file_path: Path) -> bool:
        """Check if file has changed since last scan"""
        path_str = str(file_path.absolute())

        if path_str not in self.cache:
            return True

        cached = self.cache[path_str]

        try:
            stat = file_path.stat()

            # Quick checks first (size, mtime)
            if stat.st_size != cached.size or stat.st_mtime != cached.mtime:
                return True

            # Rule version check — invalidate if rules changed
            if cached.rule_version != self.rule_version:
                return True

            # Hash check (slower but accurate)
            current_hash = self._get_file_hash(file_path)
            return current_hash != cached.hash

        except Exception:
            return True

    def update_cache(self, file_path: Path, issues_found: int, issues: list = None):
        """Update cache entry for scanned file"""
        try:
            stat = file_path.stat()
            self.cache[str(file_path.absolute())] = FileMetadata(
                path=str(file_path.absolute()),
                size=stat.st_size,
                mtime=stat.st_mtime,
                hash=self._get_file_hash(file_path),
                last_scan=datetime.now().isoformat(),
                issues_found=issues_found,
                rule_version=self.rule_version,
                cached_issues=issues or [],
            )
        except Exception:
            # Silently skip cache for files that vanish during scan (symlinks, temp files)
            pass

    def save(self):
        """Save cache to disk"""
        self._save_cache()

    def clear(self):
        """Clear all cache"""
        self.cache.clear()
        if self.cache_file.exists():
            self.cache_file.unlink()
        print("✅ Cache cleared")


class MedusaParallelScanner:
    """Parallel MEDUSA security scanner"""

    # Supported file extensions and their scanners
    FILE_SCANNERS = {
        '.sh': 'bash',
        '.bash': 'bash',
        '.bat': 'bat',
        '.cmd': 'bat',
        '.py': 'python',
        '.go': 'go',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'javascript',
        '.tsx': 'javascript',
        '.yml': 'yaml',
        '.yaml': 'yaml',
        '.tf': 'terraform',
        '.tfvars': 'terraform',
        '.md': 'markdown',
        '.dockerfile': 'docker',
        '.ps1': 'powershell',
        '.json': 'json',
        '.xml': 'xml',
        '.sol': 'solidity',
        '.env': 'env',
        # ML model files (scanned by modelscan)
        '.pkl': 'model',
        '.pickle': 'model',
        '.pt': 'model',
        '.pth': 'model',
        '.bin': 'model',
        '.h5': 'model',
        '.hdf5': 'model',
        '.safetensors': 'model',
        '.joblib': 'model',
        '.ckpt': 'model',
        '.onnx': 'model',
        '.gguf': 'model',
        # Dependency manifests (CVE scanner)
        '.txt': 'requirements',
        '.lock': 'lockfile',
        '.toml': 'toml',
        '.cfg': 'config',
        '.mod': 'gomod',
        '.sum': 'gosum',
        '.gradle': 'gradle',
        '.kts': 'gradle',
    }

    def __init__(self,
                 project_root: Path,
                 workers: int = None,
                 use_cache: bool = True,
                 quick_mode: bool = False,
                 extra_excludes: list = None):
        self.project_root = project_root.absolute()
        self.workers = workers or cpu_count()
        self.use_cache = use_cache
        self.quick_mode = quick_mode
        self.cache = MedusaCacheManager() if use_cache else None
        self.force_ascii = not self._is_modern_terminal()

        # Load configuration from medusa.yml (or .medusa.yml)
        from medusa.config import ConfigManager
        self.config = ConfigManager.load_config()

        # Merge CLI --exclude paths into config exclusions
        if extra_excludes:
            for path in extra_excludes:
                if path not in self.config.exclude_paths:
                    self.config.exclude_paths.append(path)

        # Pre-mapped scanner lookup (populated by _pre_map_scanners, reused by scan_file)
        self._scanner_map: Dict[str, list] = {}

        # Find medusa.sh (optional - only needed for non-Python scanners)
        self.medusa_script = self._find_medusa_script()

        _icon = '>' if self.force_ascii else '\U0001f40d'
        print(f"{_icon} MEDUSA Parallel Scanner v1.1.0")
        print(f"   Workers: {self.workers} cores")
        print(f"   Cache: {'enabled' if use_cache else 'disabled'}")
        print(f"   Mode: {'quick (changed files only)' if quick_mode else 'full'}")
        print()

    @staticmethod
    def _is_modern_terminal() -> bool:
        """Detect if the terminal supports Unicode box-drawing characters.

        Legacy PowerShell and CMD on Windows don't render Unicode progress
        bars (█░) correctly. Modern terminals (Windows Terminal, Ghostty,
        iTerm2, etc.) handle them fine.
        """
        if sys.platform != 'win32':
            return True  # Linux/macOS terminals are fine

        # Windows Terminal sets WT_SESSION
        if os.environ.get('WT_SESSION'):
            return True
        # Modern third-party terminals set TERM_PROGRAM
        if os.environ.get('TERM_PROGRAM'):
            return True
        # ConEmu / Cmder
        if os.environ.get('ConEmuPID') or os.environ.get('CMDER_ROOT'):
            return True
        # VS Code integrated terminal
        if os.environ.get('TERM_PROGRAM') == 'vscode':
            return True

        # Legacy PowerShell or CMD — no Unicode support
        return False

    def _find_medusa_script(self) -> Optional[Path]:
        """Find medusa.sh script (optional - only for non-Python files)"""
        candidates = [
            self.project_root / ".claude/agents/medusa/medusa.sh",
            Path(__file__).parent / "medusa.sh",
            Path.cwd() / "medusa.sh",
        ]

        for candidate in candidates:
            if candidate.exists():
                return candidate

        # Return None if not found - Python scanning will still work
        return None

    def _detect_virtual_environments(self) -> List[str]:
        """Auto-detect virtual environment directories in the project"""
        venv_markers = ['pyvenv.cfg', 'pip-selfcheck.json']
        detected_venvs = []

        # Scan top-level directories for venv markers
        try:
            for item in self.project_root.iterdir():
                if item.is_dir():
                    # Check for pyvenv.cfg (definitive venv marker)
                    if (item / 'pyvenv.cfg').exists():
                        detected_venvs.append(item.name + '/')
                    # Check for typical venv structure (bin/activate or Scripts/activate.bat)
                    elif (item / 'bin' / 'activate').exists() or (item / 'Scripts' / 'activate.bat').exists():
                        detected_venvs.append(item.name + '/')
        except PermissionError:
            pass

        return detected_venvs

    def find_scannable_files(self) -> List[Path]:
        """Find all files that can be scanned.

        Uses a single os.walk() pass to classify all files, replacing
        the previous ~57 separate rglob/glob calls.
        """
        files: List[Path] = []
        files_set: Set[Path] = set()

        # Use exclusions from config + auto-detected virtual environments
        exclude_paths = list(self.config.exclude_paths)  # Make a copy
        exclude_file_patterns = self.config.exclude_files

        # Auto-detect virtual environments and add to exclusions
        detected_venvs = self._detect_virtual_environments()
        for venv in detected_venvs:
            if venv not in exclude_paths:
                exclude_paths.append(venv)

        # -- Task 2: Pre-compile exclusion patterns into regex -----------
        # Build a set of exact directory names for O(1) dir pruning
        _exact_dir_excludes: Set[str] = set()
        _path_exclude_patterns_cleaned: List[str] = []
        _fnmatch_dir_regexes: List[re.Pattern] = []
        for pattern in exclude_paths:
            pattern_clean = pattern.rstrip('/')
            _path_exclude_patterns_cleaned.append(pattern_clean)
            if '*' not in pattern_clean and '?' not in pattern_clean and '[' not in pattern_clean:
                _exact_dir_excludes.add(pattern_clean)
            else:
                try:
                    _fnmatch_dir_regexes.append(
                        re.compile(fnmatch.translate(pattern_clean))
                    )
                except re.error:
                    pass

        # Pre-compile file exclusion patterns into a single combined regex
        _file_exclude_re: Optional[re.Pattern] = None
        if exclude_file_patterns:
            _file_parts = []
            for fp in exclude_file_patterns:
                try:
                    _file_parts.append(fnmatch.translate(fp))
                except re.error:
                    pass
            if _file_parts:
                _file_exclude_re = re.compile('|'.join(_file_parts))

        # Pre-compile full-path exclusion regexes (for substring and wildcard checks)
        _fullpath_regexes: List[re.Pattern] = []
        for pc in _path_exclude_patterns_cleaned:
            # For substring matching: compile a pattern that matches pc anywhere in the path
            try:
                _fullpath_regexes.append(re.compile(re.escape(pc)))
            except re.error:
                pass
            # For wildcard patterns, also add a full-path wildcard match
            if '*' in pc or '?' in pc or '[' in pc:
                try:
                    _fullpath_regexes.append(
                        re.compile(fnmatch.translate('*' + pc + '*'))
                    )
                except re.error:
                    pass

        def _is_dir_excluded(dir_name: str) -> bool:
            """Fast check if a single directory component should be pruned."""
            if dir_name in _exact_dir_excludes:
                return True
            for regex in _fnmatch_dir_regexes:
                if regex.match(dir_name):
                    return True
            return False

        def _is_path_excluded(relative_path: str, path_parts: List[str], file_name: str) -> bool:
            """Check if a file's relative path matches any exclusion."""
            # Check each path component against dir exclusions
            for part in path_parts:
                if part in _exact_dir_excludes:
                    return True
                for regex in _fnmatch_dir_regexes:
                    if regex.match(part):
                        return True

            # Check full path for substring/wildcard matches
            for regex in _fullpath_regexes:
                if regex.search(relative_path):
                    return True

            # Check file name exclusions
            if _file_exclude_re and _file_exclude_re.match(file_name):
                return True

            return False

        # -- Task 1: Build lookup sets for file classification -----------
        scannable_extensions: Set[str] = set(self.FILE_SCANNERS.keys())

        # Exact special file names (case-sensitive)
        special_exact_names: Set[str] = {
            'mcp.json', 'mcp-config.json', 'mcp_config.json',
            'claude_desktop_config.json', '.mcp.json',
            '.cursorrules', 'cursorrules', '.cursor-rules',
            'CLAUDE.md', '.claude.md', 'claude.md',
            'AGENTS.md', 'agents.md',
            'copilot-instructions.md',
            'ai-instructions.md', 'system-prompt.md', 'system-prompt.txt',
        }

        # Prefixes for special file matching
        special_prefixes = ('Dockerfile', '.env')

        # .env suffix matching (*.env files like production.env)
        env_suffix = '.env'

        # AI context directories where we collect *.md files
        ai_context_dir_names: Set[str] = {'.claude', '.github', '.cursor'}

        # Helper to add a file with quick-mode/cache check
        def _maybe_add(file_path: Path) -> None:
            if file_path in files_set:
                return
            if self.quick_mode and self.cache:
                if not self.cache.is_file_changed(file_path):
                    return
            files.append(file_path)
            files_set.add(file_path)

        # -- Single os.walk() pass over the project tree -----------------
        project_root_str = str(self.project_root)

        for root, dirs, filenames in os.walk(self.project_root):
            # Prune excluded directories in-place to skip entire subtrees.
            # .git is always excluded (version control internals, not scannable).
            # Note: .github is NOT excluded here -- it may contain AI context files.
            dirs[:] = [
                d for d in dirs
                if d != '.git' and not _is_dir_excluded(d)
            ]

            # Compute relative path components once for this directory
            rel_dir = os.path.relpath(root, project_root_str)
            if rel_dir == '.':
                dir_parts: List[str] = []
            else:
                dir_parts = rel_dir.split(os.sep)

            # Check if this is an AI context directory (top-level only)
            is_ai_context_dir = (
                len(dir_parts) == 1 and dir_parts[0] in ai_context_dir_names
            )

            for filename in filenames:
                file_path = Path(root) / filename

                # Build relative path for exclusion checking
                if dir_parts:
                    relative_path = os.sep.join(dir_parts) + os.sep + filename
                    all_parts = dir_parts + [filename]
                else:
                    relative_path = filename
                    all_parts = [filename]

                # Check exclusions
                if _is_path_excluded(relative_path, all_parts, filename):
                    continue

                # Classify the file
                matched = False
                ext = os.path.splitext(filename)[1].lower()

                # 1. Extension match (covers the ~33 rglob calls)
                if ext in scannable_extensions:
                    matched = True

                # 2. Exact special file names (MCP configs, AI context files)
                if not matched and filename in special_exact_names:
                    matched = True

                # 3. Prefix match: Dockerfile*, .env*
                if not matched:
                    for prefix in special_prefixes:
                        if filename.startswith(prefix):
                            matched = True
                            break

                # 4. Suffix match: *.env (e.g., production.env)
                if not matched and filename.endswith(env_suffix):
                    matched = True

                # 5. *.md files inside AI context directories
                if not matched and is_ai_context_dir and ext == '.md':
                    matched = True

                if matched:
                    _maybe_add(file_path)

        # -- Direct path checks outside the target directory -------------
        # User home MCP configs (Claude Desktop, Cursor)
        home = Path.home()
        user_mcp_configs = [
            home / '.config' / 'Claude' / 'claude_desktop_config.json',
            home / '.cursor' / 'mcp.json',
        ]
        for mcp_file in user_mcp_configs:
            if mcp_file.exists() and mcp_file.is_file():
                _maybe_add(mcp_file)

        return sorted(files)

    @staticmethod
    def _file_size(file_path: Path) -> int:
        """Return file size in bytes, 0 on error."""
        try:
            return file_path.stat().st_size
        except OSError:
            return 0

    def scan_file(self, file_path: Path) -> ScanResult:
        """Scan a single file using ALL applicable scanners from registry.

        Enforces two safety mechanisms to prevent hangs on large data files:
        1. Files larger than MAX_SCAN_FILE_SIZE are skipped entirely.
        2. Each individual scanner is wrapped in a PER_SCANNER_TIMEOUT guard.
        """
        start_time = time.time()

        # Skip symlinks — following them during --git scans can leak host files
        if file_path.is_symlink():
            return ScanResult(
                file=str(file_path),
                scanner='skipped-symlink',
                issues=[],
                scan_time=0.0,
                cached=False
            )

        # Check cache first
        if self.use_cache and self.cache and not self.cache.is_file_changed(file_path):
            cached_meta = self.cache.cache.get(str(file_path.absolute()))
            if cached_meta:
                return ScanResult(
                    file=str(file_path),
                    scanner='cached',
                    issues=cached_meta.cached_issues,
                    scan_time=time.time() - start_time,
                    cached=True
                )

        # --- File size guard ---
        # Data files (73MB JSON datasets, large logs, vendor bundles) will
        # hang regex scanners for minutes.  Skip them outright.
        file_size = self._file_size(file_path)
        if file_size > MAX_SCAN_FILE_SIZE:
            return ScanResult(
                file=str(file_path),
                scanner='skipped-large-file',
                issues=[],
                scan_time=time.time() - start_time,
                cached=False,
                scanner_stats={'skipped-large-file': 0}
            )

        # Reuse pre-mapped scanners if available, otherwise look up fresh
        scanners = self._scanner_map.get(str(file_path))
        if scanners is None:
            scanners = scanner_registry.get_scanners_for_file(file_path)

        all_issues = []
        scanner_names = []
        scanner_issue_counts = {}  # Track issues per scanner
        seen_issues = set()  # Deduplicate by (line, message_prefix)

        for scanner in scanners:
            try:
                scanner_result = self._run_scanner_with_timeout(
                    scanner, file_path, PER_SCANNER_TIMEOUT
                )
                if scanner_result is None:
                    # Scanner timed out -- skip it
                    continue
                scanner_name = scanner_result.scanner_name
                scanner_names.append(scanner_name)
                issues_from_this = 0

                for issue in scanner_result.issues:
                    # Deduplicate: same line + first 80 chars of message
                    dedup_key = (issue.line, issue.message[:80] if issue.message else '')
                    if dedup_key not in seen_issues:
                        seen_issues.add(dedup_key)
                        d = issue.to_dict()
                        d['_scanner_name'] = scanner_name  # Per-issue attribution
                        all_issues.append(d)
                        issues_from_this += 1

                scanner_issue_counts[scanner_name] = issues_from_this
            except Exception:
                # Don't let one scanner failure stop others
                continue

        # Count lines from the file content (avoids re-opening in generate_report)
        _line_count = 0
        try:
            with open(file_path, 'rb') as _f:
                _line_count = _f.read().count(b'\n') + 1
        except Exception:
            _line_count = 0

        if scanner_names:
            result = ScanResult(
                file=str(file_path),
                scanner=scanner_names[0],  # Primary scanner (highest confidence)
                issues=all_issues,
                scan_time=time.time() - start_time,
                cached=False,
                scanner_stats=scanner_issue_counts,
                line_count=_line_count
            )
        else:
            result = ScanResult(
                file=str(file_path),
                scanner='unsupported',
                issues=[],
                scan_time=time.time() - start_time,
                cached=False,
                line_count=_line_count
            )

        # Update cache — store serialized issues so cache hits return real findings
        if self.use_cache and self.cache:
            serialized = [i.to_dict() if hasattr(i, 'to_dict') else i for i in result.issues]
            self.cache.update_cache(file_path, len(result.issues), serialized)

        return result

    @staticmethod
    def _run_scanner_with_timeout(scanner, file_path: Path, timeout: int):
        """Run a single scanner with a wall-clock timeout.

        Uses signal.SIGALRM on Unix.  On Windows (no SIGALRM) the scanner
        runs without a hard timeout -- the file-size guard above is the
        primary protection there.

        Returns:
            ScannerResult on success, None on timeout.
        """
        # signal.alarm is only available on Unix
        if sys.platform == 'win32':
            return scanner.scan_file(file_path)

        class _ScannerTimeout(Exception):
            pass

        def _alarm_handler(signum, frame):
            raise _ScannerTimeout()

        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(timeout)
        try:
            result = scanner.scan_file(file_path)
            signal.alarm(0)  # cancel alarm
            return result
        except _ScannerTimeout:
            return None
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    def _pre_map_scanners(self, files: List[Path]) -> Dict[str, int]:
        """Pre-compute how many files each scanner will handle.

        Also populates self._scanner_map so scan_file() can skip the
        duplicate get_scanners_for_file() call.

        Reads the first 8KB of each file once and passes it as
        ``content_head`` so that scanners which override
        ``get_confidence_score()`` can avoid redundant file I/O.
        """
        scanner_file_counts: Dict[str, int] = {}
        self._scanner_map = {}
        for file_path in files:
            # Read first 8KB once; shared across all scanners for this file
            content_head: Optional[str] = None
            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
                    content_head = fh.read(8192)
            except (OSError, IOError):
                pass

            scanners = scanner_registry.get_scanners_for_file(
                file_path, content_head=content_head
            )
            self._scanner_map[str(file_path)] = scanners
            for scanner in scanners:
                name = scanner.name
                scanner_file_counts[name] = scanner_file_counts.get(name, 0) + 1
        return scanner_file_counts

    @staticmethod
    def _accumulate_scanner_stats(result: 'ScanResult',
                                  scanner_totals: Dict[str, Dict[str, int]]) -> int:
        """Accumulate per-scanner statistics from a single scan result.

        Updates *scanner_totals* in place and returns the number of issues
        added so the caller can maintain its own running total.
        """
        added = 0
        if result.scanner_stats:
            for name, issue_count in result.scanner_stats.items():
                if name not in scanner_totals:
                    scanner_totals[name] = {'files': 0, 'issues': 0}
                scanner_totals[name]['files'] += 1
                scanner_totals[name]['issues'] += issue_count
                added += issue_count
        return added

    def _make_progress_bar(self, completed: int, total: int, width: int = 14) -> str:
        """Create a text-based progress bar (ASCII fallback for legacy terminals)"""
        fill_char = '#' if self.force_ascii else '\u2588'
        empty_char = '-' if self.force_ascii else '\u2591'
        if total == 0:
            return empty_char * width + '  0%'
        ratio = min(completed / total, 1.0)
        filled = int(width * ratio)
        empty = width - filled
        pct = int(ratio * 100)
        return fill_char * filled + empty_char * empty + f' {pct:>3}%'

    def _build_live_table(self, scanner_expected: Dict[str, int],
                          scanner_totals: Dict[str, Dict[str, int]],
                          files_done: int, total_files: int,
                          total_issues: int) -> Table:
        """Build a Rich table showing per-scanner progress"""
        table = Table(
            title=f"MEDUSA Scan Progress ({self.workers} workers, each file \u2192 multiple scanners)",
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            pad_edge=True,
            expand=False,
        )
        table.add_column("Scanner", style="white", min_width=26)
        table.add_column("Status", justify="center", min_width=8)
        table.add_column("Files Checked", justify="right", min_width=5)
        table.add_column("Issues", justify="right", min_width=6)
        table.add_column("Progress", min_width=19)

        # Sort scanners: active with issues first, then active, then queued
        all_scanner_names = set(scanner_expected.keys()) | set(scanner_totals.keys())

        def sort_key(name):
            stats = scanner_totals.get(name, {'files': 0, 'issues': 0})
            expected = scanner_expected.get(name, 0)
            done = stats['files']
            issues = stats['issues']
            # Priority: has issues (0), active (1), done-no-issues (2), queued (3)
            if done > 0 and issues > 0:
                priority = 0
            elif done > 0 and done >= expected:
                priority = 2
            elif done > 0:
                priority = 1
            else:
                priority = 3
            return (priority, -issues, -done, name)

        sorted_names = sorted(all_scanner_names, key=sort_key)

        # Limit to top 20 scanners to keep table manageable
        show_names = sorted_names[:20]
        hidden = len(sorted_names) - len(show_names)

        scan_complete = files_done >= total_files and total_files > 0

        for name in show_names:
            expected = scanner_expected.get(name, 0)
            stats = scanner_totals.get(name, {'files': 0, 'issues': 0})
            done = stats['files']
            issues = stats['issues']

            # Status (ASCII fallback for legacy PowerShell/CMD)
            # When all files are processed, mark every scanner that ran as Done
            if (done >= expected and expected > 0) or (scan_complete and done > 0):
                status = Text("+ Done" if self.force_ascii else "\u2713 Done", style="green")
            elif done > 0:
                status = Text("> Active" if self.force_ascii else "\u27f3 Active", style="yellow")
            else:
                status = Text("- Queued" if self.force_ascii else "\u25e6 Queued", style="dim")

            # Issues display
            if issues > 0:
                issue_text = Text(str(issues), style="bold red")
            else:
                issue_text = Text("·", style="dim")

            # Progress bar - show 100% for scanners that ran when scan is complete
            if scan_complete and done > 0:
                bar = self._make_progress_bar(expected, expected)
            else:
                bar = self._make_progress_bar(done, expected)
            if (done >= expected and expected > 0) or (scan_complete and done > 0):
                bar_text = Text(bar, style="green")
            elif done > 0:
                bar_text = Text(bar, style="yellow")
            else:
                bar_text = Text(bar, style="dim")

            table.add_row(name, status, str(done), issue_text, bar_text)

        if hidden > 0:
            table.add_row(
                Text(f"  +{hidden} more scanners", style="dim"),
                Text("", style="dim"), "", "", ""
            )

        # Separator and overall row
        table.add_section()
        overall_bar = self._make_progress_bar(files_done, total_files)
        overall_bar_text = Text(overall_bar, style="bold cyan")
        table.add_row(
            Text("Overall", style="bold"),
            Text(f"{int(files_done/total_files*100)}%" if total_files > 0 else "0%", style="bold cyan"),
            f"{files_done}/{total_files}",
            Text(str(total_issues), style="bold"),
            overall_bar_text,
        )

        return table

    def scan_parallel(self, files: List[Path]) -> List[ScanResult]:
        """Scan files in parallel with live progress table"""
        _icon = '*' if self.force_ascii else '\U0001f4ca'
        print(f"{_icon} Scanning {len(files)} files across {self.workers} parallel workers (each file is checked by all applicable scanners)...\n")

        # Pre-map which scanners will handle which files
        scanner_expected = self._pre_map_scanners(files)

        # Pre-warm YAML rules in the main process before Pool() forks workers.
        # Linux fork() uses copy-on-write, so workers inherit compiled patterns
        # at zero cost. Without this, each worker independently pays the ~1.8s
        # cold-start to load and compile all 9,600+ rules from 145 YAML files.
        for scanner in scanner_registry.scanners:
            if hasattr(scanner, '_load_rules'):
                scanner._load_rules()

        # Run external tools once against the project root before the Pool forks.
        # Each tool has startup overhead per invocation; running per-file creates O(N)
        # startups. One batch run amortises that cost across all files.
        # Workers inherit the populated caches via copy-on-write fork semantics.
        if files:
            import os as _os
            _common = Path(_os.path.commonpath([str(f) for f in files]))
            _project_root = _common if _common.is_dir() else _common.parent
            _icon2 = '*' if self.force_ascii else '\U0001f50d'

            from medusa.scanners.semgrep_scanner import SemgrepScanner as _SemgrepScanner
            _semgrep = next(
                (s for s in scanner_registry.scanners if isinstance(s, _SemgrepScanner)),
                None,
            )
            if _semgrep and _semgrep.is_available():
                print(f"{_icon2} Running Semgrep batch scan on {_project_root}...")
                _semgrep.scan_project(_project_root)

            from medusa.scanners.trivy_scanner import TrivyScanner as _TrivyScanner
            _trivy = next(
                (s for s in scanner_registry.scanners if isinstance(s, _TrivyScanner)),
                None,
            )
            if _trivy and _trivy.is_available():
                print(f"{_icon2} Running Trivy batch scan on {_project_root}...")
                _trivy.scan_project(_project_root)

            from medusa.scanners.gitleaks_scanner import GitLeaksScanner as _GitLeaksScanner
            _gitleaks = next(
                (s for s in scanner_registry.scanners if isinstance(s, _GitLeaksScanner)),
                None,
            )
            if _gitleaks and _gitleaks.is_available():
                print(f"{_icon2} Running GitLeaks batch scan on {_project_root}...")
                _gitleaks.scan_project(_project_root)

        try:
            if HAS_RICH:
                results = self._scan_with_live_table(files, scanner_expected)
            elif HAS_TQDM:
                results = self._scan_with_tqdm(files)
            else:
                results = self._scan_with_pool(files)
        except (PermissionError, OSError) as e:
            # Fallback to sequential scanning if multiprocessing fails
            _ic = '!' if self.force_ascii else '\u26a0\ufe0f'
            print(f"{_ic}  Multiprocessing unavailable ({e}), falling back to sequential scan...")
            results = self._scan_sequential(files, scanner_expected)

        return results

    def _scan_with_live_table(self, files: List[Path], scanner_expected: Dict[str, int]) -> List[ScanResult]:
        """Scan with Rich live-updating table"""
        import time as _time
        results = []
        scanner_totals = {}
        total_issues = 0
        console = RichConsole()
        last_update = _time.time()
        update_interval = 0.5  # Update at most 2x per second

        # Only use Live display when stdout is a real TTY (not piped/redirected)
        # and the terminal supports it. Live fails on non-TTY or when other
        # output (warnings, cache errors) interrupts cursor movement.
        use_live = not self.force_ascii and sys.stdout.isatty()
        use_screen = sys.platform == 'win32'  # Windows needs alternate screen buffer

        # Cap chunksize to keep live table responsive on large projects.
        # Without a cap, 4000+ files with 6 workers yields chunksize=166,
        # meaning the table only updates ~24 times total.
        chunksize = min(8, max(1, len(files) // (self.workers * 4)))

        with Pool(processes=self.workers) as pool:
            if use_live:
                # Live updating table - uses stderr to avoid corruption from stray stdout
                live_console = RichConsole(stderr=True)
                with Live(
                    self._build_live_table(scanner_expected, scanner_totals, 0, len(files), 0),
                    console=live_console,
                    refresh_per_second=2,  # Lower refresh rate for stability
                    transient=True,  # Clear when done (we'll print final table after)
                    screen=use_screen,  # Use alternate screen on Windows
                ) as live:
                    for result in pool.imap_unordered(self.scan_file, files, chunksize=chunksize):
                        results.append(result)

                        # Update per-scanner stats
                        total_issues += self._accumulate_scanner_stats(result, scanner_totals)

                        # Update live table (throttled)
                        now = _time.time()
                        if now - last_update >= update_interval:
                            live.update(self._build_live_table(
                                scanner_expected, scanner_totals,
                                len(results), len(files), total_issues
                            ))
                            last_update = now

                    # Final update to show 100% complete
                    live.update(self._build_live_table(
                        scanner_expected, scanner_totals,
                        len(results), len(files), total_issues
                    ))

                # Print final table on main screen (after Live context exits)
                console.print(self._build_live_table(
                    scanner_expected, scanner_totals,
                    len(results), len(files), total_issues
                ))
                print()
            else:
                # Legacy terminals: simple progress without live table
                print(f"  Scanning: ", end="", flush=True)
                last_pct = 0
                for result in pool.imap_unordered(self.scan_file, files, chunksize=chunksize):
                    results.append(result)

                    # Update per-scanner stats
                    total_issues += self._accumulate_scanner_stats(result, scanner_totals)

                    # Show progress every 10%
                    pct = (len(results) * 100) // len(files)
                    if pct >= last_pct + 10:
                        print(f"{pct}%...", end="", flush=True)
                        last_pct = pct

                print(" Done!")
                print()
                # Print final table once for legacy terminals
                console.print(self._build_live_table(
                    scanner_expected, scanner_totals,
                    len(results), len(files), total_issues
                ))
                print()

        return results

    def _scan_with_tqdm(self, files: List[Path]) -> List[ScanResult]:
        """Fallback: scan with tqdm progress bar"""
        results = []
        scanner_totals = {}

        chunksize = min(8, max(1, len(files) // (self.workers * 4)))
        with Pool(processes=self.workers) as pool:
            pbar = tqdm(
                pool.imap_unordered(self.scan_file, files, chunksize=chunksize),
                total=len(files),
                desc="Scanning files",
                unit="file"
            )
            for result in pbar:
                results.append(result)
                self._accumulate_scanner_stats(result, scanner_totals)

        if scanner_totals:
            self._print_scanner_summary(scanner_totals)

        return results

    def _scan_with_pool(self, files: List[Path]) -> List[ScanResult]:
        """Fallback: scan with basic Pool.map"""
        with Pool(processes=self.workers) as pool:
            results = pool.map(self.scan_file, files)
            _ic = '+' if self.force_ascii else '\u2705'
            print(f"{_ic} Scanned {len(files)} files")
        return results

    def _print_scanner_summary(self, scanner_totals: Dict[str, Dict[str, int]]):
        """Print a clean per-scanner summary table (tqdm fallback)"""
        print()
        _ic = '*' if self.force_ascii else '\U0001f527'
        _sep = '-' if self.force_ascii else '\u2500'
        print(f"{_ic} Scanner Activity:")
        print(f"   {'Scanner':<30} {'Files':>6} {'Issues':>7}")
        print(f"   {_sep * 45}")

        sorted_scanners = sorted(
            scanner_totals.items(),
            key=lambda x: (-x[1]['issues'], -x[1]['files'])
        )

        for name, stats in sorted_scanners:
            issue_str = str(stats['issues']) if stats['issues'] > 0 else '·'
            print(f"   {name:<30} {stats['files']:>6} {issue_str:>7}")

        print()

    def _scan_sequential(self, files: List[Path], scanner_expected: Dict[str, int] = None) -> List[ScanResult]:
        """Fallback sequential scanning for sandboxed environments"""
        results = []
        scanner_totals = {}
        total_issues = 0

        if scanner_expected is None:
            scanner_expected = self._pre_map_scanners(files)

        if HAS_RICH and not self.force_ascii and sys.stdout.isatty():
            import time as _time
            live_console = RichConsole(stderr=True)
            last_update = _time.time()
            update_interval = 0.25  # Update display at most 4x per second
            use_screen = sys.platform == 'win32'  # Alternate screen on Windows
            with Live(
                self._build_live_table(scanner_expected, scanner_totals, 0, len(files), 0),
                console=live_console,
                refresh_per_second=2,
                transient=True,
                screen=use_screen,
            ) as live:
                for file_path in files:
                    result = self.scan_file(file_path)
                    results.append(result)
                    total_issues += self._accumulate_scanner_stats(result, scanner_totals)
                    # Throttled update
                    now = _time.time()
                    if now - last_update >= update_interval:
                        live.update(self._build_live_table(
                            scanner_expected, scanner_totals,
                            len(results), len(files), total_issues
                        ))
                        last_update = now

                # Final update
                live.update(self._build_live_table(
                    scanner_expected, scanner_totals,
                    len(results), len(files), total_issues
                ))
            # Print final table on main screen
            console.print(self._build_live_table(
                scanner_expected, scanner_totals,
                len(results), len(files), total_issues
            ))
            print()
        elif HAS_RICH:
            # Legacy Windows: simple progress then final table
            console = RichConsole()
            print(f"  Scanning: ", end="", flush=True)
            last_pct = 0
            for file_path in files:
                result = self.scan_file(file_path)
                results.append(result)
                total_issues += self._accumulate_scanner_stats(result, scanner_totals)
                pct = (len(results) * 100) // len(files)
                if pct >= last_pct + 10:
                    print(f"{pct}%...", end="", flush=True)
                    last_pct = pct
            print(" Done!")
            print()
            console.print(self._build_live_table(
                scanner_expected, scanner_totals,
                len(results), len(files), total_issues
            ))
            print()
        elif HAS_TQDM:
            for file_path in tqdm(files, desc="Scanning files", unit="file"):
                result = self.scan_file(file_path)
                results.append(result)
        else:
            for i, file_path in enumerate(files, 1):
                results.append(self.scan_file(file_path))
                if i % 10 == 0:
                    print(f"   Scanned {i}/{len(files)} files...")
            _ic = '+' if self.force_ascii else '\u2705'
            print(f"{_ic} Scanned {len(files)} files (sequential mode)")

        return results

    def generate_report(self, results: List[ScanResult], output_dir: Path, formats: List[str] = None, missing_linters: List[str] = None):
        """Generate reports in requested formats (json, html, markdown)"""
        if formats is None:
            formats = ['json', 'html']

        from medusa.core.reporter import MedusaReportGenerator
        from datetime import datetime

        # Aggregate findings from all scan results
        findings = []
        total_issues = 0
        cached_count = sum(1 for r in results if r.cached)
        file_metrics = {}

        for result in results:
            if not result.cached:
                total_issues += len(result.issues)

                # Use line_count stored during scan (avoids re-opening every file)
                file_metrics[result.file] = {'loc': result.line_count}

                # Convert to standardized format
                for issue in result.issues:
                    # Handle old dict format (backward compatibility)
                    if isinstance(issue, dict):
                        findings.append({
                            'scanner': issue.get('_scanner_name', result.scanner) or 'unknown',
                            'file': result.file,
                            'line': issue.get('line_number', issue.get('line', 0)),
                            'severity': issue.get('issue_severity', issue.get('severity', 'MEDIUM')),
                            'confidence': issue.get('issue_confidence', 'HIGH'),
                            'issue': issue.get('issue_text', issue.get('message', str(issue))),
                            'cwe': issue.get('issue_cwe', {}).get('id'),
                            'code': _truncate_code(issue.get('code', ''))
                        })
                    # Handle new ScannerIssue object format
                    else:
                        findings.append({
                            'scanner': result.scanner or 'unknown',
                            'file': result.file,
                            'line': issue.line,
                            'severity': issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity),
                            'confidence': 'HIGH',
                            'issue': issue.message,
                            'cwe': issue.cwe_id,
                            'code': _truncate_code(issue.code)
                        })

        # Apply FP filter to reduce false positives
        fp_stats = None
        likely_fps = []
        original_count = len(findings)
        try:
            from medusa.core.fp_filter import FalsePositiveFilter
            fp_filter = FalsePositiveFilter(self.project_root)
            findings, likely_fps = fp_filter.filter_findings(findings)
            # Calculate stats without re-filtering
            fp_stats = {
                'total_findings': original_count,
                'likely_fps': len(likely_fps),
                'retained': len(findings),
                'fp_rate': (len(likely_fps) / original_count * 100) if original_count > 0 else 0,
            }
        except Exception as e:
            # FP filter is optional - continue if it fails
            _ic = '!' if self.force_ascii else '\u26a0\ufe0f'
            print(f"{_ic}  FP filter skipped: {e}")

        # Calculate total lines
        total_lines = sum(m.get('loc', 0) for m in file_metrics.values())

        # Prepare scan results for reporter
        scan_results = {
            'findings': findings,
            'likely_fps': likely_fps,
            'fp_stats': fp_stats,
            'files_scanned': len(results) - cached_count,
            'total_lines_scanned': total_lines,
            'missing_linters': missing_linters or [],
        }

        # Initialize reporter
        generator = MedusaReportGenerator(output_dir)
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')

        generated_files = []

        # Generate JSON report
        if 'json' in formats:
            json_path = generator.generate_json_report(scan_results, output_dir / f"medusa-scan-{timestamp}.json")
            generated_files.append(('JSON', json_path))

        # Generate HTML report
        if 'html' in formats:
            # First need JSON for HTML generation
            if 'json' not in formats:
                json_path = generator.generate_json_report(scan_results, output_dir / f"medusa-scan-{timestamp}.json")
            html_path = generator.generate_html_report(json_path, output_dir / f"medusa-scan-{timestamp}.html")
            generated_files.append(('HTML', html_path))

        # Generate Markdown report
        if 'markdown' in formats:
            md_path = generator.generate_markdown_report(scan_results, output_dir / f"medusa-scan-{timestamp}.md")
            generated_files.append(('Markdown', md_path))

        # Print generated files
        _ascii = self.force_ascii
        if generated_files:
            _ic = '*' if _ascii else '\U0001f4ca'
            print(f"\n{_ic} Reports generated:")
            _arrow = '->' if _ascii else '\u2192'
            for format_name, file_path in generated_files:
                try:
                    display_path = os.path.relpath(file_path)
                except ValueError:
                    display_path = file_path
                print(f"   {format_name:10} {_arrow} {display_path}")

        # Show unique scanners that ran (extracted from scanner_stats)
        unique_scanners = set()
        for result in results:
            if result.scanner_stats:
                unique_scanners.update(result.scanner_stats.keys())
            elif result.scanner and result.scanner not in ('cached', 'unsupported'):
                unique_scanners.add(result.scanner)

        # Print summary with colour
        _con = RichConsole()
        _ic = '>' if _ascii else '\U0001f3af'
        _bar = "[dim]" + "\u2500" * 44 + "[/dim]"
        _con.print()
        _con.print(_bar)
        _con.print(f"  {_ic} [bold cyan]SCAN COMPLETE[/bold cyan]")
        _con.print(_bar)

        _w = 20  # label width for alignment
        total_time = sum(r.scan_time for r in results)
        _con.print(f"  [dim]{'Files scanned:':<{_w}}[/dim] [white]{len(results) - cached_count}[/white]")
        _con.print(f"  [dim]{'Lines of code:':<{_w}}[/dim] [white]{total_lines:,}[/white]")
        _con.print(f"  [dim]{'Issues found:':<{_w}}[/dim] [bold yellow]{len(findings)}[/bold yellow]")
        if likely_fps:
            _con.print(f"  [dim]{'FPs filtered:':<{_w}}[/dim] [green]{len(likely_fps)}[/green]")
            if fp_stats:
                fp_rate = fp_stats.get('fp_rate', 0)
                _con.print(f"  [dim]{'FP reduction:':<{_w}}[/dim] [green]{fp_rate:.1f}%[/green]")
        _con.print(f"  [dim]{'Scanners used:':<{_w}}[/dim] [white]{len(unique_scanners)}[/white]")
        _con.print(f"  [dim]{'Total time:':<{_w}}[/dim] [white]{total_time:.2f}s[/white]")
        if self.use_cache:
            _con.print(f"  [dim]{'Cache hit rate:':<{_w}}[/dim] [white]{100*cached_count/len(results):.1f}%[/white]")

        _con.print(_bar)
