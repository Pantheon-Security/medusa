#!/usr/bin/env python3
"""
MEDUSA Parallel Scanner v0.7.0
High-performance parallel security scanning with caching and incremental modes

Features:
- Parallel execution (auto-detect CPU cores)
- File-level caching (skip unchanged files)
- Quick scan mode (changed files only)
- Progress tracking with tqdm
- JSON/HTML reporting via medusa-report.py
- Pluggable scanner architecture with registry
"""

import os
import sys
import json
import hashlib
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from multiprocessing import Pool, cpu_count
from dataclasses import dataclass, asdict
from datetime import datetime
import argparse

# Import new scanner architecture
from medusa.scanners import registry as scanner_registry

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    print("⚠️  Install tqdm for progress bars: pip install tqdm")


@dataclass
class FileMetadata:
    """Metadata for cached file scanning"""
    path: str
    size: int
    mtime: float
    hash: str
    last_scan: str
    issues_found: int


@dataclass
class ScanResult:
    """Result from scanning a single file"""
    file: str
    scanner: str
    issues: List[Dict]
    scan_time: float
    cached: bool = False


class MedusaCacheManager:
    """Manage file scanning cache for incremental scans"""

    def __init__(self, cache_dir: Path = None):
        self.cache_dir = cache_dir or Path.home() / ".medusa" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "file_cache.json"
        self.cache: Dict[str, FileMetadata] = self._load_cache()

    def _load_cache(self) -> Dict[str, FileMetadata]:
        """Load cache from disk"""
        if not self.cache_file.exists():
            return {}

        try:
            with open(self.cache_file) as f:
                data = json.load(f)
            return {
                path: FileMetadata(**meta)
                for path, meta in data.items()
            }
        except Exception as e:
            print(f"⚠️  Cache load error: {e}")
            return {}

    def _save_cache(self):
        """Save cache to disk"""
        try:
            data = {
                path: asdict(meta)
                for path, meta in self.cache.items()
            }
            with open(self.cache_file, 'w') as f:
                json.dump(data, f, indent=2)
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

            # Hash check (slower but accurate)
            current_hash = self._get_file_hash(file_path)
            return current_hash != cached.hash

        except Exception:
            return True

    def update_cache(self, file_path: Path, issues_found: int):
        """Update cache entry for scanned file"""
        try:
            stat = file_path.stat()
            self.cache[str(file_path.absolute())] = FileMetadata(
                path=str(file_path.absolute()),
                size=stat.st_size,
                mtime=stat.st_mtime,
                hash=self._get_file_hash(file_path),
                last_scan=datetime.now().isoformat(),
                issues_found=issues_found
            )
        except Exception as e:
            print(f"⚠️  Cache update error for {file_path}: {e}")

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
    }

    def __init__(self,
                 project_root: Path,
                 workers: int = None,
                 use_cache: bool = True,
                 quick_mode: bool = False):
        self.project_root = project_root.absolute()
        self.workers = workers or cpu_count()
        self.use_cache = use_cache
        self.quick_mode = quick_mode
        self.cache = MedusaCacheManager() if use_cache else None

        # Load configuration from .medusa.yml
        from medusa.config import ConfigManager
        self.config = ConfigManager.load_config()

        # Find medusa.sh (optional - only needed for non-Python scanners)
        self.medusa_script = self._find_medusa_script()

        print(f"🐍 MEDUSA Parallel Scanner v0.7.0")
        print(f"   Workers: {self.workers} cores")
        print(f"   Cache: {'enabled' if use_cache else 'disabled'}")
        print(f"   Mode: {'quick (changed files only)' if quick_mode else 'full'}")
        print()

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
        """Find all files that can be scanned"""
        import fnmatch

        files = []

        # Use exclusions from config + auto-detected virtual environments
        exclude_paths = list(self.config.exclude_paths)  # Make a copy
        exclude_file_patterns = self.config.exclude_files

        # Auto-detect virtual environments and add to exclusions
        detected_venvs = self._detect_virtual_environments()
        for venv in detected_venvs:
            if venv not in exclude_paths:
                exclude_paths.append(venv)

        def is_path_excluded(file_path: Path) -> bool:
            """Check if path matches any exclusion pattern"""
            relative_path = str(file_path.relative_to(self.project_root))
            path_parts = relative_path.split('/')

            # Check path exclusions
            for pattern in exclude_paths:
                # Remove trailing slash for directory matching
                pattern_clean = pattern.rstrip('/')

                # Check if any part of the path matches the pattern
                for part in path_parts:
                    # Exact match
                    if part == pattern_clean:
                        return True
                    # Wildcard match (e.g., *-env matches medusa-env)
                    if fnmatch.fnmatch(part, pattern_clean):
                        return True

                # Check if pattern appears anywhere in the full path
                # This catches site-packages nested inside lib/python3.x/
                if pattern_clean in relative_path:
                    return True

                # Check full path wildcard patterns (e.g., lib/python*/)
                if fnmatch.fnmatch(relative_path, f"*{pattern}*") or fnmatch.fnmatch(relative_path, f"*{pattern_clean}*"):
                    return True

            # Check file name exclusions
            file_name = file_path.name
            for pattern in exclude_file_patterns:
                if fnmatch.fnmatch(file_name, pattern):
                    return True

            return False

        for ext in self.FILE_SCANNERS.keys():
            for file_path in self.project_root.rglob(f"*{ext}"):
                if not file_path.is_file():
                    continue

                # Skip excluded paths/files
                if is_path_excluded(file_path):
                    continue

                # Quick mode: only scan changed files
                if self.quick_mode and self.cache:
                    if not self.cache.is_file_changed(file_path):
                        continue

                files.append(file_path)

        # Special cases (Dockerfile without extension)
        for dockerfile in self.project_root.rglob("Dockerfile*"):
            if dockerfile.is_file() and dockerfile not in files:
                # Skip excluded paths
                if is_path_excluded(dockerfile):
                    continue

                if not self.quick_mode or not self.cache or self.cache.is_file_changed(dockerfile):
                    files.append(dockerfile)

        # Special cases (.env files - various patterns)
        env_patterns = ['.env', '.env.*', '*.env']
        for pattern in env_patterns:
            for env_file in self.project_root.rglob(pattern):
                if env_file.is_file() and env_file not in files:
                    # Skip excluded paths
                    if is_path_excluded(env_file):
                        continue

                    if not self.quick_mode or not self.cache or self.cache.is_file_changed(env_file):
                        files.append(env_file)

        # Special cases (MCP config files)
        mcp_patterns = [
            'mcp.json', 'mcp-config.json', 'mcp_config.json',
            'claude_desktop_config.json', '.mcp.json'
        ]
        # Also check common MCP config directories
        mcp_dirs = ['.cursor', '.vscode', 'claude', '.config/Claude']
        for pattern in mcp_patterns:
            for mcp_file in self.project_root.rglob(pattern):
                if mcp_file.is_file() and mcp_file not in files:
                    if is_path_excluded(mcp_file):
                        continue
                    if not self.quick_mode or not self.cache or self.cache.is_file_changed(mcp_file):
                        files.append(mcp_file)

        # Check home directory for user MCP configs (Claude Desktop, etc.)
        home = Path.home()
        user_mcp_configs = [
            home / '.config' / 'Claude' / 'claude_desktop_config.json',
            home / '.cursor' / 'mcp.json',
        ]
        for mcp_file in user_mcp_configs:
            if mcp_file.exists() and mcp_file.is_file() and mcp_file not in files:
                if not self.quick_mode or not self.cache or self.cache.is_file_changed(mcp_file):
                    files.append(mcp_file)

        # Special cases (AI context files - cursor rules, claude instructions, etc.)
        ai_context_patterns = [
            '.cursorrules', 'cursorrules', '.cursor-rules',
            'CLAUDE.md', '.claude.md', 'claude.md',
            'AGENTS.md', 'agents.md',
            'copilot-instructions.md',
            'ai-instructions.md', 'system-prompt.md', 'system-prompt.txt',
        ]
        for pattern in ai_context_patterns:
            for ai_file in self.project_root.rglob(pattern):
                if ai_file.is_file() and ai_file not in files:
                    if is_path_excluded(ai_file):
                        continue
                    if not self.quick_mode or not self.cache or self.cache.is_file_changed(ai_file):
                        files.append(ai_file)

        # Also check .claude and .github directories for AI context files
        ai_context_dirs = ['.claude', '.github', '.cursor']
        for dir_name in ai_context_dirs:
            ai_dir = self.project_root / dir_name
            if ai_dir.is_dir():
                for ai_file in ai_dir.glob('*.md'):
                    if ai_file.is_file() and ai_file not in files:
                        if is_path_excluded(ai_file):
                            continue
                        if not self.quick_mode or not self.cache or self.cache.is_file_changed(ai_file):
                            files.append(ai_file)

        return sorted(files)

    def scan_file(self, file_path: Path) -> ScanResult:
        """Scan a single file using appropriate scanner from registry"""
        start_time = time.time()

        # Check cache first
        if self.use_cache and self.cache and not self.cache.is_file_changed(file_path):
            cached_meta = self.cache.cache.get(str(file_path.absolute()))
            if cached_meta:
                return ScanResult(
                    file=str(file_path),
                    scanner='cached',
                    issues=[],
                    scan_time=time.time() - start_time,
                    cached=True
                )

        # Find appropriate scanner from registry
        scanner = scanner_registry.get_scanner_for_file(file_path)

        if scanner:
            # Use new scanner architecture
            scanner_result = scanner.scan_file(file_path)

            # Convert new ScannerResult to old ScanResult format
            result = ScanResult(
                file=str(file_path),
                scanner=scanner_result.scanner_name.lower(),
                issues=[issue.to_dict() for issue in scanner_result.issues],
                scan_time=scanner_result.scan_time,
                cached=False
            )
        else:
            # No scanner available for this file type
            result = ScanResult(
                file=str(file_path),
                scanner='unsupported',
                issues=[],
                scan_time=time.time() - start_time,
                cached=False
            )

        # Update cache
        if self.use_cache and self.cache:
            self.cache.update_cache(file_path, len(result.issues))

        return result

    def _scan_with_bandit(self, file_path: Path) -> ScanResult:
        """Scan Python file with Bandit"""
        try:
            cmd = ['bandit', '-f', 'json', str(file_path)]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            # Bandit returns non-zero if issues found
            if result.returncode in (0, 1):
                try:
                    data = json.loads(result.stdout)
                    issues = data.get('results', [])
                    return ScanResult(
                        file=str(file_path),
                        scanner='bandit',
                        issues=issues,
                        scan_time=0
                    )
                except json.JSONDecodeError:
                    pass

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return ScanResult(
            file=str(file_path),
            scanner='bandit',
            issues=[],
            scan_time=0
        )

    def _scan_with_medusa(self, file_path: Path) -> ScanResult:
        """Scan file with medusa.sh (for non-Python files)"""
        # If medusa.sh not found, skip non-Python files
        if self.medusa_script is None:
            return ScanResult(
                file=str(file_path),
                scanner='skipped',
                issues=[],
                scan_time=0
            )

        try:
            cmd = [str(self.medusa_script), str(file_path)]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=self.project_root
            )

            # Parse output for issues (simplified - medusa.sh outputs text)
            issues = []
            # For now, just count lines with severity indicators
            for line in result.stdout.split('\n'):
                if any(sev in line for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']):
                    issues.append({'line': line})

            return ScanResult(
                file=str(file_path),
                scanner='medusa',
                issues=issues,
                scan_time=0
            )

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return ScanResult(
            file=str(file_path),
            scanner='medusa',
            issues=[],
            scan_time=0
        )

    def scan_parallel(self, files: List[Path]) -> List[ScanResult]:
        """Scan files in parallel, with fallback to sequential if multiprocessing fails"""
        print(f"📊 Scanning {len(files)} files with {self.workers} workers...")
        print()

        try:
            if HAS_TQDM:
                with Pool(processes=self.workers) as pool:
                    results = list(tqdm(
                        pool.imap(self.scan_file, files),
                        total=len(files),
                        desc="Scanning files",
                        unit="file"
                    ))
            else:
                with Pool(processes=self.workers) as pool:
                    results = pool.map(self.scan_file, files)
                    print(f"✅ Scanned {len(files)} files")
        except (PermissionError, OSError) as e:
            # Fallback to sequential scanning if multiprocessing fails
            # This happens in sandboxed environments (Codex, Docker, etc.)
            print(f"⚠️  Multiprocessing unavailable ({e}), falling back to sequential scan...")
            results = self._scan_sequential(files)

        return results

    def _scan_sequential(self, files: List[Path]) -> List[ScanResult]:
        """Fallback sequential scanning for sandboxed environments"""
        results = []
        if HAS_TQDM:
            for file_path in tqdm(files, desc="Scanning files", unit="file"):
                results.append(self.scan_file(file_path))
        else:
            for i, file_path in enumerate(files, 1):
                results.append(self.scan_file(file_path))
                if i % 10 == 0:
                    print(f"   Scanned {i}/{len(files)} files...")
            print(f"✅ Scanned {len(files)} files (sequential mode)")
        return results

    def generate_report(self, results: List[ScanResult], output_dir: Path, formats: List[str] = None):
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

                # Track file metrics
                try:
                    stat = Path(result.file).stat()
                    file_metrics[result.file] = {
                        'loc': stat.st_size // 50  # Rough line count
                    }
                except:
                    file_metrics[result.file] = {'loc': 0}

                # Convert to standardized format
                for issue in result.issues:
                    # Handle old dict format (backward compatibility)
                    if isinstance(issue, dict):
                        findings.append({
                            'scanner': result.scanner or 'unknown',
                            'file': result.file,
                            'line': issue.get('line_number', issue.get('line', 0)),
                            'severity': issue.get('issue_severity', issue.get('severity', 'MEDIUM')),
                            'confidence': issue.get('issue_confidence', 'HIGH'),
                            'issue': issue.get('issue_text', issue.get('message', str(issue))),
                            'cwe': issue.get('issue_cwe', {}).get('id', issue.get('code')),
                            'code': issue.get('code', '')
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
                            'cwe': issue.code,
                            'code': issue.code
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
            print(f"⚠️  FP filter skipped: {e}")

        # Calculate total lines
        total_lines = sum(m.get('loc', 0) for m in file_metrics.values())

        # Prepare scan results for reporter
        scan_results = {
            'findings': findings,
            'likely_fps': likely_fps,
            'fp_stats': fp_stats,
            'files_scanned': len(results) - cached_count,
            'total_lines_scanned': total_lines
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
        if generated_files:
            print(f"\n📊 Reports generated:")
            for format_name, file_path in generated_files:
                print(f"   {format_name:10} → {file_path}")

        # Print summary
        print()
        print("=" * 60)
        print(f"🎯 PARALLEL SCAN COMPLETE")
        print("=" * 60)
        print(f"📂 Files scanned: {len(results) - cached_count}")
        print(f"⚡ Files cached: {cached_count}")
        print(f"🔍 Issues found: {len(findings)}")
        if likely_fps:
            print(f"🎭 Likely false positives filtered: {len(likely_fps)}")
            if fp_stats:
                fp_rate = fp_stats.get('fp_rate', 0)
                print(f"📉 FP reduction: {fp_rate:.1f}% of findings filtered")
        print(f"⏱️  Total time: {sum(r.scan_time for r in results):.2f}s")
        if self.use_cache:
            print(f"📈 Cache hit rate: {100*cached_count/len(results):.1f}%")

        # Show which scanners/tools were actually used
        scanners_used = set()
        for result in results:
            if result.scanner and result.scanner != 'cached':
                scanners_used.add(result.scanner)

        if scanners_used:
            print(f"🔧 Scanners used: {', '.join(sorted(scanners_used))}")

        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="MEDUSA Parallel Scanner v0.7.0 - High-performance security scanning"
    )
    parser.add_argument(
        'target',
        nargs='?',
        default='.',
        help='Directory to scan (default: current directory)'
    )
    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=None,
        help=f'Number of worker processes (default: {cpu_count()})'
    )
    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Disable file caching'
    )
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick scan mode (changed files only)'
    )
    parser.add_argument(
        '--clear-cache',
        action='store_true',
        help='Clear cache and exit'
    )
    parser.add_argument(
        '-o', '--output',
        type=Path,
        default=Path.cwd() / ".medusa" / "reports",
        help='Output directory for reports'
    )

    args = parser.parse_args()

    # Clear cache if requested
    if args.clear_cache:
        cache = MedusaCacheManager()
        cache.clear()
        return

    # Initialize scanner
    project_root = Path(args.target).absolute()
    if not project_root.exists():
        print(f"❌ Target not found: {project_root}")
        sys.exit(1)

    scanner = MedusaParallelScanner(
        project_root=project_root,
        workers=args.workers,
        use_cache=not args.no_cache,
        quick_mode=args.quick
    )

    # Find files
    files = scanner.find_scannable_files()
    if not files:
        print("✅ No files to scan")
        return

    print(f"📁 Found {len(files)} scannable files")
    if args.quick and scanner.cache:
        changed = sum(1 for f in files if scanner.cache.is_file_changed(f))
        print(f"   {changed} changed files (quick mode)")
    print()

    # Scan files
    start_time = time.time()
    results = scanner.scan_parallel(files)
    scan_duration = time.time() - start_time

    print(f"\n⏱️  Scan completed in {scan_duration:.2f}s")
    print(f"   Average: {scan_duration/len(files)*1000:.1f}ms per file")
    print()

    # Generate reports
    args.output.mkdir(parents=True, exist_ok=True)
    scanner.generate_report(results, args.output)

    # Save cache
    if scanner.cache:
        scanner.cache.save()
        print("💾 Cache saved")


if __name__ == '__main__':
    main()
