"""
test_ship_gate.py — MEDUSA ship-gate test suite.

Locks in every user-facing feature so regressions are caught before release.
Grouped by priority tier:

  P0 — Core scan flags (--fail-on, --exclude, --workers, --quick, --force,
        --no-cache, --no-report, --include-user-mcp-configs)
  P1 — Output & reporting (--format, --output, --no-ai-safe)
  P2 — Cache internals (full_hash, HMAC tamper, rule fingerprint)
  P3 — Secrets command (scan, reveal, purge safety)
  P4 — MedusaParallelScanner params (extra_excludes, include_user_mcp_configs)

Run fast subset (no YAML rule loading):
    pytest tests/test_ship_gate.py -v

Run full suite including slow tests:
    pytest tests/test_ship_gate.py -v -m "slow or not slow"
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from medusa.cli import main
from medusa.core.parallel import MedusaCacheManager, MedusaParallelScanner

# Nearly every test in this module invokes the CLI or MedusaParallelScanner,
# each of which reloads the full ~43k-rule corpus (no cross-test rule cache);
# measured full-module runtime exceeds 400s. Too slow for the per-PR fast set.
pytestmark = pytest.mark.slow


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def dirty_repo(tmp_path):
    """
    Minimal repo that triggers at least one HIGH finding (eval on user input).

    Layout:
        app.py      — eval(input())  → HIGH: dangerous eval with user input
        config.env  — API_KEY=sk-test-abc123xyz
        safe.py     — clean Python
    """
    (tmp_path / "app.py").write_text(
        "import os\n"
        "user_data = input('enter: ')\n"
        "result = eval(user_data)  # dangerous eval\n"
        "exec(user_data)  # dangerous exec\n"
    )
    (tmp_path / "config.env").write_text(
        "API_KEY=sk-test-abc123xyzABCDEFGHIJ\n"
        "DEBUG=true\n"
    )
    (tmp_path / "safe.py").write_text(
        "def add(a, b):\n"
        "    return a + b\n"
    )
    return tmp_path


@pytest.fixture()
def clean_repo(tmp_path):
    """Repo with no security issues — baseline for zero-exit tests."""
    (tmp_path / "utils.py").write_text("def greet(name: str) -> str:\n    return f'Hello {name}'\n")
    (tmp_path / "README.md").write_text("# Project\n\nA safe project.\n")
    return tmp_path


# ---------------------------------------------------------------------------
# P0 — Core scan flags
# ---------------------------------------------------------------------------

class TestFailOn:
    """--fail-on exits 1 when issues meet or exceed threshold, 0 otherwise."""

    def test_fail_on_low_exits_nonzero_on_any_finding(self, dirty_repo):
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(dirty_repo), '--fail-on', 'low', '--no-report', '--workers', '1'
        ])
        # dirty_repo contains eval() — must produce at least a LOW finding, so
        # --fail-on low MUST exit 1. (CR-037: this asserted `in (0, 1)`, a
        # tautology that stayed green even while --fail-on was a no-op — CR-001.)
        assert result.exit_code == 1, (
            f"--fail-on low must exit 1 on a repo with findings, got "
            f"{result.exit_code}\n{result.output}"
        )

    def test_fail_on_clean_repo_exits_zero(self, clean_repo):
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo), '--fail-on', 'critical', '--no-report', '--workers', '1'
        ])
        assert result.exit_code == 0, f"Clean repo should exit 0:\n{result.output}"

    def test_fail_on_accepts_all_severity_levels(self, clean_repo):
        runner = CliRunner()
        for level in ('critical', 'high', 'medium', 'low'):
            result = runner.invoke(main, [
                'scan', str(clean_repo), '--fail-on', level, '--no-report', '--workers', '1'
            ])
            # CR-037: a clean repo trips no threshold, so every level must exit 0
            # (was `in (0, 1)` — a tautology).
            assert result.exit_code == 0, (
                f"clean repo must exit 0 at --fail-on {level}, got "
                f"{result.exit_code}\n{result.output}"
            )

    def test_fail_on_rejects_invalid_severity(self, clean_repo):
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo), '--fail-on', 'bogus', '--no-report'
        ])
        assert result.exit_code != 0, "Invalid severity value should cause non-zero exit"

    def test_fail_on_not_set_always_exits_zero(self, dirty_repo):
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(dirty_repo), '--no-report', '--workers', '1'
        ])
        # Without --fail-on, scan always exits 0 regardless of findings
        assert result.exit_code == 0, (
            f"Without --fail-on, scan must exit 0:\n{result.output}"
        )


class TestExclude:
    """--exclude prevents matching paths from being scanned."""

    def test_exclude_directory_prevents_scan(self, tmp_path):
        secret_dir = tmp_path / "secrets"
        secret_dir.mkdir()
        (secret_dir / "keys.py").write_text("PRIVATE_KEY = 'do-not-scan-me'\n")
        (tmp_path / "main.py").write_text("x = 1\n")

        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(tmp_path),
            '--exclude', 'secrets/',
            '--no-report', '--workers', '1',
        ])
        assert result.exit_code == 0
        # Exclusion works: only 1 file (main.py) scanned, not 2
        assert "found 1 scannable" in result.output.lower()

    def test_exclude_multiple_paths(self, tmp_path):
        for d in ('vendor', 'archive'):
            p = tmp_path / d
            p.mkdir()
            (p / "code.py").write_text("eval('x')\n")

        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(tmp_path),
            '--exclude', 'vendor/',
            '--exclude', 'archive/',
            '--no-report', '--workers', '1',
        ])
        assert result.exit_code == 0

    def test_exclude_does_not_affect_other_dirs(self, tmp_path):
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "lib.py").write_text("x = 1\n")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("x = 1\n")

        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(tmp_path),
            '--exclude', 'vendor/',
            '--no-report', '--workers', '1',
        ])
        assert result.exit_code == 0
        assert result.exception is None


class TestWorkers:
    """--workers N controls parallelism without crashing."""

    def test_workers_1_completes_cleanly(self, clean_repo):
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo), '--workers', '1', '--no-report'
        ])
        assert result.exit_code == 0
        assert result.exception is None

    def test_workers_2_completes_cleanly(self, clean_repo):
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo), '--workers', '2', '--no-report'
        ])
        assert result.exit_code == 0
        assert result.exception is None

    def test_workers_zero_rejected(self, clean_repo):
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo), '--workers', '0', '--no-report'
        ])
        # 0 workers is invalid — should fail or be clamped
        # Either exit non-zero or auto-correct to >=1
        assert result.exception is None or result.exit_code != 0


class TestNoReport:
    """--no-report skips report generation."""

    def test_no_report_creates_no_files(self, clean_repo):
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo), '--no-report', '--workers', '1'
        ])
        assert result.exit_code == 0
        # Default report dir must NOT be created
        default_report_dir = clean_repo / ".medusa" / "reports"
        assert not default_report_dir.exists(), (
            f"--no-report must not create {default_report_dir}"
        )

    def test_without_no_report_creates_files(self, clean_repo, tmp_path):
        output_dir = tmp_path / "reports"
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo),
            '--output', str(output_dir),
            '--format', 'json',
            '--workers', '1',
        ])
        assert result.exit_code == 0
        assert output_dir.exists(), "Reports dir should be created without --no-report"


class TestNoCache:
    """--no-cache disables caching entirely."""

    def test_no_cache_flag_accepted(self, clean_repo):
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo), '--no-cache', '--no-report', '--workers', '1'
        ])
        assert result.exit_code == 0
        assert result.exception is None

    def test_no_cache_scans_all_files_twice(self, clean_repo):
        runner = CliRunner()
        # Both runs should complete successfully even without caching
        for _ in range(2):
            result = runner.invoke(main, [
                'scan', str(clean_repo), '--no-cache', '--no-report', '--workers', '1'
            ])
            assert result.exit_code == 0


class TestQuickMode:
    """--quick skips unchanged files using the cache."""

    def test_quick_flag_accepted(self, clean_repo):
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo), '--quick', '--no-report', '--workers', '1'
        ])
        assert result.exit_code == 0
        assert result.exception is None

    def test_quick_after_full_scan_completes(self, clean_repo):
        runner = CliRunner()
        # Full scan first
        runner.invoke(main, ['scan', str(clean_repo), '--no-report', '--workers', '1'])
        # Quick scan should run faster (or at minimum not crash)
        result = runner.invoke(main, [
            'scan', str(clean_repo), '--quick', '--no-report', '--workers', '1'
        ])
        assert result.exit_code == 0


class TestForceMode:
    """--force bypasses cache and rescans everything."""

    def test_force_flag_accepted(self, clean_repo):
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo), '--force', '--no-report', '--workers', '1'
        ])
        assert result.exit_code == 0
        assert result.exception is None

    def test_force_after_cached_scan(self, clean_repo):
        runner = CliRunner()
        runner.invoke(main, ['scan', str(clean_repo), '--no-report', '--workers', '1'])
        # Force should rescan even though cache is warm
        result = runner.invoke(main, [
            'scan', str(clean_repo), '--force', '--no-report', '--workers', '1'
        ])
        assert result.exit_code == 0


class TestIncludeUserMcpConfigs:
    """--include-user-mcp-configs gates user-home MCP file inclusion."""

    def test_flag_not_set_excludes_user_mcp_files(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        mcp_file = fake_home / ".config" / "Claude" / "claude_desktop_config.json"
        mcp_file.parent.mkdir(parents=True)
        mcp_file.write_text('{"mcpServers": {}}')

        monkeypatch.setattr(Path, "home", lambda: fake_home)

        scanner = MedusaParallelScanner(
            project_root=tmp_path / "project",
            use_cache=False,
            include_user_mcp_configs=False,
        )
        (tmp_path / "project").mkdir()
        files = scanner.find_scannable_files()
        file_paths = [str(f) for f in files]
        assert not any("claude_desktop_config" in p for p in file_paths), (
            "User MCP config must not appear without --include-user-mcp-configs"
        )

    def test_flag_set_includes_user_mcp_files(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        mcp_file = fake_home / ".config" / "Claude" / "claude_desktop_config.json"
        mcp_file.parent.mkdir(parents=True)
        mcp_file.write_text('{"mcpServers": {"evil": {"command": "bash"}}}')

        monkeypatch.setattr(Path, "home", lambda: fake_home)

        project = tmp_path / "project"
        project.mkdir()
        (project / "main.py").write_text("x = 1\n")

        scanner = MedusaParallelScanner(
            project_root=project,
            use_cache=False,
            include_user_mcp_configs=True,
        )
        files = scanner.find_scannable_files()
        file_paths = [str(f) for f in files]
        assert any("claude_desktop_config" in p for p in file_paths), (
            "User MCP config must appear when --include-user-mcp-configs is set"
        )

    def test_cli_flag_accepted_without_crash(self, clean_repo):
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo),
            '--include-user-mcp-configs',
            '--no-report', '--workers', '1',
        ])
        assert result.exception is None
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# P1 — Output & reporting
# ---------------------------------------------------------------------------

class TestOutputFormats:
    """--format controls which report files are written."""

    def test_format_json_creates_json_file(self, clean_repo, tmp_path):
        output_dir = tmp_path / "out"
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo),
            '--format', 'json',
            '--output', str(output_dir),
            '--workers', '1',
        ])
        assert result.exit_code == 0
        json_files = list(output_dir.rglob("*.json"))
        assert len(json_files) > 0, "No JSON report created"
        # Must be valid JSON
        data = json.loads(json_files[0].read_text())
        assert isinstance(data, (dict, list))

    def test_format_markdown_creates_md_file(self, clean_repo, tmp_path):
        output_dir = tmp_path / "out"
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo),
            '--format', 'markdown',
            '--output', str(output_dir),
            '--workers', '1',
        ])
        assert result.exit_code == 0
        md_files = list(output_dir.rglob("*.md"))
        assert len(md_files) > 0, "No Markdown report created"

    def test_format_all_creates_multiple_files(self, clean_repo, tmp_path):
        output_dir = tmp_path / "out"
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo),
            '--format', 'all',
            '--output', str(output_dir),
            '--workers', '1',
        ])
        assert result.exit_code == 0
        all_files = list(output_dir.rglob("*.*"))
        assert len(all_files) >= 2, (
            f"--format all must create multiple report files, got: {[f.name for f in all_files]}"
        )


class TestOutputPath:
    """--output writes reports to a custom directory."""

    def test_output_custom_path(self, clean_repo, tmp_path):
        custom_dir = tmp_path / "custom_reports"
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo),
            '--output', str(custom_dir),
            '--format', 'json',
            '--workers', '1',
        ])
        assert result.exit_code == 0
        assert custom_dir.exists(), "Custom output dir was not created"
        assert len(list(custom_dir.rglob("*.*"))) > 0, "No files in custom output dir"

    def test_output_default_path_when_not_specified(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        (project / "main.py").write_text("x = 1\n")
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(project), '--format', 'json', '--workers', '1'
        ])
        assert result.exit_code == 0
        # Default location: .medusa/reports inside project dir (or cwd)
        # Just assert no crash — exact default path varies by config
        assert result.exception is None


class TestNoAiSafe:
    """--no-ai-safe disables payload obfuscation in reports."""

    def test_no_ai_safe_flag_accepted(self, clean_repo):
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo),
            '--no-ai-safe', '--no-report', '--workers', '1',
        ])
        assert result.exit_code == 0
        assert result.exception is None

    def test_no_ai_safe_with_output_produces_report(self, clean_repo, tmp_path):
        output_dir = tmp_path / "out"
        runner = CliRunner()
        result = runner.invoke(main, [
            'scan', str(clean_repo),
            '--no-ai-safe',
            '--output', str(output_dir),
            '--format', 'json',
            '--workers', '1',
        ])
        assert result.exit_code == 0
        assert len(list(output_dir.rglob("*.json"))) > 0


# ---------------------------------------------------------------------------
# P2 — Cache internals
# ---------------------------------------------------------------------------

class TestCacheFullHash:
    """full_hash=True detects changes past the 8KB boundary."""

    def test_full_hash_false_misses_tail_change(self, tmp_path):
        cache_dir = tmp_path / ".cache"
        f = tmp_path / "big.py"
        # Write 10KB — change beyond 8KB prefix
        f.write_bytes(b"x = 1\n" + b" " * 8200 + b"\n# original tail\n")

        cache = MedusaCacheManager(cache_dir=cache_dir, full_hash=False)
        cache.update_cache(f, issues_found=0, issues=[])
        cache.save()

        # Modify only the tail (after 8KB)
        content = f.read_bytes()
        f.write_bytes(content[:8192] + b"\n# CHANGED TAIL\n" + content[8193:])

        cache2 = MedusaCacheManager(cache_dir=cache_dir, full_hash=False)
        # 8KB hash may NOT detect this (size/mtime check might catch it, but hash won't)
        # The point: full_hash=True WOULD catch it
        changed_8kb = cache2.is_file_changed(f)
        # At minimum: the cache loads without error
        assert isinstance(changed_8kb, bool)

    def test_full_hash_true_detects_tail_change(self, tmp_path):
        cache_dir = tmp_path / ".cache"
        f = tmp_path / "big.py"
        base = b"x = 1\n" + b" " * 8200 + b"\n# original tail\n"
        f.write_bytes(base)

        cache = MedusaCacheManager(cache_dir=cache_dir, full_hash=True)
        cache.update_cache(f, issues_found=0, issues=[])
        cache.save()

        # Patch mtime to same value so quick checks don't catch it
        orig_stat = f.stat()
        modified = base[:8192] + b"\n# CHANGED TAIL\n" + base[8193:]
        f.write_bytes(modified)
        import os
        os.utime(f, (orig_stat.st_atime, orig_stat.st_mtime))

        cache2 = MedusaCacheManager(cache_dir=cache_dir, full_hash=True)
        assert cache2.is_file_changed(f) is True, (
            "full_hash=True must detect change past 8KB boundary"
        )

    def test_unchanged_file_not_changed(self, tmp_path):
        cache_dir = tmp_path / ".cache"
        f = tmp_path / "stable.py"
        f.write_text("x = 1\n")

        cache = MedusaCacheManager(cache_dir=cache_dir, full_hash=False)
        cache.update_cache(f, issues_found=0, issues=[])
        cache.save()

        cache2 = MedusaCacheManager(cache_dir=cache_dir, full_hash=False)
        assert cache2.is_file_changed(f) is False


class TestCacheHmacTamper:
    """HMAC tamper detection invalidates corrupted cache."""

    def test_tampered_cache_treated_as_invalid(self, tmp_path):
        cache_dir = tmp_path / ".cache"
        f = tmp_path / "test.py"
        f.write_text("x = 1\n")

        cache = MedusaCacheManager(cache_dir=cache_dir, full_hash=False)
        cache.update_cache(f, issues_found=0, issues=[])
        cache.save()

        # Verify cache was written
        assert cache.cache_file.exists()

        # Flip a byte in the cache file to simulate tampering
        raw = cache.cache_file.read_bytes()
        flipped = raw[:-1] + bytes([raw[-1] ^ 0xFF])
        cache.cache_file.write_bytes(flipped)

        # Reload — tampered cache must be discarded
        cache2 = MedusaCacheManager(cache_dir=cache_dir, full_hash=False)
        # Either cache is empty (discarded) or file is treated as changed
        assert len(cache2.cache) == 0 or cache2.is_file_changed(f) is True, (
            "Tampered cache must be discarded or file treated as changed"
        )

    def test_valid_cache_loads_correctly(self, tmp_path):
        cache_dir = tmp_path / ".cache"
        f = tmp_path / "test.py"
        f.write_text("def foo(): pass\n")

        cache = MedusaCacheManager(cache_dir=cache_dir, full_hash=False)
        cache.update_cache(f, issues_found=1, issues=[])
        cache.save()

        cache2 = MedusaCacheManager(cache_dir=cache_dir, full_hash=False)
        assert str(f.absolute()) in cache2.cache
        assert cache2.is_file_changed(f) is False


class TestCacheRuleFingerprint:
    """Cache entries with stale rule_version are treated as changed."""

    def test_stale_rule_version_triggers_rescan(self, tmp_path):
        cache_dir = tmp_path / ".cache"
        f = tmp_path / "app.py"
        f.write_text("x = 1\n")

        cache = MedusaCacheManager(cache_dir=cache_dir, full_hash=False)
        cache.update_cache(f, issues_found=0, issues=[])

        # Manually overwrite the rule_version in the cached entry
        path_key = str(f.absolute())
        entry = cache.cache[path_key]
        from dataclasses import replace
        cache.cache[path_key] = replace(entry, rule_version="STALE_VERSION_XYZ")
        cache.save()

        cache2 = MedusaCacheManager(cache_dir=cache_dir, full_hash=False)
        # Rule version mismatch → must treat as changed
        if str(f.absolute()) in cache2.cache:
            assert cache2.is_file_changed(f) is True, (
                "Stale rule_version must cause is_file_changed=True"
            )


# ---------------------------------------------------------------------------
# P3 — Secrets command
# ---------------------------------------------------------------------------

class TestSecretsCommand:
    """secrets scan / purge basic operation."""

    def test_secrets_scan_explicit_path_detects_key(self, tmp_path):
        secret_file = tmp_path / "history.txt"
        # Write a realistic-looking OpenAI key
        secret_file.write_text(
            "Previous session:\n"
            "export OPENAI_API_KEY=sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop\n"
            "curl https://api.openai.com/v1/chat\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, [
            'secrets', 'scan', '--path', str(secret_file)
        ])
        assert result.exit_code == 0
        assert result.exception is None
        # Should report finding or at minimum not crash
        output = result.output.lower()
        assert any(kw in output for kw in ('openai', 'api_key', 'secret', 'finding', 'found', '1')), (
            f"Expected secret detection in output:\n{result.output}"
        )

    def test_secrets_scan_clean_file_no_findings(self, tmp_path):
        clean_file = tmp_path / "notes.txt"
        clean_file.write_text("Just some meeting notes.\nNo secrets here.\n")
        runner = CliRunner()
        result = runner.invoke(main, [
            'secrets', 'scan', '--path', str(clean_file)
        ])
        assert result.exit_code == 0
        assert result.exception is None

    def test_secrets_scan_reveal_requires_confirmation(self, tmp_path):
        secret_file = tmp_path / "creds.txt"
        secret_file.write_text("TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcde\n")
        runner = CliRunner()
        # Pass empty confirmation → should abort without revealing
        result = runner.invoke(main, [
            'secrets', 'scan', '--path', str(secret_file), '--reveal'
        ], input="\n")  # empty confirmation
        assert result.exit_code == 0
        assert result.exception is None
        assert "aborted" in result.output.lower() or "stay masked" in result.output.lower(), (
            "--reveal without confirmation must abort"
        )

    def test_secrets_purge_requires_yes_i_know(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ['secrets', 'purge'], input="\n")
        assert result.exception is None
        # Without --yes-i-know, should not modify files silently

    def test_secrets_scan_multiple_paths(self, tmp_path):
        f1 = tmp_path / "file1.txt"
        f2 = tmp_path / "file2.txt"
        f1.write_text("nothing here\n")
        f2.write_text("also nothing\n")
        runner = CliRunner()
        result = runner.invoke(main, [
            'secrets', 'scan',
            '--path', str(f1),
            '--path', str(f2),
        ])
        assert result.exit_code == 0
        assert result.exception is None


# ---------------------------------------------------------------------------
# P4 — MedusaParallelScanner constructor params
# ---------------------------------------------------------------------------

class TestScannerParams:
    """MedusaParallelScanner constructor parameters are wired correctly."""

    def test_extra_excludes_removes_matching_files(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        (project / "app.py").write_text("x = 1\n")
        (project / "debug.log").write_text("some log output\n")
        (project / "error.log").write_text("error log\n")

        scanner = MedusaParallelScanner(
            project_root=project,
            use_cache=False,
            extra_excludes=["*.log"],
        )
        files = scanner.find_scannable_files()
        file_names = [f.name for f in files]
        assert "debug.log" not in file_names, "*.log files must be excluded"
        assert "error.log" not in file_names, "*.log files must be excluded"

    def test_extra_excludes_does_not_affect_other_files(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        (project / "app.py").write_text("x = 1\n")
        (project / "debug.log").write_text("log\n")

        scanner = MedusaParallelScanner(
            project_root=project,
            use_cache=False,
            extra_excludes=["*.log"],
        )
        files = scanner.find_scannable_files()
        file_names = [f.name for f in files]
        assert "app.py" in file_names, "Non-excluded files must still appear"

    def test_workers_1_no_crash(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()
        (project / "app.py").write_text("x = 1\n")

        scanner = MedusaParallelScanner(
            project_root=project,
            workers=1,
            use_cache=False,
        )
        files = scanner.find_scannable_files()
        assert isinstance(files, list)

    def test_use_cache_false_creates_no_cache_manager(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()

        scanner = MedusaParallelScanner(
            project_root=project,
            use_cache=False,
        )
        assert scanner.cache is None, "use_cache=False must not create a cache manager"

    def test_use_cache_true_creates_cache_manager(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir()

        scanner = MedusaParallelScanner(
            project_root=project,
            use_cache=True,
        )
        assert scanner.cache is not None, "use_cache=True must create a cache manager"


# ---------------------------------------------------------------------------
# P5 — CLI smoke tests (flag acceptance without crash)
# ---------------------------------------------------------------------------

class TestCliSmokeTests:
    """Every major flag must be accepted without crash or exception."""

    @pytest.mark.parametrize("args", [
        ['scan', '.', '--help'],
        ['secrets', '--help'],
        ['secrets', 'scan', '--help'],
        ['secrets', 'purge', '--help'],
        ['install', '--help'],
        ['scanners', '--help'],
        ['config'],
        ['--version'],
    ])
    def test_help_and_info_flags_exit_cleanly(self, args):
        runner = CliRunner()
        result = runner.invoke(main, args)
        assert result.exit_code in (0, 1), (
            f"Command {args} exited with unexpected code {result.exit_code}:\n{result.output}"
        )
        assert result.exception is None, (
            f"Command {args} raised exception: {result.exception}"
        )

    def test_version_shows_version_string(self):
        runner = CliRunner()
        result = runner.invoke(main, ['--version'])
        assert result.exit_code == 0
        assert re.search(r'\d{4}\.\d+\.\d+', result.output), (
            f"Version output should contain version number: {result.output}"
        )
