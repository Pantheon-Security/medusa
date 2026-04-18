#!/usr/bin/env python3
"""
Security hardening tests for v2026.5.5.

Covers:

C-1a: External-tool cmd lists must include a ``--`` separator before the
      trailing path positional, so that a maliciously named file like
      ``--config=https://evil.tld/rce.yaml`` cannot be re-parsed by the tool
      as a CLI option.

C-1b: As defense-in-depth, scanners must refuse (without spawning a
      subprocess) any file whose basename starts with ``-``.

M-1:  Markdown report code fences must not be escapable by source content,
      and inline backtick spans must not be escapable by filenames containing
      backticks.

These tests mock ``BaseScanner._run_command`` to capture argv without invoking
the real external tool for C-1 cases, and directly invoke reporter helpers
for M-1 cases.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import List
from unittest.mock import patch

import pytest

from medusa.scanners.semgrep_scanner import SemgrepScanner
from medusa.scanners.trivy_scanner import TrivyScanner
from medusa.scanners.gitleaks_scanner import GitLeaksScanner


def _fake_completed(stdout: str = "", returncode: int = 0):
    """Return a stand-in for subprocess.CompletedProcess used by _run_command."""
    return SimpleNamespace(stdout=stdout, stderr="", returncode=returncode)


def _make_scanner(cls):
    """Instantiate a scanner with a deterministic tool_path (bypasses PATH lookup)."""
    with patch.object(cls, "_find_tool", return_value=Path(f"/fake/bin/{cls.__name__}")):
        scanner = cls()
    # _find_tool is called in __init__; ensure tool_path is set regardless.
    scanner.tool_path = Path(f"/fake/bin/{cls.__name__}")
    return scanner


# ---------------------------------------------------------------------------
# C-1a: '--' separator before trailing path positional
# ---------------------------------------------------------------------------


def test_semgrep_argv_has_dashdash_separator(tmp_path):
    """semgrep _scan_file_subprocess must insert '--' before the file path."""
    scanner = _make_scanner(SemgrepScanner)
    target = tmp_path / "safe.py"
    target.write_text("print('ok')\n")

    captured: List[List[str]] = []

    def fake_run(cmd, timeout=30):
        captured.append(list(cmd))
        return _fake_completed(stdout="")

    with patch.object(scanner, "_run_command", side_effect=fake_run):
        scanner._scan_file_subprocess(target, time.time())

    assert captured, "expected _run_command to be called once"
    cmd = captured[0]
    assert cmd[-1] == str(target), f"last arg should be the target path, got {cmd[-1]!r}"
    assert cmd[-2] == "--", f"expected '--' immediately before path, got {cmd[-2]!r}"


def test_trivy_config_argv_has_dashdash_separator(tmp_path):
    """trivy config-scan cmd must insert '--' before the file path."""
    scanner = _make_scanner(TrivyScanner)
    # .tf extension routes to 'config' scan type
    target = tmp_path / "main.tf"
    target.write_text('resource "aws_s3_bucket" "b" {}\n')

    captured: List[List[str]] = []

    def fake_run(cmd, timeout=30):
        captured.append(list(cmd))
        return _fake_completed(stdout="")

    with patch.object(scanner, "_run_command", side_effect=fake_run):
        scanner._scan_file_subprocess(target, time.time())

    assert captured, "expected _run_command to be called"
    cmd = captured[0]
    assert "config" in cmd, f"expected trivy config path, got {cmd}"
    assert cmd[-1] == str(target)
    assert cmd[-2] == "--", f"expected '--' before path in config cmd, got {cmd[-2]!r}"


def test_trivy_fs_argv_has_dashdash_separator(tmp_path):
    """trivy fs-scan cmd must insert '--' before the parent-dir path."""
    scanner = _make_scanner(TrivyScanner)
    # requirements.txt routes to 'fs' scan type (scans parent directory)
    target = tmp_path / "requirements.txt"
    target.write_text("requests==2.0.0\n")

    captured: List[List[str]] = []

    def fake_run(cmd, timeout=30):
        captured.append(list(cmd))
        return _fake_completed(stdout="")

    with patch.object(scanner, "_run_command", side_effect=fake_run):
        scanner._scan_file_subprocess(target, time.time())

    assert captured, "expected _run_command to be called"
    cmd = captured[0]
    assert "fs" in cmd, f"expected trivy fs path, got {cmd}"
    assert cmd[-1] == str(target.parent)
    assert cmd[-2] == "--", f"expected '--' before parent path in fs cmd, got {cmd[-2]!r}"


def test_gitleaks_argv_safe(tmp_path):
    """
    gitleaks uses '--source <value>' (value form), so the attack surface is
    different from semgrep/trivy: there is no trailing positional to inject
    into. This test pins that invariant so a future refactor that adds a
    trailing positional is forced to re-evaluate the defense.
    """
    scanner = _make_scanner(GitLeaksScanner)
    target = tmp_path / "config.env"
    target.write_text("FOO=bar\n")

    captured: List[List[str]] = []

    def fake_run(cmd, timeout=30):
        captured.append(list(cmd))
        return _fake_completed(stdout="")

    with patch.object(scanner, "_run_command", side_effect=fake_run):
        scanner._scan_file_subprocess(target, time.time())

    assert captured, "expected _run_command to be called"
    cmd = captured[0]
    # The path appears as the value after '--source', not as a trailing positional.
    assert "--source" in cmd
    src_idx = cmd.index("--source")
    assert cmd[src_idx + 1] == str(target)
    # Last arg should be a flag or its value, NOT the scanned path.
    assert cmd[-1] != str(target), (
        f"gitleaks should not end with the target path; got cmd={cmd}"
    )


# ---------------------------------------------------------------------------
# C-1b: reject dash-prefixed basenames without spawning a subprocess
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scanner_cls",
    [SemgrepScanner, TrivyScanner, GitLeaksScanner],
    ids=["semgrep", "trivy", "gitleaks"],
)
def test_scanner_rejects_dash_prefixed_basename(scanner_cls, tmp_path):
    """
    A file whose basename starts with '-' must be refused before any
    subprocess is invoked. The returned ScannerResult must be unsuccessful
    and its error message must mention the defense.
    """
    scanner = _make_scanner(scanner_cls)
    # Literal malicious filename from the advertised attack.
    malicious = tmp_path / "--config=evil.yaml"
    malicious.write_text("rules: []\n")
    assert malicious.name.startswith("-")

    with patch.object(scanner, "_run_command") as mock_run:
        result = scanner._scan_file_subprocess(malicious, time.time())

    assert mock_run.call_count == 0, (
        f"{scanner_cls.__name__} must NOT spawn a subprocess for a dash-prefixed "
        f"filename; got {mock_run.call_count} calls"
    )
    assert result.success is False
    assert result.issues == []
    assert result.error_message is not None
    assert "argv injection defense" in result.error_message.lower()
    assert result.scanner_name == scanner.name
    assert result.file_path == str(malicious)


def test_reject_helper_passes_safe_paths(tmp_path):
    """The helper must return None for safe (non-dash-prefixed) basenames."""
    scanner = _make_scanner(SemgrepScanner)
    safe = tmp_path / "app.py"
    safe.write_text("print('ok')\n")
    assert scanner._reject_if_dash_prefixed(safe, time.time()) is None


def test_reject_helper_rejects_dash_prefix(tmp_path):
    """The helper must return an error ScannerResult for dash-prefixed names."""
    scanner = _make_scanner(TrivyScanner)
    evil = tmp_path / "-rf"
    evil.write_text("")
    result = scanner._reject_if_dash_prefixed(evil, time.time())
    assert result is not None
    assert result.success is False
    assert "argv injection defense" in (result.error_message or "").lower()


# ---------------------------------------------------------------------------
# M-1: Markdown report escape
# ---------------------------------------------------------------------------

from medusa.core.reporter import _md_code_fence, _md_sanitize_inline, MedusaReportGenerator


class TestMarkdownFenceEscape:
    """Source code with embedded triple-backticks cannot break out of the fence."""

    def test_plain_code_uses_three_backtick_fence(self):
        out = _md_code_fence("print('hello')")
        assert out.startswith("```\n")
        assert out.endswith("\n```")
        # Default 3-backtick fence when code has no runs of backticks.
        assert out.count("`" * 3) >= 2

    def test_triple_backtick_in_code_bumps_fence(self):
        malicious = "```\n# break out\n<script>alert(1)</script>"
        out = _md_code_fence(malicious)
        # The fence MUST be at least 4 backticks long so the embedded 3-run
        # cannot close it.
        lines = out.split("\n")
        assert len(lines[0]) >= 4
        assert lines[0].rstrip("`") == ""  # fence is pure backticks
        assert lines[-1] == lines[0]       # open == close
        # The malicious triple-backtick run appears somewhere between the
        # opening and closing fence but does not equal either.
        assert "```" in out
        # Re-parse: split on the fence; the middle chunk must include the run.
        parts = out.split(lines[0])
        assert "```" in parts[1]

    def test_arbitrary_run_of_backticks(self):
        # 7-backtick run in code must force an 8+ fence.
        malicious = "`" * 7 + "pwn"
        out = _md_code_fence(malicious)
        fence_line = out.split("\n", 1)[0]
        assert len(fence_line) >= 8

    def test_empty_code_is_valid(self):
        out = _md_code_fence("")
        assert out == "```\n\n```"


class TestMarkdownInlineSanitize:
    """Filenames with backticks cannot break out of inline code spans."""

    def test_plain_filename_unchanged(self):
        assert _md_sanitize_inline("src/foo.py") == "src/foo.py"

    def test_backtick_stripped(self):
        assert _md_sanitize_inline("evil`name.py") == "evilname.py"

    def test_newlines_stripped(self):
        assert _md_sanitize_inline("a\nb\r\nc") == "abc"


class TestReportMarkdownIntegration:
    """End-to-end: generated markdown contains no fence breakout."""

    def _make_scan_results(self, code_payload: str, filename: str) -> dict:
        return {
            "version": "test",
            "timestamp": "2026-04-18T00:00:00Z",
            "summary": {
                "total_files": 1,
                "total_issues": 1,
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "findings": [
                {
                    "severity": "CRITICAL",
                    "issue": "hardcoded secret",
                    "file": filename,
                    "line": 1,
                    "scanner": "testscanner",
                    "confidence": 0.9,
                    "code": code_payload,
                }
            ],
            "missing_linters": [],
        }

    def test_generated_markdown_survives_tripleback_payload(self, tmp_path):
        gen = MedusaReportGenerator()
        payload = "```\n# SENTINEL_BREAKOUT\n<script>alert(1)</script>"
        out_path = tmp_path / "report.md"
        gen.generate_markdown_report(
            self._make_scan_results(payload, "safe.py"),
            output_path=out_path,
        )
        md = out_path.read_text(encoding="utf-8")
        # The breakout marker must appear inside a code block, never as raw
        # markdown outside one. The payload's embedded ``` run must not close
        # the outer fence.
        assert "SENTINEL_BREAKOUT" in md
        # The script tag must appear AFTER the first fence (inside the block).
        idx_script = md.find("<script>alert(1)</script>")
        idx_first_fence = md.find("```")
        assert idx_first_fence != -1
        assert idx_first_fence < idx_script
        # The opening fence at that position must be AT LEAST 4 backticks long
        # because the payload contains a 3-run; a 3-backtick open fence would
        # be closed by the payload's 3-run and the script would escape.
        # Find the exact fence sequence at idx_first_fence.
        fence_run = 0
        while idx_first_fence + fence_run < len(md) and md[idx_first_fence + fence_run] == "`":
            fence_run += 1
        assert fence_run >= 4, f"expected fence >= 4 backticks for payload with 3-run, got {fence_run}"

    def test_filename_backtick_sanitized(self, tmp_path):
        gen = MedusaReportGenerator()
        out_path = tmp_path / "report.md"
        gen.generate_markdown_report(
            self._make_scan_results("safe code", "evil`name.py"),
            output_path=out_path,
        )
        md = out_path.read_text(encoding="utf-8")
        # The raw filename-with-backtick must not appear; the sanitized form must.
        assert "evil`name.py" not in md
        assert "evilname.py" in md


# ---------------------------------------------------------------------------
# L-3: scan_history.json resilience
# ---------------------------------------------------------------------------


class TestHistoryLoadResilience:
    """_update_history must tolerate corrupted or malicious history files."""

    def _make_report(self):
        return {
            "timestamp": "2026-04-18T00:00:00Z",
            "scan_summary": {
                "security_score": 100,
                "risk_level": "LOW",
                "total_issues": 0,
            },
            "severity_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        }

    def test_garbage_bytes_resets_history(self, tmp_path):
        """Binary garbage in history file → _update_history resets, no crash."""
        gen = MedusaReportGenerator()
        gen.history_file = tmp_path / "scan_history.json"
        gen.history_file.write_bytes(b"\x00\xff\x01\x02not-json-at-all")
        # Must not raise.
        gen._update_history(self._make_report())
        # File is now valid JSON containing exactly our fresh entry.
        loaded = __import__('json').loads(gen.history_file.read_text(encoding='utf-8'))
        assert isinstance(loaded, list)
        assert len(loaded) == 1
        assert loaded[0]["timestamp"] == "2026-04-18T00:00:00Z"

    def test_json_but_not_list_resets_history(self, tmp_path):
        """Valid JSON but wrong schema (object not list) → reset."""
        gen = MedusaReportGenerator()
        gen.history_file = tmp_path / "scan_history.json"
        gen.history_file.write_text('{"injected": "attacker object"}', encoding='utf-8')
        gen._update_history(self._make_report())
        loaded = __import__('json').loads(gen.history_file.read_text(encoding='utf-8'))
        assert isinstance(loaded, list)
        assert len(loaded) == 1

    def test_list_of_non_dicts_resets_history(self, tmp_path):
        """List containing non-dict entries → schema reject, reset."""
        gen = MedusaReportGenerator()
        gen.history_file = tmp_path / "scan_history.json"
        gen.history_file.write_text('["string", 42, null]', encoding='utf-8')
        gen._update_history(self._make_report())
        loaded = __import__('json').loads(gen.history_file.read_text(encoding='utf-8'))
        assert len(loaded) == 1
        assert loaded[0]["timestamp"] == "2026-04-18T00:00:00Z"

    def test_valid_history_appended(self, tmp_path):
        """Legitimate existing history survives and new entry appends."""
        gen = MedusaReportGenerator()
        gen.history_file = tmp_path / "scan_history.json"
        gen.history_file.write_text(
            '[{"timestamp": "2026-04-17T00:00:00Z", "security_score": 90, '
            '"risk_level": "MEDIUM", "total_issues": 5, "severity_breakdown": {}}]',
            encoding='utf-8',
        )
        gen._update_history(self._make_report())
        loaded = __import__('json').loads(gen.history_file.read_text(encoding='utf-8'))
        assert len(loaded) == 2
        assert loaded[0]["timestamp"] == "2026-04-17T00:00:00Z"
        assert loaded[1]["timestamp"] == "2026-04-18T00:00:00Z"


# ---------------------------------------------------------------------------
# H-1 / M-2: Git URL SSRF defense (host allowlist + private IP rejection)
# ---------------------------------------------------------------------------

import socket as _socket
import click
from medusa.cli import _resolve_git_url, _host_is_allowlisted


def _fake_getaddrinfo(*ips):
    """Build a getaddrinfo stub returning the given IP strings (v4 or v6 auto-detected)."""
    def _stub(host, port, *args, **kwargs):
        results = []
        for ip in ips:
            family = _socket.AF_INET6 if ":" in ip else _socket.AF_INET
            results.append((family, _socket.SOCK_STREAM, 0, "", (ip, port or 0)))
        return results
    return _stub


class TestGitHostAllowlist:
    """Default allowlist accepts known public git hosts and their subdomains."""

    def test_host_allowlist_exact(self):
        assert _host_is_allowlisted("github.com")
        assert _host_is_allowlisted("gitlab.com")
        assert _host_is_allowlisted("bitbucket.org")
        assert _host_is_allowlisted("codeberg.org")

    def test_host_allowlist_subdomain(self):
        assert _host_is_allowlisted("gist.github.com")
        assert _host_is_allowlisted("raw.githubusercontent.com") is False  # NOT a subdomain of github.com
        assert _host_is_allowlisted("x.y.gitlab.com")

    def test_host_allowlist_rejects_unknown(self):
        assert not _host_is_allowlisted("evil.tld")
        assert not _host_is_allowlisted("github.com.evil.tld")  # suffix attack

    def test_host_allowlist_case_insensitive_and_trailing_dot(self):
        assert _host_is_allowlisted("GitHub.com")
        assert _host_is_allowlisted("github.com.")  # trailing dot normalised


class TestGitSSRFDefense:
    """_resolve_git_url rejects SSRF primitives and accepts legit URLs."""

    # --- Accept cases ---

    def test_shorthand_user_repo(self):
        # Shorthand builds a github.com URL and bypasses DNS (known host).
        # But our impl does NOT DNS-check the shorthand path for simplicity.
        assert _resolve_git_url("user/repo") == "https://github.com/user/repo"

    def test_github_https_passes(self):
        with patch("socket.getaddrinfo", _fake_getaddrinfo("140.82.121.3")):
            out = _resolve_git_url("https://github.com/user/repo")
        assert out == "https://github.com/user/repo"

    def test_gitlab_https_passes(self):
        with patch("socket.getaddrinfo", _fake_getaddrinfo("172.65.251.78")):
            out = _resolve_git_url("https://gitlab.com/user/repo")
        assert out == "https://gitlab.com/user/repo"

    def test_bitbucket_https_passes(self):
        with patch("socket.getaddrinfo", _fake_getaddrinfo("104.192.141.1")):
            out = _resolve_git_url("https://bitbucket.org/user/repo")
        assert out == "https://bitbucket.org/user/repo"

    def test_codeberg_https_passes(self):
        with patch("socket.getaddrinfo", _fake_getaddrinfo("217.197.91.145")):
            out = _resolve_git_url("https://codeberg.org/user/repo")
        assert out == "https://codeberg.org/user/repo"

    def test_github_subdomain_passes(self):
        with patch("socket.getaddrinfo", _fake_getaddrinfo("140.82.121.3")):
            out = _resolve_git_url("https://gist.github.com/user/abc")
        assert out == "https://gist.github.com/user/abc"

    def test_git_ssh_github_passes(self):
        with patch("socket.getaddrinfo", _fake_getaddrinfo("140.82.121.3")):
            out = _resolve_git_url("git@github.com:user/repo.git")
        assert out == "git@github.com:user/repo.git"

    # --- Allowlist rejections ---

    def test_unknown_host_rejected_by_default(self):
        with pytest.raises(click.BadParameter, match="allowlist"):
            _resolve_git_url("https://evil.tld/user/repo")

    def test_suffix_attack_rejected(self):
        with pytest.raises(click.BadParameter, match="allowlist"):
            _resolve_git_url("https://github.com.evil.tld/user/repo")

    def test_git_ssh_evil_host_rejected(self):
        with pytest.raises(click.BadParameter, match="allowlist"):
            _resolve_git_url("git@evil.tld:x/y.git")

    def test_git_ssh_malformed_rejected(self):
        with pytest.raises(click.BadParameter, match="Malformed SSH"):
            _resolve_git_url("git@:missing-host/repo")

    # --- Private IP rejections (even with allow_any_host) ---

    def test_loopback_ipv4_rejected(self):
        with patch("socket.getaddrinfo", _fake_getaddrinfo("127.0.0.1")):
            with pytest.raises(click.BadParameter, match="non-public IP"):
                _resolve_git_url("https://github.com/x/y")

    def test_loopback_ipv6_rejected(self):
        with patch("socket.getaddrinfo", _fake_getaddrinfo("::1")):
            with pytest.raises(click.BadParameter, match="non-public IP"):
                _resolve_git_url("https://github.com/x/y")

    def test_rfc1918_10_rejected(self):
        with patch("socket.getaddrinfo", _fake_getaddrinfo("10.0.0.5")):
            with pytest.raises(click.BadParameter, match="non-public IP"):
                _resolve_git_url("https://github.com/x/y")

    def test_rfc1918_192_168_rejected(self):
        with patch("socket.getaddrinfo", _fake_getaddrinfo("192.168.1.1")):
            with pytest.raises(click.BadParameter, match="non-public IP"):
                _resolve_git_url("https://github.com/x/y")

    def test_aws_metadata_link_local_rejected(self):
        with patch("socket.getaddrinfo", _fake_getaddrinfo("169.254.169.254")):
            with pytest.raises(click.BadParameter, match="non-public IP"):
                _resolve_git_url("https://github.com/x/y")

    def test_dns_rebind_rejected_even_with_allow_any_host(self):
        # Attacker-controlled DNS points evil-rebind.corp at 10.0.0.1.
        # --allow-any-host bypasses the hostname check but private-IP check stays.
        with patch("socket.getaddrinfo", _fake_getaddrinfo("10.0.0.1")):
            with pytest.raises(click.BadParameter, match="non-public IP"):
                _resolve_git_url("https://evil-rebind.corp/x", allow_any_host=True)

    def test_dns_rebind_any_of_multiple_ips(self):
        # getaddrinfo returns multiple IPs; any private one rejects.
        with patch(
            "socket.getaddrinfo",
            _fake_getaddrinfo("140.82.121.3", "10.0.0.1"),
        ):
            with pytest.raises(click.BadParameter, match="non-public IP"):
                _resolve_git_url("https://github.com/x/y")

    def test_resolution_failure_rejected(self):
        def _fail(*args, **kwargs):
            raise _socket.gaierror("Name or service not known")
        with patch("socket.getaddrinfo", side_effect=_fail):
            with pytest.raises(click.BadParameter, match="Could not resolve"):
                _resolve_git_url("https://github.com/x/y")

    # --- allow_any_host escape hatch ---

    def test_allow_any_host_bypasses_allowlist(self):
        # Use a routable public IP (Cloudflare DNS). Avoid 203.0.113.x
        # (TEST-NET-3) — flagged as is_reserved by the ipaddress module.
        with patch("socket.getaddrinfo", _fake_getaddrinfo("1.1.1.1")):
            out = _resolve_git_url(
                "https://internal-gitlab.corp/x/y",
                allow_any_host=True,
            )
        assert out == "https://internal-gitlab.corp/x/y"


# ---------------------------------------------------------------------------
# H-2a: cache HMAC integrity
# ---------------------------------------------------------------------------

import json as _json
from medusa.core.parallel import MedusaCacheManager, FileMetadata
from dataclasses import asdict


class TestCacheHMACIntegrity:
    """The cache file is HMAC-signed; tampered or unsigned content is discarded."""

    def _mk_manager(self, tmp_path, cache_dir_name="cache"):
        """Create a manager rooted in tmp_path (not ~/.medusa)."""
        return MedusaCacheManager(cache_dir=tmp_path / cache_dir_name)

    def _mk_meta(self, path: str = "/fake/a.py"):
        return FileMetadata(
            path=path,
            size=100,
            mtime=12345.0,
            hash="abc123",
            last_scan="2026-04-18T00:00:00Z",
            issues_found=3,
            rule_version="v1",
            cached_issues=[
                {"severity": "HIGH", "issue": "bad thing", "line": 1}
            ],
        )

    def test_hmac_key_created_on_first_run(self, tmp_path):
        mgr = self._mk_manager(tmp_path)
        assert mgr.hmac_key_file.exists()
        key_bytes = mgr.hmac_key_file.read_bytes()
        assert len(key_bytes) >= 32
        # POSIX mode check (skip on non-POSIX hosts).
        if os.name == "posix":
            mode = mgr.hmac_key_file.stat().st_mode & 0o777
            assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_save_then_load_roundtrip(self, tmp_path):
        mgr = self._mk_manager(tmp_path)
        meta = self._mk_meta()
        mgr.cache[meta.path] = meta
        mgr._save_cache()

        mgr2 = self._mk_manager(tmp_path)  # re-load from disk
        assert meta.path in mgr2.cache
        assert mgr2.cache[meta.path].cached_issues == meta.cached_issues

    def test_envelope_has_hmac_and_entries(self, tmp_path):
        mgr = self._mk_manager(tmp_path)
        mgr.cache[self._mk_meta().path] = self._mk_meta()
        mgr._save_cache()

        envelope = _json.loads(mgr.cache_file.read_text(encoding="utf-8"))
        assert "hmac" in envelope
        assert "entries" in envelope
        assert isinstance(envelope["entries"], dict)

    def test_tampered_entries_discarded_silently(self, tmp_path, capsys):
        mgr = self._mk_manager(tmp_path)
        mgr.cache[self._mk_meta().path] = self._mk_meta()
        mgr._save_cache()

        # Tamper: blank out cached_issues to simulate finding-suppression attack.
        envelope = _json.loads(mgr.cache_file.read_text(encoding="utf-8"))
        envelope["entries"]["/fake/a.py"]["cached_issues"] = []
        mgr.cache_file.write_text(_json.dumps(envelope), encoding="utf-8")

        # New manager, same key file — load must discard the tampered entry.
        mgr2 = self._mk_manager(tmp_path)
        assert mgr2.cache == {}, "tampered cache must be discarded"
        # No warning should be printed (silent discard).
        captured = capsys.readouterr()
        assert "Cache load error" not in captured.out

    def test_missing_hmac_envelope_discarded(self, tmp_path):
        """Upgrade path: v5.4 caches have no HMAC envelope — discard silently."""
        mgr = self._mk_manager(tmp_path)
        # Write old-style cache file (bare dict, no envelope).
        old_format = {self._mk_meta().path: asdict(self._mk_meta())}
        mgr.cache_file.write_text(_json.dumps(old_format), encoding="utf-8")

        mgr2 = self._mk_manager(tmp_path)
        assert mgr2.cache == {}

    def test_corrupted_json_discarded(self, tmp_path):
        mgr = self._mk_manager(tmp_path)
        mgr.cache_file.write_bytes(b"\x00\xff not json")
        mgr2 = self._mk_manager(tmp_path)
        assert mgr2.cache == {}

    def test_wrong_key_invalidates_all(self, tmp_path):
        """Deleting the HMAC key file forces every entry to be discarded."""
        mgr = self._mk_manager(tmp_path)
        mgr.cache[self._mk_meta().path] = self._mk_meta()
        mgr._save_cache()

        # Rotate key: delete and let next manager regenerate.
        mgr.hmac_key_file.unlink()
        mgr2 = self._mk_manager(tmp_path)
        assert mgr2.cache == {}, "rotated key must invalidate existing entries"
