"""Tests for the `medusa secrets scan` pattern detection.

All planted credentials below are syntactically valid but use repeating
characters / dictionary-form padding so they are NOT real, working keys
issued by the upstream services.
"""

from pathlib import Path

import pytest

from medusa.core.secret_obfuscator import mask_finding, mask_secret
from medusa.scanners.ai_chat_history_scanner import scan_file


# Each entry: (planted_text, expected_rule_id)
_PATTERN_FIXTURES = [
    (
        "pypi-AgEIcHlwaS5vcmcCJDExMTExMTExLWFhYWEtYmJiYi1jY2NjLWRkZGRkZGRkZGRkZA",
        "MEDUSA-SECRET-PYPI",
    ),
    (
        "ghp_" + "A" * 36,
        "MEDUSA-SECRET-GITHUB-PAT",
    ),
    (
        "github_pat_11A" + "BCDEFGHIJ" * 8 + "_FAKE",
        "MEDUSA-SECRET-GITHUB-FINEGRAINED",
    ),
    (
        "AKIAIOSFODNN7EXAMPLE",
        "MEDUSA-SECRET-AWS-ACCESS-KEY",
    ),
    (
        "sk-ant-api03-" + "A" * 95,
        "MEDUSA-SECRET-ANTHROPIC",
    ),
    (
        "hf_" + "A" * 35,
        "MEDUSA-SECRET-HUGGINGFACE",
    ),
    (
        "npm_" + "A" * 36,
        "MEDUSA-SECRET-NPM",
    ),
    (
        "sk_live_" + "A" * 30,
        "MEDUSA-SECRET-STRIPE-LIVE",
    ),
]


@pytest.fixture
def planted_chat(tmp_path: Path) -> Path:
    """Build a fake chat-history file containing every planted credential.

    Lines are JSON-shaped to exercise both the scanner and the
    JSONL-safe redaction path used by the purger.
    """
    path = tmp_path / "history.jsonl"
    lines = []
    for i, (secret, _) in enumerate(_PATTERN_FIXTURES, 1):
        lines.append(f'{{"role":"user","content":"line {i}: {secret} please","ts":{i}}}')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("planted_secret,rule_id", _PATTERN_FIXTURES)
def test_each_pattern_fires(tmp_path: Path, planted_secret: str, rule_id: str):
    """Every shipped pattern must detect its corresponding planted credential."""
    path = tmp_path / "single.txt"
    path.write_text(f"context here: {planted_secret} more context\n", encoding="utf-8")

    result = scan_file(path)

    assert result.error is None, f"scan failed: {result.error}"
    matching = [f for f in result.findings if f.rule_id == rule_id]
    assert matching, (
        f"pattern {rule_id} did not fire on its planted credential. "
        f"Findings instead: {[f.rule_id for f in result.findings]}"
    )


def test_offsets_round_trip(tmp_path: Path):
    """Byte offsets must point exactly at the secret string."""
    secret = "ghp_" + "Z" * 36
    path = tmp_path / "offsets.txt"
    text = f"prefix---{secret}---suffix\n"
    path.write_text(text, encoding="utf-8")

    result = scan_file(path)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert text[f.byte_start : f.byte_end] == secret


def test_anthropic_not_double_matched_as_openai(tmp_path: Path):
    """Anthropic and OpenAI both start with `sk-` — the OpenAI pattern
    must NOT swallow Anthropic keys."""
    anthropic = "sk-ant-api03-" + "Q" * 95
    path = tmp_path / "ai.txt"
    path.write_text(f"key: {anthropic}\n", encoding="utf-8")

    result = scan_file(path)
    rule_ids = [f.rule_id for f in result.findings]
    assert "MEDUSA-SECRET-ANTHROPIC" in rule_ids
    assert "MEDUSA-SECRET-OPENAI" not in rule_ids


def test_no_findings_in_clean_file(tmp_path: Path):
    """Innocuous text must not produce any findings."""
    path = tmp_path / "clean.md"
    path.write_text(
        "This is a perfectly normal note about cats.\n"
        "It mentions tokens of affection but no credentials.\n"
        "Bearer is a word that means 'one who carries'.\n",
        encoding="utf-8",
    )
    result = scan_file(path)
    assert result.findings == []


def test_oversized_file_is_skipped(tmp_path: Path, monkeypatch):
    """Files past the cap are skipped with an error rather than read."""
    from medusa.scanners import ai_chat_history_scanner as mod

    monkeypatch.setattr(mod, "_MAX_FILE_BYTES", 100)
    path = tmp_path / "huge.txt"
    path.write_text("X" * 500, encoding="utf-8")
    result = scan_file(path)
    assert result.error is not None
    assert "exceeds" in result.error
    assert result.findings == []


def test_mask_never_includes_full_secret():
    """A masked render must not contain the trailing bytes of the secret."""
    secret = "pypi-AgEIcHlwaS5vcmc-this-must-stay-hidden-XXXXXX"
    rendered = mask_secret(secret, 10)
    assert "this-must-stay-hidden" not in rendered
    assert "XXXXXX" not in rendered
    assert rendered.startswith("pypi-AgEIc")


def test_mask_finding_uses_pattern_prefix(tmp_path: Path):
    """`mask_finding` must consult the pattern's mask_prefix, not a default."""
    pypi_secret = "pypi-AgEIcHlwaS5vcmcCJDExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEx"
    path = tmp_path / "x.txt"
    path.write_text(pypi_secret + "\n", encoding="utf-8")
    finding = scan_file(path).findings[0]
    rendered = mask_finding(finding)
    # PyPI's mask_prefix is 10.
    assert rendered.startswith("pypi-AgEIc")
    assert pypi_secret not in rendered
