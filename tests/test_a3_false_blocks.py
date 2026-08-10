#!/usr/bin/env python3
"""Born-RED guards for the two false blocks the A3 corpus baseline surfaced.

Both are the same shape: a rule firing on a file whose CONVENTION guarantees the
content is benign, at a severity that hard-blocks. Neither was caught by the unit
suite, the benchmark, or the corpus verdict-delta — they only appeared when the
full labelled corpus was swept and a `clean` repo came back DO_NOT_INSTALL.

  fastapi     26x MEDUSA-IMG-SVGSCRIPT-001 HIGH, every one on a docs/**/*.drawio.svg
  llmgateway  36x CRITICAL from a single .env.example of `change_this_*` values

26 HIGH and 36 CRITICAL both clear the hard-block threshold, so two of the most
ordinary things a repo can do — document itself with diagrams, ship an env
template — produced DO_NOT_INSTALL.
"""
import json
import tempfile
from pathlib import Path

import pytest

from medusa.scanners.env_scanner import EnvScanner
from medusa.scanners.image_embedded_threat_scanner import ImageEmbeddedThreatScanner

_SVG = "MEDUSA-IMG-SVGSCRIPT-001"


def _svg(tmp_path, body):
    p = tmp_path / "d.svg"
    p.write_text(body)
    return [i for i in ImageEmbeddedThreatScanner().scan_file(p).issues
            if i.rule_id == _SVG]


def _env(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body)
    return EnvScanner().scan_file(p).issues


# --- fastapi: <foreignObject> is layout, not active content ------------------
# drawio renders diagram text as HTML inside a <foreignObject>. Reporting the
# bare element meant "this repo has drawio diagrams" scored as active content.

def test_drawio_style_foreign_object_is_not_active_content(tmp_path):
    assert not _svg(tmp_path, (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<foreignObject width="100" height="20">'
        '<div xmlns="http://www.w3.org/1999/xhtml">Client</div>'
        '</foreignObject></svg>')), \
        "a diagram text box is not active content"


@pytest.mark.parametrize("inner,label", [
    ('<iframe src="//evil.tld"></iframe>', "iframe"),
    ('<object data="//evil.tld"></object>', "object"),
    ('<embed src="//evil.tld">', "embed"),
])
def test_foreign_object_embedding_remote_content_still_fires(tmp_path, inner, label):
    """The element still matters as a CONTAINER — that is why it isn't just deleted."""
    assert _svg(tmp_path, f'<svg><foreignObject>{inner}</foreignObject></svg>'), \
        f"<foreignObject> hosting a remote {label} renders when the SVG does"


@pytest.mark.parametrize("body,label", [
    ('<svg><script>alert(1)</script></svg>', "script element"),
    ('<svg><rect onload="evil()"/></svg>', "on*= handler"),
    ('<svg><a href="javascript:evil()">x</a></svg>', "javascript: URI"),
])
def test_real_svg_active_content_unaffected(tmp_path, body, label):
    assert _svg(tmp_path, body), f"{label} must still be reported"


def test_fastapi_documentation_svgs_are_clean():
    """The actual repo that hard-blocked. Skips if the corpus isn't present."""
    docs = Path("/home/ross/Documents/medusa/medusa-test-targets"
                "/normal/python/fastapi/docs/en/docs/img")
    if not docs.is_dir():
        pytest.skip("corpus not present on this box")
    scanner = ImageEmbeddedThreatScanner()
    flagged = [p for p in docs.rglob("*.svg")
               if any(i.rule_id == _SVG for i in scanner.scan_file(p).issues)]
    assert not flagged, (
        f"{len(flagged)} fastapi doc SVGs flagged as active content "
        f"(26 of these hard-blocked the repo): {[p.name for p in flagged[:5]]}")


# --- llmgateway: a template's placeholders are the file doing its job --------

@pytest.mark.parametrize("line,label", [
    ("DB_PASSWORD=change_this_secure_password", "change_this_* value"),
    ("DATABASE_URL=postgres://u:change_this_pw@h:5432/d", "URL with placeholder credential"),
    ("OPENAI_API_KEY=sk-your_openai_key_here", "real prefix + fill-me-in body"),
    ("STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key", "stripe prefixed placeholder"),
    ("STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret", "whsec prefixed placeholder"),
    ("API_KEY=your-key-here", "your-*-here"),
    ("TOKEN=<YOUR_TOKEN>", "angle-bracket placeholder"),
    ("SECRET=${SECRET_FROM_VAULT}", "shell-expansion reference"),
])
def test_template_env_placeholders_are_not_secrets(tmp_path, line, label):
    assert not _env(tmp_path, ".env.example", line + "\n"), \
        f"{label}: a placeholder in a template is not a leaked credential"


@pytest.mark.parametrize("name", [".env.example", ".env.sample", ".env.template", ".env.dist"])
def test_all_template_suffixes_covered(tmp_path, name):
    assert not _env(tmp_path, name, "DB_PASSWORD=change_this_password\n")


@pytest.mark.parametrize("line,label", [
    ("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AWS-shaped key"),
    ("GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "GitHub PAT"),
])
def test_a_real_key_pasted_into_a_template_still_fires(tmp_path, line, label):
    """Templates are scanned precisely because they sometimes hold real values."""
    assert _env(tmp_path, ".env.example", line + "\n"), \
        f"{label} in a template is the mistake this scanner exists to catch"


def test_a_real_env_file_is_unchanged(tmp_path):
    """The softening is scoped to templates — a live .env keeps today's behaviour."""
    assert _env(tmp_path, ".env", "DB_PASSWORD=change_this_secure_password\n")


def test_llmgateway_env_example_no_longer_hard_blocks():
    """The actual repo that hard-blocked. Skips if the corpus isn't present."""
    p = Path("/home/ross/Documents/medusa/medusa-test-targets"
             "/harvested/llmgateway/.env.example")
    if not p.is_file():
        pytest.skip("corpus not present on this box")
    sev = [str(i.severity).split(".")[-1] for i in EnvScanner().scan_file(p).issues]
    assert sev.count("CRITICAL") == 0, (
        f"{sev.count('CRITICAL')} CRITICALs from a placeholder template "
        f"(36 of these hard-blocked the repo)")
