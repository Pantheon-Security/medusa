#!/usr/bin/env python3
"""
ML/AI content-applicability gate for the AI-only scanners.

ModelAttackScanner (adversarial-ML / model-poisoning harvest) and
OWASPLLMScanner (OWASP LLM Top-10 harvest) load large AI-specific YAML rule
corpora. Many of those harvested rules match very generic tokens (or collide with
emoji-dictionary keys like ``"gemini"`` / ``"hugging_face"``) and were firing on
plain non-AI code (requests / urllib3 / jinja2 / rich), producing the bulk of
those scanners' false positives on a benign corpus.

The fix reuses the same content-applicability gate built for LLMOpsScanner,
factored into ``medusa.scanners._ml_context.has_ml_context``: the AI-specific YAML
rules are scanned ONLY when the file shows genuine ML/AI/LLM/inference context. A
real attack in an AI-context file still carries that context, so it still fires —
coverage is preserved and no rule is removed.

These tests run through the REAL scan path (Scanner.scan on disk files) plus the
actual FalsePositiveFilter:
  * NEGATIVE: a benign urllib3/requests-style .py (no AI imports) -> ModelAttack
    and OWASP produce 0 findings.
  * NEGATIVE: an emoji-dictionary data file (AI names only as quoted emoji keys)
    -> 0 findings (the gate ignores quoted-name -> emoji-glyph data lines).
  * POSITIVE: an AI-context .py (imports transformers/torch/langchain/openai)
    with a real model/LLM attack -> the finding STILL fires.
"""

import tempfile
from pathlib import Path

import pytest

from medusa.scanners.model_attack_scanner import ModelAttackScanner
from medusa.scanners.owasp_llm_scanner import OWASPLLMScanner
from medusa.scanners._ml_context import has_ml_context
from medusa.core.fp_filter import FalsePositiveFilter


# --- Fixtures ----------------------------------------------------------------

# Benign urllib3-style SSL/connection module — no AI/ML imports at all.
BENIGN_URLLIB3 = '''\
import socket
import ssl
from .exceptions import ConnectTimeoutError


class HTTPSConnection:
    """A thin TLS connection wrapper (urllib3-style)."""

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.chunk_size = 4

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(sock, server_hostname=self.host)
'''


# Emoji-dictionary data file: AI/ML names appear ONLY as quoted keys mapped to
# emoji glyphs (rich/_emoji_codes.py shape). This was the single largest residual
# FP source for the AI scanners (a `"gemini"` key faked an LLM signal).
EMOJI_DICT = '''\
EMOJI = {
    "gemini": "♊",
    "hugging_face": "\U0001f917",
    "robot": "\U0001f916",
    "brain": "\U0001f9e0",
    "bullettrain_side": "\U0001f684",
}
'''


# AI-context file with a REAL unsafe model load (torch.load on a remote/untrusted
# source — classic deserialization RCE vector). The transformers/torch context is
# what the gate requires; the unsafe load is the genuine finding that MUST survive.
AI_TORCH_UNSAFE_LOAD = '''\
import torch
from transformers import AutoModel

# Loads a checkpoint from an untrusted URL without verification (pickle RCE risk)
ckpt = torch.load("http://example.com/model.bin")
model = AutoModel.from_pretrained("bert-base-uncased")
'''


# AI-context file with a REAL prompt-injection sink for the OWASP scanner: user
# input concatenated directly into an LLM prompt via an LLM SDK.
AI_PROMPT_INJECTION = '''\
import openai


def answer(user_input):
    # Direct prompt injection: untrusted input concatenated into the system prompt
    prompt = "You are a helpful assistant. " + user_input
    resp = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "system", "content": prompt}],
    )
    return resp
'''


def _scan(scanner, content: str, filename: str):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / filename
        p.write_text(content)
        result = scanner.scan(p)
    assert result.success, f"scan failed: {result.error_message}"
    return result.issues


def _findings(issues, filename, scanner_name):
    return [
        {
            "file": filename,
            "line": i.line,
            "scanner": scanner_name,
            "issue": i.message,
            "severity": i.severity.value,
            "rule_id": i.rule_id,
        }
        for i in issues
    ]


# --- NEGATIVE: benign / data files -> AI scanners silent --------------------

def test_model_attack_silent_on_benign_ssl():
    issues = _scan(ModelAttackScanner(), BENIGN_URLLIB3, "connection.py")
    assert issues == [], f"ModelAttack should be silent on benign SSL code, got {[i.rule_id for i in issues]}"


def test_owasp_silent_on_benign_ssl():
    issues = _scan(OWASPLLMScanner(), BENIGN_URLLIB3, "connection.py")
    assert issues == [], f"OWASP should be silent on benign SSL code, got {[i.rule_id for i in issues]}"


def test_model_attack_silent_on_emoji_dict():
    """AI names as quoted emoji-dict keys must NOT trigger the AI rule corpus."""
    issues = _scan(ModelAttackScanner(), EMOJI_DICT, "_emoji_codes.py")
    assert issues == [], f"ModelAttack should be silent on emoji data, got {[i.rule_id for i in issues]}"


def test_owasp_silent_on_emoji_dict():
    issues = _scan(OWASPLLMScanner(), EMOJI_DICT, "_emoji_codes.py")
    assert issues == [], f"OWASP should be silent on emoji data, got {[i.rule_id for i in issues]}"


def test_benign_passes_through_fp_filter_clean():
    """End-to-end: benign + emoji files yield no retained AI-scanner findings."""
    flt = FalsePositiveFilter()
    for scanner, name in ((ModelAttackScanner(), "ModelAttackScanner"),
                          (OWASPLLMScanner(), "OWASPLLMScanner")):
        for content, fname in ((BENIGN_URLLIB3, "connection.py"),
                               (EMOJI_DICT, "_emoji_codes.py")):
            issues = _scan(scanner, content, fname)
            retained, _ = flt.filter_findings(_findings(issues, fname, name))
            assert retained == [], (
                f"{name} retained findings on benign {fname}: "
                f"{[f['rule_id'] for f in retained]}"
            )


# --- POSITIVE: AI-context code -> real attack STILL fires -------------------

def test_model_attack_fires_on_ai_context():
    """HARD GUARD: an unsafe torch.load in AI-context code MUST still fire."""
    issues = _scan(ModelAttackScanner(), AI_TORCH_UNSAFE_LOAD, "train.py")
    assert issues, "ModelAttack must fire on unsafe model load in AI code"
    # The deserialization / model-load risk family must be present.
    rule_ids = [i.rule_id for i in issues]
    assert any(r and (r.startswith("MA01") or "SCAN" in r) for r in rule_ids), (
        f"expected a model-attack finding (MA0xx / harvest), got {rule_ids}"
    )


def test_model_attack_survives_fp_filter_in_ai_code():
    issues = _scan(ModelAttackScanner(), AI_TORCH_UNSAFE_LOAD, "train.py")
    flt = FalsePositiveFilter()
    retained, _ = flt.filter_findings(_findings(issues, "train.py", "ModelAttackScanner"))
    assert retained, "real model-attack finding must survive the FP filter in AI code"


def test_owasp_fires_on_ai_context():
    """HARD GUARD: prompt injection in AI-context code MUST still fire."""
    issues = _scan(OWASPLLMScanner(), AI_PROMPT_INJECTION, "chatbot.py")
    assert issues, "OWASP must fire on prompt injection in AI code"
    rule_ids = [i.rule_id for i in issues]
    assert any(r and (r.startswith("LLM01") or "SCAN" in r or "JB" in r) for r in rule_ids), (
        f"expected an OWASP-LLM finding (LLM01 / harvest), got {rule_ids}"
    )


def test_owasp_survives_fp_filter_in_ai_code():
    issues = _scan(OWASPLLMScanner(), AI_PROMPT_INJECTION, "chatbot.py")
    flt = FalsePositiveFilter()
    retained, _ = flt.filter_findings(_findings(issues, "chatbot.py", "OWASPLLMScanner"))
    assert retained, "real OWASP-LLM finding must survive the FP filter in AI code"


# --- Shared gate unit -------------------------------------------------------

@pytest.mark.parametrize("snippet", [
    "import torch",
    "from transformers import AutoModel",
    "import openai",
    "from langchain.llms import OpenAI",
    "import anthropic",
    "model = AutoModel.from_pretrained('bert-base')",
    "import google.generativeai as genai\nmodel = genai.GenerativeModel('gemini-pro')",
])
def test_gate_positive(snippet):
    assert has_ml_context(snippet), f"should detect AI context: {snippet!r}"


@pytest.mark.parametrize("snippet", [
    "import socket\nimport ssl",
    "chunk_size = 4",
    "from .exceptions import ConnectTimeoutError",
    'EMOJI = {\n    "gemini": "♊",\n    "hugging_face": "\U0001f917",\n}',
])
def test_gate_negative(snippet):
    assert not has_ml_context(snippet), f"should NOT detect AI context (benign): {snippet!r}"
