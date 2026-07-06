#!/usr/bin/env python3
"""
Applicability gate for the inference_infrastructure harvest corpus.

The LLMOpsScanner loads ~3k harvested ``inference_infrastructure`` rules
(MEDUSA-INF-SCAN-* / MEDUSA-INFRA-SCAN-*). Many of those rules match very
generic tokens (``chunk_size``, ``compression_ratio``, ``import socket``,
``host: 0.0.0.0``) and were firing on benign non-ML code (urllib3-style
SSL/network/utility modules), producing the bulk of LLMOpsScanner false
positives on clean projects.

The fix is a CONTENT-APPLICABILITY GATE in LLMOpsScanner: the YAML
inference_infrastructure rules are only reported when the file shows genuine ML /
model-serving / inference context (imports/usage of torch/transformers/vllm/
onnx/triton/... or model-serving terms). A real inference-infra issue in an
ML-context file still carries that context, so it still fires — coverage is
preserved, the rule corpus is untouched (~42.7k rules), and benign files go
quiet.

These tests run through the REAL scan path (LLMOpsScanner.scan on disk files)
plus the actual FalsePositiveFilter, not to_dict shortcuts:
  * NEGATIVE: a benign urllib3-style SSL/connection .py (no ML imports) ->
    inference-infra findings suppressed (the gate fires).
  * POSITIVE: an ML-context .py (imports vllm/torch/transformers) with a real
    inference-infra issue -> the finding STILL fires.
"""

import tempfile
from pathlib import Path

import pytest

from medusa.scanners.llmops_scanner import LLMOpsScanner
from medusa.core.fp_filter import FalsePositiveFilter


# --- Fixtures: source files exercised through the real scanner ---------------

# Benign urllib3-style SSL/connection module. No ML/inference imports at all.
# Deliberately contains the exact generic tokens the harvest rules key on
# (chunk_size, compression_ratio, import socket, ssl) so we prove the gate — not
# luck — is what keeps it quiet.
BENIGN_URLLIB3 = '''\
import socket
import ssl
from .exceptions import ConnectTimeoutError, NewConnectionError


class HTTPSConnection:
    """A thin TLS connection wrapper (urllib3-style)."""

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.chunk_size = 4
        self.compression_ratio = 0.0
        self.sock = None

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(sock, server_hostname=self.host)

    def stream(self, amt=None):
        while True:
            data = self.sock.recv(self.chunk_size)
            if not data:
                break
            yield data
'''


# ML-context file with a REAL inference-infra issue: a vLLM serving stack bound
# to 0.0.0.0 (MEDUSA-INFRA-SCAN-001 / CWE-284, vLLM #9797). The ML context
# (vllm import + LLM(model=...)) is what the gate requires; the insecure bind is
# the genuine finding that MUST survive.
ML_VLLM_INSECURE_BIND = '''\
from vllm import LLM, SamplingParams

# Serve the model on all interfaces (insecure: exposes inference API publicly)
config = {"host": "0.0.0.0", "port": 8000}

llm = LLM(model="meta-llama/Llama-2-7b-hf")
params = SamplingParams(temperature=0.7)
'''


# Same insecure host:0.0.0.0 config but NO ML context — a generic web service.
# The identical insecure datum must be suppressed here, proving the gate keys on
# ML context and not merely on the absence of the pattern.
BENIGN_SAME_CONFIG_NO_ML = '''\
# generic web service configuration
config = {"host": "0.0.0.0", "port": 8000}


def start_server(cfg):
    return cfg
'''


def _scan(content: str, filename: str):
    """Run the real LLMOpsScanner over an on-disk file; return ScannerIssues."""
    scanner = LLMOpsScanner()
    # PR-013: these tests exercise harvested-provenance inference rules' detection
    # (screening/vet capability) AND their ML-context/FP-filter benign suppression —
    # both were the pre-PR-013 all-rules behavior, which screening reproduces.
    scanner._screening = True
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / filename
        p.write_text(content)
        result = scanner.scan(p)
    assert result.success, f"scan failed: {result.error_message}"
    return result.issues


def _infra_issue_ids(issues):
    """Rule IDs from the inference_infrastructure harvest corpus."""
    return [
        i.rule_id for i in issues
        if i.rule_id and ("INF-SCAN" in i.rule_id or "INFRA-SCAN" in i.rule_id)
    ]


# --- NEGATIVE: benign non-ML code -> inference-infra FPs suppressed ----------

def test_benign_ssl_connection_suppresses_inference_infra():
    """A urllib3-style SSL/connection file (no ML imports) must produce ZERO
    inference_infrastructure findings — the applicability gate suppresses the
    harvest corpus when there is no ML/inference context."""
    issues = _scan(BENIGN_URLLIB3, "connection.py")
    infra = _infra_issue_ids(issues)
    assert infra == [], (
        f"benign SSL/connection file should have no inference_infra findings, "
        f"got: {infra}"
    )


def test_benign_same_insecure_config_without_ml_is_gated():
    """The exact insecure `host: 0.0.0.0` datum, with NO ML context, is
    suppressed — proving the gate keys on ML context, not on the pattern."""
    issues = _scan(BENIGN_SAME_CONFIG_NO_ML, "app.py")
    infra = _infra_issue_ids(issues)
    assert "MEDUSA-INFRA-SCAN-001" not in infra, (
        f"insecure-host-binding must be gated in non-ML code, got: {infra}"
    )


def test_benign_passes_through_fp_filter_clean():
    """End-to-end through the real FalsePositiveFilter: the benign file yields no
    retained inference-infra findings (gate happens upstream, filter confirms)."""
    issues = _scan(BENIGN_URLLIB3, "connection.py")
    findings = [
        {
            "file": "connection.py",
            "line": i.line,
            "scanner": "LLMOpsScanner",
            "issue": i.message,
            "severity": i.severity.value,
            "rule_id": i.rule_id,
        }
        for i in issues
    ]
    flt = FalsePositiveFilter()
    retained, _fps = flt.filter_findings(findings)
    retained_infra = [
        f for f in retained
        if f.get("rule_id") and (
            "INF-SCAN" in f["rule_id"] or "INFRA-SCAN" in f["rule_id"]
        )
    ]
    assert retained_infra == [], (
        f"no inference-infra findings should survive on benign code, "
        f"got: {[f['rule_id'] for f in retained_infra]}"
    )


# --- POSITIVE: ML-context code -> real inference-infra issue STILL fires -----

def test_ml_context_insecure_bind_still_fires():
    """HARD GUARD: a real inference-infra issue (vLLM bound to 0.0.0.0) in an
    ML-context file MUST still fire. The gate must never trade coverage."""
    issues = _scan(ML_VLLM_INSECURE_BIND, "serve.py")
    infra = _infra_issue_ids(issues)
    assert "MEDUSA-INFRA-SCAN-001" in infra, (
        f"insecure-host-binding (INFRA-SCAN-001) must fire in ML-context code, "
        f"got inference-infra ids: {infra}"
    )


def test_ml_context_survives_fp_filter():
    """The genuine inference-infra finding in ML code survives the real
    FalsePositiveFilter (it is retained, not suppressed)."""
    issues = _scan(ML_VLLM_INSECURE_BIND, "serve.py")
    findings = [
        {
            "file": "serve.py",
            "line": i.line,
            "scanner": "LLMOpsScanner",
            "issue": i.message,
            "severity": i.severity.value,
            "rule_id": i.rule_id,
        }
        for i in issues
        if i.rule_id == "MEDUSA-INFRA-SCAN-001"
    ]
    assert findings, "expected INFRA-SCAN-001 in raw scan output"
    flt = FalsePositiveFilter()
    retained, _fps = flt.filter_findings(findings)
    assert any(f.get("rule_id") == "MEDUSA-INFRA-SCAN-001" for f in retained), (
        "real inference-infra finding must survive the FP filter in ML code"
    )


# --- Gate unit: the ML-context detector itself ------------------------------

@pytest.mark.parametrize("snippet", [
    "import torch",
    "from transformers import AutoModel",
    "from vllm import LLM",
    "import onnxruntime as ort",
    "import tritonclient.http as httpclient",
    "model = AutoModel.from_pretrained('bert-base')",
    "import mlflow",
    "from langchain.llms import OpenAI",
])
def test_ml_context_detector_positive(snippet):
    assert LLMOpsScanner._has_ml_context(snippet), f"should detect ML context: {snippet!r}"


@pytest.mark.parametrize("snippet", [
    "import socket\nimport ssl",
    "chunk_size = 4",
    "compression_ratio = 0.0",
    "from .exceptions import ConnectTimeoutError",
    "def observe_array(self):\n    return self.library",  # observe/array/library != serve/ray
    "config = {'host': '0.0.0.0', 'port': 8000}",
])
def test_ml_context_detector_negative(snippet):
    assert not LLMOpsScanner._has_ml_context(snippet), (
        f"should NOT detect ML context (benign): {snippet!r}"
    )
