"""Gate for #24 — CVE-2018-7575 (TensorFlow buffer overflow) must not fire on
unrelated Python (PC001 handover 2026-07-22-fp-realworld #7).

The rule engine matches patterns per-line with OR semantics (yaml_rule_scanner: fires on
the first matching pattern on a line). CVE-2018-7575's live harvest patterns were generic
C functions (`strncpy(`, `snprintf(`, `memcpy(`, `buffer_size`) plus a bare `tf\.` — so
`tf.write(...)` on a *tempfile* variable in a repo with NO tensorflow was flagged CRITICAL
"buffer overflow". A supply-chain CVE must anchor to the vulnerable PACKAGE, not generic
code tokens. Fixed patterns require an actual tensorflow import / dependency.
"""
import re

import yaml
from pathlib import Path

RULE_FILE = (Path(__file__).resolve().parent.parent / "medusa" / "rules" /
             "ai_security" / "ai_security_harvest_2026.yaml")


def _load_rule(rule_id):
    doc = yaml.safe_load(RULE_FILE.read_text())
    rules = doc["rules"] if isinstance(doc, dict) else doc
    for r in rules:
        if isinstance(r, dict) and r.get("id") == rule_id:
            return r
    raise AssertionError(f"{rule_id} not found in {RULE_FILE}")


def _fires(rule, text):
    return any(re.search(p, text) for p in rule["patterns"])


def test_cve_not_fired_by_bare_tf_or_generic_c():
    rule = _load_rule("CVE-2018-7575")
    # documented FP class: tempfile var `tf`, generic C funcs in non-tensorflow code
    for benign in ("with tempfile.NamedTemporaryFile() as tf:\n    tf.write(data)",
                   "tf.close()",
                   "buffer_size = 4096",
                   "snprintf_result = format_line(x)"):
        assert not _fires(rule, benign), f"CVE must NOT fire on non-tensorflow code: {benign!r}"


def test_cve_still_fires_on_tensorflow_dependency():
    rule = _load_rule("CVE-2018-7575")
    for real in ("import tensorflow as tf", "from tensorflow import keras",
                 "tensorflow==1.7.0"):
        assert _fires(rule, real), f"CVE must still fire on a tensorflow dependency: {real!r}"
