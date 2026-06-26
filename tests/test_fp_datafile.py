"""Real-path tests for Phase B FP-filter data-file recognition.

Covers the two new content-safety guards added to ``FalsePositiveFilter``:

  * B1 — security-rule / signature DEFINITION files (YAML/JSON matching a rule
    schema, or living under a rules/signatures/patterns directory) are DATA and
    their findings are suppressed.
  * B2 — attack-pattern LITERAL source: a string element inside a module-level
    ``*_PATTERNS``/``*_SIGNATURES`` constant in a .py is definition data, not a
    vulnerability, and is suppressed.

CRITICAL GUARD: a real vulnerability in normal application code (e.g.
``eval(user_input)`` / ``subprocess.run(..., shell=True)``) MUST still fire.

All assertions run findings through the ACTUAL pipeline used by parallel.py:
``FalsePositiveFilter.filter_findings`` (and the ``filter_scan_results``
convenience wrapper around it), with synthetic files on disk so the filter's
own ``_get_source_context`` loads real content — no convenience shims.
"""

import copy

import pytest

from medusa.core.fp_filter import (
    FalsePositiveFilter,
    FPReason,
    filter_scan_results,
)


# --------------------------------------------------------------------------
# Fixtures: synthetic source files written to a temp tree, plus a finding
# factory that mirrors the scanner finding dict shape parallel.py produces.
# --------------------------------------------------------------------------

def _make_finding(file_path, line, *, issue="Command injection via os.system",
                  scanner="pythonscanner", severity="CRITICAL"):
    return {
        "file": str(file_path),
        "line": line,
        "issue": issue,
        "scanner": scanner,
        "severity": severity,
    }


def _filter(root, finding):
    """Run a single finding through the real filter_findings pipeline.

    Returns (kept, fps) as the pipeline does. source_root is the temp tree so
    relative-path logic and on-disk context loading work exactly as in prod.
    """
    fp_filter = FalsePositiveFilter(source_root=root)
    return fp_filter.filter_findings([finding])


# --------------------------------------------------------------------------
# B1 — rule/signature definition YAML -> suppressed
# --------------------------------------------------------------------------

def test_rule_definition_yaml_in_rules_dir_is_suppressed(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    yaml_file = rules_dir / "command_injection.yaml"
    yaml_file.write_text(
        "rules:\n"
        "  - id: cmd-injection-001\n"
        "    severity: CRITICAL\n"
        "    message: Command injection\n"
        "    patterns:\n"
        "      - 'os.system('\n"
        "      - 'subprocess.run(cmd, shell=True)'\n"
    )
    # The scanner self-matched the attack literal on line 7.
    finding = _make_finding(yaml_file, 7, scanner="llmopsscanner")

    kept, fps = _filter(tmp_path, finding)

    assert kept == [], "rule-definition YAML finding should be suppressed"
    assert len(fps) == 1
    assert fps[0]["fp_analysis"]["reason"] == FPReason.SIGNATURE_DATA.value


def test_rule_schema_yaml_outside_rules_dir_is_suppressed(tmp_path):
    """Content schema alone (not under rules/) is enough for a data file."""
    yaml_file = tmp_path / "my_vendored_sigs.yaml"
    yaml_file.write_text(
        "- rule_id: SIG-1\n"
        "  severity: HIGH\n"
        "  pattern: 'eval(request.args)'\n"
    )
    finding = _make_finding(yaml_file, 3, scanner="aiattacksignaturescanner")

    kept, fps = _filter(tmp_path, finding)

    assert kept == []
    assert fps[0]["fp_analysis"]["reason"] == FPReason.SIGNATURE_DATA.value


def test_ordinary_config_yaml_with_lone_severity_not_suppressed(tmp_path):
    """Guard: a generic config with a stray severity: but no id is NOT a rule file."""
    yaml_file = tmp_path / "logging_config.yaml"
    yaml_file.write_text(
        "logging:\n"
        "  severity: HIGH\n"
        "  command: os.system('rotate-logs')\n"
    )
    finding = _make_finding(yaml_file, 3, scanner="pythonscanner")

    kept, fps = _filter(tmp_path, finding)

    assert len(kept) == 1, "generic config must not be cleared as signature data"
    assert fps == []


# --------------------------------------------------------------------------
# B2 — *_PATTERNS literal .py -> suppressed
# --------------------------------------------------------------------------

def test_pattern_literal_constant_is_suppressed(tmp_path):
    scanner_py = tmp_path / "scanners" / "cmd_scanner.py"
    scanner_py.parent.mkdir()
    scanner_py.write_text(
        "import re\n"                                  # 1
        "\n"                                           # 2
        "COMMAND_INJECTION_PATTERNS = [\n"             # 3
        "    r'os\\.system\\(',\n"                     # 4
        "    r'subprocess.*shell=True',\n"             # 5
        "    r'eval\\(',\n"                            # 6
        "]\n"                                          # 7
    )
    # Finding on the literal element line 5.
    finding = _make_finding(scanner_py, 5, scanner="pythonscanner")

    kept, fps = _filter(tmp_path, finding)

    assert kept == [], "attack-pattern literal element should be suppressed"
    assert len(fps) == 1
    assert fps[0]["fp_analysis"]["reason"] == FPReason.PATTERN_LITERAL.value


def test_pattern_literal_dict_values_suppressed(tmp_path):
    scanner_py = tmp_path / "rules.py"
    scanner_py.write_text(
        "DANGEROUS_SIGNATURES = {\n"                   # 1
        "    'shell': 'subprocess.run(x, shell=True)',\n"  # 2
        "}\n"                                          # 3
    )
    finding = _make_finding(scanner_py, 2, scanner="pythonscanner")

    kept, fps = _filter(tmp_path, finding)

    assert kept == []
    assert fps[0]["fp_analysis"]["reason"] == FPReason.PATTERN_LITERAL.value


# --------------------------------------------------------------------------
# GUARD — real vuln in normal .py code must NOT be suppressed
# --------------------------------------------------------------------------

def test_real_eval_in_normal_code_not_suppressed(tmp_path):
    app_py = tmp_path / "app" / "handlers.py"
    app_py.parent.mkdir()
    app_py.write_text(
        "def handle(request):\n"                       # 1
        "    user_input = request.args.get('q')\n"     # 2
        "    result = eval(user_input)\n"              # 3  <-- real vuln
        "    return result\n"                          # 4
    )
    finding = _make_finding(
        app_py, 3, issue="Use of eval() on untrusted input"
    )

    kept, fps = _filter(tmp_path, finding)

    assert len(kept) == 1, "real eval(user_input) must still fire"
    assert fps == [], "real vulnerability must NOT be suppressed"


def test_real_subprocess_shell_true_not_suppressed(tmp_path):
    app_py = tmp_path / "service.py"
    app_py.write_text(
        "import subprocess\n"                          # 1
        "def run(cmd):\n"                              # 2
        "    subprocess.run(cmd, shell=True)\n"        # 3  <-- real vuln
    )
    finding = _make_finding(
        app_py, 3, issue="subprocess with shell=True"
    )

    kept, fps = _filter(tmp_path, finding)

    assert len(kept) == 1, "real subprocess shell=True must still fire"
    assert fps == []


def test_real_vuln_in_rules_named_py_not_suppressed(tmp_path):
    """A .py UNDER rules/ is still executable code: B1 path-suppression must
    not clear it, and B2 only fires on string-literal lines, not on a call."""
    py = tmp_path / "rules" / "engine.py"
    py.parent.mkdir()
    py.write_text(
        "def evaluate(expr):\n"                        # 1
        "    return eval(expr)\n"                      # 2  <-- real vuln, in rules/
    )
    finding = _make_finding(py, 2, issue="eval on expr")

    kept, fps = _filter(tmp_path, finding)

    assert len(kept) == 1, ".py under rules/ is code, real vuln must fire"
    assert fps == []


def test_executable_call_after_pattern_block_not_suppressed(tmp_path):
    """B2 guard: once the *_PATTERNS literal closes, real code below it fires."""
    py = tmp_path / "scanner.py"
    py.write_text(
        "PATTERNS = [\n"                               # 1
        "    r'eval\\(',\n"                            # 2
        "]\n"                                          # 3
        "def scan(src):\n"                             # 4
        "    return eval(src)\n"                       # 5  <-- real vuln below block
    )
    finding = _make_finding(py, 5, issue="eval on src")

    kept, fps = _filter(tmp_path, finding)

    assert len(kept) == 1, "real eval() after the literal block must still fire"
    assert fps == []


# --------------------------------------------------------------------------
# Idempotency / no-mutation of inputs
# --------------------------------------------------------------------------

def test_filter_is_idempotent_and_does_not_double_suppress(tmp_path):
    rules_dir = tmp_path / "signatures"
    rules_dir.mkdir()
    yaml_file = rules_dir / "sig.yaml"
    yaml_file.write_text(
        "- id: s1\n  severity: HIGH\n  pattern: 'os.system('\n"
    )
    finding = _make_finding(yaml_file, 3, scanner="llmopsscanner")

    fp_filter = FalsePositiveFilter(source_root=tmp_path)

    # First pass.
    kept1, fps1 = fp_filter.filter_findings([copy.deepcopy(finding)])
    # Second pass over the already-annotated finding object.
    kept2, fps2 = fp_filter.filter_findings(fps1)

    assert kept1 == [] and len(fps1) == 1
    assert kept2 == [] and len(fps2) == 1, "re-filtering keeps the same verdict"
    assert (
        fps2[0]["fp_analysis"]["reason"]
        == FPReason.SIGNATURE_DATA.value
    )


def test_filter_does_not_mutate_original_finding_identity_fields(tmp_path):
    """The pipeline annotates with fp_analysis but must not alter core fields."""
    app_py = tmp_path / "app.py"
    app_py.write_text("def f(x):\n    return eval(x)\n")
    finding = _make_finding(app_py, 2, issue="eval on x")
    snapshot = copy.deepcopy(finding)

    _filter(tmp_path, finding)

    for key in ("file", "line", "issue", "scanner", "severity"):
        assert finding[key] == snapshot[key], f"{key} must be unchanged"


# --------------------------------------------------------------------------
# Convenience wrapper exercises the same real path (used by some callers)
# --------------------------------------------------------------------------

def test_filter_scan_results_wrapper_suppresses_signature_data(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    yaml_file = rules_dir / "r.yaml"
    yaml_file.write_text(
        "- id: r1\n  severity: CRITICAL\n  patterns: ['eval(']\n"
    )
    finding = _make_finding(yaml_file, 3, scanner="garakscanner")

    filtered, fps, stats = filter_scan_results([finding], source_root=tmp_path)

    assert filtered == []
    assert len(fps) == 1
    assert stats["likely_fps"] == 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
