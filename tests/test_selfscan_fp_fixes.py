"""Regression gate for the self-scan false-positive fixes (2026-07-18).

A default-config self-scan of MEDUSA surfaced four detector patterns that were
flagging BENIGN, ordinary code as CRITICAL/HIGH — not only in MEDUSA's own tree
but for ANY user with the same shapes:

  LLG002  `dob|...` / `address...street|ave|road` were mis-grouped, so bare
          `dob`/`ave`/`road` matched as substrings -> `PayloadObfuscator`, `have`,
          `roadmap` were reported as exposed PII.
  MA013   the SafeLoader negative-lookahead was positioned so it never saw the
          loader -> `yaml.load(x, Loader=SafeLoader)` was reported as unsafe.
  CGS-039 `=.{0,5}['"]` let a getter call slip in before the quote ->
          `api_key = os.getenv("KEY")` was reported as a hardcoded secret.
  CGS-054 bare `open.{0,20}request` -> the prose "...openai...requested..."
          matched the file-open-traversal rule.

Each FP assertion is BORN-RED (fails on the pre-fix pattern). Each paired TP
assertion guards against over-correcting: the real vulnerability must still fire.
The fixes tighten precision for every scan, not just MEDUSA's self-scan.
"""
import tempfile
from pathlib import Path

from medusa.scanners.llm_guard_scanner import LLMGuardScanner
from medusa.scanners.model_attack_scanner import ModelAttackScanner
from medusa.scanners.owasp_llm_scanner import OWASPLLMScanner

# LLM/AI context header so the applicability-gated scanners actually run.
_LLM_CTX = "import openai\nsystem_prompt = 'x'\nclient = openai.OpenAI()\n"
# Model context header for ModelAttackScanner's ml-indicator gate.
_MODEL_CTX = "import torch\n"


def _rule_ids(scanner, content: str) -> set:
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "probe.py"
        f.write_text(content)
        return {getattr(i, "rule_id", None) for i in scanner.scan_file(f).issues}


# --------------------------------------------------------------------------- #
# LLG002 — PII grouping bug (bare dob/ave/road substrings)
# --------------------------------------------------------------------------- #
def test_llg002_no_fp_on_benign_identifiers():
    ids = _rule_ids(LLMGuardScanner(),
                    _LLM_CTX + "obfuscator = PayloadObfuscator()\nhave = average(3)\nabroad = True\n")
    assert "LLG002" not in ids, "PII rule fired on benign identifiers (dob/ave substring bug)"


def test_llg002_still_flags_real_pii():
    ids = _rule_ids(LLMGuardScanner(), _LLM_CTX + 'patient_dob = "01/02/1990"\n')
    assert "LLG002" in ids, "real date-of-birth PII must still be detected"


# --------------------------------------------------------------------------- #
# MA013 — yaml.load SafeLoader lookahead
# --------------------------------------------------------------------------- #
def test_ma013_no_fp_on_explicit_safe_loader():
    ids = _rule_ids(ModelAttackScanner(),
                    _MODEL_CTX + "model_cfg = yaml.load(data, Loader=yaml.CSafeLoader)\n")
    assert "MA013" not in ids, "unsafe-yaml rule fired despite an explicit safe Loader="


def test_ma013_still_flags_bare_yaml_load():
    ids = _rule_ids(ModelAttackScanner(), _MODEL_CTX + "model = yaml.load(open('m.yaml').read())\n")
    assert "MA013" in ids, "bare yaml.load (no Loader) must still be detected"


# --------------------------------------------------------------------------- #
# CGS-039 — hardcoded-credential vs getter call
# --------------------------------------------------------------------------- #
def test_cgs039_no_fp_on_env_getter():
    ids = _rule_ids(OWASPLLMScanner(), _LLM_CTX + 'api_key = os.getenv("OPENAI_API_KEY")\n')
    assert "MEDUSA-CGS-SCAN-039" not in ids, "env-var read flagged as a hardcoded secret"


def test_cgs039_still_flags_hardcoded_secret():
    # obviously-fake literal: still the hardcoded-secret SHAPE CGS-039 keys on,
    # but the placeholder markers keep it out of any secret-scanning pre-commit hook.
    ids = _rule_ids(OWASPLLMScanner(), _LLM_CTX + 'api_key = "sk-fake-placeholder-not-a-real-key-000"\n')
    assert "MEDUSA-CGS-SCAN-039" in ids, "a genuine hardcoded credential literal must still fire"


# --------------------------------------------------------------------------- #
# CGS-054 — file-open traversal vs prose containing "open...request"
# --------------------------------------------------------------------------- #
def test_cgs054_no_fp_on_prose():
    ids = _rule_ids(OWASPLLMScanner(),
                    _LLM_CTX + 'msg = "backend openai-api requested but no OPENAI_API_KEY is set"\n')
    assert "MEDUSA-CGS-SCAN-054" not in ids, "'openai...requested' prose matched the file-open rule"


def test_cgs054_still_flags_open_with_user_input():
    ids = _rule_ids(OWASPLLMScanner(), _LLM_CTX + "data = open(request.args['file'])\n")
    assert "MEDUSA-CGS-SCAN-054" in ids, "open() on user-controlled input must still be detected"
