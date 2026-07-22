"""Gate for FX-003b (option a) — env-secrets precision + a *safe* soft-tier.

The FN-trap this fixes: EnvScanner Check 2 routed a HIGH-ENTROPY value in a sensitive-
named var (`API_KEY=<real base64 secret>`) through the name-based `env-sensitive-var-*`
id (it fired on the line and shadowed the high-entropy Check 3). That made it unsafe to
soft-tier `env-sensitive-var-*` — a real leaked secret would be downgraded.

Fix (option a): the scanner splits Check 2 by the VALUE's entropy —
  * high-entropy value -> `env-secret-var-*`    (confirmed secret, stays HARD malice)
  * low-entropy  value -> `env-sensitive-var-*`  (name-only match -> soft, caps at CAUTION)
so `env-sensitive-var-*` can be soft-tiered with NO false-negative.
"""
import os
import tempfile

import medusa.core.scan_api as api
from medusa.scanners.env_scanner import EnvScanner


def _scan_env(line):
    d = tempfile.mkdtemp()
    p = os.path.join(d, ".env")
    with open(p, "w") as fh:
        fh.write(line + "\n")
    return [i.rule_id for i in EnvScanner().scan_file(p).issues]


# --- scanner: the VALUE's entropy chooses the rule id -------------------------- #
def test_high_entropy_value_gets_hard_secret_id():
    # a real, high-entropy key value -> env-secret-var-* (NOT the soft name-only id)
    ids = _scan_env("API_KEY=aF3xQ9zP1kR7wL2mN8bV4cD6eG0hJ5sT")
    assert any(r.startswith("env-secret-var-") for r in ids), ids
    assert not any(r.startswith("env-sensitive-var-") for r in ids), ids


def test_low_entropy_value_gets_soft_name_id():
    # config default / low-entropy value -> env-sensitive-var-* (name-only, soft)
    for val in ("API_KEY=myprodserver", "API_KEY=aaaaaaaaaaaaaaaaaaaa"):
        ids = _scan_env(val)
        assert any(r.startswith("env-sensitive-var-") for r in ids), (val, ids)
        assert not any(r.startswith("env-secret-var-") for r in ids), (val, ids)


# --- vet verdict: the soft-tier is safe --------------------------------------- #
def _f(rule_id, sev="HIGH"):
    return {"rule_id": rule_id, "scanner": "EnvScanner", "severity": sev,
            "file": ".env", "line": 1, "issue": ""}


def test_name_only_env_caps_at_caution():
    # low-entropy sensitive-NAME matches -> CAUTION, never DO_NOT_INSTALL (was DNI at >=3 HIGH)
    r = api._summarize([_f("env-sensitive-var-api_key") for _ in range(4)], root="/x")
    assert r["verdict"] == api.CAUTION, r["verdict"]


def test_high_entropy_secrets_still_dni():
    # confirmed high-entropy secrets (env-secret-var) are NOT soft -> still hard-block
    r = api._summarize([_f("env-secret-var-api_key") for _ in range(3)], root="/x")
    assert r["verdict"] == api.DO_NOT_INSTALL, r["verdict"]


def test_known_format_secret_still_dni():
    # Check-1 known-pattern secret (env-secret-*) still hard-blocks
    r = api._summarize([_f("env-secret-openai-api-key") for _ in range(3)], root="/x")
    assert r["verdict"] == api.DO_NOT_INSTALL, r["verdict"]


def test_helper_membership():
    assert api._is_env_name_only_signal(_f("env-sensitive-var-api_key"))
    assert not api._is_env_name_only_signal(_f("env-secret-var-api_key"))
    assert not api._is_env_name_only_signal(_f("env-secret-openai-api-key"))
