"""Gate for FX-001 — GitLeaks (GL-*) findings on test certs / example tokens / doc
snippets must NOT hard-block a clean repo, while a REAL leaked secret in shipped
source / root STILL hard-blocks (FN-safety, born-red both ways).

Mirrors the CredentialFileScanner test-fixture exemption: a test TLS private key or a
``Authorization: Bearer <TOKEN>`` doc example is a fixture / documentation snippet, not
a leaked secret. The same secret in shipped source (``src/`` / root) is a real leak and
still DO_NOT_INSTALLs. A GL exemption is deliberately scoped to GitLeaks (leaked-secret
class) only — a poisoned README carrying a prompt-injection directive is a *different*
scanner and must keep driving the verdict even in ``docs/``.
"""
import medusa.core.scan_api as api


def _gl(path, rule="GL-private-key", sev="CRITICAL"):
    return {"rule_id": rule, "scanner": "GitLeaksScanner", "severity": sev,
            "file": path, "line": 1, "issue": ""}


# --- signal-level: GL in a test / doc path is NOT a verdict signal ------------- #
def test_gitleaks_on_test_cert_not_signal():
    for p in ("repo/tests/certs/server.key",
              "repo/test/fixtures/key.pem",
              "repo/testdata/id_rsa",
              "repo/examples/config.env"):
        assert not api._is_vet_signal(_gl(p)), f"GL should be dismissed in test path: {p}"


def test_gitleaks_in_docs_not_signal():
    # rampart: curl `Authorization: Bearer <TOKEN>` examples live in the tool's docs
    for p in ("repo/docs/quickstart.md", "repo/doc/api.md"):
        assert not api._is_vet_signal(_gl(p, rule="GL-curl-auth-header")), \
            f"GL should be dismissed in doc path: {p}"


# --- FN-safety: a REAL leaked secret in shipped source / root STILL signals ---- #
def test_gitleaks_in_real_source_still_signals():
    for p in ("repo/src/config.py", "repo/server.key", "repo/app/settings.py"):
        assert api._is_vet_signal(_gl(p)), f"real leaked secret must stay a signal: {p}"


def test_real_leaked_key_repo_still_dni():
    r = api._summarize([_gl("repo/src/secrets.py")], root="/repo")
    assert r["verdict"] == api.DO_NOT_INSTALL, f"real leak must DO_NOT_INSTALL, got {r['verdict']}"


def test_test_cert_repo_not_dni():
    r = api._summarize([_gl("repo/tests/certs/server.key")], root="/repo")
    assert r["verdict"] == api.SAFE, f"test cert must not hard-block (SAFE like requests), got {r['verdict']}"


# --- adversarial: a parked LIVE payload (mcp.json dropper) in tests/ STILL blocks #
def test_parked_live_payload_in_tests_still_signal():
    # NOT a GL finding -> the GL exemption must not apply; the live-payload rule
    # (MCP017 dropper parked in tests/fixtures/) must keep driving the verdict.
    mcp = {"rule_id": "MCP017", "scanner": "MCPConfigScanner", "severity": "CRITICAL",
           "file": "repo/tests/fixtures/mcp.json", "line": 1, "issue": ""}
    assert api._is_vet_signal(mcp), "parked mcp.json dropper in tests/ must stay a signal"
