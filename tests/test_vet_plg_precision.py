"""Gate for the PLG (PluginSecurityScanner) FP fix — the #1 clean-repo false-block
driver (PLG008 = 25x across nanoclaw/agentshield/openshield/rampart/superagent).

Two parts:
  (a) TIER — PLG001-010 are plugin CODE-QUALITY / info-leak findings (a weakness in
      the repo's own plugin code), not an install-time attack on the installer, so
      they cap the verdict at CAUTION, never DO_NOT_INSTALL alone.
  (b) PRECISION — PLG008's `return.*(secret|key|token|…)` matched bare `key`/`token`
      as substrings: `return [...registry.keys()]`, `continuationKey`, code comments
      ("Returns … key …"), test strings ("returns false when no credentials"). The
      tightened pattern requires a word-boundary secret CONTEXT (api_key / access_token
      / private_key / password / secret / credentials), so those FPs stop while a real
      sensitive return still fires.
"""
import medusa.core.scan_api as api


# --------------------------------------------------------------------------- #
# (a) PLG caps at CAUTION (plugin code-quality != install attack)
# --------------------------------------------------------------------------- #
def _vf(rule_id, sev="CRITICAL"):
    return {"rule_id": rule_id, "scanner": "PluginSecurityScanner", "severity": sev,
            "file": "x/plugin.py", "line": 1, "issue": ""}


def test_plg_rules_cap_at_caution():
    for rid in ("PLG008", "PLG001", "PLG003", "PLG004"):
        r = api._summarize([_vf(rid) for _ in range(4)], root="/x")
        assert r["verdict"] == api.CAUTION, f"{rid} should cap at CAUTION, got {r['verdict']}"


def test_plg_helper_membership():
    assert api._is_plugin_security_signal(_vf("PLG008"))
    assert not api._is_plugin_security_signal(_vf("MCP017"))


# --------------------------------------------------------------------------- #
# (b) PLG008 pattern precision (born-red on the pre-fix pattern)
# --------------------------------------------------------------------------- #
def _plg008_fires(content: str, tmp_path) -> bool:
    from medusa.scanners.plugin_security_scanner import PluginSecurityScanner
    f = tmp_path / "plugin.py"
    # give the scanner plugin context + the sensitive-return line
    f.write_text("class MyPlugin:\n    def handle(self):\n        " + content + "\n")
    sc = PluginSecurityScanner()
    return any(getattr(i, "rule_id", None) == "PLG008" for i in sc.scan_file(f).issues)


def test_plg008_no_fp_on_benign_returns(tmp_path):
    for line in ("return [*registry.keys()]",
                 "return getValue(continuationKey(name))"):
        assert not _plg008_fires(line, tmp_path), f"PLG008 FP on: {line}"


def test_plg008_still_flags_real_sensitive_return(tmp_path):
    for line in ("return api_key", "return self.access_token", "return password"):
        assert _plg008_fires(line, tmp_path), f"PLG008 missed real sensitive return: {line}"
