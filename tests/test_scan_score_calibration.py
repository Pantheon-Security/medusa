"""Gate for FX-H04 (#25c) — score calibration: low-severity noise must not read as
CRITICAL, and the risk level is bounded by the worst severity present (Ross: "both").

Bug (PC001 handover 2026-07-22-fp-realworld): agent-reach had 0 CRITICAL / 1 HIGH /
8 MEDIUM / 38 LOW, and the 38 LOW findings (-1 each) dragged the score to 41 -> the <50
"CRITICAL" band. A repo with no critical issues read "Risk: CRITICAL" purely from
low-severity noise.

Two fixes:
  (a) cap the total LOW / MEDIUM contribution (noise can't tank the score);
  (b) floor the score by the worst severity so the risk LEVEL never exceeds what the
      worst finding warrants — no CRITICAL finding => at most CONCERNING, etc.
"""
from medusa.core.reporter import MedusaReportGenerator


def _r():
    return MedusaReportGenerator()


def _f(sev, i=0):
    return {"severity": sev, "file": f"src/mod{i}.py", "line": 1, "rule_id": "X", "issue": ""}


def _score_and_level(findings):
    g = _r()
    s = g.calculate_security_score(findings)
    return s, g.calculate_risk_level(s)


def test_low_noise_repo_not_critical():
    # agent-reach shape: 1 HIGH + 8 MEDIUM + 38 LOW -> must NOT read CRITICAL
    findings = [_f("HIGH")] + [_f("MEDIUM", i) for i in range(8)] + [_f("LOW", i) for i in range(38)]
    score, level = _score_and_level(findings)
    assert level != "CRITICAL", f"a 0-critical repo must not read CRITICAL (got {level} @ {score})"
    assert level == "CONCERNING", f"worst=HIGH should bound risk at CONCERNING, got {level} @ {score}"


def test_low_only_repo_is_not_alarming():
    # 40 LOW findings, nothing else -> at most GOOD (low-severity best-practice noise)
    score, level = _score_and_level([_f("LOW", i) for i in range(40)])
    assert level in ("GOOD", "EXCELLENT", "MODERATE"), f"LOW-only must not alarm, got {level} @ {score}"
    assert level != "CRITICAL" and level != "CONCERNING", f"LOW-only over-severe: {level} @ {score}"


def test_low_contribution_is_capped():
    # 100 LOW findings must not zero the score (noise cap)
    score, _ = _score_and_level([_f("LOW", i) for i in range(100)])
    assert score >= 70, f"100 LOW findings should not tank the score below 70, got {score}"


# --- worst-severity bound still lets real severity through -------------------- #
def test_single_critical_still_critical():
    score, level = _score_and_level([_f("CRITICAL")])
    assert level == "CRITICAL", f"a real CRITICAL must read CRITICAL, got {level} @ {score}"


def test_single_high_is_concerning_not_critical():
    score, level = _score_and_level([_f("HIGH")])
    assert level == "CONCERNING", f"a lone HIGH should be CONCERNING, got {level} @ {score}"


def test_high_plus_noise_stays_concerning():
    # a HIGH plus a mountain of noise is still bounded at CONCERNING (not worse)
    findings = [_f("HIGH")] + [_f("LOW", i) for i in range(200)]
    _, level = _score_and_level(findings)
    assert level == "CONCERNING", f"HIGH+noise should stay CONCERNING, got {level}"


def test_clean_repo_excellent():
    assert _score_and_level([])[1] == "EXCELLENT"
