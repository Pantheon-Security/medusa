"""PR-018: the README vet example must match the CLI's ACTUAL current output format,
so a future cli.py copy change that drifts from the docs fails CI (the stale-example bug)."""
from pathlib import Path
README = (Path(__file__).resolve().parent.parent / "README.md").read_text()


def test_readme_uses_current_vet_output_format():
    # The current format the CLI prints (medusa/cli.py vet command):
    assert "VERDICT:" in README
    assert "blocking · " in README and "detected (non-blocking)" in README
    assert "Blocking findings:" in README
    # The OLD format the CLI no longer prints must be gone:
    assert "Top findings (" not in README, "stale vet example format in README"


def test_readme_exit_code_table_complete():
    for row in ("`0`", "`1`", "`2`", "`3`"):   # SAFE/CAUTION/DO_NOT_INSTALL/ERROR
        assert row in README, f"README exit-code table missing {row}"
    assert "DO_NOT_INSTALL" in README and "ERROR" in README


def test_readme_numbers_are_the_reconciled_ones():
    # PR-019: the honest, reproducible figures — and NOT the drift-prone old ones.
    assert "42,684" in README
    assert "310" in README                      # CVEs (not 265)
    assert "79 scanner" not in README           # reframed to built-in + optional
    assert "265 CVE" not in README
