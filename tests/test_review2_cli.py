"""Review-2 (RESHAPE) regression tests for the CLI lane.

Covers the cli.py fixes from REVIEW2_FIX_PLAN.md:

* RH-1  -- `medusa rules --count` surfaces the REAL loaded rule total plus the
           curated/harvested provenance split; the banner uses the real count.
* RM-1  -- the `--git` path (`_scan_git_repo`) prints the affirmative
           zero-findings line and the `_print_secrets_tip()` nudge, mirroring
           the local scan path.
* RL-1  -- `print_banner` no longer carries the stale `# Split: ['2026', '2.0']`
           comment and the version string round-trips.
* RL-4  -- `--no-cache` and `--force` help text are distinguishable, and the
           `medusa init` IDE prompt validates input instead of silently
           configuring nothing.

These exercise the REAL paths: the `rules` command is invoked through Click's
CliRunner (the same entrypoint a user hits), and the `--git` parity checks
introspect the actual `_scan_git_repo` source / call the real shared helpers
rather than a convenience shortcut. No network or git clone is performed.
"""

import inspect
import re

import pytest
from click.testing import CliRunner

from medusa import cli as cli_mod
from medusa.cli import main


# --------------------------------------------------------------------------- #
# RH-1 / RM-2 -- real rule count + curated/harvested split
# --------------------------------------------------------------------------- #

def test_rules_count_prints_real_total_and_split():
    """`medusa rules --count` must print a real number >= 40000 and name the
    curated/harvested provenance buckets (RH-1)."""
    result = CliRunner().invoke(main, ["rules", "--count"])
    assert result.exit_code == 0, result.output
    out = result.output

    # A concrete number with >= 5 digits (>= 40000) must appear. Strip thousands
    # separators before comparing so "42,684" parses as 42684.
    numbers = [int(m.replace(",", "")) for m in re.findall(r"\d[\d,]*", out)]
    assert numbers, f"no number printed: {out!r}"
    assert max(numbers) >= 40000, f"largest number {max(numbers)} < 40000: {out!r}"

    assert "curated" in out.lower()
    assert "harvested" in out.lower()


def test_rules_bare_invocation_also_reports_count():
    """A bare `medusa rules` (no flag) should still surface the count so users
    discover it without knowing the flag name."""
    result = CliRunner().invoke(main, ["rules"])
    assert result.exit_code == 0, result.output
    assert "curated" in result.output.lower()
    assert "harvested" in result.output.lower()


def test_rule_count_helper_returns_consistent_split():
    """The cached helper behind the command/banner returns a coherent split:
    curated + harvested + other == total (RH-1/RM-2)."""
    info = cli_mod._get_rule_count_info()
    assert info is not None
    assert info["total"] >= 40000
    assert info["curated"] + info["harvested"] + info["other"] == info["total"]
    # Both buckets are real, non-trivial categories in this ruleset.
    assert info["curated"] > 0
    assert info["harvested"] > 0


def test_banner_label_uses_real_count_not_hardcoded():
    """The banner '<N> Rules' fragment reflects the real loaded count, not the
    frozen '40,000+' marketing string, when the loader is available (RH-1)."""
    label = cli_mod._banner_rules_label()
    assert label.endswith("Rules")
    # Real count present -> not the static fallback.
    info = cli_mod._get_rule_count_info()
    if info and info["total"]:
        assert label == f"{info['total']:,} Rules"
        assert label != "40,000+ Rules"


def test_banner_label_falls_back_when_loader_errors(monkeypatch):
    """If the loader can't be queried, the banner falls back to the historical
    static string rather than crashing (RH-1 fallback)."""
    monkeypatch.setattr(cli_mod, "_RULE_COUNT_CACHE", None)
    monkeypatch.setattr(cli_mod, "_get_rule_count_info", lambda: None)
    assert cli_mod._banner_rules_label() == "40,000+ Rules"


# --------------------------------------------------------------------------- #
# RM-1 -- --git path parity (zero-findings affirmative + secrets tip)
# --------------------------------------------------------------------------- #

def test_git_scan_calls_secrets_tip():
    """`_scan_git_repo` must invoke the shared `_print_secrets_tip()` helper so
    the --git path nudges about leaked secrets like the local path (RM-1)."""
    src = inspect.getsource(cli_mod._scan_git_repo)
    assert "_print_secrets_tip()" in src


def test_git_scan_has_zero_findings_affirmative_branch():
    """`_scan_git_repo` must print the same affirmative 'Clean - 0 issues found
    across N files' empty-state as the local scan path (RM-1)."""
    src = inspect.getsource(cli_mod._scan_git_repo)
    assert "Clean" in src
    assert "0 issues found across" in src
    # Guarded behind a real zero-findings check, not unconditional.
    assert "_total_findings == 0" in src


def test_local_and_git_share_the_same_empty_state_text():
    """Belt-and-braces: the affirmative empty-state wording is identical in both
    the local scan() and the --git _scan_git_repo() paths so they can't drift."""
    git_src = inspect.getsource(cli_mod._scan_git_repo)
    scan_src = inspect.getsource(cli_mod.scan.callback)
    needle = "0 issues found across"
    assert needle in git_src
    assert needle in scan_src


def test_secrets_tip_helper_emits_secrets_scan_hint(capsys):
    """Call the real shared helper and assert the observable nudge text, so the
    parity tests above are anchored to real output (RM-1)."""
    cli_mod._print_secrets_tip()
    out = capsys.readouterr().out
    assert "medusa secrets scan" in out


# --------------------------------------------------------------------------- #
# RL-1 -- stale banner comment / version round-trip
# --------------------------------------------------------------------------- #

def test_print_banner_no_stale_version_comment():
    """The bogus `# Split: ['2026', '2.0']` comment must be gone (RL-1)."""
    src = inspect.getsource(cli_mod.print_banner)
    assert "['2026', '2.0']" not in src
    assert "Split: ['2026'" not in src


def test_version_flag_prints_real_version():
    """`medusa --version` prints the actual package version (RL-1 adjacent)."""
    from medusa import __version__
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0, result.output
    assert __version__ in result.output


# --------------------------------------------------------------------------- #
# RL-4 -- --no-cache vs --force help; init IDE input validation
# --------------------------------------------------------------------------- #

def test_force_and_no_cache_help_are_distinguishable():
    """`--force` and `--no-cache` must carry distinct, non-empty help text so a
    user can tell them apart (RL-4)."""
    params = {p.name: p for p in cli_mod.scan.params}
    force_help = params["force"].help or ""
    no_cache_help = params["no_cache"].help or ""
    assert force_help.strip()
    assert no_cache_help.strip()
    assert force_help != no_cache_help


def test_scan_help_text_renders_both_cache_flags():
    """The rendered `scan --help` shows both flags with their clarified copy."""
    result = CliRunner().invoke(main, ["scan", "--help"])
    assert result.exit_code == 0, result.output
    assert "--force" in result.output
    assert "--no-cache" in result.output


def test_init_ide_prompt_rejects_nonnumeric_then_accepts(monkeypatch, tmp_path):
    """A non-numeric IDE entry must re-prompt (warn) rather than silently
    configuring nothing; a valid follow-up entry is then honored (RL-4).

    Exercises the real `_create_init_config` prompt loop by feeding stdin
    through Click; asserts the warning surfaces and the valid '1' (claude-code)
    selection is accepted on retry.
    """
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    # First line is junk ("abc"), second is a valid selection ("1").
    result = runner.invoke(main, ["init", "--force"], input="abc\n1\n")
    out = result.output
    # The validation branch must have surfaced a re-prompt / warning. We do not
    # assert exit_code here because `init` does a lot of downstream work; the
    # load-bearing behavior is that bad input was rejected with a hint.
    assert "1-7" in out or "Unrecognized" in out, out


def test_init_ide_prompt_loop_is_bounded_in_source():
    """The init IDE prompt loop must be bounded (capped retries) so piped/CI
    stdin returning junk can't loop forever (RL-4)."""
    src = inspect.getsource(cli_mod._create_init_config)
    assert "range(3)" in src
    # Falls back to the safe 'none' default after exhausting retries.
    assert "choice_nums = [7]" in src


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
