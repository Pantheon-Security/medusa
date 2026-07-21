"""Gate for the vet-perf fix — screening skips external SAST/lint subprocesses.

Profiling a screening scan showed ~99% of wall-clock was spawning + waiting on
external linter subprocesses (bandit/eslint/semgrep — one per file / heavy batch),
while the built-in 42k-pattern matching (the actual trust signal) was ~0.06s.
`vet` is a fast TRUST gate, external-linter findings are informational only (never
a verdict signal), so screening skips them. gitleaks/modelscan (which DO drive the
verdict) are kept. This locks that policy so a regression can't quietly reintroduce
the per-file subprocess storm.
"""
from medusa.core.parallel import _is_screening_skippable_external as _skip


class _Fake:
    def __init__(self, tool, tool_path):
        self._tool = tool
        self.tool_path = tool_path

    def get_tool_name(self):
        return self._tool


def test_external_linters_are_screening_skippable():
    # installed external SAST/lint tools -> skipped in screening/vet
    for tool in ("bandit", "eslint", "semgrep", "shellcheck", "hadolint", "ruff", "stylelint"):
        assert _skip(_Fake(tool, f"/usr/bin/{tool}")), f"{tool} should be skippable in screening"


def test_verdict_signal_external_tools_are_kept():
    # these external tools DRIVE the verdict (secrets / malicious model) -> never skipped
    for tool in ("gitleaks", "modelscan"):
        assert not _skip(_Fake(tool, f"/usr/bin/{tool}")), f"{tool} must not be skipped (verdict signal)"


def test_builtin_and_uninstalled_are_not_skipped():
    assert not _skip(_Fake("python", None)), "built-in in-process scanner must not be skipped"
    assert not _skip(_Fake("python3", None))
    # an external tool that isn't installed resolves to no tool_path -> no-op, not 'skipped'
    assert not _skip(_Fake("bandit", None))


def test_screening_scan_does_not_spawn_perfile_linters(tmp_path):
    """Behavioural: a screening scan of a .py file must not shell out to a per-file
    linter (bandit/ruff/eslint). Skipped if none are installed on this host."""
    import shutil
    if not any(shutil.which(t) for t in ("bandit", "ruff", "eslint")):
        import pytest
        pytest.skip("no per-file external linter installed to exercise the skip")

    import subprocess
    from medusa.core.parallel import MedusaParallelScanner, _apply_screening_to_scanners

    spawned = []
    orig = subprocess.Popen

    class _TracePopen(orig):
        def __init__(self, *a, **k):
            cmd = a[0] if a else k.get("args")
            spawned.append(str(cmd[0]) if isinstance(cmd, (list, tuple)) else str(cmd))
            super().__init__(*a, **k)

    (tmp_path / "m.py").write_text("import os\napi_key = os.getenv('K')\n")
    sc = MedusaParallelScanner(project_root=tmp_path, use_cache=False, screening=True)
    sc.screening = True
    _apply_screening_to_scanners(True, False)
    f = sc.find_scannable_files()[0]
    subprocess.Popen = _TracePopen
    try:
        sc.scan_file(f)
    finally:
        subprocess.Popen = orig
    linters = [c for c in spawned if any(t in c for t in ("bandit", "ruff", "eslint", "semgrep"))]
    assert not linters, f"screening scan spawned per-file linter subprocesses: {linters}"
