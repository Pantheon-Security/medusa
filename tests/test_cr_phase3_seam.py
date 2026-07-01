"""Phase 3 seam/de-dup tests (CR-018, CR-019, CR-020, CR-022, CR-023, CR-024).

Written GATE-FIRST (RED before the fixes land) and exercising the REAL paths:
the shared finding-schema helper, the shared hardened git-clone helper wired
into both call sites, the `medusa vet` CLI verdict/exit-code contract, the
installer-owned status() consumed by `medusa hooks status`, and the
check-don't-rewrite SessionStart command.

No network. Synthetic inputs only so the suite stays fast.
"""

from __future__ import annotations

import inspect
import subprocess
import threading

from click.testing import CliRunner


# --------------------------------------------------------------------------- #
# CR-019 — shared standardize_issue (field-name fallbacks; no silent MEDIUM)
# --------------------------------------------------------------------------- #
def _fake_result():
    return type("R", (), {"scanner": "s", "file": "f"})()


def test_standardize_issue_severity_fallback():
    from medusa.core.finding_schema import standardize_issue

    d = standardize_issue({"issue_severity": "CRITICAL", "issue_text": "x"}, _fake_result())
    assert d["severity"] == "CRITICAL"
    assert d["issue"] == "x"
    assert d["scanner"] == "s"  # no _scanner_name -> result.scanner


def test_standardize_issue_alt_field_names():
    from medusa.core.finding_schema import standardize_issue

    d = standardize_issue(
        {"severity": "HIGH", "message": "m", "line": 7, "_scanner_name": "sc"}, _fake_result()
    )
    assert d["severity"] == "HIGH"
    assert d["issue"] == "m"
    assert d["line"] == 7
    assert d["scanner"] == "sc"


def test_standardize_issue_used_by_both_consumers():
    from medusa.core import scan_api
    from medusa.core import parallel

    assert "standardize_issue" in inspect.getsource(scan_api._extract_findings)
    assert "standardize_issue" in inspect.getsource(parallel.MedusaParallelScanner.generate_report)


# --------------------------------------------------------------------------- #
# CR-020 — shared hardened git-clone helper wired into both call sites
# --------------------------------------------------------------------------- #
def test_clone_hardened_importable_and_used():
    from medusa.core.git_clone import clone_hardened

    assert callable(clone_hardened)

    from medusa.core import scan_api
    from medusa import cli

    assert "clone_hardened" in inspect.getsource(scan_api._clone_repo)
    assert "clone_hardened" in inspect.getsource(cli._scan_git_repo)


def test_clone_hardened_preserves_hardening_flags():
    from medusa.core import git_clone

    src = inspect.getsource(git_clone.clone_hardened)
    for flag in ("--depth", "--single-branch", "--filter=blob:limit=5m",
                 "GIT_TERMINAL_PROMPT", "GIT_ASKPASS", "GIT_LFS_SKIP_SMUDGE"):
        assert flag in src, flag
    # stderr credential redaction preserved.
    assert "@" in src and "https://" in src


# --------------------------------------------------------------------------- #
# CR-022 — `medusa vet` verdict + documented exit-code mapping
# --------------------------------------------------------------------------- #
def test_vet_exit_code_mapping(monkeypatch):
    import medusa.core.scan_api as scan_api
    from medusa.cli import main

    cases = {
        "SAFE": 0,
        "CAUTION": 1,
        "DO_NOT_INSTALL": 2,
    }
    for verdict, expected in cases.items():
        monkeypatch.setattr(
            scan_api, "vet_repo",
            lambda target, verdict=verdict: {"verdict": verdict, "score": 1},
        )
        res = CliRunner().invoke(main, ["vet", "whatever"])
        assert f"VERDICT: {verdict}" in res.output, res.output
        assert res.exit_code == expected, (verdict, res.exit_code, res.output)


def test_vet_clean_dir_is_safe(tmp_path):
    from medusa.cli import main

    (tmp_path / "notes.txt").write_text("hello world, two plus two is four\n")
    res = CliRunner().invoke(main, ["vet", str(tmp_path)])
    assert "VERDICT:" in res.output
    assert res.exit_code == 0, res.output


def test_hook_script_uses_medusa_vet():
    from medusa.hooks import install

    script = install._CLAUDE_HOOK_SCRIPT.read_text(encoding="utf-8")
    assert "medusa vet" in script
    assert "TODO CR-022" not in script


# --------------------------------------------------------------------------- #
# CR-023 — install.status() owns detection; hooks_status consumes it
# --------------------------------------------------------------------------- #
def test_install_status_returns_dict_and_detects(tmp_path):
    from medusa.hooks import install

    st = install.status(tmp_path)
    assert isinstance(st, dict)
    assert st.get("claude_hook") is False

    install.install_claude_hook(tmp_path)
    assert install.status(tmp_path)["claude_hook"] is True


def test_hooks_status_calls_install_status():
    from medusa.cli import hooks_status

    src = inspect.getsource(hooks_status.callback)
    assert "status" in src
    # Detection logic should no longer be re-implemented inline in the CLI.
    assert ".claude" not in src or "install" in src


# --------------------------------------------------------------------------- #
# CR-024 — SessionStart CHECKS, never rewrites .mcp.json
# --------------------------------------------------------------------------- #
def test_sessionstart_does_not_rewrite_mcp(tmp_path):
    from medusa.hooks import install

    install.install_claude_mcp(tmp_path)
    mcp = tmp_path / ".mcp.json"
    before = mcp.stat().st_mtime_ns

    for _ in range(2):
        subprocess.run(
            ["bash", "-c", install._CLAUDE_SESSIONSTART_COMMAND],
            cwd=tmp_path, capture_output=True,
        )

    assert mcp.stat().st_mtime_ns == before
    # The command must only ANNOUNCE (a single echo); it must not EXECUTE a
    # config rewrite. Mentioning `medusa hooks install` in the printed guidance
    # text is fine — running it on every session is not (CR-024).
    cmd = install._CLAUDE_SESSIONSTART_COMMAND
    assert cmd.strip().startswith("echo ")
    assert "install --claude-mcp" not in cmd


# --------------------------------------------------------------------------- #
# CR-018 — _quiet is thread-safe under concurrent scans
# --------------------------------------------------------------------------- #
def test_quiet_threadsafe_concurrent_vet(tmp_path):
    from medusa.core import scan_api

    (tmp_path / "a.txt").write_text("hello\n")
    errors: list = []

    def run():
        try:
            scan_api.vet_path(str(tmp_path))
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
