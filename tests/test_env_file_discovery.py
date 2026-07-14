"""Regression (PC001 functional tests): the directory walker must NOT drop a
secret/code file in a directory scan. Two distinct bugs, both finding-suppression:

1. SUBSTRING bleed (fixed 9898cb9): a dir-exclude token applied as re.search over
   the whole path skipped environment.py, config.env, distribution.py, etc.
2. EXACT-FILENAME-EQUALS-DIR-TOKEN (PC001 2026-07-14): `_is_path_excluded` checked
   the *filename* against directory-exclude tokens, so a file whose name equals a
   bare token — `.env` (the canonical secrets file), `build`, `dist`, `env`, … —
   was dropped on any DEFAULT-config scan.

CRITICAL test-methodology note: these assertions MUST pin the shipped DEFAULT
config. `MedusaParallelScanner` loads `.medusa.yml` from the CWD upward, and THIS
repo's `.medusa.yml` omits `.env/` from its excludes — so a test run from the repo
root silently exercised a config in which the bug cannot occur (falsely green).
We set `scanner.config = MedusaConfig()` so the default `.env/`/`env/`/`build/`
excludes are in play, which is what a user's clean install actually uses.
"""
from pathlib import Path
from medusa.core.parallel import MedusaParallelScanner
from medusa.config import MedusaConfig


def _w(p: Path, txt="x = 1\n"):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(txt)


def _discover_default_config(proj: Path):
    """find_scannable_files() under the SHIPPED default excludes (never the repo's
    ambient .medusa.yml)."""
    scanner = MedusaParallelScanner(project_root=proj, use_cache=False)
    scanner.config = MedusaConfig()  # pin default excludes; exclude sets are built at call time
    return {f.name for f in scanner.find_scannable_files()}


def test_env_file_scanned_under_default_config(tmp_path):
    """The canonical `.env` secrets file must be scanned even though `.env/` is a
    default DIRECTORY exclude. (Exact-filename-equals-dir-token bug.)"""
    proj = tmp_path / "proj"
    # A real-looking value is unnecessary here — the assertion is DISCOVERY
    # (.env reaches the file list), not secret detection — and a genuine
    # AWS-key pattern in a committed fixture would (rightly) trip the
    # pre-commit secret hook. Placeholder keeps the intent without the pattern.
    _w(proj / ".env", "AWS_SECRET_ACCESS_KEY=placeholder-not-a-real-secret\n")
    _w(proj / "normal.py")
    found = _discover_default_config(proj)
    assert ".env" in found, ".env secret file dropped in a default-config directory scan"


def test_substring_named_files_are_scanned(tmp_path):
    """Files whose PATH merely contains a dir-token substring must be scanned."""
    proj = tmp_path / "proj"
    _w(proj / "config.env", "TOKEN=xyz\n")
    _w(proj / "environment.py")
    _w(proj / "distribution.py")
    _w(proj / "binance_client.py")
    _w(proj / "normal.py")
    found = _discover_default_config(proj)
    for must in ("config.env", "environment.py", "distribution.py",
                 "binance_client.py", "normal.py"):
        assert must in found, f"{must!r} wrongly dropped by a dir-exclude token"


def test_real_excluded_directory_still_pruned(tmp_path):
    """A genuine excluded DIRECTORY (env/, node_modules/) must still be pruned —
    the fix must not lose exclusion coverage."""
    proj = tmp_path / "proj"
    _w(proj / "env" / "inside.py")
    _w(proj / "node_modules" / "pkg.js")
    _w(proj / "keep.py")
    found = _discover_default_config(proj)
    assert "keep.py" in found
    assert "inside.py" not in found, "contents of an env/ directory must still be pruned"
    assert "pkg.js" not in found, "contents of node_modules/ must still be pruned"
