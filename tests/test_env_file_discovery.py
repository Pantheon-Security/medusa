"""Regression (PC001 functional test): the directory walker must NOT drop files
whose path merely CONTAINS a dir-exclude token (env/dist/build/bin/...).

Old bug: each dir-exclude was re.compile(re.escape(pc)) applied with regex.search
over the whole path -> a substring match that silently skipped environment.py,
config.env, distribution.py, binance_client.py, and EVERY .env secret file,
defeating secret detection on a directory scan. Real excluded DIRECTORIES (env/)
must still be pruned.
"""
from pathlib import Path
from medusa.core.parallel import MedusaParallelScanner


def _w(p: Path, txt="x = 1\n"):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(txt)


def test_substring_named_and_env_files_are_scanned(tmp_path):
    proj = tmp_path / "proj"
    _w(proj / ".env", "SECRET_KEY=abc123\n")
    _w(proj / "config.env", "TOKEN=xyz\n")
    _w(proj / "environment.py")
    _w(proj / "distribution.py")
    _w(proj / "binance_client.py")
    _w(proj / "normal.py")
    _w(proj / "env" / "inside.py")   # a genuine excluded DIRECTORY

    found = {f.name for f in
             MedusaParallelScanner(project_root=proj, use_cache=False).find_scannable_files()}
    for must in (".env", "config.env", "environment.py", "distribution.py",
                 "binance_client.py", "normal.py"):
        assert must in found, f"{must!r} wrongly dropped by substring-exclude bug"
    assert "inside.py" not in found, "contents of an env/ directory must still be pruned"
