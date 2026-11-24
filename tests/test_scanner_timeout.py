"""
MEDUSA_SCANNER_TIMEOUT sets the per-scanner timeout of the parallel scanner.
"""
import os
import subprocess
import sys
import time

import pytest

TIMEOUT = "import medusa.core.parallel as p; print(p.PER_SCANNER_TIMEOUT)"
SCANNER = TIMEOUT + "; from pathlib import Path; p.MedusaParallelScanner(Path('.'))"
VERSION = "import sys; from medusa.cli import main; sys.argv = ['medusa', '--version']; main()"
LATER = (
    "import os; from pathlib import Path; import medusa.core.parallel as p; "
    "os.environ['MEDUSA_SCANNER_TIMEOUT'] = '600'; "
    "p.MedusaParallelScanner(Path('.'), use_cache=False); print(p.PER_SCANNER_TIMEOUT)"
)
INVALID = ["abc", "-5", "1.5", "10s", "2147483648", "12345678901", "9" * 5000]


def run_under(value, code):
    """Runs code in a fresh interpreter with MEDUSA_SCANNER_TIMEOUT set to value
    (None leaves it unset) and returns the finished process."""
    env = {k: v for k, v in os.environ.items() if k != "MEDUSA_SCANNER_TIMEOUT"}
    env["PYTHONIOENCODING"] = "utf-8"
    if value is not None:
        env["MEDUSA_SCANNER_TIMEOUT"] = value
    return subprocess.run(
        [sys.executable, "-c", code],
        env=env, capture_output=True, text=True, timeout=120, check=False,
    )


@pytest.mark.parametrize(
    "value, expected",
    [(None, "60"), ("", "60"), ("600", "600"), (" 900 ", "900"), ("0", "0"),
     ("2147483647", "2147483647"), ("00000000060", "60"), ("0" * 5000, "0")],
)
def test_the_variable_sets_the_timeout_and_its_absence_keeps_60(value, expected):
    done = run_under(value, TIMEOUT)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == expected


@pytest.mark.parametrize("value", INVALID)
def test_anything_but_whole_seconds_in_c_int_range_fails_the_scanner_naming_the_value(value):
    done = run_under(value, SCANNER)
    assert done.stdout.strip() == "60"
    assert done.returncode != 0
    assert "MEDUSA_SCANNER_TIMEOUT must be whole seconds from 0 to 2147483647" in done.stderr
    assert repr(value) in done.stderr


def test_a_value_set_after_import_applies_from_the_next_scanner_on():
    done = run_under(None, LATER)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip().splitlines()[-1] == "600"


def test_a_bad_value_leaves_commands_that_never_scan_working():
    done = run_under("abc", VERSION)
    assert done.returncode == 0, done.stderr


@pytest.mark.skipif(sys.platform == "win32", reason="the guard uses SIGALRM")
def test_zero_sets_no_alarm_so_a_slow_scanner_finishes():
    from medusa.core.parallel import MedusaParallelScanner

    class Slow:
        def scan_file(self, path):
            time.sleep(2)
            return "done"

    assert MedusaParallelScanner._run_scanner_with_timeout(Slow(), "x.py", 0) == "done"
    assert MedusaParallelScanner._run_scanner_with_timeout(Slow(), "x.py", 1) is None
