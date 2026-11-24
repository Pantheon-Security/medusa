"""Scan pool tasks: a scan with fewer files than workers splits each file's
scanners over the pool and must report exactly what one sequential pass does,
and no task carries the scanners or their compiled rules."""

import pickle

import pytest

from medusa.core.parallel import (
    MedusaParallelScanner,
    _init_scan_worker,
    _scan_file_task,
    _scan_slice_task,
)

SOURCE = (
    "import subprocess\n"
    "import requests\n"
    "password = 'hunter2-not-a-real-secret'\n"
    "def run(cmd):\n"
    "    subprocess.call(cmd, shell=True)\n"
    "    requests.get(url_from_user)\n"
    "    return eval(cmd)\n"
)


class RecordingPool:
    """In-process stand-in for a multiprocessing pool: records the tasks and
    hands their results back in reverse order, as a pool may finish them."""

    def __init__(self):
        self.tasks = []
        self.funcs = set()

    def imap_unordered(self, func, iterable, chunksize=1):
        items = list(iterable)
        self.tasks.extend(items)
        self.funcs.add(func)
        return reversed([func(item) for item in items])


@pytest.fixture
def project(tmp_path):
    (tmp_path / "app.py").write_text(SOURCE)
    (tmp_path / "tool.py").write_text(SOURCE.replace("eval", "exec"))
    return tmp_path


def _scanner(project, workers):
    """A scanner over the project's files, planned as scan_parallel plans it.

    Only rule-based scanners stay in the map: external tools such as Semgrep
    are not deterministic between two runs, which would hide what the
    comparison is about. Their rules load up front, as scan_parallel loads
    them, so no scanner spends its per-scanner timeout on the rule load.
    """
    scanner = MedusaParallelScanner(project, workers=workers, use_cache=False)
    files = scanner.find_scannable_files()
    scanner._pre_map_scanners(files)
    for key, scanners in scanner._scanner_map.items():
        scanner._scanner_map[key] = [s for s in scanners if hasattr(s, '_load_rules')]
        for kept in scanner._scanner_map[key]:
            kept._load_rules()
    scanner._slice_plan = scanner._plan_slices(files)
    _init_scan_worker(None, scanner)
    return scanner, files


def _views(results):
    return {
        result.file: (result.scanner, result.issues, result.scanner_stats,
                      result.line_count, result.scanner_errors, result.cached)
        for result in results
    }


def test_slices_report_what_one_sequential_pass_reports(project):
    scanner, files = _scanner(project, workers=8)
    expected = _views(scanner.scan_file(path) for path in files)
    pool = RecordingPool()

    assert _views(scanner._imap_results(pool, files, 1)) == expected
    assert any(view[1] for view in expected.values())
    assert pool.funcs == {_scan_slice_task}
    assert len(pool.tasks) > len(files)


def test_as_many_files_as_workers_keep_one_task_per_file(project):
    scanner, files = _scanner(project, workers=2)
    pool = RecordingPool()

    assert scanner._slice_plan is None
    assert len(_views(scanner._imap_results(pool, files, 1))) == len(files)
    assert (pool.funcs, pool.tasks) == ({_scan_file_task}, files)


def test_tasks_pickle_without_scanners_or_rules(project):
    scanner, files = _scanner(project, workers=8)
    _early, tasks, _pending = scanner._slice_plan

    assert max(len(pickle.dumps(task)) for task in tasks) < 1024
    assert max(len(pickle.dumps(path)) for path in files) < 1024


def test_slices_run_in_real_worker_processes(project):
    scanner, files = _scanner(project, workers=4)
    expected = _views(scanner.scan_file(path) for path in files)

    with scanner._pool() as pool:
        assert _views(scanner._imap_results(pool, files, 1)) == expected
