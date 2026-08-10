"""CPU detection must respect cgroup quotas and CPU affinity, not just os.cpu_count().

Docker's `--cpus 4` is a cgroup CPU *bandwidth quota*. It does not change the set of
CPUs the container can see, so `os.cpu_count()` inside a `--cpus 4` container on an
8-core host still returns **8** (verified live, 2026-08-06). Every worker pool medusa
sizes off that number therefore over-subscribes its own quota by the host/quota ratio —
on CI runners, on Docker users' machines, and on the corpus audit sandbox.

`taskset`/CPU pinning is the same class of bug seen from the other side: the quota is
unlimited but the affinity mask is narrow.

These gates cover the detection helper's full fallback matrix plus the two call paths
that actually size pools: `check_system_load()` (which `medusa scan` uses) and
`MedusaParallelScanner` (which `medusa vet` reaches, and which has no CLI knob at all).
"""
import os

import pytest

from medusa.core import system
from medusa.core.system import check_system_load, get_cpu_count


# --------------------------------------------------------------- helpers

def _v2(cgroup, text):
    """cgroup v2 layout: <root>/cpu.max holding '<quota> <period>' or 'max <period>'."""
    (cgroup.root / "cpu.max").write_text(text)


def _v1(cgroup, quota, period=100000, subdir="cpu"):
    """cgroup v1 layout: <root>/<subdir>/cpu.cfs_{quota,period}_us."""
    d = cgroup.root / subdir if subdir else cgroup.root
    d.mkdir(parents=True, exist_ok=True)
    (d / "cpu.cfs_quota_us").write_text(str(quota))
    (d / "cpu.cfs_period_us").write_text(str(period))


class _Cgroup:
    """Fake /sys/fs/cgroup root, plus a setter for the CPU-affinity signal."""

    def __init__(self, root, monkeypatch):
        self.root = root
        self._mp = monkeypatch

    def affinity(self, n):
        self._mp.setattr(os, "sched_getaffinity", lambda _pid: set(range(n)),
                         raising=False)


@pytest.fixture
def cgroup(tmp_path, monkeypatch):
    """Point the detector at a fake /sys/fs/cgroup and pin the other two signals."""
    # No raising=False: if _CGROUP_ROOT is ever renamed these gates must fail
    # loudly rather than silently start reading the real /sys/fs/cgroup.
    monkeypatch.setattr(system, "_CGROUP_ROOT", str(tmp_path))
    monkeypatch.setattr(os, "cpu_count", lambda: 64)
    monkeypatch.setattr(os, "sched_getaffinity", lambda _pid: set(range(64)),
                        raising=False)
    return _Cgroup(tmp_path, monkeypatch)


# ------------------------------------------------------- cgroup v2 (quota)

def test_v2_quota_caps_the_count(cgroup):
    """`docker run --cpus 4` on a 64-core host must report 4, not 64."""
    _v2(cgroup, "400000 100000\n")
    assert get_cpu_count() == 4


def test_v2_fractional_quota_rounds_down(cgroup):
    """2.5 cores of quota must not become 3 workers."""
    _v2(cgroup, "250000 100000\n")
    assert get_cpu_count() == 2


def test_v2_sub_core_quota_floors_at_one(cgroup):
    """`--cpus 0.5` must yield 1 worker, never 0."""
    _v2(cgroup, "50000 100000\n")
    assert get_cpu_count() == 1


def test_v2_unlimited_falls_through(cgroup):
    """'max' means no quota — do not treat it as a limit."""
    _v2(cgroup, "max 100000\n")
    assert get_cpu_count() == 64


# ------------------------------------------------------- cgroup v1 (quota)

def test_v1_quota_caps_the_count(cgroup):
    _v1(cgroup, 200000)
    assert get_cpu_count() == 2


def test_v1_unlimited_quota_falls_through(cgroup):
    """-1 is cgroup v1's 'unlimited' sentinel, not a negative core count."""
    _v1(cgroup, -1)
    assert get_cpu_count() == 64


def test_v1_cpuacct_layout_is_found(cgroup):
    """Many v1 hosts mount the controller as `cpu,cpuacct`."""
    _v1(cgroup, 300000, subdir="cpu,cpuacct")
    assert get_cpu_count() == 3


def test_v1_flat_layout_is_found(cgroup):
    """Inside a v1 container the files often sit at the cgroup root."""
    _v1(cgroup, 100000, subdir="")
    assert get_cpu_count() == 1


def test_v2_wins_when_both_layouts_exist(cgroup):
    """A v2 host with stale v1 files must use v2."""
    _v2(cgroup, "200000 100000\n")
    _v1(cgroup, 800000)
    assert get_cpu_count() == 2


# ------------------------------------------------------------- affinity

def test_affinity_narrower_than_cpu_count_wins(cgroup):
    """`taskset -c 0-3` pins to 4 CPUs with no cgroup quota in sight."""
    cgroup.affinity(4)
    assert get_cpu_count() == 4


def test_minimum_of_affinity_and_quota_wins(cgroup):
    """Both restrictions present: the tighter one governs."""
    _v2(cgroup, "600000 100000\n")           # quota = 6
    cgroup.affinity(2)                       # affinity = 2
    assert get_cpu_count() == 2


def test_quota_wins_when_tighter_than_affinity(cgroup):
    _v2(cgroup, "200000 100000\n")           # quota = 2
    cgroup.affinity(8)                       # affinity = 8
    assert get_cpu_count() == 2


# ------------------------------------------------- fallback / robustness

def test_missing_cgroup_files_fall_back(cgroup):
    """No cgroup at all (macOS, Windows, bare metal) — today's behaviour."""
    assert get_cpu_count() == 64


def test_unreadable_cgroup_falls_back(cgroup, monkeypatch):
    """A /sys that raises on read must not take the scanner down."""
    _v2(cgroup, "400000 100000\n")
    real = open

    def boom(path, *a, **k):
        if "cpu.max" in str(path):
            raise PermissionError(str(path))
        return real(path, *a, **k)

    monkeypatch.setattr("builtins.open", boom)
    assert get_cpu_count() == 64


@pytest.mark.parametrize("junk", ["", "\n", "garbage", "400000", "abc def",
                                  "400000 0", "0 100000", "max"])
def test_malformed_cgroup_content_falls_back(cgroup, junk):
    """Never crash and never return 0 on an unexpected /sys format."""
    _v2(cgroup, junk)
    assert get_cpu_count() == 64


def test_no_sched_getaffinity_is_survivable(cgroup, monkeypatch):
    """Windows/macOS have no sched_getaffinity — must not raise."""
    monkeypatch.delattr(os, "sched_getaffinity", raising=False)
    assert get_cpu_count() == 64


def test_unknown_cpu_count_keeps_the_historical_default(cgroup, monkeypatch):
    """os.cpu_count() can return None; the old code read `os.cpu_count() or 4`."""
    monkeypatch.delattr(os, "sched_getaffinity", raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: None)
    assert get_cpu_count() == 4


def test_never_returns_zero_or_negative(cgroup):
    for text in ("1 100000", "0 100000", "-1 100000", "1 1000000000"):
        _v2(cgroup, text)
        assert get_cpu_count() >= 1, text


# ------------------------------------- the call paths that size real pools

def test_check_system_load_respects_the_quota(cgroup):
    """`medusa scan`'s auto-detect must not recommend 62 workers under `--cpus 4`."""
    _v2(cgroup, "400000 100000\n")
    workers = check_system_load().recommended_workers
    assert workers <= 4, f"recommended {workers} workers against a 4-CPU quota"


def test_parallel_scanner_default_workers_respect_the_quota(cgroup, tmp_path):
    """`medusa vet` reaches MedusaParallelScanner with workers=None and no CLI knob —
    this is the path with no other way to bound it."""
    from medusa.core.parallel import MedusaParallelScanner

    _v2(cgroup, "400000 100000\n")
    root = tmp_path / "proj"
    root.mkdir()
    scanner = MedusaParallelScanner(project_root=root)
    assert scanner.workers <= 4, f"forked {scanner.workers} workers under a 4-CPU quota"


def test_explicit_workers_still_wins(cgroup, tmp_path):
    """Auto-detect only changes the DEFAULT — an explicit workers= is untouched."""
    from medusa.core.parallel import MedusaParallelScanner

    _v2(cgroup, "400000 100000\n")
    root = tmp_path / "proj"
    root.mkdir()
    assert MedusaParallelScanner(project_root=root, workers=16).workers == 16
