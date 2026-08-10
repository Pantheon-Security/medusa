#!/usr/bin/env python3
"""
MEDUSA System Monitoring
Check system load before launching parallel scans
"""

import os
from typing import Tuple, Optional
from dataclasses import dataclass

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


@dataclass
class SystemLoad:
    """System load information"""
    cpu_percent: float
    memory_percent: float
    load_average_1min: float
    recommended_workers: int
    can_scan: bool
    warning_message: Optional[str] = None


# Where the cgroup hierarchy is mounted. Module-level so tests can point the
# detector at a fixture directory.
_CGROUP_ROOT = "/sys/fs/cgroup"

# What this module has always fallen back to when the platform cannot report a
# core count (the historical `os.cpu_count() or 4`). Kept so behaviour on such
# platforms is unchanged.
_UNKNOWN_CPU_DEFAULT = 4


def _read_int(path: str) -> Optional[int]:
    """Read a single integer from a sysfs file, or None if unreadable."""
    try:
        with open(path) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _cgroup_cpu_quota(root: str) -> Optional[float]:
    """CPU count permitted by the cgroup CPU bandwidth quota, or None if none is set.

    None means "no quota visible", never "zero CPUs". Both hierarchies:

        v2:  <root>/cpu.max  ->  "<quota_us> <period_us>"  |  "max <period_us>"
        v1:  <root>[/cpu | /cpu,cpuacct]/cpu.cfs_quota_us + cpu.cfs_period_us
             (quota -1 = unlimited)

    Docker `--cpus`, Kubernetes CPU limits and CI runner caps are all expressed
    this way, and none of them change the *visible* CPU list — which is exactly
    why os.cpu_count() cannot see them.
    """
    # cgroup v2 first: if it is mounted it is authoritative.
    try:
        with open(os.path.join(root, "cpu.max")) as fh:
            quota_s, _, period_s = fh.read().strip().partition(" ")
        if quota_s == "max":
            return None                                  # explicitly unlimited
        quota, period = int(quota_s), int(period_s)
        if quota > 0 and period > 0:
            return quota / period
    except (OSError, ValueError):
        pass                                             # absent or malformed -> try v1

    # cgroup v1: the controller may sit at the root or under cpu/ or cpu,cpuacct/.
    for sub in ("", "cpu", "cpu,cpuacct"):
        base = os.path.join(root, sub) if sub else root
        quota = _read_int(os.path.join(base, "cpu.cfs_quota_us"))
        period = _read_int(os.path.join(base, "cpu.cfs_period_us"))
        if quota is not None and period is not None and quota > 0 and period > 0:
            return quota / period
    return None


def get_cpu_count() -> int:
    """CPUs this process may actually use — the number to size worker pools from.

    Takes the MINIMUM of every restriction that is visible, floored at 1:

      * cgroup CPU quota  — containers (`docker --cpus`, Kubernetes limits, CI caps)
      * CPU affinity mask — `taskset`, cpuset pinning, some CI schedulers
      * os.cpu_count()    — the machine's cores, and the answer everywhere else

    `os.cpu_count()` on its own is wrong inside a container: a CPU *quota* does
    not change the visible CPU list, so a `--cpus 4` container on a 64-core host
    still reports 64 and any pool sized from it over-subscribes its own quota
    16x. Affinity is the same bug seen from the other side — unlimited quota,
    narrow CPU mask.

    Every source is best-effort: anything absent, unreadable or malformed is
    skipped, so macOS, Windows and bare metal keep today's behaviour.
    """
    counts = []

    try:
        affinity = len(os.sched_getaffinity(0))          # Linux only
    except (AttributeError, OSError):
        affinity = None
    if affinity:
        counts.append(affinity)

    quota = _cgroup_cpu_quota(_CGROUP_ROOT)
    if quota:
        counts.append(int(quota))                        # round down; never over-commit

    counts.append(os.cpu_count() or _UNKNOWN_CPU_DEFAULT)
    return max(1, min(counts))


def check_system_load() -> SystemLoad:
    """
    Check current system load and recommend worker count

    Returns:
        SystemLoad with metrics and recommendations
    """
    # If psutil not available, return safe defaults
    if not HAS_PSUTIL:
        cpu_count = get_cpu_count()
        return SystemLoad(
            cpu_percent=0.0,
            memory_percent=0.0,
            load_average_1min=0.0,
            recommended_workers=max(2, cpu_count - 2) if cpu_count > 4 else cpu_count,
            can_scan=True,
            warning_message=None
        )

    # Get CPU usage (averaged over 1 second)
    cpu_percent = psutil.cpu_percent(interval=1)

    # Get memory usage
    memory = psutil.virtual_memory()
    memory_percent = memory.percent

    # Get load average (Linux/macOS only)
    try:
        load_avg = os.getloadavg()[0]  # 1-minute load average
    except (AttributeError, OSError):
        # Windows doesn't have load average
        # (get_cpu_count never returns None, unlike the bare os.cpu_count() this
        #  replaced — which raised TypeError here on platforms that can't count)
        load_avg = cpu_percent / 100.0 * get_cpu_count()

    # Get total CPU cores available to THIS process (cgroup quota / affinity aware)
    cpu_count = get_cpu_count()

    # Determine if system is overloaded
    is_overloaded = False
    warning_msg = None

    # Check CPU load
    if cpu_percent > 80:
        is_overloaded = True
        warning_msg = f"High CPU usage: {cpu_percent:.1f}%"

    # Check memory
    elif memory_percent > 85:
        is_overloaded = True
        warning_msg = f"High memory usage: {memory_percent:.1f}%"

    # Check load average (should be below CPU count)
    elif load_avg > cpu_count * 0.8:
        is_overloaded = True
        warning_msg = f"High load average: {load_avg:.2f} (CPUs: {cpu_count})"

    # Recommend worker count based on load
    if is_overloaded:
        # Reduce workers when system is loaded
        recommended_workers = max(2, cpu_count // 4)
        can_scan = True  # Still allow scanning, just with fewer workers
    elif cpu_percent > 50:
        # Medium load: use half the cores
        recommended_workers = max(2, cpu_count // 2)
        can_scan = True
    else:
        # Low load: use most cores (leave 1-2 for system)
        recommended_workers = max(2, cpu_count - 2) if cpu_count > 4 else cpu_count
        can_scan = True

    return SystemLoad(
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        load_average_1min=load_avg,
        recommended_workers=recommended_workers,
        can_scan=can_scan,
        warning_message=warning_msg
    )


def get_optimal_workers(requested_workers: Optional[int] = None) -> int:
    """
    Get optimal worker count based on system load

    Args:
        requested_workers: User-requested worker count (None = auto)

    Returns:
        Optimal worker count
    """
    load = check_system_load()

    # If user specified workers, respect it (but warn if too high)
    if requested_workers is not None:
        if requested_workers > load.recommended_workers * 2:
            print(f"⚠️  Warning: System load is high. Consider using {load.recommended_workers} workers instead of {requested_workers}")
        return requested_workers

    # Auto-detect optimal workers
    return load.recommended_workers


def print_system_status():
    """Print current system status (for debugging)"""
    load = check_system_load()

    print(f"System Status:")
    print(f"  CPU: {load.cpu_percent:.1f}%")
    print(f"  Memory: {load.memory_percent:.1f}%")
    print(f"  Load Avg (1min): {load.load_average_1min:.2f}")
    print(f"  Recommended Workers: {load.recommended_workers}")

    if load.warning_message:
        print(f"  ⚠️  {load.warning_message}")
