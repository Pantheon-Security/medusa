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


def check_system_load() -> SystemLoad:
    """
    Check current system load and recommend worker count

    Returns:
        SystemLoad with metrics and recommendations
    """
    # If psutil not available, return safe defaults
    if not HAS_PSUTIL:
        cpu_count = os.cpu_count() or 4
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
        load_avg = cpu_percent / 100.0 * os.cpu_count()

    # Get total CPU cores
    cpu_count = os.cpu_count() or 4

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
