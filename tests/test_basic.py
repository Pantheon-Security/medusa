"""
Basic tests for MEDUSA
"""
import pytest
from medusa.cli import main


def test_import():
    """Test that we can import the main module"""
    # Using assert in tests is standard pytest practice
    assert main is not None


def test_version():
    """Test version is accessible and is a valid 3-part YEAR.MONTH.PATCH string.

    Do NOT hardcode a literal version here — that goes stale on every release
    (it did: this asserted 2026.6.0 long after the package moved on). Exact
    cross-file version consistency is guarded by tests/test_version_consistency.py.
    """
    from medusa import __version__
    parts = __version__.split(".")
    assert len(parts) == 3, f"version must be 3-part YEAR.MONTH.PATCH, got {__version__!r}"
    assert all(p.isdigit() for p in parts), f"version parts must be numeric, got {__version__!r}"
