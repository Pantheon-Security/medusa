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
    """Test version is accessible"""
    from medusa import __version__
    # Using assert in tests is standard pytest practice
    assert __version__ == "2025.8.5.11"
