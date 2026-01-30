"""
MEDUSA v2026.2 Simplified Installer

Only installs AI security tools via pip. No more 47-tool nightmare.
"""

import subprocess
import shutil
import sys
from typing import Optional


def _in_virtualenv() -> bool:
    """Check if we're running in a virtual environment."""
    return hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)


# The ONLY tools we install now
AI_TOOLS = {
    'modelscan': {
        'pip': 'modelscan',
        'description': 'ML model security scanner (scans .pkl, .pt, .h5 files)',
        'required': True,
    },
    # Future: add more if needed, but keep it minimal
}


def is_pip_available() -> bool:
    """Check if pip is available."""
    return shutil.which('pip') is not None or shutil.which('pip3') is not None


def get_pip_command() -> list:
    """Get the pip command to use as a list."""
    # If in virtualenv, use sys.executable -m pip
    if _in_virtualenv():
        return [sys.executable, '-m', 'pip']
    # Otherwise use system pip
    if shutil.which('pip3'):
        return ['pip3']
    return ['pip']


def is_tool_installed(tool_name: str) -> bool:
    """Check if a tool is installed."""
    if tool_name == 'modelscan':
        # Check if modelscan is importable
        try:
            result = subprocess.run(
                get_pip_command() + ['show', 'modelscan'],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    return shutil.which(tool_name) is not None


def install_ai_tools(verbose: bool = False) -> dict:
    """
    Install AI security tools via pip.

    Returns dict with results: {'modelscan': True/False, ...}
    """
    if not is_pip_available():
        return {'error': 'pip not found. Please install Python/pip first.'}

    results = {}
    pip_cmd = get_pip_command()

    for tool_name, tool_info in AI_TOOLS.items():
        if is_tool_installed(tool_name):
            results[tool_name] = {'status': 'already_installed'}
            continue

        try:
            # Build install command
            cmd = pip_cmd + ['install', tool_info['pip']]
            # Add --user only if not in virtualenv
            if not _in_virtualenv():
                cmd.append('--user')
            if not verbose:
                cmd.append('-q')

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                results[tool_name] = {'status': 'installed'}
            else:
                results[tool_name] = {
                    'status': 'failed',
                    'error': result.stderr
                }
        except Exception as e:
            results[tool_name] = {
                'status': 'failed',
                'error': str(e)
            }

    return results


def get_ai_tools_status() -> dict:
    """Get installation status of AI tools."""
    status = {}
    for tool_name, tool_info in AI_TOOLS.items():
        status[tool_name] = {
            'installed': is_tool_installed(tool_name),
            'description': tool_info['description'],
            'required': tool_info.get('required', False),
        }
    return status


def get_detected_tools() -> list:
    """
    Detect which external tools the user already has installed.
    We don't install these, but we'll use them if present.
    """
    optional_tools = [
        'bandit',
        'semgrep',
        'shellcheck',
        'hadolint',
        'yamllint',
        'eslint',
        'trivy',
        'gitleaks',
        'tflint',
        'golangci-lint',
    ]

    detected = []
    for tool in optional_tools:
        if shutil.which(tool):
            detected.append(tool)

    return detected


def get_optional_tools() -> list:
    """Get list of optional tools that enhance scanning (but we don't install)."""
    all_optional = [
        ('bandit', 'Python security linter'),
        ('semgrep', 'Pattern matching engine'),
        ('shellcheck', 'Shell script analyzer'),
        ('hadolint', 'Dockerfile linter'),
        ('yamllint', 'YAML linter'),
        ('eslint', 'JavaScript linter'),
        ('trivy', 'Container scanner'),
        ('gitleaks', 'Secrets scanner'),
    ]

    return [
        {'name': name, 'description': desc, 'installed': shutil.which(name) is not None}
        for name, desc in all_optional
    ]
