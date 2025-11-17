#!/usr/bin/env python3
"""
MEDUSA PATH Setup Utility
Automatically configures PATH for macOS/Linux users
"""

import os
import sys
import subprocess
from pathlib import Path


def get_shell():
    """Detect user's shell"""
    shell = os.environ.get('SHELL', '')
    if 'zsh' in shell:
        return 'zsh', Path.home() / '.zshrc'
    elif 'bash' in shell:
        return 'bash', Path.home() / '.bashrc'
    elif 'fish' in shell:
        return 'fish', Path.home() / '.config' / 'fish' / 'config.fish'
    else:
        return 'unknown', None


def find_medusa_path():
    """Find where medusa is installed"""
    # Try common pip install locations
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}"

    possible_paths = [
        Path.home() / 'Library' / 'Python' / python_version / 'bin',  # macOS user install
        Path.home() / '.local' / 'bin',  # Linux user install
        Path('/usr/local/bin'),  # Global install
    ]

    for path in possible_paths:
        medusa_bin = path / 'medusa'
        if medusa_bin.exists():
            return path

    return None


def is_in_path(directory):
    """Check if directory is in PATH"""
    path_dirs = os.environ.get('PATH', '').split(':')
    return str(directory) in path_dirs


def add_to_path(directory, shell, rc_file):
    """Add directory to shell RC file"""
    if not rc_file or not rc_file.exists():
        rc_file.parent.mkdir(parents=True, exist_ok=True)
        rc_file.touch()

    # Check if already in RC file
    content = rc_file.read_text() if rc_file.exists() else ''
    path_line = f'export PATH="{directory}:$PATH"'

    if str(directory) in content:
        print(f"✅ {directory} already in {rc_file}")
        return False

    # Add to RC file
    with open(rc_file, 'a') as f:
        f.write(f'\n# Added by MEDUSA installer\n')
        f.write(f'{path_line}\n')

    print(f"✅ Added {directory} to {rc_file}")
    return True


def main():
    print("🐍 MEDUSA PATH Setup Utility\n")

    # Find medusa installation
    medusa_path = find_medusa_path()

    if not medusa_path:
        print("❌ Could not find medusa installation")
        print("\nPlease install MEDUSA first:")
        print("  pip3 install medusa-security")
        sys.exit(1)

    print(f"✅ Found medusa at: {medusa_path}")

    # Check if already in PATH
    if is_in_path(medusa_path):
        print(f"✅ {medusa_path} is already in PATH")
        print("\nTry running: medusa --version")
        sys.exit(0)

    # Detect shell
    shell, rc_file = get_shell()

    if shell == 'unknown' or not rc_file:
        print(f"⚠️  Could not detect shell configuration file")
        print(f"\nManually add this to your shell configuration:")
        print(f'  export PATH="{medusa_path}:$PATH"')
        sys.exit(1)

    print(f"✅ Detected shell: {shell}")
    print(f"✅ Config file: {rc_file}")

    # Add to PATH
    added = add_to_path(medusa_path, shell, rc_file)

    if added:
        print(f"\n✅ PATH updated successfully!")
        print(f"\nTo apply changes, run one of:")
        print(f"  source {rc_file}")
        print(f"  # OR open a new terminal")
        print(f"\nThen test with: medusa --version")
    else:
        print(f"\n✅ PATH already configured")
        print(f"\nIf 'medusa' still not found, try:")
        print(f"  source {rc_file}")
        print(f"  # OR open a new terminal")


if __name__ == '__main__':
    main()
