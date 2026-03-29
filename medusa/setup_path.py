#!/usr/bin/env python3
"""
MEDUSA PATH Setup Utility
Automatically configures PATH for Windows, macOS, and Linux users
"""

import os
import sys
import sysconfig
from pathlib import Path

_warned = False  # module-level sentinel — warn once per process


def get_scripts_dir() -> Path | None:
    """Get the pip scripts directory for the current Python install."""
    scripts = sysconfig.get_path('scripts')
    return Path(scripts) if scripts else None


def is_in_path(directory: Path) -> bool:
    """Check if directory is already in the current PATH."""
    sep = ';' if sys.platform == 'win32' else ':'
    path_str = os.environ.get('PATH', '')
    if not path_str:
        return False
    path_dirs = [Path(p) for p in path_str.split(sep) if p]
    return directory in path_dirs


def _is_venv() -> bool:
    """Return True when running inside a virtual environment."""
    return sys.prefix != sys.base_prefix


# ── Windows ────────────────────────────────────────────────────────────────

def _win_fix_path(scripts_dir: Path) -> bool:
    """
    Permanently add scripts_dir to the Windows User PATH via the registry.
    Returns True if PATH was modified, False if it was already present.
    """
    import winreg  # only available on Windows

    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r'Environment',
        0,
        winreg.KEY_READ | winreg.KEY_WRITE,
    )
    try:
        try:
            current, reg_type = winreg.QueryValueEx(key, 'Path')
        except FileNotFoundError:
            current = ''
            reg_type = winreg.REG_SZ

        scripts_str = str(scripts_dir)

        # Use proper path-segment split to avoid false substring matches
        sep = ';'
        existing = [p.strip() for p in current.split(sep) if p.strip()]
        if any(Path(p) == scripts_dir for p in existing):
            return False  # already present

        new_path = current.rstrip(sep) + sep + scripts_str
        # Preserve original registry value type (REG_SZ or REG_EXPAND_SZ)
        winreg.SetValueEx(key, 'Path', 0, reg_type, new_path)
    finally:
        winreg.CloseKey(key)

    # Broadcast WM_SETTINGCHANGE so Explorer / new terminals pick it up
    try:
        import ctypes
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, 'Environment', 2, 5000, None
        )
    except Exception:
        pass  # non-fatal

    return True


def main_windows(scripts_dir: Path) -> None:
    print("MEDUSA PATH Setup — Windows\n")
    print(f"Scripts directory: {scripts_dir}")

    if is_in_path(scripts_dir):
        print("\nPATH already configured — medusa should work in any new terminal.")
        return

    print("\nScripts directory is not on PATH.")
    print("Adding it permanently to your User PATH via the registry...\n")

    try:
        modified = _win_fix_path(scripts_dir)
        if modified:
            print("PATH updated successfully.")
            print("\nOpen a NEW PowerShell/Command Prompt window and run:")
            print("  medusa --version")
            print("\nOr refresh PATH in your current session with:")
            print('  $env:Path = [System.Environment]::GetEnvironmentVariable("Path","User") + ";" + [System.Environment]::GetEnvironmentVariable("Path","Machine")')
        else:
            print("PATH already contains the Scripts directory.")
    except Exception as e:
        print(f"Could not update registry automatically: {e}")
        print("\nManual fix — run this once in PowerShell:")
        print(f'  $p = [System.Environment]::GetEnvironmentVariable("Path","User")')
        print(f'  [System.Environment]::SetEnvironmentVariable("Path", "$p;{scripts_dir}", "User")')
        print("\nThen open a new terminal and run: medusa --version")


# ── macOS / Linux ──────────────────────────────────────────────────────────

def get_shell():
    """Detect user's shell and rc file."""
    shell = os.environ.get('SHELL', '')
    if 'zsh' in shell:
        return 'zsh', Path.home() / '.zshrc'
    elif 'bash' in shell:
        return 'bash', Path.home() / '.bashrc'
    elif 'fish' in shell:
        return 'fish', Path.home() / '.config' / 'fish' / 'config.fish'
    return 'unknown', None


def main_unix(scripts_dir: Path) -> None:
    print("MEDUSA PATH Setup — macOS/Linux\n")
    print(f"Scripts directory: {scripts_dir}")

    if is_in_path(scripts_dir):
        print("\nPATH already configured — medusa should work in any new terminal.")
        return

    shell, rc_file = get_shell()
    if shell == 'unknown' or not rc_file:
        print("\nCould not detect shell. Add this to your shell config manually:")
        print(f'  export PATH="{scripts_dir}:$PATH"')
        return

    print(f"\nDetected shell: {shell} ({rc_file})")

    rc_file.parent.mkdir(parents=True, exist_ok=True)
    content = rc_file.read_text() if rc_file.exists() else ''
    path_line = f'export PATH="{scripts_dir}:$PATH"'

    if str(scripts_dir) in content:
        print("PATH entry already present in rc file.")
    else:
        with open(rc_file, 'a') as f:
            f.write(f'\n# Added by MEDUSA\n{path_line}\n')
        print(f"Added PATH entry to {rc_file}")

    print(f"\nApply with:  source {rc_file}")
    print("Then run:    medusa --version")


# ── Entry point ────────────────────────────────────────────────────────────

def main() -> None:
    scripts_dir = get_scripts_dir()
    if scripts_dir is None:
        print("Could not determine the pip scripts directory on this system.")
        return
    if sys.platform == 'win32':
        main_windows(scripts_dir)
    else:
        main_unix(scripts_dir)


def check_and_warn() -> None:
    """
    Called once at CLI startup. If medusa.exe is not on PATH on Windows,
    print a one-time actionable warning rather than a cryptic error.

    This function must NEVER raise — it is a convenience warning only.
    """
    global _warned
    if _warned:
        return

    try:
        if sys.platform != 'win32':
            return

        # Skip warning when running inside a virtual environment — the venv's
        # Scripts directory is typically on PATH already, and we should not
        # encourage users to add a venv path to the system PATH permanently.
        if _is_venv():
            return

        scripts_dir = get_scripts_dir()
        if scripts_dir is None or is_in_path(scripts_dir):
            return

        # medusa is running (python found it) but Scripts isn't on PATH —
        # user ran `python -m medusa` and will hit issues running `medusa` directly.
        print(
            "\n[MEDUSA] NOTE: The Scripts directory is not on your PATH.\n"
            f"  {scripts_dir}\n"
            "\n"
            "  Run this once to fix it permanently:\n"
            "    python -m medusa setup_path\n"
            "\n"
            "  Or refresh PATH in your current session:\n"
            '    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","User") + ";" '
            '+ [System.Environment]::GetEnvironmentVariable("Path","Machine")\n'
        )
        _warned = True
    except Exception:
        pass  # Never let this crash the CLI


if __name__ == '__main__':
    main()
