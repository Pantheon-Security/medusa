#!/usr/bin/env python3
"""
MEDUSA macOS Installer
Package installer for macOS using Homebrew
"""

import subprocess
import shutil
from pathlib import Path
from medusa.platform.installers.base import BaseInstaller, ToolMapper


class HomebrewInstaller(BaseInstaller):
    """macOS package installer using Homebrew"""

    # Tools that need special handling on macOS (checked BEFORE ToolMapper)
    SPECIAL_INSTALLS = {
        'dart': {'tap': 'dart-lang/dart', 'package': 'dart'},
        'swiftlint': {'brew_package': 'swiftlint', 'requires_xcode': True},
        'rubocop': {'gem_user': True},  # Use gem install --user-install
        'perlcritic': {'cpanm_first': True, 'brew_package': 'perl-critic'},  # Try cpanm before cpan
        'codenarc': {'skip': True, 'reason': 'Groovy linter - install via SDKMAN or download JAR'},
    }

    # Helpful hints for tools that commonly fail on macOS
    INSTALL_HINTS = {
        'swiftlint': 'Requires Xcode CLI tools. Run: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer',
        'perlcritic': 'Requires C compiler. Run: xcode-select --install',
        'codenarc': 'Install SDKMAN first: curl -s "https://get.sdkman.io" | bash && sdk install groovy',
        'rubocop': 'Add gem bin to PATH: export PATH="~/.gem/ruby/$(ruby -e "puts RUBY_VERSION")/bin:$PATH"',
    }

    @classmethod
    def get_install_hint(cls, tool: str) -> str:
        """Get helpful installation hint for a tool"""
        return cls.INSTALL_HINTS.get(tool, '')

    def __init__(self):
        super().__init__('brew')

    def _tap_if_needed(self, tap: str) -> bool:
        """Add a homebrew tap if not already present"""
        try:
            # Check if tap exists
            result = self.run_command(['brew', 'tap'], check=False)
            if tap in result.stdout:
                return True
            # Add tap
            result = self.run_command(['brew', 'tap', tap], check=False)
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            return False

    def _find_cargo(self) -> str:
        """Find cargo, checking ~/.cargo/bin even if not in PATH"""
        cargo = shutil.which('cargo')
        if cargo:
            return cargo

        # Check common locations
        home = Path.home()
        cargo_paths = [
            home / '.cargo' / 'bin' / 'cargo',
        ]
        for path in cargo_paths:
            if path.exists():
                return str(path)
        return None

    def _install_via_gem(self, package: str) -> bool:
        """Install Ruby gem with --user-install to avoid permission issues"""
        gem = shutil.which('gem')
        if not gem:
            return False

        try:
            result = subprocess.run(
                [gem, 'install', '--user-install', package],
                capture_output=True, text=True, timeout=120
            )
            # gem install returns 0 on success, even with PATH warnings
            # The warning "You don't have ~/.gem/ruby/X.X.X/bin in your PATH" is normal
            if result.returncode == 0:
                # Gem succeeded - check if binary exists anywhere
                if shutil.which(package):
                    return True

                # Check user gem bin directories and show PATH hint
                user_gem_bin = Path.home() / '.gem' / 'ruby'
                gem_bin_path = None
                if user_gem_bin.exists():
                    for version_dir in user_gem_bin.iterdir():
                        bin_path = version_dir / 'bin' / package
                        if bin_path.exists():
                            gem_bin_path = version_dir / 'bin'
                            break

                # Show PATH hint if gem installed but not in PATH
                if gem_bin_path:
                    from rich.console import Console
                    console = Console()
                    console.print(f"[green]  ✅ Installed via gem (add gem bin to PATH)[/green]")
                    console.print(f"[yellow]     Add to your shell profile:[/yellow]")
                    console.print(f"[cyan]     export PATH=\"{gem_bin_path}:$PATH\"[/cyan]")
                    return True

                # Even if binary not in PATH, gem install succeeded
                return True
            return False
        except Exception:
            return False

    def _install_via_cpanm(self, module: str) -> bool:
        """Install Perl module via cpanm (faster than cpan)"""
        cpanm = shutil.which('cpanm')
        if not cpanm:
            # Try to install cpanm first
            cpan = shutil.which('cpan')
            if cpan:
                try:
                    subprocess.run([cpan, '-T', 'App::cpanminus'],
                                   capture_output=True, timeout=300)
                    cpanm = shutil.which('cpanm')
                except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError):
                    pass

        if not cpanm:
            return False

        try:
            result = subprocess.run(
                [cpanm, '--notest', module],
                capture_output=True, text=True, timeout=300
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError):
            return False

    def _install_via_cargo(self, crate: str) -> bool:
        """Install Rust crate via cargo"""
        cargo = self._find_cargo()
        if not cargo:
            return False

        try:
            result = subprocess.run(
                [cargo, 'install', crate],
                capture_output=True, text=True, timeout=600
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError):
            return False

    def _check_xcode_cli_tools(self) -> bool:
        """Check if Xcode command line tools are properly configured"""
        try:
            result = subprocess.run(
                ['xcode-select', '-p'],
                capture_output=True, text=True
            )
            # Should point to Xcode.app, not just CommandLineTools
            return 'Xcode.app' in result.stdout or result.returncode == 0
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            return False

    def _install_with_xcode_check(self, brew_package: str) -> bool:
        """Install a package that requires Xcode, with helpful error message"""
        # First check Xcode setup
        if not self._check_xcode_cli_tools():
            from rich.console import Console
            console = Console()
            console.print("[yellow]  ⚠ Xcode CLI tools may not be configured correctly[/yellow]")
            console.print("[yellow]    Run: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer[/yellow]")

        # Try the install anyway
        try:
            result = self.run_command(['brew', 'install', brew_package], check=False)
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            return False

    def install(self, package: str, sudo: bool = False) -> bool:
        """Install package using brew (no sudo needed)"""
        if not self.pm_path:
            return False

        # Check for special install handling FIRST
        if package in self.SPECIAL_INSTALLS:
            special = self.SPECIAL_INSTALLS[package]

            # Skip tools that can't be auto-installed
            if special.get('skip'):
                return False

            # Handle Ruby gems with user install
            if special.get('gem_user'):
                return self._install_via_gem(package)

            # Handle Perl modules - try cpanm first
            if special.get('cpanm_first'):
                if self._install_via_cpanm('Perl::Critic'):
                    return True
                # Fall back to brew
                brew_pkg = special.get('brew_package', package)
                try:
                    result = self.run_command(['brew', 'install', brew_pkg], check=False)
                    return result.returncode == 0
                except (subprocess.SubprocessError, OSError, FileNotFoundError):
                    return False

            # Handle tools that require Xcode (like swiftlint)
            if special.get('requires_xcode'):
                brew_pkg = special.get('brew_package', package)
                return self._install_with_xcode_check(brew_pkg)

            # Handle taps (e.g., dart needs dart-lang/dart tap)
            if 'tap' in special:
                if not self._tap_if_needed(special['tap']):
                    return False

            # Use special package name if specified
            package_name = special.get('package', package)
        else:
            package_name = ToolMapper.get_package_name(package, 'brew')

        if not package_name:
            return False

        cmd = ['brew', 'install', package_name]

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            return False

    def is_installed(self, package: str) -> bool:
        """Check if package is installed via brew"""
        package_name = ToolMapper.get_package_name(package, 'brew')
        if not package_name:
            return False

        try:
            result = self.run_command(['brew', 'list', package_name], check=False)
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            return False

    def uninstall(self, package: str, sudo: bool = False) -> bool:
        """Uninstall package using brew (no sudo needed)"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'brew')
        if not package_name:
            return False

        cmd = ['brew', 'uninstall', package_name]

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            return False

    def get_install_command(self, package: str, sudo: bool = False) -> str:
        package_name = ToolMapper.get_package_name(package, 'brew')
        if not package_name:
            return f"# Package '{package}' not available via Homebrew"
        return f"brew install {package_name}"
