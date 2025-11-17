#!/usr/bin/env python3
"""
MEDUSA Base Installer Class
Base class for platform-specific linter installers
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional
import subprocess
import shutil


class BaseInstaller(ABC):
    """
    Abstract base class for platform-specific installers
    """

    def __init__(self, package_manager: str):
        self.package_manager = package_manager
        self.pm_path = shutil.which(package_manager)

    @abstractmethod
    def install(self, package: str, sudo: bool = True) -> bool:
        """
        Install a package

        Args:
            package: Package name to install
            sudo: Whether to use sudo (default True)

        Returns:
            True if installation succeeded
        """
        pass

    @abstractmethod
    def is_installed(self, package: str) -> bool:
        """
        Check if a package is already installed

        Args:
            package: Package name to check

        Returns:
            True if package is installed
        """
        pass

    @abstractmethod
    def uninstall(self, package: str, sudo: bool = True) -> bool:
        """
        Uninstall a package

        Args:
            package: Package name to uninstall
            sudo: Whether to use sudo (default True)

        Returns:
            True if uninstallation succeeded
        """
        pass

    def get_install_command(self, package: str, sudo: bool = True) -> str:
        """
        Get the install command as a string

        Args:
            package: Package name to install
            sudo: Whether to use sudo

        Returns:
            Command string
        """
        return f"# Install command not implemented for {self.package_manager}"

    def run_command(self, cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """
        Run a command and return result

        Args:
            cmd: Command and arguments
            check: Whether to raise on error

        Returns:
            CompletedProcess result
        """
        return subprocess.run(cmd, capture_output=True, text=True, check=check)


class ToolMapper:
    """
    Maps scanner tool names to package names for different package managers
    """

    # Python tools that can be installed via pip as fallback
    PYTHON_TOOLS = {'bandit', 'yamllint', 'sqlfluff', 'ansible-lint', 'vint', 'cmake-lint', 'gixy'}

    # npm tools that can be installed via npm as fallback
    NPM_TOOLS = {'eslint', 'markdownlint', 'stylelint', 'htmlhint', 'tsc', 'solhint', 'graphql-schema-linter'}

    # Mapping of tool -> package name for different package managers
    TOOL_PACKAGES = {
        'bandit': {
            'apt': 'python3-bandit',  # Fixed: Ubuntu/Debian uses python3-bandit
            'yum': 'bandit',
            'dnf': 'bandit',
            'pacman': 'bandit',
            'brew': 'bandit',
            'pip': 'bandit',
        },
        'shellcheck': {
            'apt': 'shellcheck',
            'yum': 'ShellCheck',
            'dnf': 'ShellCheck',
            'pacman': 'shellcheck',
            'brew': 'shellcheck',
        },
        'yamllint': {
            'apt': 'yamllint',
            'yum': 'yamllint',
            'dnf': 'yamllint',
            'pacman': 'yamllint',
            'brew': 'yamllint',
            'pip': 'yamllint',
        },
        'hadolint': {
            'brew': 'hadolint',
            'manual': 'wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 && chmod +x /usr/local/bin/hadolint',
        },
        'markdownlint': {
            'npm': 'markdownlint-cli',
        },
        'eslint': {
            'npm': 'eslint',
        },
        'tflint': {
            'brew': 'tflint',
            'manual': 'curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash',
        },
        'golangci-lint': {
            'brew': 'golangci-lint',
            'manual': 'curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin',
        },
        'rubocop': {
            'apt': 'rubocop',
            'brew': 'rubocop',
            'manual': 'gem install rubocop',
        },
        'phpstan': {
            'brew': 'phpstan',
            'manual': 'composer global require phpstan/phpstan',
        },
        'cargo-clippy': {
            'manual': 'rustup component add clippy',
        },
        'sqlfluff': {
            'pip': 'sqlfluff',
        },
        'stylelint': {
            'npm': 'stylelint',
        },
        'htmlhint': {
            'npm': 'htmlhint',
        },
        'ktlint': {
            'brew': 'ktlint',
            'manual': 'curl -sSLO https://github.com/pinterest/ktlint/releases/latest/download/ktlint && chmod a+x ktlint && sudo mv ktlint /usr/local/bin/',
        },
        'swiftlint': {
            'brew': 'swiftlint',
            'manual': 'Download from: https://github.com/realm/SwiftLint/releases',
        },
        'cppcheck': {
            'apt': 'cppcheck',
            'yum': 'cppcheck',
            'dnf': 'cppcheck',
            'pacman': 'cppcheck',
            'brew': 'cppcheck',
        },
        'checkstyle': {
            'apt': 'checkstyle',
            'yum': 'checkstyle',
            'dnf': 'checkstyle',
            'brew': 'checkstyle',
        },
        'tsc': {
            'npm': 'typescript',
        },
        'scalastyle': {
            'brew': 'scalastyle',
            'manual': 'Download from: https://www.scalastyle.org/',
        },
        'perlcritic': {
            'apt': 'libperl-critic-perl',
            'brew': 'perl-critic',
            'manual': 'cpan Perl::Critic',
        },
        'pwsh': {
            'apt': 'powershell',
            'brew': 'powershell',
            'manual': 'https://github.com/PowerShell/PowerShell',
        },
        'Rscript': {
            'apt': 'r-base',
            'yum': 'R',
            'dnf': 'R',
            'brew': 'r',
            'manual': 'https://www.r-project.org/',
        },
        'ansible-lint': {
            'pip': 'ansible-lint',
        },
        'kube-linter': {
            'brew': 'kube-linter',
            'manual': 'https://github.com/stackrox/kube-linter',
        },
        'taplo': {
            'manual': 'cargo install taplo-cli',
        },
        'xmllint': {
            'apt': 'libxml2-utils',
            'yum': 'libxml2',
            'dnf': 'libxml2',
            'brew': 'libxml2',
        },
        'buf': {
            'brew': 'buf',
            'manual': 'https://buf.build/docs/installation',
        },
        'graphql-schema-linter': {
            'npm': 'graphql-schema-linter',
        },
        'solhint': {
            'npm': 'solhint',
        },
        'luacheck': {
            'brew': 'luacheck',
            'manual': 'luarocks install luacheck',
        },
        'mix': {
            'apt': 'elixir',
            'yum': 'elixir',
            'dnf': 'elixir',
            'pacman': 'elixir',
            'brew': 'elixir',
            'manual': 'https://elixir-lang.org/install.html',
        },
        'hlint': {
            'apt': 'hlint',
            'brew': 'hlint',
            'pacman': 'hlint',
            'manual': 'cabal install hlint',
        },
        'clj-kondo': {
            'brew': 'borkdude/brew/clj-kondo',
            'manual': 'bash <(curl -s https://raw.githubusercontent.com/clj-kondo/clj-kondo/master/script/install-clj-kondo)',
        },
        'dart': {
            'apt': 'dart',
            'brew': 'dart',
            'pacman': 'dart',
            'manual': 'https://dart.dev/get-dart',
        },
        'codenarc': {
            'brew': 'codenarc',
            'manual': 'Download from: https://github.com/CodeNarc/CodeNarc',
        },
        'vint': {
            'pip': 'vim-vint',
        },
        'cmake-lint': {
            'pip': 'cmakelang',
        },
        'checkmake': {
            'brew': 'checkmake',
            'manual': 'go install github.com/mrtazz/checkmake/cmd/checkmake@latest',
        },
        'gixy': {
            'apt': 'gixy',
            'pip': 'gixy',
        },
        'zig': {
            'apt': 'zig',
            'brew': 'zig',
            'pacman': 'zig',
            'manual': 'https://ziglang.org/download/',
        },
    }

    @classmethod
    def get_package_name(cls, tool: str, package_manager: str) -> Optional[str]:
        """
        Get the package name for a tool on a specific package manager

        Args:
            tool: Tool name (e.g., 'bandit', 'shellcheck')
            package_manager: Package manager (e.g., 'apt', 'brew')

        Returns:
            Package name, or None if not available
        """
        tool_info = cls.TOOL_PACKAGES.get(tool, {})
        return tool_info.get(package_manager)

    @classmethod
    def get_install_method(cls, tool: str, package_manager: str) -> str:
        """
        Get the install method for a tool

        Args:
            tool: Tool name
            package_manager: Package manager

        Returns:
            'package' or 'manual' or 'unavailable'
        """
        tool_info = cls.TOOL_PACKAGES.get(tool, {})

        if package_manager in tool_info:
            return 'package'
        elif 'manual' in tool_info:
            return 'manual'
        else:
            return 'unavailable'

    @classmethod
    def is_python_tool(cls, tool: str) -> bool:
        """Check if tool can be installed via pip"""
        return tool in cls.PYTHON_TOOLS

    @classmethod
    def is_npm_tool(cls, tool: str) -> bool:
        """Check if tool can be installed via npm"""
        return tool in cls.NPM_TOOLS
