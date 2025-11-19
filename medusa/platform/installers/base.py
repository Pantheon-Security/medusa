#!/usr/bin/env python3
"""
MEDUSA Base Installer Class
Base class for platform-specific linter installers
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional
import subprocess
import shutil
import platform


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
        # Use shell=True on Windows for .cmd/.bat files
        use_shell = platform.system() == 'Windows'
        return subprocess.run(cmd, capture_output=True, text=True, check=check, shell=use_shell)


class ToolMapper:
    """
    Maps scanner tool names to package names for different package managers
    """

    # Python tools that can be installed via pip as fallback
    PYTHON_TOOLS = {'ansible-lint', 'bandit', 'black', 'cmakelang', 'gixy', 'mypy', 'pylint', 'ruff', 'sqlfluff', 'vim-vint', 'yamllint'}

    # npm tools that can be installed via npm as fallback
    NPM_TOOLS = {'buf', 'eslint', 'graphql-schema-linter', 'htmlhint', 'jshint', 'markdownlint-cli', 'prettier', 'solhint', 'standard', 'stylelint', 'taplo', 'typescript'}

    # Mapping of tool -> package name for different package managers
    TOOL_PACKAGES = {
        'Rscript': {
            'apt': 'r-base',
            'yum': 'R',
            'dnf': 'R',
            'brew': 'r',
            'winget': 'RProject.R',
            'manual': 'https://www.r-project.org/',
        },
        'ansible-lint': {
            'pip': 'ansible-lint',
        },
        'bandit': {
            'apt': 'python3-bandit',
            'yum': 'bandit',
            'dnf': 'bandit',
            'pacman': 'bandit',
            'pip': 'bandit',
            'manual': 'Python security linter',
        },
        'black': {
            'pip': 'black',
        },
        'buf': {
            'yum': 'buf',
            'npm': '@bufbuild/buf',
        },
        'cargo-clippy': {
        },
        'checkmake': {
            'brew': 'checkmake',
            'manual': 'go install github.com/mrtazz/checkmake/cmd/checkmake@latest',
        },
        'checkstyle': {
            'apt': 'checkstyle',
            'yum': 'checkstyle',
            'dnf': 'checkstyle',
            'brew': 'checkstyle',
            'choco': 'checkstyle',
        },
        'clj-kondo': {
            'brew': 'borkdude/brew/clj-kondo',
            'manual': 'bash <(curl -s https://raw.githubusercontent.com/clj-kondo/clj-kondo/master/script/install-clj-kondo)',
        },
        'cmakelang': {
            'pip': 'cmakelang',
        },
        'codenarc': {
            'brew': 'codenarc',
            'manual': 'Download from: https://github.com/CodeNarc/CodeNarc',
        },
        'cppcheck': {
            'apt': 'cppcheck',
            'yum': 'cppcheck',
            'dnf': 'cppcheck',
            'pacman': 'cppcheck',
            'brew': 'cppcheck',
            'winget': 'Cppcheck.Cppcheck',
            'choco': 'cppcheck',
        },
        'dart': {
            'apt': 'dart',
            'pacman': 'dart',
            'brew': 'dart',
            'winget': 'Google.DartSDK',
            'manual': 'https://dart.dev/get-dart',
        },
        'docker-compose': {
            'apt': 'docker-compose',
            'brew': 'docker-compose',
            'winget': 'Docker.DockerCompose',
        },
        'eslint': {
            'npm': 'eslint',
        },
        'gixy': {
            'apt': 'gixy',
            'pip': 'gixy',
        },
        'golangci-lint': {
            'brew': 'golangci-lint',
            'winget': 'GolangCI.golangci-lint',
            'choco': 'golangci-lint',
            'manual': 'curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin',
        },
        'graphql-schema-linter': {
            'npm': 'graphql-schema-linter',
        },
        'hadolint': {
            'brew': 'hadolint',
            'winget': 'hadolint.hadolint',
            'choco': 'hadolint',
            'manual': 'wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 && chmod +x /usr/local/bin/hadolint',
        },
        'hlint': {
            'apt': 'hlint',
            'pacman': 'hlint',
            'brew': 'hlint',
            'manual': 'cabal install hlint',
        },
        'htmlhint': {
            'npm': 'htmlhint',
        },
        'jshint': {
            'npm': 'jshint',
        },
        'ktlint': {
            'brew': 'ktlint',
            'manual': 'curl -sSLO https://github.com/pinterest/ktlint/releases/latest/download/ktlint && chmod a+x ktlint && sudo mv ktlint /usr/local/bin/',
        },
        'kube-linter': {
            'brew': 'kube-linter',
            'winget': 'stackrox.kube-linter',
            'manual': 'https://github.com/stackrox/kube-linter',
        },
        'luacheck': {
            'brew': 'luacheck',
            'manual': 'luarocks install luacheck',
        },
        'markdownlint-cli': {
            'choco': 'markdownlint-cli',
            'npm': 'markdownlint-cli',
        },
        'mix': {
            'apt': 'elixir',
            'yum': 'elixir',
            'dnf': 'elixir',
            'pacman': 'elixir',
            'brew': 'elixir',
            'manual': 'https://elixir-lang.org/install.html',
        },
        'mypy': {
            'pip': 'mypy',
        },
        'perlcritic': {
            'apt': 'libperl-critic-perl',
            'brew': 'perl-critic',
            'manual': 'cpan Perl::Critic',
        },
        'phpstan': {
            'brew': 'phpstan',
            'choco': 'phpstan',
            'manual': 'composer global require phpstan/phpstan',
        },
        'prettier': {
            'npm': 'prettier',
        },
        'PSScriptAnalyzer': {
            'choco': 'PSScriptAnalyzer',
            'manual': 'Install-Module -Name PSScriptAnalyzer',
        },
        'pylint': {
            'pip': 'pylint',
        },
        'rubocop': {
            'apt': 'rubocop',
            'brew': 'rubocop',
            'manual': 'gem install rubocop',
        },
        'ruff': {
            'pip': 'ruff',
        },
        'scalastyle': {
            'brew': 'scalastyle',
            'manual': 'Download from: https://www.scalastyle.org/',
        },
        'shellcheck': {
            'apt': 'shellcheck',
            'yum': 'ShellCheck',
            'dnf': 'ShellCheck',
            'pacman': 'shellcheck',
            'brew': 'shellcheck',
            'winget': 'koalaman.shellcheck',
            'choco': 'shellcheck',
        },
        'solhint': {
            'npm': 'solhint',
        },
        'sqlfluff': {
            'pip': 'sqlfluff',
        },
        'standard': {
            'npm': 'standard',
        },
        'stylelint': {
            'npm': 'stylelint',
        },
        'swiftlint': {
            'brew': 'swiftlint',
            'choco': 'swiftlint',
            'manual': 'Download from: https://github.com/realm/SwiftLint/releases',
        },
        'taplo': {
            'npm': '@taplo/cli',
        },
        'tflint': {
            'brew': 'tflint',
            'winget': 'TerraformLinters.tflint',
            'choco': 'tflint',
            'manual': 'curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash',
        },
        'typescript': {
            'npm': 'typescript',
        },
        'vim-vint': {
            'pip': 'vim-vint',
        },
        'xmllint': {
            'apt': 'libxml2-utils',
            'yum': 'libxml2',
            'dnf': 'libxml2',
            'brew': 'libxml2',
        },
        'yamllint': {
            'apt': 'yamllint',
            'yum': 'yamllint',
            'dnf': 'yamllint',
            'pacman': 'yamllint',
            'brew': 'yamllint',
            'pip': 'yamllint',
        },
        'zig': {
            'apt': 'zig',
            'pacman': 'zig',
            'brew': 'zig',
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
