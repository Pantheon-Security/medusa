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
        # On Windows, we don't need shell=True when using explicit paths or when
        # the package manager executables are in PATH (winget.exe, choco.exe work fine)
        # shell=False is safer and works for all our use cases
        return subprocess.run(cmd, capture_output=True, text=True, check=check, shell=False)


class EcosystemDetector:
    """
    Detects and uses language-specific ecosystem package managers
    """

    # Mapping of tools to their ecosystem requirements
    ECOSYSTEM_MAP = {
        'hlint': {'ecosystems': ['stack', 'cabal'], 'commands': {'stack': 'stack install hlint', 'cabal': 'cabal install hlint'}},
        'rubocop': {'ecosystems': ['gem'], 'commands': {'gem': 'gem install --user-install rubocop'}},
        'checkmake': {'ecosystems': ['go'], 'commands': {'go': 'go install github.com/mrtazz/checkmake/cmd/checkmake@latest'}},
        'gitleaks': {'ecosystems': ['go'], 'commands': {'go': 'go install github.com/gitleaks/gitleaks/v8@latest'}},
        'kube-linter': {'ecosystems': ['go'], 'commands': {'go': 'go install golang.stackrox.io/kube-linter/cmd/kube-linter@latest'}},
        'luacheck': {'ecosystems': ['luarocks'], 'commands': {'luarocks': 'luarocks install luacheck'}},
        'perlcritic': {'ecosystems': ['cpanm', 'cpan'], 'commands': {'cpanm': 'cpanm --notest Perl::Critic', 'cpan': 'cpan -T Perl::Critic'}},
        'clj-kondo': {'ecosystems': ['brew', 'scoop'], 'commands': {'brew': 'brew install borkdude/brew/clj-kondo', 'scoop': 'scoop install clj-kondo'}},
        'mix': {'ecosystems': ['elixir'], 'commands': {}},  # mix comes with elixir
        'taplo': {'ecosystems': ['cargo'], 'commands': {'cargo': 'cargo install taplo-cli'}},
        'codenarc': {'ecosystems': ['sdkman', 'gradle'], 'commands': {'sdkman': 'sdk install codenarc', 'gradle': 'gradle installCodeNarc'}},
    }

    @classmethod
    def _find_cargo(cls) -> Optional[str]:
        """Find cargo binary, checking common locations if not in PATH"""
        import os
        from pathlib import Path

        # Check PATH first
        cargo = shutil.which('cargo')
        if cargo:
            return cargo

        # Check common cargo locations (after rustup install, may not be in PATH yet)
        home = Path.home()
        cargo_paths = [
            home / '.cargo' / 'bin' / 'cargo',
            home / '.rustup' / 'toolchains' / 'stable-x86_64-apple-darwin' / 'bin' / 'cargo',
            home / '.rustup' / 'toolchains' / 'stable-aarch64-apple-darwin' / 'bin' / 'cargo',
            Path('/usr/local/cargo/bin/cargo'),
        ]

        for path in cargo_paths:
            if path.exists():
                return str(path)

        return None

    @classmethod
    def detect_ecosystem(cls, tool: str) -> Optional[tuple]:
        """
        Detect if an ecosystem tool is available for the given tool

        Returns:
            Tuple of (ecosystem_name, install_command) if found, None otherwise
        """
        if tool not in cls.ECOSYSTEM_MAP:
            return None

        ecosystems = cls.ECOSYSTEM_MAP[tool]['ecosystems']
        commands = cls.ECOSYSTEM_MAP[tool]['commands']

        for ecosystem in ecosystems:
            # Special handling for cargo - check common paths
            if ecosystem == 'cargo':
                cargo_path = cls._find_cargo()
                if cargo_path:
                    # Replace 'cargo' with full path in command
                    command = commands.get(ecosystem, '')
                    if command:
                        command = command.replace('cargo ', f'{cargo_path} ')
                    return (ecosystem, command)
            elif shutil.which(ecosystem):
                command = commands.get(ecosystem, '')
                return (ecosystem, command)

        return None

    @classmethod
    def try_ecosystem_install(cls, tool: str) -> tuple:
        """
        Try to install a tool using its ecosystem package manager

        Returns:
            Tuple of (success: bool, ecosystem_name: str, message: str)
        """
        result = cls.detect_ecosystem(tool)
        if not result:
            return (False, '', 'No ecosystem found')

        ecosystem, command = result

        if not command:
            # Ecosystem exists but tool is built-in (like mix with elixir)
            return (True, ecosystem, f'{tool} is included with {ecosystem}')

        try:
            # Run the ecosystem install command
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            # For gem: returncode 0 means success, even with PATH warnings in stderr
            # gem outputs "WARNING: You don't have ~/.gem/ruby/X.X.X/bin in your PATH"
            # but the gem IS installed successfully
            if result.returncode == 0:
                return (True, ecosystem, f'Installed via {ecosystem}')

            # Real failure - check if it's just a PATH warning (gem-specific)
            if ecosystem == 'gem' and "don't have" in result.stderr and "in your PATH" in result.stderr:
                # This is just a warning, gem succeeded
                return (True, ecosystem, f'Installed via {ecosystem} (add gem bin to PATH)')

            return (False, ecosystem, f'Installation failed: {result.stderr[:100]}')
        except subprocess.TimeoutExpired:
            return (False, ecosystem, 'Installation timed out')
        except Exception as e:
            return (False, ecosystem, f'Error: {str(e)[:100]}')


class ToolMapper:
    """
    Maps scanner tool names to package names for different package managers
    """

    # Python tools that can be installed via pip as fallback
    PYTHON_TOOLS = {'ansible-lint', 'bandit', 'black', 'blinter', 'cmakelang', 'garak', 'gixy', 'llm-guard', 'modelscan', 'mypy', 'pylint', 'ruff', 'sqlfluff', 'vim-vint', 'yamllint'}

    # npm tools that can be installed via npm as fallback
    NPM_TOOLS = {'buf', 'eslint', 'graphql-schema-linter', 'htmlhint', 'jshint', 'markdownlint-cli', 'prettier', 'solhint', 'standard', 'stylelint', 'typescript'}  # Removed taplo - uses cargo

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
        'blinter': {
            'pip': 'Blinter',
        },
        'buf': {
            'yum': 'buf',
            'npm': '@bufbuild/buf',
        },
        'cargo-clippy': {
            'winget': 'Rustlang.Rustup',
            'brew': 'rustup',
            'apt': 'rustup',
            'choco': 'rustup.install',
            'manual': 'rustup component add clippy',
        },
        'checkmake': {
            'brew': 'checkmake',
            'go': 'github.com/mrtazz/checkmake/cmd/checkmake@latest',
            'manual': 'go install github.com/mrtazz/checkmake/cmd/checkmake@latest',
        },
        'checkov': {
            'pip': 'checkov',
            'brew': 'checkov',
        },
        'checkstyle': {
            'apt': 'checkstyle',
            'yum': 'checkstyle',
            'dnf': 'checkstyle',
            'brew': 'checkstyle',
            # Removed 'choco': chocolatey package has broken download link (404)
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
            'choco': 'groovy',
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
        'garak': {
            'pip': 'garak',
        },
        'gixy': {
            'apt': 'gixy',
            'pip': 'gixy',
        },
        'go': {
            'winget': 'GoLang.Go',
            'choco': 'golang',
            'brew': 'go',
            'apt': 'golang-go',
            'yum': 'golang',
            'dnf': 'golang',
            'pacman': 'go',
            'manual': 'https://go.dev/dl/',
        },
        'gitleaks': {
            'brew': 'gitleaks',
            'winget': 'Gitleaks.Gitleaks',
            'pacman': 'gitleaks',
            'go': 'github.com/gitleaks/gitleaks/v8@latest',
            'manual': 'mkdir -p ~/.local/bin && wget -qO- https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d \'"\' -f 4 | sed s/v//)_linux_x64.tar.gz | tar xz -C ~/.local/bin gitleaks',
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
            'manual': 'mkdir -p ~/.local/bin && wget -O ~/.local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 && chmod +x ~/.local/bin/hadolint',
        },
        'hlint': {
            'apt': 'hlint',
            'pacman': 'hlint',
            'brew': 'hlint',
            'choco': 'ghc',
            'manual': 'cabal install hlint',
        },
        'htmlhint': {
            'npm': 'htmlhint',
        },
        'jshint': {
            'npm': 'jshint',
        },
        'jsonlint': {
            'npm': 'jsonlint',
            'pip': 'demjson3',  # Python alternative
        },
        'ktlint': {
            'brew': 'ktlint',
            # Removed 'choco': package doesn't exist in chocolatey repository
            'manual': 'mkdir -p ~/.local/bin && curl -sSLO https://github.com/pinterest/ktlint/releases/latest/download/ktlint && chmod a+x ktlint && mv ktlint ~/.local/bin/',
        },
        'kube-linter': {
            'brew': 'kube-linter',
            'winget': 'stackrox.kube-linter',
            'go': 'golang.stackrox.io/kube-linter/cmd/kube-linter@latest',
            'manual': 'mkdir -p ~/.local/bin && curl -LO https://github.com/stackrox/kube-linter/releases/latest/download/kube-linter-linux.tar.gz && tar xzf kube-linter-linux.tar.gz && mv kube-linter ~/.local/bin/ && rm kube-linter-linux.tar.gz',
        },
        'llm-guard': {
            'pip': 'llm-guard',
        },
        'luacheck': {
            'brew': 'luacheck',
            'choco': 'lua',
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
            'choco': 'elixir',
            'manual': 'https://elixir-lang.org/install.html',
        },
        'modelscan': {
            'pip': 'modelscan',
        },
        'mypy': {
            'pip': 'mypy',
        },
        'perlcritic': {
            'apt': 'libperl-critic-perl',
            'brew': 'perl-critic',
            'choco': 'strawberryperl',
            'manual': 'cpan Perl::Critic',
        },
        'php': {
            'choco': 'php',
            'brew': 'php',
            'apt': 'php',
            'yum': 'php',
            'dnf': 'php',
            'pacman': 'php',
            'manual': 'https://windows.php.net/download/',
        },
        'phpstan': {
            'brew': 'phpstan',
            # Removed 'choco': package doesn't exist in chocolatey repository
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
            'winget': 'RubyInstallerTeam.RubyWithDevKit.3.4',
            'manual': 'gem install rubocop',
        },
        'ruff': {
            'pip': 'ruff',
        },
        'scalastyle': {
            'brew': 'scalastyle',
            'choco': 'scala',
            'manual': 'Download from: https://www.scalastyle.org/',
        },
        'semgrep': {
            'pip': 'semgrep',
            'brew': 'semgrep',
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
            # Removed 'choco': package doesn't exist in chocolatey repository
            'manual': 'Download from: https://github.com/realm/SwiftLint/releases',
        },
        'taplo': {
            'brew': 'taplo',  # Available in Homebrew as of 2024
            'apt': None,  # Not in apt
            'cargo': 'taplo-cli',  # Fallback to cargo if brew unavailable
            'manual': 'mkdir -p ~/.local/bin && curl -fsSL https://github.com/tamasfe/taplo/releases/latest/download/taplo-linux-x86_64.gz | gunzip > ~/.local/bin/taplo && chmod +x ~/.local/bin/taplo',
        },
        'tflint': {
            'brew': 'tflint',
            'winget': 'TerraformLinters.tflint',
            'choco': 'tflint',
            'manual': 'curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash',
        },
        'trivy': {
            'brew': 'trivy',
            'pacman': 'trivy',
            'choco': 'trivy',
            'apt_repo': 'sudo apt-get install wget apt-transport-https gnupg lsb-release && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list && sudo apt-get update && sudo apt-get install trivy',
            'manual': 'curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin',
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
            'choco': 'xsltproc',
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
            'winget': 'Zig.Zig',
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
