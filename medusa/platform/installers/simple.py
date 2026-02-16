"""
MEDUSA v2026.2 Simplified Installer

Only installs AI security tools via pip. No more 47-tool nightmare.
"""

import subprocess
import shutil
import sys
from pathlib import Path
from typing import Optional


def _in_virtualenv() -> bool:
    """Check if we're running in a virtual environment."""
    return hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)


def _is_pep668_system() -> bool:
    """Check if this system blocks pip install (PEP 668 externally-managed)."""
    if _in_virtualenv():
        return False
    # Check for the EXTERNALLY-MANAGED marker file in the stdlib directory
    import sysconfig
    stdlib = sysconfig.get_path('stdlib')
    marker = Path(stdlib) / 'EXTERNALLY-MANAGED'
    return marker.exists()


def _has_pipx() -> bool:
    """Check if pipx is available."""
    return shutil.which('pipx') is not None


# The ONLY tools MEDUSA installs — AI-specific security tools
AI_TOOLS = {
    'modelscan': {
        'pip': 'modelscan',
        'description': 'ML model security scanner (scans .pkl, .pt, .h5 files)',
        'required': True,
    },
    'garak': {
        'pip': 'garak==0.13.3',  # 0.14.0 has broken deps (requires transformers>=5.0 which doesn't exist)
        'description': 'LLM vulnerability scanner (probes for prompt injection, jailbreaks)',
        'required': False,
    },
    'llm-guard': {
        'pip': 'llm-guard',
        'description': 'LLM input/output safety scanner (toxicity, PII, prompt attacks)',
        'required': False,
    },
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


def get_install_command(package: str) -> list:
    """Get the best install command for a package on this system.

    On PEP 668 systems (Ubuntu 24.04+), uses pipx for CLI tools.
    In virtualenvs, uses pip directly.
    """
    if _in_virtualenv():
        return [sys.executable, '-m', 'pip', 'install', package]
    if _is_pep668_system() and _has_pipx():
        return ['pipx', 'install', package]
    # Fallback to pip --user (may fail on PEP 668 without pipx)
    pip_cmd = get_pip_command()
    return pip_cmd + ['install', '--user', package]


def is_tool_installed(tool_name: str) -> bool:
    """Check if a tool is installed (via pip, pipx, or system package)."""
    # First check if the CLI binary is on PATH (works for pipx, apt, etc.)
    if shutil.which(tool_name) is not None:
        return True
    # For Python packages, also check pip show (covers virtualenv installs)
    if tool_name in _PIP_TOOLS:
        try:
            result = subprocess.run(
                get_pip_command() + ['show', tool_name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception:
            pass
    return False


def install_ai_tools(verbose: bool = False) -> dict:
    """
    Install AI security tools.

    Uses pipx on PEP 668 systems (Ubuntu 24.04+), pip in virtualenvs.
    Returns dict with results: {'modelscan': True/False, ...}
    """
    pep668 = _is_pep668_system()
    has_pipx = _has_pipx()

    if not _in_virtualenv() and not is_pip_available() and not has_pipx:
        return {'error': 'Neither pip nor pipx found. Install pipx: sudo apt install pipx'}

    if pep668 and not _in_virtualenv() and not has_pipx:
        return {
            'error': (
                'PEP 668 system detected (externally-managed Python). '
                'Install pipx first: sudo apt install pipx && pipx ensurepath'
            )
        }

    results = {}

    for tool_name, tool_info in AI_TOOLS.items():
        if is_tool_installed(tool_name):
            results[tool_name] = {'status': 'already_installed'}
            continue

        try:
            cmd = get_install_command(tool_info['pip'])
            if not verbose and 'pipx' not in cmd[0]:
                cmd.append('-q')

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                method = 'pipx' if 'pipx' in cmd[0] else 'pip'
                results[tool_name] = {'status': 'installed', 'method': method}
            else:
                error_msg = result.stderr.strip()
                # Provide helpful PEP 668 guidance
                if 'externally-managed' in error_msg.lower():
                    error_msg = (
                        'PEP 668 blocks pip install. '
                        'Fix: sudo apt install pipx && pipx install ' + tool_info['pip']
                    )
                results[tool_name] = {
                    'status': 'failed',
                    'error': error_msg
                }
        except subprocess.TimeoutExpired:
            results[tool_name] = {
                'status': 'failed',
                'error': 'Installation timed out (5 minutes)'
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


"""
External tool registry - optional linters MEDUSA detects and uses.
MEDUSA does NOT install these. Users install them via their own package manager.
We just detect them and use them if present.

Fields:
  desc - Short description
  lang - Language/technology
  url  - Official documentation URL
"""
EXTERNAL_TOOLS = {
    # Core language linters
    'bandit':               {'desc': 'Python security scanner',   'lang': 'Python',     'url': 'https://bandit.readthedocs.io/'},
    'shellcheck':           {'desc': 'Shell script analyzer',     'lang': 'Bash',       'url': 'https://www.shellcheck.net/'},
    'markdownlint':         {'desc': 'Markdown linter',           'lang': 'Markdown',   'url': 'https://github.com/igorshubovych/markdownlint-cli'},
    'eslint':               {'desc': 'JavaScript linter',         'lang': 'JavaScript', 'url': 'https://eslint.org/docs/latest/'},
    'tsc':                  {'desc': 'TypeScript compiler',       'lang': 'TypeScript', 'url': 'https://www.typescriptlang.org/'},
    'cppcheck':             {'desc': 'C/C++ static analysis',     'lang': 'C/C++',      'url': 'https://cppcheck.sourceforge.io/'},
    'checkstyle':           {'desc': 'Java style checker',        'lang': 'Java',       'url': 'https://checkstyle.sourceforge.io/'},
    'ktlint':               {'desc': 'Kotlin linter',             'lang': 'Kotlin',     'url': 'https://pinterest.github.io/ktlint/'},
    'rubocop':              {'desc': 'Ruby linter',               'lang': 'Ruby',       'url': 'https://docs.rubocop.org/rubocop/'},
    'phpstan':              {'desc': 'PHP static analysis',       'lang': 'PHP',        'url': 'https://phpstan.org/'},
    'clippy':               {'desc': 'Rust linter (via cargo)',   'lang': 'Rust',       'url': 'https://doc.rust-lang.org/clippy/'},
    'golangci-lint':        {'desc': 'Go linter',                 'lang': 'Go',         'url': 'https://golangci-lint.run/'},
    'swiftlint':            {'desc': 'Swift linter',              'lang': 'Swift',      'url': 'https://github.com/realm/SwiftLint'},
    'dart':                 {'desc': 'Dart analyzer',             'lang': 'Dart',       'url': 'https://dart.dev/tools/dart-analyze'},
    'scalastyle':           {'desc': 'Scala style checker',       'lang': 'Scala',      'url': 'https://www.scalastyle.org/'},
    'hlint':                {'desc': 'Haskell linter',            'lang': 'Haskell',    'url': 'https://github.com/ndmitchell/hlint'},
    'perlcritic':           {'desc': 'Perl linter',               'lang': 'Perl',       'url': 'https://metacpan.org/pod/Perl::Critic'},
    'luacheck':             {'desc': 'Lua linter',                'lang': 'Lua',        'url': 'https://github.com/lunarmodules/luacheck'},
    'zig':                  {'desc': 'Zig compiler/linter',       'lang': 'Zig',        'url': 'https://ziglang.org/'},
    'Rscript':              {'desc': 'R linter (lintr)',           'lang': 'R',          'url': 'https://lintr.r-lib.org/'},
    'mix':                  {'desc': 'Elixir linter (credo)',     'lang': 'Elixir',     'url': 'https://hexdocs.pm/credo/'},
    'clj-kondo':            {'desc': 'Clojure linter',            'lang': 'Clojure',    'url': 'https://github.com/clj-kondo/clj-kondo'},
    'codenarc':             {'desc': 'Groovy linter',             'lang': 'Groovy',     'url': 'https://codenarc.org/'},
    'solhint':              {'desc': 'Solidity linter',           'lang': 'Solidity',   'url': 'https://github.com/protofire/solhint'},
    'vint':                 {'desc': 'Vim script linter',         'lang': 'Vim',        'url': 'https://github.com/Vimjas/vint'},
    # Security scanners
    'semgrep':              {'desc': 'Multi-language SAST',       'lang': 'Multi',      'url': 'https://semgrep.dev/docs/'},
    'trivy':                {'desc': 'Container/IaC scanner',     'lang': 'Multi',      'url': 'https://trivy.dev/'},
    'gitleaks':             {'desc': 'Secrets detection',         'lang': 'Multi',      'url': 'https://github.com/gitleaks/gitleaks'},
    'modelscan':            {'desc': 'ML model security',         'lang': 'ML',         'url': 'https://github.com/protectai/modelscan'},
    'garak':                {'desc': 'LLM vulnerability scanner', 'lang': 'LLM',       'url': 'https://docs.garak.ai/garak'},
    'llm-guard':            {'desc': 'LLM safety scanner',        'lang': 'LLM',       'url': 'https://llm-guard.com/'},
    # Config/data linters
    'sqlfluff':             {'desc': 'SQL linter',                'lang': 'SQL',        'url': 'https://docs.sqlfluff.com/'},
    'xmllint':              {'desc': 'XML validator',             'lang': 'XML',        'url': 'https://gnome.pages.gitlab.gnome.org/libxml2/xmllint.html'},
    'taplo':                {'desc': 'TOML linter',               'lang': 'TOML',      'url': 'https://taplo.tamasfe.dev/'},
    'stylelint':            {'desc': 'CSS/SCSS linter',           'lang': 'CSS',        'url': 'https://stylelint.io/'},
    'htmlhint':             {'desc': 'HTML linter',               'lang': 'HTML',       'url': 'https://htmlhint.com/'},
    'buf':                  {'desc': 'Protobuf linter',           'lang': 'Protobuf',   'url': 'https://buf.build/docs/lint/'},
    'graphql-schema-linter': {'desc': 'GraphQL linter',           'lang': 'GraphQL',   'url': 'https://github.com/cjoudrey/graphql-schema-linter'},
    # Infrastructure linters
    'hadolint':             {'desc': 'Dockerfile linter',         'lang': 'Docker',     'url': 'https://github.com/hadolint/hadolint'},
    'tflint':               {'desc': 'Terraform linter',          'lang': 'Terraform',  'url': 'https://github.com/terraform-linters/tflint'},
    'ansible-lint':         {'desc': 'Ansible playbook linter',   'lang': 'Ansible',    'url': 'https://docs.ansible.com/projects/lint/'},
    'kube-linter':          {'desc': 'Kubernetes linter',         'lang': 'Kubernetes', 'url': 'https://docs.kubelinter.io/'},
    'gixy':                 {'desc': 'Nginx config analyzer',     'lang': 'Nginx',      'url': 'https://github.com/yandex/gixy'},
    'checkmake':            {'desc': 'Makefile linter',           'lang': 'Make',       'url': 'https://github.com/checkmake/checkmake'},
    'cmake-lint':           {'desc': 'CMake linter',              'lang': 'CMake',      'url': 'https://github.com/cmake-lint/cmake-lint'},
    'pwsh':                 {'desc': 'PowerShell linter',         'lang': 'PowerShell', 'url': 'https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/overview'},
    'PSScriptAnalyzer':     {'desc': 'PowerShell security linter', 'lang': 'PowerShell', 'url': 'https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/overview'},
    'docker-compose':       {'desc': 'Docker Compose',            'lang': 'Docker',     'url': 'https://docs.docker.com/compose/'},
}


# Quick-reference install hints for common tools
_PIP_TOOLS = {'bandit', 'sqlfluff', 'ansible-lint', 'gixy', 'cmake-lint', 'vim-vint', 'modelscan', 'garak', 'llm-guard', 'semgrep', 'ruff'}
_NPM_TOOLS = {'eslint', 'markdownlint', 'htmlhint', 'stylelint', 'graphql-schema-linter'}


def _detect_platform() -> str:
    """Detect the current OS platform."""
    import platform as _platform
    system = _platform.system().lower()
    if system == 'linux':
        return 'linux'
    elif system == 'darwin':
        return 'macos'
    elif system == 'windows':
        return 'windows'
    return 'unknown'


def _get_pip_or_pipx() -> str:
    """Return 'pipx' on PEP 668 systems, 'pip' otherwise."""
    if _in_virtualenv():
        return 'pip'
    if _is_pep668_system():
        return 'pipx'
    return 'pip'


# Platform-specific install commands for tools (one verified command per OS)
# IMPORTANT: Every command here must be verified to actually work on that OS.
_PLATFORM_HINTS = {
    # --- Binary security tools ---
    'gitleaks': {
        'linux':   'sudo apt install gitleaks',
        'macos':   'brew install gitleaks',
        'windows': 'scoop install gitleaks',
    },
    'trivy': {
        'linux':   'sudo snap install trivy',
        'macos':   'brew install trivy',
        'windows': 'choco install trivy',
    },
    'hadolint': {
        # No apt/snap package - download binary from GitHub
        'linux':   'wget -qO /tmp/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 && sudo install /tmp/hadolint /usr/local/bin/',
        'macos':   'brew install hadolint',
        'windows': 'scoop install hadolint',
    },
    'shellcheck': {
        'linux':   'sudo apt install shellcheck',
        'macos':   'brew install shellcheck',
        'windows': 'scoop install shellcheck',
    },
    'cppcheck': {
        'linux':   'sudo apt install cppcheck',
        'macos':   'brew install cppcheck',
        'windows': 'choco install cppcheck',
    },
    'semgrep': {
        'linux':   'pip install semgrep',
        'macos':   'brew install semgrep',
        'windows': 'pip install semgrep',
    },
    'golangci-lint': {
        'linux':   'sudo snap install golangci-lint --classic',
        'macos':   'brew install golangci-lint',
        'windows': 'scoop install golangci-lint',
    },
    'kube-linter': {
        # No apt/snap - download from GitHub
        'linux':   'wget -qO /tmp/kube-linter https://github.com/stackrox/kube-linter/releases/latest/download/kube-linter-linux && sudo install /tmp/kube-linter /usr/local/bin/',
        'macos':   'brew install kube-linter',
        'windows': 'scoop install kube-linter',
    },
    'buf': {
        # No apt/snap - install via official script
        'linux':   'npm install -g @bufbuild/buf',
        'macos':   'brew install buf',
        'windows': 'npm install -g @bufbuild/buf',
    },
    'tflint': {
        'linux':   'curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash',
        'macos':   'brew install tflint',
        'windows': 'choco install tflint',
    },
    # --- pip-based tools (cross-platform) ---
    'bandit': {
        'linux':   'pip install bandit',
        'macos':   'pip install bandit',
        'windows': 'pip install bandit',
    },
    'sqlfluff': {
        'linux':   'pip install sqlfluff',
        'macos':   'pip install sqlfluff',
        'windows': 'pip install sqlfluff',
    },
    'ansible-lint': {
        'linux':   'pip install ansible-lint',
        'macos':   'pip install ansible-lint',
        'windows': 'pip install ansible-lint',
    },
    'gixy': {
        'linux':   'pip install gixy',
        'macos':   'pip install gixy',
        'windows': 'pip install gixy',
    },
    'cmake-lint': {
        'linux':   'pip install cmake-lint',
        'macos':   'pip install cmake-lint',
        'windows': 'pip install cmake-lint',
    },
    'vim-vint': {
        'linux':   'pip install vim-vint',
        'macos':   'pip install vim-vint',
        'windows': 'pip install vim-vint',
    },
    'ruff': {
        'linux':   'pip install ruff',
        'macos':   'pip install ruff',
        'windows': 'pip install ruff',
    },
    # --- AI security tools (pip-based) ---
    'modelscan': {
        'linux':   'pip install modelscan',
        'macos':   'pip install modelscan',
        'windows': 'pip install modelscan',
    },
    'garak': {
        'linux':   'pip install garak',
        'macos':   'pip install garak',
        'windows': 'pip install garak',
    },
    'llm-guard': {
        'linux':   'pip install llm-guard',
        'macos':   'pip install llm-guard',
        'windows': 'pip install llm-guard',
    },
    # --- npm-based tools ---
    'eslint': {
        'linux':   'npm install -g eslint',
        'macos':   'npm install -g eslint',
        'windows': 'npm install -g eslint',
    },
    'markdownlint': {
        'linux':   'npm install -g markdownlint-cli',
        'macos':   'npm install -g markdownlint-cli',
        'windows': 'npm install -g markdownlint-cli',
    },
    'htmlhint': {
        'linux':   'npm install -g htmlhint',
        'macos':   'npm install -g htmlhint',
        'windows': 'npm install -g htmlhint',
    },
    'stylelint': {
        'linux':   'npm install -g stylelint',
        'macos':   'npm install -g stylelint',
        'windows': 'npm install -g stylelint',
    },
    'graphql-schema-linter': {
        'linux':   'npm install -g graphql-schema-linter',
        'macos':   'npm install -g graphql-schema-linter',
        'windows': 'npm install -g graphql-schema-linter',
    },
    # --- Language-specific tools ---
    'clippy': {
        'linux':   'rustup component add clippy',
        'macos':   'rustup component add clippy',
        'windows': 'rustup component add clippy',
    },
    'rubocop': {
        'linux':   'gem install rubocop',
        'macos':   'gem install rubocop',
        'windows': 'gem install rubocop',
    },
    'PSScriptAnalyzer': {
        'linux':   'pwsh -c "Install-Module PSScriptAnalyzer -Force"',
        'macos':   'pwsh -c "Install-Module PSScriptAnalyzer -Force"',
        'windows': 'Install-Module -Name PSScriptAnalyzer -Force',
    },
    'tsc': {
        'linux':   'npm install -g typescript',
        'macos':   'npm install -g typescript',
        'windows': 'npm install -g typescript',
    },
    'checkmake': {
        'linux':   'go install github.com/mrtazz/checkmake/cmd/checkmake@latest',
        'macos':   'brew install checkmake',
        'windows': 'go install github.com/mrtazz/checkmake/cmd/checkmake@latest',
    },
    # --- Tools that were missing install hints ---
    'swiftlint': {
        'linux':   'N/A (SwiftLint requires macOS or Swift toolchain)',
        'macos':   'brew install swiftlint',
        'windows': 'N/A (SwiftLint requires macOS)',
    },
    'checkstyle': {
        'linux':   'sudo apt install checkstyle',
        'macos':   'brew install checkstyle',
        'windows': 'choco install checkstyle',
    },
    'ktlint': {
        'linux':   'sudo snap install ktlint',
        'macos':   'brew install ktlint',
        'windows': 'choco install ktlint',
    },
    'phpstan': {
        'linux':   'composer global require phpstan/phpstan',
        'macos':   'composer global require phpstan/phpstan',
        'windows': 'composer global require phpstan/phpstan',
    },
    'dart': {
        'linux':   'sudo apt install dart',
        'macos':   'brew install dart',
        'windows': 'choco install dart-sdk',
    },
    'scalastyle': {
        'linux':   'cs install scalastyle',
        'macos':   'brew install scalastyle',
        'windows': 'cs install scalastyle',
    },
    'hlint': {
        'linux':   'sudo apt install hlint',
        'macos':   'brew install hlint',
        'windows': 'cabal install hlint',
    },
    'perlcritic': {
        'linux':   'sudo apt install libperl-critic-perl',
        'macos':   'cpanm Perl::Critic',
        'windows': 'cpanm Perl::Critic',
    },
    'luacheck': {
        'linux':   'sudo apt install lua-check',
        'macos':   'brew install luacheck',
        'windows': 'luarocks install luacheck',
    },
    'zig': {
        'linux':   'sudo snap install zig --classic',
        'macos':   'brew install zig',
        'windows': 'scoop install zig',
    },
    'Rscript': {
        'linux':   'sudo apt install r-base',
        'macos':   'brew install r',
        'windows': 'choco install r',
    },
    'mix': {
        'linux':   'sudo apt install elixir',
        'macos':   'brew install elixir',
        'windows': 'choco install elixir',
    },
    'clj-kondo': {
        'linux':   'sudo bash -c "curl -sLO https://raw.githubusercontent.com/clj-kondo/clj-kondo/master/script/install-clj-kondo && chmod +x install-clj-kondo && ./install-clj-kondo"',
        'macos':   'brew install clj-kondo',
        'windows': 'scoop install clj-kondo',
    },
    'codenarc': {
        'linux':   'sdk install codenarc',
        'macos':   'sdk install codenarc',
        'windows': 'sdk install codenarc',
    },
    'solhint': {
        'linux':   'npm install -g solhint',
        'macos':   'npm install -g solhint',
        'windows': 'npm install -g solhint',
    },
    'vint': {
        'linux':   'pip install vim-vint',
        'macos':   'pip install vim-vint',
        'windows': 'pip install vim-vint',
    },
    'taplo': {
        'linux':   'cargo install taplo-cli',
        'macos':   'brew install taplo',
        'windows': 'cargo install taplo-cli',
    },
    'xmllint': {
        'linux':   'sudo apt install libxml2-utils',
        'macos':   'brew install libxml2',  # Usually pre-installed on macOS
        'windows': 'choco install xsltproc',
    },
    'docker-compose': {
        'linux':   'sudo apt install docker-compose-v2',
        'macos':   'brew install docker-compose',
        'windows': 'choco install docker-compose',
    },
    'pwsh': {
        'linux':   'sudo snap install powershell --classic',
        'macos':   'brew install powershell',
        'windows': 'N/A (built-in on Windows)',
    },
    'cargo-audit': {
        'linux':   'cargo install cargo-audit',
        'macos':   'cargo install cargo-audit',
        'windows': 'cargo install cargo-audit',
    },
}


def get_install_hint(tool_name: str) -> str:
    """Return a single install command for an external tool, targeted to the current OS.

    On PEP 668 systems (Ubuntu 24.04+), automatically uses pipx instead of pip
    for Python CLI tools.
    """
    plat = _detect_platform()
    pip_cmd = _get_pip_or_pipx()

    # Check platform-specific hints first
    if tool_name in _PLATFORM_HINTS:
        hints = _PLATFORM_HINTS[tool_name]
        if plat in hints:
            hint = hints[plat]
            # On Linux PEP 668 systems, rewrite pip -> pipx for pip-based tools
            if plat == 'linux' and pip_cmd == 'pipx' and tool_name in _PIP_TOOLS:
                hint = hint.replace('pip install', 'pipx install', 1)
            return hint
        # Fallback to linux if unknown platform
        return hints.get('linux', hints.get('macos', ''))

    # pip tools not yet in _PLATFORM_HINTS
    if tool_name in _PIP_TOOLS:
        return f"{pip_cmd} install {tool_name}"
    if tool_name in _NPM_TOOLS:
        return f"npm install -g {tool_name}"

    # Fallback: point to the URL
    info = EXTERNAL_TOOLS.get(tool_name)
    if info:
        return info['url']
    return "see medusa install --check"


def get_detected_tools() -> list:
    """
    Detect which external tools the user already has installed.
    We don't install these, but we'll use them if present.
    """
    detected = []
    for tool in EXTERNAL_TOOLS:
        if shutil.which(tool):
            detected.append(tool)
    return detected


def get_optional_tools() -> list:
    """Get list of optional tools that enhance scanning (but we don't install)."""
    return [
        {
            'name': name,
            'description': info['desc'],
            'lang': info['lang'],
            'url': info['url'],
            'installed': shutil.which(name) is not None,
        }
        for name, info in EXTERNAL_TOOLS.items()
    ]


# ─── Environment Audit ───────────────────────────────────────────────

# Python version requirements for AI tools (from PyPI metadata)
_TOOL_PYTHON_REQS = {
    'modelscan':  {'min': (3, 10), 'max': (3, 12), 'pip': 'modelscan'},
    'llm-guard':  {'min': (3, 10), 'max': (3, 12), 'pip': 'llm-guard'},
    'garak':      {'min': (3, 10), 'max': None,     'pip': 'garak'},
    'semgrep':    {'min': (3, 9),  'max': None,     'pip': 'semgrep'},
    'bandit':     {'min': (3, 8),  'max': None,     'pip': 'bandit'},
    'ruff':       {'min': (3, 7),  'max': None,     'pip': 'ruff'},
}

# MEDUSA's own requirement
_MEDUSA_PYTHON_MIN = (3, 10)
# Recommended Python for full tool compatibility
_RECOMMENDED_PYTHON = (3, 12)


def _get_python_version() -> tuple:
    """Get current Python version as tuple."""
    return (sys.version_info.major, sys.version_info.minor)


def _get_os_info() -> dict:
    """Get detailed OS information."""
    import platform as _platform
    info = {
        'system': _platform.system(),
        'release': _platform.release(),
        'version': _platform.version(),
        'machine': _platform.machine(),
        'platform': _detect_platform(),
    }
    # Get Linux distro info
    if info['system'] == 'Linux':
        try:
            import distro
            info['distro'] = distro.name(pretty=True)
            info['distro_id'] = distro.id()
            info['distro_version'] = distro.version()
        except ImportError:
            # Fallback: read /etc/os-release
            try:
                with open('/etc/os-release') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            info['distro'] = line.split('=', 1)[1].strip().strip('"')
                        elif line.startswith('ID='):
                            info['distro_id'] = line.split('=', 1)[1].strip().strip('"')
                        elif line.startswith('VERSION_ID='):
                            info['distro_version'] = line.split('=', 1)[1].strip().strip('"')
            except FileNotFoundError:
                info['distro'] = 'Unknown Linux'
    return info


def _ver_str(v: tuple) -> str:
    """Format version tuple as string."""
    return f"{v[0]}.{v[1]}"


def audit_environment() -> dict:
    """
    Audit the system environment and return actionable guidance.

    Returns a dict with:
        - python: Python version info and compatibility
        - os: OS/distro information
        - package_manager: pip/pipx/PEP668 status
        - tools: AI tool availability and install guidance
        - actions: List of recommended actions (most important first)
    """
    py_ver = _get_python_version()
    os_info = _get_os_info()
    pep668 = _is_pep668_system()
    has_pip = is_pip_available()
    has_px = _has_pipx()
    in_venv = _in_virtualenv()

    # ── Python version analysis ──
    python_ok = py_ver >= _MEDUSA_PYTHON_MIN
    python_optimal = _MEDUSA_PYTHON_MIN <= py_ver <= _RECOMMENDED_PYTHON

    # Check which tools are compatible with current Python
    compatible_tools = {}
    for tool, reqs in _TOOL_PYTHON_REQS.items():
        meets_min = py_ver >= reqs['min']
        meets_max = reqs['max'] is None or py_ver <= reqs['max']
        compatible_tools[tool] = {
            'compatible': meets_min and meets_max,
            'min': _ver_str(reqs['min']),
            'max': _ver_str(reqs['max']) if reqs['max'] else 'any',
            'installed': is_tool_installed(tool),
            'issue': None,
        }
        if not meets_min:
            compatible_tools[tool]['issue'] = f'Requires Python >= {_ver_str(reqs["min"])}'
        elif not meets_max:
            compatible_tools[tool]['issue'] = f'Requires Python <= {_ver_str(reqs["max"])}'

    # ── Build action list ──
    actions = []

    if not python_ok:
        actions.append({
            'priority': 'critical',
            'message': f'Python {_ver_str(py_ver)} is too old. MEDUSA requires >= {_ver_str(_MEDUSA_PYTHON_MIN)}.',
            'fix': _get_python_upgrade_hint(os_info),
        })

    if py_ver > _RECOMMENDED_PYTHON:
        broken = [t for t, c in compatible_tools.items() if not c['compatible']]
        if broken:
            actions.append({
                'priority': 'warning',
                'message': (
                    f'Python {_ver_str(py_ver)} is too new for: {", ".join(broken)}. '
                    f'These tools require Python <= {_ver_str(_RECOMMENDED_PYTHON)}.'
                ),
                'fix': (
                    f'Install Python {_ver_str(_RECOMMENDED_PYTHON)} alongside current version, '
                    f'or use: pipx install --python python{_ver_str(_RECOMMENDED_PYTHON)} <tool>'
                ),
            })

    if pep668 and not in_venv and not has_px:
        actions.append({
            'priority': 'warning',
            'message': 'PEP 668 system detected - pip install is blocked.',
            'fix': 'sudo apt install pipx && pipx ensurepath && source ~/.bashrc',
        })

    if not has_pip and not has_px and not in_venv:
        actions.append({
            'priority': 'warning',
            'message': 'No Python package manager found.',
            'fix': 'sudo apt install pipx' if os_info['platform'] == 'linux' else 'Install pip or pipx',
        })

    # Suggest installing missing AI tools
    for tool, status in compatible_tools.items():
        if not status['installed'] and status['compatible']:
            actions.append({
                'priority': 'info',
                'message': f'{tool} not installed (optional AI security tool).',
                'fix': get_install_hint(tool),
            })

    return {
        'python': {
            'version': _ver_str(py_ver),
            'version_tuple': py_ver,
            'ok': python_ok,
            'optimal': python_optimal,
            'recommended': _ver_str(_RECOMMENDED_PYTHON),
            'min_required': _ver_str(_MEDUSA_PYTHON_MIN),
        },
        'os': os_info,
        'package_manager': {
            'pip': has_pip,
            'pipx': has_px,
            'pep668': pep668,
            'in_virtualenv': in_venv,
            'recommended': 'pip' if in_venv else ('pipx' if pep668 else 'pip'),
        },
        'tools': compatible_tools,
        'actions': actions,
    }


def _get_python_upgrade_hint(os_info: dict) -> str:
    """Get platform-specific Python upgrade instructions."""
    plat = os_info.get('platform', 'unknown')
    distro_id = os_info.get('distro_id', '')

    if plat == 'linux':
        if distro_id in ('ubuntu', 'debian', 'pop', 'mint'):
            return 'sudo apt update && sudo apt install python3.12 python3.12-venv'
        elif distro_id in ('fedora', 'rhel', 'centos', 'rocky', 'alma'):
            return 'sudo dnf install python3.12'
        elif distro_id in ('arch', 'manjaro'):
            return 'sudo pacman -S python'
        return 'Install Python 3.12 via your package manager or https://python.org'
    elif plat == 'macos':
        return 'brew install python@3.12'
    elif plat == 'windows':
        return 'Download Python 3.12 from https://python.org/downloads/'
    return 'Install Python 3.12 from https://python.org/downloads/'


def format_audit_report(audit: dict) -> str:
    """Format the audit result as a human-readable report."""
    lines = []
    py = audit['python']
    pm = audit['package_manager']
    os_info = audit['os']

    # Header
    lines.append("Environment Audit")
    lines.append("=" * 50)

    # OS
    distro = os_info.get('distro', os_info.get('system', 'Unknown'))
    lines.append(f"  OS:      {distro}")
    lines.append(f"  Arch:    {os_info.get('machine', 'unknown')}")

    # Python
    py_status = 'OK' if py['optimal'] else ('OK (tools limited)' if py['ok'] else 'UPGRADE NEEDED')
    lines.append(f"  Python:  {py['version']} ({py_status})")
    if not py['optimal']:
        lines.append(f"           Recommended: {py['recommended']}")

    # Package manager
    if pm['in_virtualenv']:
        lines.append(f"  Pkg Mgr: pip (virtualenv)")
    elif pm['pep668']:
        px_status = 'installed' if pm['pipx'] else 'NOT INSTALLED'
        lines.append(f"  Pkg Mgr: pipx ({px_status}) [PEP 668 system]")
    else:
        lines.append(f"  Pkg Mgr: pip")

    # Tools
    lines.append("")
    lines.append("AI Security Tools")
    lines.append("-" * 50)
    for name, info in audit['tools'].items():
        if info['installed']:
            status = "INSTALLED"
        elif info['compatible']:
            status = "not installed"
        else:
            status = f"INCOMPATIBLE ({info['issue']})"
        lines.append(f"  {name:15s} {status}")

    # Actions
    if audit['actions']:
        lines.append("")
        lines.append("Recommended Actions")
        lines.append("-" * 50)
        for i, action in enumerate(audit['actions'], 1):
            icon = {'critical': '!!', 'warning': '! ', 'info': '  '}
            prefix = icon.get(action['priority'], '  ')
            lines.append(f"  {prefix} {action['message']}")
            lines.append(f"     $ {action['fix']}")
    else:
        lines.append("")
        lines.append("  All good! Environment is fully configured.")

    return "\n".join(lines)
