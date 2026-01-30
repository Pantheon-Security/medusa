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


"""
External tool registry - all 41 optional linters MEDUSA can use.
Each entry links to the vendor's official documentation so users
always get up-to-date install instructions.
"""
EXTERNAL_TOOLS = {
    # Security scanners
    'semgrep':      {'desc': 'Multi-language SAST',           'lang': 'Multi',       'url': 'https://semgrep.dev/docs/'},
    'trivy':        {'desc': 'Container/IaC scanner',         'lang': 'Multi',       'url': 'https://trivy.dev/'},
    'gitleaks':     {'desc': 'Secrets detection',             'lang': 'Multi',       'url': 'https://github.com/gitleaks/gitleaks'},
    'modelscan':    {'desc': 'ML model security',             'lang': 'ML',          'url': 'https://github.com/protectai/modelscan'},
    'garak':        {'desc': 'LLM vulnerability scanner',     'lang': 'LLM',         'url': 'https://docs.garak.ai/garak'},
    # Language linters
    'shellcheck':   {'desc': 'Shell script analyzer',         'lang': 'Bash',        'url': 'https://www.shellcheck.net/'},
    'eslint':       {'desc': 'JavaScript linter',             'lang': 'JavaScript',  'url': 'https://eslint.org/docs/latest/'},
    'tsc':          {'desc': 'TypeScript compiler',           'lang': 'TypeScript',  'url': 'https://www.typescriptlang.org/'},
    'cppcheck':     {'desc': 'C/C++ static analysis',         'lang': 'C/C++',       'url': 'https://cppcheck.sourceforge.io/'},
    'checkstyle':   {'desc': 'Java style checker',            'lang': 'Java',        'url': 'https://checkstyle.sourceforge.io/'},
    'ktlint':       {'desc': 'Kotlin linter',                 'lang': 'Kotlin',      'url': 'https://pinterest.github.io/ktlint/'},
    'rubocop':      {'desc': 'Ruby linter',                   'lang': 'Ruby',        'url': 'https://docs.rubocop.org/rubocop/'},
    'phpstan':      {'desc': 'PHP static analysis',           'lang': 'PHP',         'url': 'https://phpstan.org/'},
    'clippy':       {'desc': 'Rust linter (via cargo)',        'lang': 'Rust',        'url': 'https://doc.rust-lang.org/clippy/'},
    'swiftlint':    {'desc': 'Swift linter',                  'lang': 'Swift',       'url': 'https://github.com/realm/SwiftLint'},
    'dart':         {'desc': 'Dart analyzer',                  'lang': 'Dart',        'url': 'https://dart.dev/tools/dart-analyze'},
    'scalastyle':   {'desc': 'Scala style checker',            'lang': 'Scala',       'url': 'https://www.scalastyle.org/'},
    'hlint':        {'desc': 'Haskell linter',                 'lang': 'Haskell',     'url': 'https://github.com/ndmitchell/hlint'},
    'perlcritic':   {'desc': 'Perl linter',                    'lang': 'Perl',        'url': 'https://metacpan.org/pod/Perl::Critic'},
    'luacheck':     {'desc': 'Lua linter',                     'lang': 'Lua',         'url': 'https://github.com/lunarmodules/luacheck'},
    'zig':          {'desc': 'Zig compiler/linter',            'lang': 'Zig',         'url': 'https://ziglang.org/'},
    'Rscript':      {'desc': 'R linter (lintr)',               'lang': 'R',           'url': 'https://lintr.r-lib.org/'},
    'mix':          {'desc': 'Elixir linter (credo)',          'lang': 'Elixir',      'url': 'https://hexdocs.pm/credo/'},
    'clj-kondo':    {'desc': 'Clojure linter',                 'lang': 'Clojure',     'url': 'https://github.com/clj-kondo/clj-kondo'},
    'codenarc':     {'desc': 'Groovy linter',                  'lang': 'Groovy',      'url': 'https://codenarc.org/'},
    'solhint':      {'desc': 'Solidity linter',                'lang': 'Solidity',    'url': 'https://github.com/protofire/solhint'},
    'vint':         {'desc': 'Vim script linter',              'lang': 'Vim',         'url': 'https://github.com/Vimjas/vint'},
    # Config/data linters
    'sqlfluff':     {'desc': 'SQL linter',                     'lang': 'SQL',         'url': 'https://docs.sqlfluff.com/'},
    'xmllint':      {'desc': 'XML validator',                  'lang': 'XML',         'url': 'https://gnome.pages.gitlab.gnome.org/libxml2/xmllint.html'},
    'taplo':        {'desc': 'TOML linter',                    'lang': 'TOML',        'url': 'https://taplo.tamasfe.dev/'},
    'stylelint':    {'desc': 'CSS/SCSS linter',                'lang': 'CSS',         'url': 'https://stylelint.io/'},
    'htmlhint':     {'desc': 'HTML linter',                    'lang': 'HTML',        'url': 'https://htmlhint.com/'},
    'buf':          {'desc': 'Protobuf linter',                'lang': 'Protobuf',    'url': 'https://buf.build/docs/lint/'},
    'graphql-schema-linter': {'desc': 'GraphQL linter',        'lang': 'GraphQL',     'url': 'https://github.com/cjoudrey/graphql-schema-linter'},
    # Infrastructure linters
    'ansible-lint': {'desc': 'Ansible playbook linter',        'lang': 'Ansible',     'url': 'https://docs.ansible.com/projects/lint/'},
    'kube-linter':  {'desc': 'Kubernetes linter',              'lang': 'Kubernetes',  'url': 'https://docs.kubelinter.io/'},
    'gixy':         {'desc': 'Nginx config analyzer',          'lang': 'Nginx',       'url': 'https://github.com/yandex/gixy'},
    'checkmake':    {'desc': 'Makefile linter',                'lang': 'Make',        'url': 'https://github.com/checkmake/checkmake'},
    'cmake-lint':   {'desc': 'CMake linter',                   'lang': 'CMake',       'url': 'https://github.com/cmake-lint/cmake-lint'},
    'pwsh':         {'desc': 'PowerShell linter',              'lang': 'PowerShell',  'url': 'https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/overview'},
    'docker-compose': {'desc': 'Docker Compose',               'lang': 'Docker',      'url': 'https://docs.docker.com/compose/'},
}


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
