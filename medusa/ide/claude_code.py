#!/usr/bin/env python3
"""
MEDUSA Multi-IDE Integration
Auto-setup for Claude Code, Gemini CLI, OpenAI Codex, GitHub Copilot, and Cursor
"""

import json
from pathlib import Path
from typing import Dict, Any, List

# For TOML writing (Gemini CLI .toml commands)
try:
    import tomli_w
except ImportError:
    tomli_w = None


def setup_claude_code(project_root: Path) -> bool:
    """
    Setup Claude Code integration for MEDUSA

    Creates:
    - .claude/agents/medusa/agent.json
    - .claude/commands/medusa-scan.md
    - .claude/commands/medusa-install.md
    - CLAUDE.md (project context)

    Args:
        project_root: Project root directory

    Returns:
        True if setup successful
    """
    try:
        # Create .claude directories
        claude_dir = project_root / ".claude"
        agents_dir = claude_dir / "agents" / "medusa"
        commands_dir = claude_dir / "commands"
        skills_dir = claude_dir / "skills"

        agents_dir.mkdir(parents=True, exist_ok=True)
        commands_dir.mkdir(parents=True, exist_ok=True)
        skills_dir.mkdir(parents=True, exist_ok=True)

        # Create agent.json
        agent_config = create_agent_config()
        agent_file = agents_dir / "agent.json"
        with open(agent_file, 'w') as f:
            json.dump(agent_config, f, indent=2)

        # Create scan command
        scan_command = create_scan_command()
        command_file = commands_dir / "medusa-scan.md"
        with open(command_file, 'w') as f:
            f.write(scan_command)

        # Create install command
        install_command = create_install_command()
        install_file = commands_dir / "medusa-install.md"
        with open(install_file, 'w') as f:
            f.write(install_command)

        # Create CLAUDE.md project context
        claude_md = create_claude_md(project_root)
        claude_md_file = project_root / "CLAUDE.md"
        with open(claude_md_file, 'w') as f:
            f.write(claude_md)

        return True

    except Exception as e:
        print(f"Error setting up Claude Code integration: {e}")
        return False


def create_agent_config() -> Dict[str, Any]:
    """Create Claude Code agent configuration"""
    return {
        "name": "MEDUSA Security Scanner",
        "description": "Automated security scanning agent for your codebase",
        "version": "1.0.0",
        "triggers": {
            "file_save": {
                "enabled": True,
                "patterns": ["*.py", "*.js", "*.ts", "*.sh", "*.yml", "*.yaml"]
            },
            "on_demand": {
                "enabled": True,
                "commands": ["/medusa-scan"]
            }
        },
        "actions": {
            "scan_on_save": {
                "description": "Run MEDUSA security scan when files are saved",
                "command": "medusa scan --quick {file_path}",
                "show_output": True
            },
            "full_scan": {
                "description": "Run full security scan on project",
                "command": "medusa scan .",
                "show_output": True
            }
        },
        "notifications": {
            "on_issues_found": {
                "enabled": True,
                "severity": "medium",
                "format": "Found {count} security issues ({critical} critical, {high} high)"
            }
        },
        "settings": {
            "auto_scan": True,
            "inline_annotations": True,
            "fail_on_critical": False
        }
    }


def create_scan_command() -> str:
    """Create MEDUSA scan slash command for Claude Code"""
    return """# MEDUSA Security Scan

Run MEDUSA security scanner on the project or specific files.

## Usage

```bash
/medusa-scan [options]
```

## Examples

### Quick scan (changed files only)
```bash
/medusa-scan --quick
```

### Full project scan
```bash
/medusa-scan
```

### Scan specific directory
```bash
/medusa-scan src/
```

### Scan with custom workers
```bash
/medusa-scan --workers 8
```

### Fail on high severity
```bash
/medusa-scan --fail-on high
```

## Command

```bash
medusa scan . --quick
```

## Integration

This command integrates with MEDUSA's 42-headed security scanner, providing:

- ✅ 42 language/format support
- ✅ Auto-detection of file types
- ✅ Parallel scanning for speed
- ✅ Beautiful HTML/JSON reports
- ✅ Inline issue annotations

## Configuration

Edit `.medusa.yml` to customize:
- Exclusion patterns
- Scanner enable/disable
- Severity thresholds
- IDE integration settings

## Learn More

- Documentation: https://docs.medusa-security.dev
- Report Issues: https://github.com/chimera/medusa/issues
"""


def create_install_command() -> str:
    """Create MEDUSA install slash command for Claude Code"""
    return """# MEDUSA Tool Installation

Install security linters needed for MEDUSA scanning.

## Usage

```bash
/medusa-install [options]
```

## Examples

### Check what's installed
```bash
/medusa-install --check
```

### Install all missing tools
```bash
/medusa-install --all
```

### Install specific tool
```bash
/medusa-install --tool shellcheck
```

## Command

```bash
medusa install --check
```

## What Gets Installed

MEDUSA uses 42 different security linters:
- **Shell**: shellcheck, bashate
- **Python**: bandit, pylint, mypy
- **JavaScript/TypeScript**: eslint, tsc
- **Docker**: hadolint
- **YAML**: yamllint
- **And 34 more...**

All tools are installed via your system package manager (apt, brew, npm, pip).

## Learn More

See `.medusa.yml` for configuration options.
"""


def create_claude_md(project_root: Path) -> str:
    """Create CLAUDE.md project context file"""
    project_name = project_root.name
    return f"""# {project_name} - MEDUSA Security Scanning

## Project Overview

This project uses **MEDUSA** - The 42-Headed Security Guardian for automated security scanning.

## MEDUSA Configuration

**Location**: `.medusa.yml`

### Quick Commands

```bash
# Run security scan
medusa scan .

# Quick scan (cached results)
medusa scan . --quick

# Check installed scanners
medusa install --check

# Install missing tools
medusa install --all
```

## Available Slash Commands

- `/medusa-scan` - Run security scan on project
- `/medusa-install` - Install missing security tools

## Integration Features

### Claude Code Integration

- **Auto-scan on save**: Automatically scans files when you save them
- **Inline annotations**: Security issues appear directly in your IDE
- **Smart detection**: Only scans relevant file types
- **Parallel processing**: Fast scanning with multi-core support

### 42 Language Support

MEDUSA scans:
- Python, JavaScript, TypeScript, Go, Rust, Java, C/C++
- Shell scripts (bash, sh, zsh)
- Docker, Kubernetes, Terraform
- YAML, JSON, XML, TOML
- And 30+ more languages/formats

## Security Scanning

### Scan Reports

Reports are generated in `.medusa/reports/`:
- HTML dashboard (visual report)
- JSON data (for CI/CD integration)
- CLI output (terminal summary)

### Severity Levels

- **CRITICAL**: Immediate security threats
- **HIGH**: Significant vulnerabilities
- **MEDIUM**: Moderate issues
- **LOW**: Minor concerns
- **INFO**: Best practice suggestions

### Fail Thresholds

Configure scan to fail CI/CD on certain severity:

```bash
medusa scan . --fail-on high
```

## Configuration

Edit `.medusa.yml` to customize:

```yaml
version: 0.8.0
scanners:
  enabled: []     # Empty = all enabled
  disabled: []    # List scanners to disable
fail_on: high     # critical | high | medium | low
exclude:
  paths:
    - node_modules/
    - .venv/
    - dist/
workers: null     # null = auto-detect CPU cores
cache_enabled: true
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: MEDUSA Security Scan
  run: |
    pip install medusa-security
    medusa scan . --fail-on high --no-report
```

### GitLab CI

```yaml
security_scan:
  script:
    - pip install medusa-security
    - medusa scan . --fail-on high
```

## Troubleshooting

### Missing Scanners

If you see warnings about missing tools:

```bash
medusa install --check    # See what's missing
medusa install --all      # Install everything
```

### False Positives

Exclude files or directories in `.medusa.yml`:

```yaml
exclude:
  paths:
    - "tests/fixtures/"
    - "vendor/"
  files:
    - "*.min.js"
```

## Learn More

- **Documentation**: https://docs.medusa-security.dev
- **GitHub**: https://github.com/chimera/medusa
- **Report Issues**: https://github.com/chimera/medusa/issues

---

*This file provides context for Claude Code about MEDUSA integration*
"""


def setup_gemini_cli(project_root: Path) -> bool:
    """
    Setup Gemini CLI integration for MEDUSA

    Creates:
    - .gemini/commands/scan.toml
    - .gemini/commands/install.toml
    - GEMINI.md (project context)

    Args:
        project_root: Project root directory

    Returns:
        True if setup successful
    """
    try:
        # Create .gemini directories
        gemini_dir = project_root / ".gemini"
        commands_dir = gemini_dir / "commands"

        commands_dir.mkdir(parents=True, exist_ok=True)

        # Create scan command (.toml format)
        scan_toml = create_gemini_scan_command()
        scan_file = commands_dir / "scan.toml"
        if tomli_w:
            with open(scan_file, 'wb') as f:
                tomli_w.dump(scan_toml, f)
        else:
            # Fallback: write as text
            with open(scan_file, 'w') as f:
                f.write(_dict_to_toml_text(scan_toml))

        # Create install command (.toml format)
        install_toml = create_gemini_install_command()
        install_file = commands_dir / "install.toml"
        if tomli_w:
            with open(install_file, 'wb') as f:
                tomli_w.dump(install_toml, f)
        else:
            with open(install_file, 'w') as f:
                f.write(_dict_to_toml_text(install_toml))

        # Create GEMINI.md project context
        gemini_md = create_gemini_md(project_root)
        gemini_md_file = project_root / "GEMINI.md"
        with open(gemini_md_file, 'w') as f:
            f.write(gemini_md)

        return True

    except Exception as e:
        print(f"Error setting up Gemini CLI integration: {e}")
        return False


def create_gemini_scan_command() -> Dict[str, Any]:
    """Create Gemini CLI scan command (.toml format)"""
    return {
        "command": {
            "name": "scan",
            "description": "Run MEDUSA security scan on project",
            "usage": "scan [path] [options]",
        },
        "execute": {
            "command": "medusa",
            "args": ["scan", "."],
            "options": {
                "quick": {"flag": "--quick", "description": "Quick scan with cache"},
                "workers": {"flag": "--workers", "description": "Number of parallel workers"},
                "fail-on": {"flag": "--fail-on", "description": "Fail on severity level"},
            }
        },
        "output": {
            "format": "terminal",
            "show_progress": True,
        }
    }


def create_gemini_install_command() -> Dict[str, Any]:
    """Create Gemini CLI install command (.toml format)"""
    return {
        "command": {
            "name": "install",
            "description": "Install missing MEDUSA security tools",
            "usage": "install [options]",
        },
        "execute": {
            "command": "medusa",
            "args": ["install"],
            "options": {
                "check": {"flag": "--check", "description": "Check installed tools"},
                "all": {"flag": "--all", "description": "Install all missing tools"},
                "tool": {"flag": "--tool", "description": "Install specific tool"},
            }
        },
        "output": {
            "format": "terminal",
            "show_progress": True,
        }
    }


def create_gemini_md(project_root: Path) -> str:
    """Create GEMINI.md project context file"""
    project_name = project_root.name
    return f"""# {project_name} - MEDUSA Security Scanning

## MEDUSA Integration for Gemini CLI

This project uses **MEDUSA** - The 42-Headed Security Guardian.

## Custom Commands

### /scan - Security Scan

```bash
/scan                 # Full project scan
/scan --quick         # Quick scan (cache enabled)
/scan --fail-on high  # Fail on high severity
```

### /install - Tool Installation

```bash
/install --check      # Check installed tools
/install --all        # Install all missing tools
/install --tool NAME  # Install specific tool
```

## Configuration

Location: `.medusa.yml`

```yaml
version: 0.8.0
fail_on: high
exclude:
  paths: [node_modules/, .venv/]
workers: null  # auto-detect
cache_enabled: true
```

## Supported Languages (42 total)

Python, JavaScript, TypeScript, Go, Rust, Java, C/C++, Shell, Docker, Kubernetes, Terraform, YAML, JSON, and 30+ more.

## Reports

Generated in `.medusa/reports/`:
- HTML dashboard
- JSON data
- Terminal output

## Severity Levels

- CRITICAL: Immediate threats
- HIGH: Significant vulnerabilities
- MEDIUM: Moderate issues
- LOW: Minor concerns
- INFO: Best practices

---

*Context file for Gemini CLI*
"""


def setup_openai_codex(project_root: Path) -> bool:
    """
    Setup OpenAI Codex integration for MEDUSA

    Creates:
    - AGENTS.md (project context)

    Args:
        project_root: Project root directory

    Returns:
        True if setup successful
    """
    try:
        # Create AGENTS.md project context
        agents_md = create_agents_md(project_root)
        agents_md_file = project_root / "AGENTS.md"
        with open(agents_md_file, 'w') as f:
            f.write(agents_md)

        return True

    except Exception as e:
        print(f"Error setting up OpenAI Codex integration: {e}")
        return False


def create_agents_md(project_root: Path) -> str:
    """Create AGENTS.md project context file for OpenAI Codex"""
    project_name = project_root.name
    return f"""# {project_name}

## Project Type

Security-scanned codebase using MEDUSA.

## MEDUSA Security Scanner

**Version**: 0.8.0
**Purpose**: Automated multi-language security scanning

### Quick Commands

```bash
# Security scan
medusa scan .

# Quick scan (cached)
medusa scan . --quick

# Install missing tools
medusa install --all

# Check tool status
medusa install --check
```

### Slash Commands

Use these in OpenAI Codex CLI:

- `/scan` - Run security scan
- `/install-tools` - Install missing linters

### Configuration

File: `.medusa.yml`

Key settings:
- `fail_on`: Severity threshold (critical/high/medium/low)
- `workers`: Parallel scanner threads
- `exclude`: Paths/files to skip
- `cache_enabled`: Speed up repeat scans

### Language Support

42 languages including:
- Python (bandit, pylint, mypy)
- JavaScript/TypeScript (eslint, tsc)
- Go (golangci-lint, go vet)
- Rust (clippy)
- Shell (shellcheck, bashate)
- Docker (hadolint)
- Kubernetes (kubeval, kube-linter)
- Terraform (tflint, tfsec)
- YAML, JSON, XML, TOML

### Security Reports

Location: `.medusa/reports/`

Formats:
- **HTML**: Visual dashboard with charts
- **JSON**: Machine-readable for CI/CD
- **Terminal**: Colored CLI output

### CI/CD Integration

```yaml
# GitHub Actions
- run: medusa scan . --fail-on high

# GitLab CI
script:
  - medusa scan . --fail-on high
```

### Severity Levels

1. **CRITICAL**: Exploitable vulnerabilities, immediate action required
2. **HIGH**: Significant security risks
3. **MEDIUM**: Moderate issues, should be addressed
4. **LOW**: Minor concerns
5. **INFO**: Best practice suggestions

### Exclusions

Common patterns already excluded:
- `node_modules/`
- `.venv/`, `venv/`
- `dist/`, `build/`
- `*.min.js`

Add custom exclusions in `.medusa.yml`.

### Troubleshooting

**Missing scanners warning?**
```bash
medusa install --check    # See what's missing
medusa install --all      # Install everything
```

**False positives?**
Add to `.medusa.yml`:
```yaml
exclude:
  paths: ["tests/fixtures/"]
  files: ["*.generated.ts"]
```

### Documentation

- Docs: https://docs.medusa-security.dev
- GitHub: https://github.com/chimera/medusa
- Issues: https://github.com/chimera/medusa/issues

---

*Generated by MEDUSA for OpenAI Codex integration*
"""


def setup_github_copilot(project_root: Path) -> bool:
    """
    Setup GitHub Copilot integration for MEDUSA

    Creates:
    - .github/copilot-instructions.md

    Args:
        project_root: Project root directory

    Returns:
        True if setup successful
    """
    try:
        # Create .github directory
        github_dir = project_root / ".github"
        github_dir.mkdir(parents=True, exist_ok=True)

        # Create copilot-instructions.md
        copilot_md = create_copilot_instructions(project_root)
        copilot_file = github_dir / "copilot-instructions.md"
        with open(copilot_file, 'w') as f:
            f.write(copilot_md)

        return True

    except Exception as e:
        print(f"Error setting up GitHub Copilot integration: {e}")
        return False


def create_copilot_instructions(project_root: Path) -> str:
    """Create copilot-instructions.md for GitHub Copilot"""
    project_name = project_root.name
    return f"""# GitHub Copilot Instructions for {project_name}

## Security Scanning with MEDUSA

This project uses **MEDUSA** (v0.8.0) for automated security scanning.

### Commands

```bash
# Run security scan
medusa scan .

# Quick scan (uses cache)
medusa scan . --quick

# Check/install tools
medusa install --check
medusa install --all
```

### Code Quality Standards

When suggesting code changes:

1. **Security First**: All code must pass MEDUSA security scans
2. **Run scans**: Suggest running `medusa scan .` after code changes
3. **Fix issues**: Help fix any CRITICAL or HIGH severity findings
4. **Avoid patterns**: Don't suggest code with known vulnerabilities

### Common Security Issues to Avoid

**Python:**
- SQL injection (use parameterized queries)
- Command injection (avoid `os.system`, `subprocess.call` with shell=True)
- Hardcoded secrets (use environment variables)

**JavaScript/TypeScript:**
- XSS vulnerabilities (sanitize user input)
- Prototype pollution (avoid unsafe merges)
- Insecure dependencies (keep packages updated)

**Shell Scripts:**
- Command injection (quote variables)
- Path traversal (validate paths)
- Unsafe permissions (avoid chmod 777)

**Docker:**
- Running as root (use USER directive)
- Hardcoded secrets (use secrets management)
- Unverified base images (use official images)

### Configuration File

Location: `.medusa.yml`

```yaml
version: 0.8.0
fail_on: high     # Fail CI on high+ severity
exclude:
  paths:
    - node_modules/
    - .venv/
    - dist/
cache_enabled: true
```

### CI/CD Integration

Always include MEDUSA in pull requests:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install MEDUSA
        run: pip install medusa-security
      - name: Run Security Scan
        run: medusa scan . --fail-on high
```

### Severity Guidelines

- **CRITICAL**: Block PRs, fix immediately
- **HIGH**: Should fix before merging
- **MEDIUM**: Fix in follow-up PR
- **LOW**: Optional, good to address
- **INFO**: Best practices

### Language Support

MEDUSA scans 42 languages:
- Python, JavaScript, TypeScript, Go, Rust, Java, C/C++
- Shell, Docker, Kubernetes, Terraform
- YAML, JSON, XML, TOML
- And 30+ more

### Reports

Generated in `.medusa/reports/`:
- `report.html` - Visual dashboard
- `report.json` - JSON data
- Terminal output - CLI summary

### Best Practices

1. **Run scans locally** before pushing
2. **Fix CRITICAL/HIGH** before code review
3. **Document exceptions** in `.medusa.yml`
4. **Keep tools updated**: `medusa install --all`
5. **Review reports**: Check HTML dashboard regularly

### Getting Help

- Documentation: https://docs.medusa-security.dev
- GitHub Issues: https://github.com/chimera/medusa/issues
- Run: `medusa --help`

---

*Copilot: Always prioritize security. Suggest `medusa scan .` after code changes.*
"""


def setup_cursor(project_root: Path) -> bool:
    """
    Setup Cursor integration for MEDUSA

    Creates:
    - .cursor/mcp-config.json (MCP server configuration)
    - Reuses .claude/ structure (Cursor is VS Code fork)

    Args:
        project_root: Project root directory

    Returns:
        True if setup successful
    """
    try:
        # Cursor can use Claude Code's .claude/ structure
        # But also create Cursor-specific MCP config
        cursor_dir = project_root / ".cursor"
        cursor_dir.mkdir(parents=True, exist_ok=True)

        # Create MCP config
        mcp_config = create_cursor_mcp_config()
        mcp_file = cursor_dir / "mcp-config.json"
        with open(mcp_file, 'w') as f:
            json.dump(mcp_config, f, indent=2)

        # Also setup Claude Code structure for compatibility
        setup_claude_code(project_root)

        return True

    except Exception as e:
        print(f"Error setting up Cursor integration: {e}")
        return False


def create_cursor_mcp_config() -> Dict[str, Any]:
    """Create MCP server configuration for Cursor"""
    return {
        "mcpServers": {
            "medusa-security": {
                "command": "medusa",
                "args": ["mcp-server"],
                "description": "MEDUSA Security Scanner MCP Server",
                "tools": [
                    {
                        "name": "scan_project",
                        "description": "Run MEDUSA security scan on project or specific path",
                        "parameters": {
                            "path": "Target directory to scan (default: current directory)",
                            "quick": "Enable quick scan with caching",
                            "fail_on": "Fail threshold (critical/high/medium/low)"
                        }
                    },
                    {
                        "name": "install_tools",
                        "description": "Install missing security scanning tools",
                        "parameters": {
                            "check_only": "Only check what's installed, don't install",
                            "tool": "Specific tool to install (optional)"
                        }
                    },
                    {
                        "name": "get_report",
                        "description": "Get latest security scan report",
                        "parameters": {
                            "format": "Report format (html/json/text)"
                        }
                    }
                ]
            }
        },
        "settings": {
            "auto_scan": False,
            "show_inline_issues": True,
            "fail_on_critical": True
        }
    }


def _dict_to_toml_text(data: Dict[str, Any], indent: int = 0) -> str:
    """
    Fallback: Convert dict to TOML text format (basic implementation)
    Only used if tomli_w is not available
    """
    lines = []
    prefix = "  " * indent

    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}[{key}]")
            lines.append(_dict_to_toml_text(value, indent + 1))
        elif isinstance(value, str):
            lines.append(f'{prefix}{key} = "{value}"')
        elif isinstance(value, bool):
            lines.append(f'{prefix}{key} = {str(value).lower()}')
        elif isinstance(value, (int, float)):
            lines.append(f'{prefix}{key} = {value}')
        elif isinstance(value, list):
            if all(isinstance(v, str) for v in value):
                values_str = ", ".join(f'"{v}"' for v in value)
                lines.append(f'{prefix}{key} = [{values_str}]')

    return "\n".join(lines)
