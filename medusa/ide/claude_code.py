#!/usr/bin/env python3
"""
MEDUSA Multi-IDE Integration
Auto-setup for Claude Code, Gemini CLI, OpenAI Codex, GitHub Copilot, and Cursor
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional

# For TOML writing (Gemini CLI .toml commands)
try:
    import tomli_w
except ImportError:
    tomli_w = None

# Import backup manager
from medusa.ide.backup import IDEBackupManager


def setup_claude_code(project_root: Path, backup_manager: Optional[IDEBackupManager] = None) -> tuple:
    """
    Setup Claude Code integration for MEDUSA

    Creates:
    - .claude/agents/medusa/agent.json
    - .claude/commands/medusa-scan.md
    - .claude/commands/medusa-install.md
    - CLAUDE.md (project context) - only if it doesn't exist

    Args:
        project_root: Project root directory
        backup_manager: Optional backup manager for backing up existing files

    Returns:
        Tuple of (success: bool, claude_md_created: bool, backed_up_files: list)
    """
    claude_md_created = False
    backed_up_files = []

    try:
        # Backup existing files before making changes
        if backup_manager:
            for file_path in ['CLAUDE.md', '.claude/agents/medusa/agent.json',
                              '.claude/commands/medusa-scan.md', '.claude/commands/medusa-install.md']:
                was_backed_up, _ = backup_manager.backup_if_exists(file_path)
                if was_backed_up:
                    backed_up_files.append(file_path)

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

        # Create CLAUDE.md project context (only if it doesn't exist)
        claude_md_file = project_root / "CLAUDE.md"
        if not claude_md_file.exists():
            claude_md = create_claude_md(project_root)
            with open(claude_md_file, 'w') as f:
                f.write(claude_md)
            claude_md_created = True
        # If CLAUDE.md exists, don't overwrite - user may have custom content

        return (True, claude_md_created, backed_up_files)

    except Exception as e:
        print(f"Error setting up Claude Code integration: {e}")
        return (False, claude_md_created, backed_up_files)


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

## Intelligent False Positive Handling

After running scan, intelligently triage results:

### Likely False Positives (FPs)
- B404/B603/B607: subprocess in CLI tools, installers, build scripts
- B602: `shell=variable` where variable is NOT literal `True`
- B101: assert in test files (pytest standard)
- Secrets in .env.example with placeholder values

### Real Issues (Must Fix)
- `shell=True` with user-controlled input
- High-entropy strings matching real API keys
- SQL built with string concatenation
- eval/exec with external data

### Handling FPs
Create `.bandit` config to skip project-wide:
```yaml
skips:
  - B404  # import subprocess
  - B603  # subprocess call
  - B101  # assert in tests
```

## Integration

This command integrates with MEDUSA's 43-headed security scanner, providing:

- ✅ 43 language/format support
- ✅ Auto-detection of file types
- ✅ Parallel scanning for speed
- ✅ Beautiful HTML/JSON reports
- ✅ Inline issue annotations
- ✅ AI-powered false positive detection

## Configuration

Edit `.medusa.yml` to customize:
- Exclusion patterns
- Scanner enable/disable
- Severity thresholds
- IDE integration settings

## Learn More

- Documentation: https://pantheonsecurity.io/docs
- Report Issues: https://github.com/Pantheon-Security/medusa/issues
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
    """
    Create CLAUDE.md project context file

    Best practices per https://www.anthropic.com/engineering/claude-code-best-practices:
    - Keep concise and human-readable
    - Use short, declarative bullet points
    - Group related items under headings
    - Only include rules Claude needs to know
    """
    project_name = project_root.name
    return f"""# {project_name}

## Commands

```bash
# Security scan
medusa scan .

# Quick scan (cached)
medusa scan . --quick

# Install missing tools
medusa install --all
```

## Slash Commands

- `/medusa-scan` - Run security scan
- `/medusa-install` - Install security tools

## Security Standards

- All code must pass `medusa scan .` with no CRITICAL findings
- Fix HIGH severity issues before committing
- Run `medusa scan . --quick` after changes

## Configuration

File: `.medusa.yml`

```yaml
fail_on: high
exclude:
  paths:
    - node_modules/
    - .venv/
    - dist/
```

## Severity Levels

- CRITICAL: Fix immediately
- HIGH: Fix before commit
- MEDIUM: Should fix
- LOW/INFO: Optional

## Intelligent False Positive Handling

When MEDUSA reports issues, use AI judgment to triage:

### Likely False Positives (FPs)
- `subprocess` imports/calls in CLI tools, installers, or build scripts (B404/B603/B607)
- `shell=variable` where variable is not `True` (B602 triggers on any `shell=` keyword)
- `assert` statements in test files (B101) - standard pytest practice
- Secrets in `.env.example` files with placeholder values like `xxx`, `changeme`

### Real Issues to Fix
- Actual `shell=True` in subprocess with user input
- Real secrets/tokens (check entropy, not just pattern match)
- SQL string concatenation with variables
- `eval()`/`exec()` with any external input

### How to Handle FPs
1. **Project-wide**: Create/update `.bandit` config file with `skips:` list
2. **Per-file**: Only use `# nosec` comments as last resort, document why
3. **Exclude paths**: Add test fixtures, vendor code to `.medusa.yml` exclude

### Example .bandit Config
```yaml
# For CLI tools that legitimately use subprocess
skips:
  - B404  # import subprocess
  - B603  # subprocess without shell
  - B607  # partial executable path
  - B101  # assert in tests
```

After handling FPs, re-run `medusa scan .` to verify reduction.

## Do Not

- Do not commit code with CRITICAL security findings
- Do not disable security scanners without documenting why
- Do not ignore HIGH severity issues in PRs
- Do not blindly add `# nosec` - understand each finding first

## Troubleshooting

- Missing tools: `medusa install --all`
- False positives: Create `.bandit` config or add to `.medusa.yml` exclude
- Slow scans: Use `medusa scan . --quick`
"""


def setup_gemini_cli(project_root: Path, backup_manager: Optional[IDEBackupManager] = None) -> tuple:
    """
    Setup Gemini CLI integration for MEDUSA

    Creates:
    - .gemini/commands/medusa-scan.toml
    - .gemini/commands/medusa-install.toml
    - GEMINI.md (project context)

    Args:
        project_root: Project root directory
        backup_manager: Optional backup manager for backing up existing files

    Returns:
        Tuple of (success: bool, backed_up_files: list)
    """
    backed_up_files = []

    try:
        # Backup existing files before making changes
        if backup_manager:
            for file_path in ['GEMINI.md', '.gemini/commands/medusa-scan.toml',
                              '.gemini/commands/medusa-install.toml']:
                was_backed_up, _ = backup_manager.backup_if_exists(file_path)
                if was_backed_up:
                    backed_up_files.append(file_path)

        # Create .gemini directories
        gemini_dir = project_root / ".gemini"
        commands_dir = gemini_dir / "commands"

        commands_dir.mkdir(parents=True, exist_ok=True)

        # Create scan command (.toml format) - use medusa- prefix to avoid conflicts
        # Commands are now plain TOML text (description + prompt format per Gemini CLI spec)
        scan_file = commands_dir / "medusa-scan.toml"
        with open(scan_file, 'w') as f:
            f.write(create_gemini_scan_command())

        # Create install command (.toml format) - use medusa- prefix to avoid conflicts
        install_file = commands_dir / "medusa-install.toml"
        with open(install_file, 'w') as f:
            f.write(create_gemini_install_command())

        # Create GEMINI.md project context (only if it doesn't exist)
        gemini_md_file = project_root / "GEMINI.md"
        if not gemini_md_file.exists():
            gemini_md = create_gemini_md(project_root)
            with open(gemini_md_file, 'w') as f:
                f.write(gemini_md)
        # If GEMINI.md exists, don't overwrite - user may have custom content

        return (True, backed_up_files)

    except Exception as e:
        print(f"Error setting up Gemini CLI integration: {e}")
        return (False, backed_up_files)


def create_gemini_scan_command() -> str:
    """
    Create Gemini CLI scan command (.toml format)

    Official format per https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/custom-commands.md:
    - description: Brief one-line description
    - prompt: The prompt sent to Gemini (can use {{args}} for user input)
    """
    return '''description = "Run MEDUSA security scan on the project"
prompt = """
Run the MEDUSA security scanner on this project.

Command to execute:
```bash
medusa scan . {{args}}
```

After scanning, intelligently triage the results:

## Step 1: Identify False Positives
These are likely FALSE POSITIVES (don't report as issues):
- B404/B603/B607: subprocess usage in CLI tools, build scripts, installers
- B602: `shell=variable` where variable is NOT literal `True`
- B101: assert statements in test files (standard pytest)
- Secrets in .env.example with placeholders like `xxx`, `changeme`, `your-key-here`

## Step 2: Identify Real Issues
These are REAL ISSUES (must fix):
- `shell=True` with user-controlled input
- High-entropy strings that look like actual API keys/tokens
- SQL queries built with string concatenation
- `eval()` or `exec()` with external input

## Step 3: Report Summary
1. Show count by severity: CRITICAL, HIGH, MEDIUM, LOW
2. List only REAL issues (skip false positives)
3. For each real issue, explain the risk and suggest a fix
4. If many FPs, suggest creating a `.bandit` config file

## Step 4: Handle FPs Project-Wide
If there are many false positives, suggest creating `.bandit`:
```yaml
skips:
  - B404  # import subprocess - CLI tool
  - B603  # subprocess call - safe usage
  - B101  # assert in tests
```

Common options the user might pass via {{args}}:
- --quick : Use cached results for faster scanning
- --fail-on high : Fail if high severity issues found
- --workers N : Use N parallel workers
"""
'''


def create_gemini_install_command() -> str:
    """
    Create Gemini CLI install command (.toml format)

    Official format per https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/custom-commands.md:
    - description: Brief one-line description
    - prompt: The prompt sent to Gemini
    """
    return '''description = "Install missing MEDUSA security scanning tools"
prompt = """
Help install missing security tools for MEDUSA.

First, check what tools are installed:
```bash
medusa install --check
```

Then, based on the output:
- If tools are missing, offer to install them with: `medusa install --all`
- If a specific tool is missing, install it with: `medusa install <tool-name>`
- If all tools are installed, confirm the setup is complete

Explain what each missing tool does and why it's useful for security scanning.
"""
'''


def create_gemini_md(project_root: Path) -> str:
    """Create GEMINI.md project context file"""
    project_name = project_root.name
    return f"""# {project_name}

## Commands

```bash
# Security scan
medusa scan .

# Quick scan (cached)
medusa scan . --quick

# Install tools
medusa install --all
```

## Slash Commands

- `/medusa-scan` - Run security scan
- `/medusa-install` - Install missing tools

## Security Standards

- All code must pass `medusa scan .` with no CRITICAL findings
- Fix HIGH severity issues before committing
- Configuration: `.medusa.yml`

## Severity Levels

- CRITICAL: Fix immediately
- HIGH: Fix before commit
- MEDIUM: Should fix
- LOW/INFO: Optional

## Intelligent False Positive Handling

When reviewing MEDUSA scan results, intelligently triage findings:

### Common False Positives
- **B404/B603/B607**: subprocess usage in CLI tools, build scripts, installers - legitimate
- **B602**: `shell=variable` where variable isn't `True` (e.g., `shell=self.detect_shell()`)
- **B101**: assert in test files - standard pytest practice
- **Secrets**: `.env.example` with placeholders like `xxx`, `your-key-here`

### Real Issues (Fix These)
- `shell=True` with user-controlled input
- High-entropy strings that look like real API keys/tokens
- SQL queries built with string concatenation
- `eval()`/`exec()` with external input

### Handling FPs
1. Create `.bandit` config with `skips:` for project-wide rules
2. Add test fixtures/vendor code to `.medusa.yml` exclude paths
3. Use `# nosec BXXX` comments only as last resort (document why)

### Example .bandit
```yaml
skips:
  - B404  # import subprocess - CLI tool
  - B603  # subprocess call - validated input
  - B101  # assert in tests
```
"""


def setup_openai_codex(project_root: Path, backup_manager: Optional[IDEBackupManager] = None) -> tuple:
    """
    Setup OpenAI Codex integration for MEDUSA

    Creates:
    - AGENTS.md (project context)

    Args:
        project_root: Project root directory
        backup_manager: Optional backup manager for backing up existing files

    Returns:
        Tuple of (success: bool, backed_up_files: list)
    """
    backed_up_files = []

    try:
        # Backup existing files before making changes
        if backup_manager:
            was_backed_up, _ = backup_manager.backup_if_exists('AGENTS.md')
            if was_backed_up:
                backed_up_files.append('AGENTS.md')

        # Create AGENTS.md project context (only if it doesn't exist)
        agents_md_file = project_root / "AGENTS.md"
        if not agents_md_file.exists():
            agents_md = create_agents_md(project_root)
            with open(agents_md_file, 'w') as f:
                f.write(agents_md)
        # If AGENTS.md exists, don't overwrite - user may have custom content

        return (True, backed_up_files)

    except Exception as e:
        print(f"Error setting up OpenAI Codex integration: {e}")
        return (False, backed_up_files)


def create_agents_md(project_root: Path) -> str:
    """Create AGENTS.md project context file for OpenAI Codex"""
    project_name = project_root.name
    return f"""# {project_name}

## Dev Environment

This project uses MEDUSA for automated security scanning.

### Before committing code

```bash
# Run security scan
medusa scan .

# Quick scan (uses cache, faster for incremental changes)
medusa scan . --quick
```

Fix any CRITICAL or HIGH severity issues before committing.

### Installing dependencies

If you see warnings about missing security tools:

```bash
medusa install --check    # See what's missing
medusa install --all      # Install all required tools
```

## Project Standards

### Security requirements

- All code changes must pass `medusa scan .` with no CRITICAL findings
- HIGH severity findings should be addressed before merge
- Use `medusa scan . --fail-on high` in CI/CD pipelines

### Code quality

MEDUSA scans for:
- Security vulnerabilities (injection, XSS, hardcoded secrets, etc.)
- Code quality issues (unused variables, complexity, etc.)
- Best practice violations (Docker as root, insecure defaults, etc.)

## Intelligent False Positive Handling

When reviewing scan results, use judgment to distinguish real issues from false positives:

### Common False Positives (Don't Fix)
| Code | Description | Why it's a FP |
|------|-------------|---------------|
| B404 | import subprocess | CLI tools need subprocess |
| B603 | subprocess call | Safe when not using shell=True |
| B607 | partial path | Tools validated before execution |
| B602 | shell=True | FP when `shell=variable` not literal True |
| B101 | assert statement | Standard in pytest test files |

### Real Issues (Must Fix)
- `subprocess.run(cmd, shell=True)` with user input
- High-entropy strings matching API key patterns (not placeholders)
- SQL built with f-strings or .format() with variables
- `eval()` or `exec()` with any external data

### How to Handle FPs Project-Wide
Create a `.bandit` config file:
```yaml
skips:
  - B404  # import subprocess - this is a CLI tool
  - B603  # subprocess without shell - safe usage
  - B101  # assert in tests - pytest standard
```

This reduces noise from 70+ findings to just real issues.

## Configuration

Security scanning is configured in `.medusa.yml`:

```yaml
fail_on: high     # Fail CI on high+ severity
exclude:
  paths:
    - node_modules/
    - .venv/
    - dist/
```

To exclude false positives, add paths or files to the exclude section.

## Testing

After making changes, verify security compliance:

```bash
# Full scan
medusa scan .

# Generate HTML report for review
medusa scan . --report html
```

Reports are saved to `.medusa/reports/`.

## Troubleshooting

**Scan shows "tool not found"**: Run `medusa install --all`

**Too many false positives**: Create `.bandit` config with appropriate skips

**Slow scans**: Use `medusa scan . --quick` for cached results

---

*Security scanning powered by [MEDUSA](https://github.com/Pantheon-Security/medusa)*
"""


def setup_github_copilot(project_root: Path, backup_manager: Optional[IDEBackupManager] = None) -> tuple:
    """
    Setup GitHub Copilot integration for MEDUSA

    Creates:
    - .github/copilot-instructions.md

    Args:
        project_root: Project root directory
        backup_manager: Optional backup manager for backing up existing files

    Returns:
        Tuple of (success: bool, backed_up_files: list)
    """
    backed_up_files = []

    try:
        # Backup existing files before making changes
        if backup_manager:
            was_backed_up, _ = backup_manager.backup_if_exists('.github/copilot-instructions.md')
            if was_backed_up:
                backed_up_files.append('.github/copilot-instructions.md')

        # Create .github directory
        github_dir = project_root / ".github"
        github_dir.mkdir(parents=True, exist_ok=True)

        # Create copilot-instructions.md (only if it doesn't exist)
        copilot_file = github_dir / "copilot-instructions.md"
        if not copilot_file.exists():
            copilot_md = create_copilot_instructions(project_root)
            with open(copilot_file, 'w') as f:
                f.write(copilot_md)
        # If copilot-instructions.md exists, don't overwrite - user may have custom content

        return (True, backed_up_files)

    except Exception as e:
        print(f"Error setting up GitHub Copilot integration: {e}")
        return (False, backed_up_files)


def create_copilot_instructions(project_root: Path) -> str:
    """
    Create copilot-instructions.md for GitHub Copilot

    Best practices per https://github.blog/ai-and-ml/github-copilot/5-tips-for-writing-better-custom-instructions-for-copilot/:
    - Keep instructions concise (under 2 pages)
    - Use short, self-contained statements
    - No external links (Copilot won't follow them)
    - Broadly applicable to entire project
    """
    project_name = project_root.name
    return f"""# Copilot Instructions for {project_name}

## Security Requirements

This project uses MEDUSA for security scanning. All code must pass security checks.

## Before Suggesting Code

- Avoid SQL injection: use parameterized queries, never string concatenation
- Avoid command injection: don't use shell=True with subprocess
- Avoid XSS: sanitize all user input before rendering
- Avoid hardcoded secrets: use environment variables
- Avoid unsafe file operations: validate paths, prevent traversal

## After Code Changes

Remind users to run security scans:
- `medusa scan .` for full scan
- `medusa scan . --quick` for cached results

## Code Standards

- All new code must pass `medusa scan .` with no CRITICAL findings
- HIGH severity issues should be fixed before merge
- MEDIUM issues should be documented if not fixed

## Intelligent False Positive Handling

When reviewing MEDUSA scan results, distinguish real issues from false positives:

### False Positives (Don't report as issues)
- B404/B603/B607: subprocess in CLI tools, installers, build scripts
- B602: shell=variable where variable is not literal True
- B101: assert in test files (pytest standard)
- Secrets in .env.example with placeholder values

### Real Issues (Must fix)
- shell=True with user input
- High-entropy strings matching real API key patterns
- SQL with string concatenation
- eval/exec with external data

### Handling FPs
Create .bandit config:
```yaml
skips:
  - B404  # import subprocess
  - B603  # subprocess call
  - B101  # assert in tests
```

## Security Patterns by Language

Python:
- Use `subprocess.run()` with list args, not shell=True
- Use parameterized queries with SQLAlchemy or psycopg2
- Never use `eval()` or `exec()` with user input

JavaScript/TypeScript:
- Sanitize HTML output to prevent XSS
- Validate and sanitize all URL parameters
- Use `Object.create(null)` for user-controlled objects

Shell:
- Always quote variables: "$var" not $var
- Use `set -euo pipefail` in scripts
- Validate file paths before operations

Docker:
- Never run as root in production (use USER directive)
- Pin base image versions
- Don't copy secrets into images

## Configuration

Security settings are in `.medusa.yml`. For false positives, create `.bandit` config.

## Severity Levels

- CRITICAL: Must fix immediately, blocks deployment
- HIGH: Fix before merging PR
- MEDIUM: Should fix, can be follow-up
- LOW/INFO: Best practice suggestions
"""


def setup_cursor(project_root: Path, backup_manager: Optional[IDEBackupManager] = None) -> tuple:
    """
    Setup Cursor integration for MEDUSA

    Creates:
    - .cursor/mcp.json (MCP server configuration)
    - Reuses .claude/ structure (Cursor is VS Code fork)

    Args:
        project_root: Project root directory
        backup_manager: Optional backup manager for backing up existing files

    Returns:
        Tuple of (success: bool, backed_up_files: list)
    """
    backed_up_files = []

    try:
        # Backup existing files before making changes
        if backup_manager:
            was_backed_up, _ = backup_manager.backup_if_exists('.cursor/mcp.json')
            if was_backed_up:
                backed_up_files.append('.cursor/mcp.json')

        # Cursor can use Claude Code's .claude/ structure
        # But also create Cursor-specific MCP config
        cursor_dir = project_root / ".cursor"
        cursor_dir.mkdir(parents=True, exist_ok=True)

        # MCP config - correct filename is mcp.json (not mcp-config.json)
        mcp_file = cursor_dir / "mcp.json"
        medusa_mcp_config = create_cursor_mcp_config()

        if mcp_file.exists():
            # Merge with existing config - don't overwrite user's other MCP servers
            try:
                with open(mcp_file, 'r') as f:
                    existing_config = json.load(f)

                # Only update the medusa-security entry, preserve everything else
                if 'mcpServers' not in existing_config:
                    existing_config['mcpServers'] = {}

                existing_config['mcpServers']['medusa-security'] = medusa_mcp_config['mcpServers']['medusa-security']

                with open(mcp_file, 'w') as f:
                    json.dump(existing_config, f, indent=2)
            except (json.JSONDecodeError, IOError):
                # Corrupted file, overwrite it
                with open(mcp_file, 'w') as f:
                    json.dump(medusa_mcp_config, f, indent=2)
        else:
            # No existing config, create new
            with open(mcp_file, 'w') as f:
                json.dump(medusa_mcp_config, f, indent=2)

        # Also setup Claude Code structure for compatibility
        claude_success, _, claude_backed_up = setup_claude_code(project_root, backup_manager)
        backed_up_files.extend(claude_backed_up)

        return (True, backed_up_files)

    except Exception as e:
        print(f"Error setting up Cursor integration: {e}")
        return (False, backed_up_files)


def create_cursor_mcp_config() -> Dict[str, Any]:
    """
    Create MCP server configuration for Cursor

    Official format per https://docs.cursor.com/context/model-context-protocol:
    - mcpServers: object with server configs
    - Each server has: command, args, env (optional)
    - No other fields are recognized
    """
    return {
        "mcpServers": {
            "medusa-security": {
                "command": "medusa",
                "args": ["mcp-server"]
            }
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
