#!/usr/bin/env python3
"""
MEDUSA Claude Code Integration
Auto-setup for Claude Code IDE
"""

import json
from pathlib import Path
from typing import Dict, Any


def setup_claude_code(project_root: Path) -> bool:
    """
    Setup Claude Code integration for MEDUSA

    Creates:
    - .claude/agents/medusa/agent.json
    - .claude/commands/medusa-scan.md

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

        agents_dir.mkdir(parents=True, exist_ok=True)
        commands_dir.mkdir(parents=True, exist_ok=True)

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


def create_cursor_config(project_root: Path) -> bool:
    """Setup Cursor integration (future implementation)"""
    return False


def create_vscode_config(project_root: Path) -> bool:
    """Setup VS Code integration (future implementation)"""
    return False
