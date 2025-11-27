# IDE Integration Guide

MEDUSA integrates with popular AI-powered IDEs to provide intelligent security scanning with automatic false positive detection.

## Supported IDEs

| IDE | Context File | Commands | AI FP Detection |
|-----|--------------|----------|-----------------|
| Claude Code | CLAUDE.md | `/medusa-scan`, `/medusa-install` | ✅ Full |
| Gemini CLI | GEMINI.md | `/medusa-scan`, `/medusa-install` | ✅ Full |
| GitHub Copilot | .github/copilot-instructions.md | Manual | ✅ Guided |
| OpenAI Codex | AGENTS.md | Manual | ✅ Guided |
| Cursor | .cursor/mcp.json + CLAUDE.md | `/medusa-scan` | ✅ Full |

## Quick Setup

Run this command in your project root:

```bash
medusa init
```

This creates all necessary configuration files for detected IDEs.

## Claude Code Integration

### What Gets Created

```
project/
├── CLAUDE.md                     # Project context with FP handling
├── .claude/
│   ├── agents/medusa/
│   │   └── agent.json           # Agent configuration
│   └── commands/
│       ├── medusa-scan.md       # Scan command
│       └── medusa-install.md    # Install command
```

### Using the Commands

**Run a security scan:**
```
/medusa-scan
```

**Quick scan (cached):**
```
/medusa-scan --quick
```

**Install missing tools:**
```
/medusa-install
```

### AI-Powered Triage

Claude Code reads CLAUDE.md and automatically:

1. Identifies likely false positives (B404, B603, B607, B101)
2. Highlights real security issues
3. Suggests creating `.bandit` config for project-wide FP handling
4. Provides fix suggestions for real vulnerabilities

### Example Interaction

```
You: /medusa-scan

Claude: Running MEDUSA security scan...

Found 45 findings. After intelligent triage:

**False Positives (43):** Subprocess usage in CLI tool - expected
**Real Issues (2):**
1. HIGH: api/auth.py:156 - SQL query built with string concatenation
   Fix: Use parameterized query with SQLAlchemy
2. MEDIUM: config.py:23 - Debug mode enabled
   Fix: Use environment variable for DEBUG setting

Shall I create a `.bandit` config to suppress the FPs?
```

## Gemini CLI Integration

### What Gets Created

```
project/
├── GEMINI.md                     # Project context
├── .gemini/
│   └── commands/
│       ├── medusa-scan.toml     # Scan command
│       └── medusa-install.toml  # Install command
```

### Using the Commands

```bash
# In Gemini CLI
/medusa-scan
/medusa-install
```

### Smart Scan Prompt

The `/medusa-scan` command includes a 4-step triage process:

1. **Identify False Positives** - Known FP patterns
2. **Identify Real Issues** - Actual vulnerabilities
3. **Report Summary** - Filtered results
4. **Handle FPs** - Suggest `.bandit` config

## GitHub Copilot Integration

### What Gets Created

```
project/
├── .github/
│   └── copilot-instructions.md  # Copilot context
```

### How It Works

Copilot reads `copilot-instructions.md` and applies the rules when:

- Suggesting code completions
- Reviewing security scan results
- Answering questions about security

### Key Instructions

The file teaches Copilot:

- Security patterns to avoid (SQL injection, XSS, etc.)
- How to recognize false positives
- When to suggest running `medusa scan .`
- How to handle FPs with `.bandit` config

## OpenAI Codex Integration

### What Gets Created

```
project/
├── AGENTS.md                     # Codex context
```

### Content Includes

- Security requirements
- Common FP patterns with explanations
- Table of Bandit rules and when they're FPs
- How to create `.bandit` config

## Cursor Integration

Cursor uses both Claude Code and MCP (Model Context Protocol):

### What Gets Created

```
project/
├── CLAUDE.md                     # Shared with Claude Code
├── .claude/                      # Shared commands
├── .cursor/
│   └── mcp.json                 # MCP server config
```

### MCP Server

The `mcp.json` configures MEDUSA as an MCP server:

```json
{
  "mcpServers": {
    "medusa-security": {
      "command": "medusa",
      "args": ["mcp-server"]
    }
  }
}
```

## Customizing IDE Context

### Adding Project-Specific Rules

Edit the generated context file (e.g., CLAUDE.md) to add:

```markdown
## Project-Specific Security Rules

- All API endpoints must validate JWT tokens
- Database queries must use the ORM, never raw SQL
- File uploads must be scanned for malware
```

### Preserving Custom Content

MEDUSA's `init` command **won't overwrite** existing context files. Your customizations are safe.

To regenerate (and overwrite):
```bash
medusa init --force
```

## Configuring Auto-Scan

### Claude Code Agent Config

Edit `.claude/agents/medusa/agent.json`:

```json
{
  "triggers": {
    "file_save": {
      "enabled": true,
      "patterns": ["*.py", "*.js", "*.ts"]
    }
  },
  "settings": {
    "auto_scan": true,
    "inline_annotations": true
  }
}
```

### Disable Auto-Scan

Set in `.medusa.yml`:

```yaml
ide:
  claude_code:
    enabled: true
    auto_scan: false
```

## IDE-Specific Tips

### Claude Code

- Use `/medusa-scan --quick` for fast feedback during development
- Ask Claude to explain findings: "What does B602 mean?"
- Request fixes: "Fix the SQL injection in auth.py"

### Gemini CLI

- The scan command includes detailed triage steps
- Gemini will suggest `.bandit` config when seeing many FPs

### GitHub Copilot

- Copilot applies security rules when suggesting code
- After completing code, it may suggest running a scan
- Ask: "Is this code secure?" for instant review

### Cursor

- Works like Claude Code with additional MCP capabilities
- Can run scans through MCP protocol
- Shares context files with Claude Code

## Troubleshooting

### Commands Not Working

```bash
# Regenerate IDE files
medusa init --force

# Check files were created
ls -la .claude/ .gemini/ .github/ .cursor/
```

### Context Not Being Read

Ensure the context file is in the project root:
- CLAUDE.md (not .claude/CLAUDE.md)
- GEMINI.md (not .gemini/GEMINI.md)

### Too Many False Positives

Create `.bandit` config as described in [Handling False Positives](./handling-false-positives.md).

### IDE Not Detecting MEDUSA

```bash
# Verify MEDUSA is installed
medusa --version

# Verify it's in PATH
which medusa
```

## Further Reading

- [Handling False Positives](./handling-false-positives.md)
- [MEDUSA Configuration](../configuration.md)
- [Claude Code Best Practices](https://www.anthropic.com/engineering/claude-code-best-practices)
- [Gemini CLI Custom Commands](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/custom-commands.md)
