# Vulnerable Application Examples

**WARNING: These examples contain INTENTIONALLY VULNERABLE code.**

They exist to demonstrate what MEDUSA detects. **Do NOT deploy these in production.**

## Purpose

These sample apps show real-world AI/ML security anti-patterns that MEDUSA's 9,600+ rules catch:

| Example | What It Demonstrates |
|---------|---------------------|
| `flask-llm-app/` | Prompt injection, insecure RAG pipeline, leaked API keys, unsafe deserialization |
| `mcp-server/` | Excessive agency, no sandboxing, tool poisoning, insecure MCP config |
| `node-ai-agent/` | Secrets in code, unsafe eval of LLM output, SSRF via agent tool use |
| `docker-ml-pipeline/` | Privileged containers, exposed model endpoints, insecure ML serving |

## How to Scan

```bash
# Scan all vulnerable examples at once
medusa scan examples/vulnerable-apps/

# Scan a specific example
medusa scan examples/vulnerable-apps/flask-llm-app/

# Get JSON output for programmatic analysis
medusa scan examples/vulnerable-apps/ --output json
```

## Expected Findings

Each example is designed to trigger specific MEDUSA rules. After scanning, you should see findings across categories like:

- **CRITICAL**: Hardcoded secrets, RCE via deserialization, prompt injection
- **HIGH**: Excessive agency, insecure model loading, SSRF
- **MEDIUM**: Missing input validation, verbose error messages, weak auth
- **LOW**: Missing security headers, logging sensitive data

## Contributing

Want to add a new vulnerable example? Follow this pattern:

1. Create a folder under `examples/vulnerable-apps/`
2. Add a `README.md` explaining what vulnerabilities are present
3. Include realistic but clearly fake credentials (use `FAKE-KEY-xxx`)
4. Run `medusa scan` to verify your example triggers the intended rules
