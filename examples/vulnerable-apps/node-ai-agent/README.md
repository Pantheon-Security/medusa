# Vulnerable Node.js AI Agent

**DO NOT DEPLOY — intentionally vulnerable for MEDUSA demonstration.**

## Vulnerabilities Present

| # | Category | Location | Risk |
|---|----------|----------|------|
| 1 | Hardcoded Secrets | `agent.js:22-24` | API keys in source code |
| 2 | System Prompt Leak | `agent.js:28-31` | Internal URLs and credentials in system prompt |
| 3 | Unsafe Code Execution | `agent.js:84-93` | vm.runInNewContext with require/process access |
| 4 | SSRF | `agent.js:97-100` | No URL validation on fetch tool |
| 5 | Path Traversal | `agent.js:104-113` | Unrestricted filesystem operations |
| 6 | Unbounded Agent Loop | `agent.js:128` | No iteration limit on tool-calling loop |
| 7 | No Human-in-the-Loop | `agent.js:133` | Dangerous actions executed without approval |
| 8 | Data Exfiltration | `agent.js:148` | Tool output returned unfiltered |
| 9 | Stack Trace Exposure | `agent.js:160` | Internal errors leaked to client |
| 10 | Unverified Webhooks | `agent.js:165` | No signature check on GitHub webhooks |
| 11 | Env Exposure | `agent.js:173` | Debug endpoint dumps all environment variables |

## Scan This Example

```bash
medusa scan examples/vulnerable-apps/node-ai-agent/
```

## Key Lessons

1. **Agent loops need bounds** — without iteration limits, a manipulated agent runs forever
2. **Tool outputs need filtering** — agents can be tricked into exfiltrating data
3. **Code execution needs real sandboxing** — `vm` module is NOT a security boundary
4. **System prompts leak** — never put secrets in prompts, they can be extracted
