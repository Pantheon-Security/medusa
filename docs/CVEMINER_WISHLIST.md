# CVEMiner Wish List

Priority CVEs for automated rule extraction. Focus on **Tier 1** vulnerabilities:
CVSS 9.0+, remote exploitation, no authentication required, framework-level impact.

**Status Legend:** `DONE` = rules generated | `NEEDED` = priority target | `LOW` = future

---

## Output Files

CVEMiner produces **two separate YAML rule files** with distinct detection approaches:

| File | Detection Type | Scanner | Purpose |
|------|---------------|---------|---------|
| `cveminer_cves.yaml` | **Pattern-based** (regex) | YAML rule scanners | Detects vulnerable *code patterns* in source files (e.g., unsafe API calls, insecure configurations, known-bad function usage) |
| `cveminer_critical_cves.yaml` | **Version-based** (dependency manifest) | CriticalCVEScanner | Detects vulnerable *package versions* in dependency files (requirements.txt, pom.xml, go.mod, etc.) |

### Why Two Files?

- **`cveminer_cves.yaml`** catches developers *writing* vulnerable code (AI security patterns, prompt injection, unsafe deserialization calls). These are regex rules loaded by the YAML rule engine.
- **`cveminer_critical_cves.yaml`** catches developers *using* vulnerable dependencies (Log4Shell, Spring4Shell, PyTorch RCE). These feed into the `CriticalCVEScanner` version-range database.

Different detection mechanisms, different scanners, different files. No overlap.

---

## FILE 1: cveminer_cves.yaml (Pattern-Based AI Security Rules)

This is the **existing** output file. Contains regex patterns for detecting vulnerable code.
Already has 326+ rules. CVEMiner continues expanding this with AI/ML security patterns.

**Location:** `medusa/rules/ai_security/cveminer_cves.yaml`

---

## FILE 2: cveminer_critical_cves.yaml (Version-Based Critical CVEs)

This is the **new** output file. Contains version-range data for dependency scanning.
Feeds into `CriticalCVEScanner` at `medusa/scanners/critical_cve_scanner.py`.

**Location:** `medusa/rules/ai_security/cveminer_critical_cves.yaml`

**Format:**
```yaml
# CVEMiner Critical CVE Database
# Generated: 2026-01-30
# Detection: version-range matching against dependency manifests

rules:
  - id: CCVE-001
    cve: CVE-2021-44228
    name: Log4Shell
    cvss: 10.0
    ecosystem: maven
    packages:
      - "org.apache.logging.log4j:log4j-core"
    vulnerable_range:
      min: "2.0.0"
      max: "2.17.0"
    fixed: "2.17.1"
    description: "Log4j2 JNDI injection allows unauthenticated RCE"
    url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    cwe: CWE-917
    severity: CRITICAL
```

---

## Sections 1-3: Feed into FILE 2 (cveminer_critical_cves.yaml)
## Sections 4-5: Feed into BOTH files (pattern + version rules)
## Section 6: Feed into FILE 1 (cveminer_cves.yaml)

---

## 1. AI/ML Agent Framework CVEs (HIGHEST PRIORITY)

These are the bleeding-edge AI security vulnerabilities that make MEDUSA unique.
**Output: FILE 2** (version-based) + **FILE 1** (pattern-based where code patterns exist)

| CVE | CVSS | Package | Ecosystem | Description | Status |
|-----|------|---------|-----------|-------------|--------|
| CVE-2025-68664 | 9.3 | langchain-core | pip | LangGrinch serialization injection (dumps/dumpd RCE) | NEEDED |
| CVE-2025-68665 | 8.6 | @langchain/core | npm | LangGrinch JS variant (toJSON secret extraction) | NEEDED |
| CVE-2025-1793 | 9.8 | llama-index-core | pip | Vector store SQL injection across 8 backends | NEEDED |
| CVE-2024-3271 | 9.8 | llama-index | pip | safe_eval bypass -> OS command injection via LLM output | NEEDED |
| CVE-2024-5480 | 9.8 | langchain | pip | SQL agent prompt injection -> arbitrary code execution | NEEDED |
| CVE-2024-3571 | 9.8 | langchain-experimental | pip | Python REPL tool arbitrary code execution | NEEDED |
| CVE-2024-21513 | 8.5 | langchain-experimental | pip | VectorSQLDatabaseChain eval() -> ACE | NEEDED |
| CVE-2024-46946 | 9.8 | langserve | pip | LCEL playground SSRF via prompt chaining | NEEDED |
| CVE-2025-32434 | 9.3 | torch (PyTorch) | pip | weights_only=True bypass -> RCE via .tar deserialization | NEEDED |
| CVE-2025-49596 | 9.4 | @modelcontextprotocol/inspector | npm | MCP Inspector missing auth (Clawdbot/Moltbot related) | NEEDED |
| CVE-2025-6514 | 9.6 | mcp-remote | npm | MCP remote command injection RCE | NEEDED |
| CVE-2025-52882 | 8.8 | mcp-* | npm | MCP arbitrary file access and code execution | NEEDED |

---

## 2. Classic Framework RCE (HIGH PRIORITY)

Historic Tier 1 vulnerabilities that still appear in the wild.
**Output: FILE 2** (version-based dependency scanning)

| CVE | CVSS | Package | Ecosystem | Description | Status |
|-----|------|---------|-----------|-------------|--------|
| CVE-2021-44228 | 10.0 | log4j-core | maven | Log4Shell JNDI injection RCE | NEEDED |
| CVE-2021-45046 | 9.0 | log4j-core | maven | Log4Shell incomplete fix bypass | NEEDED |
| CVE-2022-22965 | 9.8 | spring-beans | maven | Spring4Shell data binding RCE | NEEDED |
| CVE-2017-5638 | 10.0 | struts2-core | maven | Struts RCE via Content-Type (Equifax breach) | NEEDED |
| CVE-2021-26084 | 9.8 | confluence | maven | Confluence OGNL injection RCE | NEEDED |
| CVE-2023-22515 | 10.0 | confluence | maven | Confluence auth bypass -> admin creation | NEEDED |
| CVE-2024-24576 | 10.0 | std (Rust) | cargo | Rust Command injection on Windows | NEEDED |
| CVE-2024-24790 | 9.8 | stdlib (Go) | go | Go net/netip IPv4-mapped IPv6 access control bypass | NEEDED |
| CVE-2023-29404 | 9.8 | stdlib (Go) | go | Go toolchain command injection via linker flags | NEEDED |

---

## 3. Supply Chain & Dependency Attacks (HIGH PRIORITY)

**Output: FILE 2** (version-based) + **FILE 1** (pattern-based for code indicators)

| CVE | CVSS | Package | Ecosystem | Description | Status |
|-----|------|---------|-----------|-------------|--------|
| CVE-2022-23812 | 9.8 | node-ipc | npm | Protestware file-wiping malware | NEEDED |
| CVE-2023-37920 | 9.8 | certifi | pip | Compromised root CA certificate | NEEDED |
| CVE-2024-3094 | 10.0 | xz-utils | system | XZ Utils backdoor (liblzma) | NEEDED |
| N/A | 9.8 | polyfill.io | cdn | CDN supply chain compromise (redirected to malware) | NEEDED |
| CVE-2024-34064 | 9.8 | jinja2 | pip | Sandbox escape via xmlattr filter | NEEDED |

---

## 4. Web Framework CVEs (MEDIUM PRIORITY)

**Output: BOTH files** (version ranges + code pattern detection)

| CVE | CVSS | Package | Ecosystem | Description | Status |
|-----|------|---------|-----------|-------------|--------|
| CVE-2025-55182 | 10.0 | react-server-dom-* | npm | React2Shell RSC deserialization RCE | DONE (React2ShellScanner) |
| CVE-2025-66478 | 10.0 | next | npm | Next.js React2Shell variant | DONE (React2ShellScanner) |
| CVE-2023-22795 | 9.1 | actionpack | gem | Rails Action Dispatch ReDoS | NEEDED |
| CVE-2023-28362 | 9.1 | actionpack | gem | Rails arbitrary file read | NEEDED |
| CVE-2023-3824 | 9.8 | php | system | PHP phar buffer overflow RCE | NEEDED |
| CVE-2023-44270 | 9.1 | postcss | npm | PostCSS line return -> external CSS injection | NEEDED |
| CVE-2024-28849 | 9.1 | follow-redirects | npm | Authorization header leak on cross-origin redirect | NEEDED |

---

## 5. Infrastructure & Container CVEs (MEDIUM PRIORITY)

**Output: FILE 1** (pattern-based - these are system-level, not in dependency manifests)

| CVE | CVSS | Package | Ecosystem | Description | Status |
|-----|------|---------|-----------|-------------|--------|
| CVE-2024-21626 | 8.6 | runc | go | Container escape via leaked fd (Leaky Vessels) | NEEDED |
| CVE-2024-32002 | 9.8 | git | system | Git clone RCE via symlinks on case-insensitive FS | NEEDED |
| CVE-2023-42465 | 9.8 | sudo | system | Sudo ROWHAMMER bypass (authentication) | NEEDED |
| CVE-2023-38408 | 9.8 | openssh | system | OpenSSH agent forwarding RCE | NEEDED |
| CVE-2024-6387 | 8.1 | openssh | system | regreSSHion - OpenSSH race condition RCE | NEEDED |

---

## 6. Future Research Targets (LOW PRIORITY)

These need monitoring - new CVEs may emerge.
**Output: FILE 1** (pattern-based AI security rules as CVEs are discovered)

| Area | Keywords for CVEMiner | Notes |
|------|----------------------|-------|
| CrewAI | crewai, crew-ai | Multi-agent framework, growing attack surface |
| AutoGPT | autogpt, auto-gpt | Autonomous agent, code execution risks |
| Ollama | ollama | Local LLM server, API exposure risks |
| vLLM | vllm | GPU LLM serving, model loading risks |
| HuggingFace Hub | huggingface, transformers | Model supply chain attacks |
| Gradio | gradio | ML demo framework, SSR vulnerabilities |
| Streamlit | streamlit | ML app framework, code injection risks |
| OpenWebUI | open-webui | LLM frontend, auth bypass risks |
| Dify | dify | LLM app platform, agent execution risks |
| n8n | n8n | Workflow automation, code execution |

---

## CVEMiner Keyword Expansion

Add these search terms to CVEMiner's keyword config:

```yaml
# AI/ML Framework Keywords
keywords_ai_ml:
  - langchain
  - langchain-core
  - langchain-community
  - langchain-experimental
  - langserve
  - llama-index
  - llama-index-core
  - llamaindex
  - pytorch
  - torch
  - transformers
  - huggingface
  - modelcontextprotocol
  - mcp-inspector
  - mcp-remote
  - crewai
  - autogpt
  - ollama
  - vllm
  - gradio
  - streamlit
  - open-webui
  - dify

# Classic Framework Keywords
keywords_frameworks:
  - log4j
  - spring-framework
  - spring-beans
  - struts2
  - confluence
  - rails
  - actionpack
  - django
  - flask
  - express
  - fastapi

# Supply Chain Keywords
keywords_supply_chain:
  - polyfill
  - xz-utils
  - node-ipc
  - certifi
  - jinja2
  - pickle
  - deserialization

# Infrastructure Keywords
keywords_infra:
  - runc
  - containerd
  - kubernetes
  - openssh
  - sudo
  - git
  - docker
```

---

## Priority Order for CVEMiner Processing

1. **AI/ML Agent CVEs** (Section 1) - This is our differentiator
2. **Supply Chain Attacks** (Section 3) - High impact, hard to detect
3. **Classic Framework RCEs** (Section 2) - Well-documented, easy to verify
4. **MCP Ecosystem CVEs** (CVE-2025-49596, CVE-2025-6514) - Emerging attack surface
5. **Web Framework CVEs** (Section 4) - Good coverage value
6. **Infrastructure CVEs** (Section 5) - Broader audience

---

*Last updated: 2026-01-30 | Target: 50+ critical CVE rules by v2026.2.1*
