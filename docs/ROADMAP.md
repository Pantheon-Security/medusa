# MEDUSA Roadmap

## Current Status

**Current Version**: v2025.8.5.12
**Status**: Free Tier Complete
**Last Updated**: 2025-12-12

---

## 2025 Releases

### v2025.8.5.x (Current - December 2025)
**Free Tier Completion Release**

- ✅ 64 Security Scanners
- ✅ 16 AI Security Scanners
- ✅ 150+ Detection Rules
- ✅ Zero False Positives (virtual env auto-detection)
- ✅ Cross-platform support (macOS, Linux, Windows)
- ✅ Auto-installer for all dependencies (except Java)
- ✅ External tool version checker (`scripts/update_tool_versions.py`)
- ✅ Dependency manifest system (`medusa/dependencies.json`)
- ✅ Rubocop gem PATH fix
- ✅ CVE-2025-55182 detection (React2Shell)

### v2025.8.0.0 (November 2025)
**AI Security Powerhouse Release**

- ✅ 16 AI Security Scanners (doubled from 8)
- ✅ 150+ AI-specific detection rules (tripled from 50)
- ✅ OWASP Top 10 for LLM Applications 2025 compliance
- ✅ CVE-2025-6514 detection (mcp-remote OAuth RCE)
- ✅ Advanced Confused Deputy patterns (MCP118)
- ✅ Comprehensive AI Security documentation (docs/AI_SECURITY.md)
- ✅ Published @pan-sec/notebooklm-mcp to npm

### v2025.7.0.0 (November 2025)
**AI Agent Security Release**

- ✅ MCP Config Scanner (MCP001-013)
- ✅ MCP Server Scanner (MCP101-116)
- ✅ AI Context Scanner (AIC001-030)
- ✅ Agent Memory Scanner (AIM001-010)
- ✅ RAG Security Scanner (AIR001-012)
- ✅ A2A Scanner, Prompt Leakage Scanner
- ✅ Tool Callback Scanner, Agent Reflection Scanner
- ✅ Agent Planning Scanner, Multi-Agent Scanner
- ✅ Model Attack Scanner, LLMOps Scanner, Vector DB Scanner

### v2025.3-2025.6 (October-November 2025)
- ✅ MCP Config Scanner (44th scanner)
- ✅ MCP Server Scanner (45th scanner)
- ✅ Env Scanner
- ✅ AI-powered false positive handling

### v2025.1.x (January 2025)
- ✅ Calendar versioning (CalVer) adoption
- ✅ PowerShell installer fixes
- ✅ Upfront runtime detection
- ✅ Windows installation improvements

---

## Free Tier Summary

The free tier of MEDUSA is now **complete** with:

| Feature | Count |
|---------|-------|
| Security Scanners | 64 |
| AI Security Scanners | 16 |
| Detection Rules | 150+ |
| Supported Languages | 42+ |
| Platforms | 3 (macOS, Linux, Windows) |

### Tools & Scripts

| Tool | Purpose |
|------|---------|
| `scripts/check_dependencies.py` | Check/update pip dependencies |
| `scripts/update_tool_versions.py` | Check/update external tools |
| `medusa/dependencies.json` | Dependency tracking manifest |
| `medusa/tool-versions.lock` | Pinned external tool versions |

### Not Auto-Installing (By Design)

- **Java/JDK**: Security concern - users should install themselves
  - Install via: `brew install openjdk` (macOS) or `apt install openjdk-17-jdk` (Linux)
  - Required for: Checkstyle, PMD, SpotBugs

---

## v2026.1.0 (Planned - Q1 2026)

### Paid Version Launch

- Commercial licensing model
- Premium features:
  - Advanced reporting
  - CI/CD integrations
  - Priority support
  - Custom rule development
- Enterprise support tiers
- Cloud scanning architecture

---

## Backlog (Paid Features)

### High Priority
- SaaS dashboard with real-time scanning
- GitHub/GitLab integration (webhook-based)
- SBOM generation and tracking

### Medium Priority
- GUI interface
- IDE plugin improvements (VS Code, IntelliJ)
- Container image scanning

### Low Priority
- Custom scanner SDK
- Multi-tenant cloud architecture
- Compliance reporting (SOC2, HIPAA, etc.)

---

**Maintained by**: Pantheon Security
**GitHub**: https://github.com/Pantheon-Security/medusa
