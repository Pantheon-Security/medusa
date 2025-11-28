# MEDUSA Roadmap

## 2025 Releases

### v2025.8.0.0 (Current - November 2025)
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

### v2025.2.0 (Planned - Q1 2025)

#### Auto Version Pin Updater Script

**Priority**: Medium
**Status**: Planned
**Target**: v2025.2.0

**Problem**:
- Manual version updates in `tools-manifest.csv` are error-prone
- Recent issues: checkstyle 10.22.1, clj-kondo v2025.01.20 didn't exist
- 49 tools need version tracking across multiple platforms
- No automated way to detect when tool versions are outdated

**Solution**:
Create automated script to update tool versions in `tools-manifest.csv`

**Features**:
1. **GitHub Release Checker**
   - Query GitHub API for latest releases
   - Support different tag formats (v1.2.3, 1.2.3, tool-1.2.3, etc.)
   - Handle rate limiting with authentication token

2. **Multi-Source Version Detection**
   - GitHub releases (primary)
   - npm registry API
   - PyPI API
   - Homebrew formulae
   - Winget package manifests

3. **Smart Version Selection**
   - Detect semantic versioning vs calendar versioning
   - Skip pre-releases by default (flag to include)
   - Verify version exists before updating

4. **Update Modes**
   - `--check`: Show outdated versions (no changes)
   - `--update`: Update tools-manifest.csv
   - `--tool <name>`: Update specific tool only
   - `--verify`: Verify all current versions exist

5. **Safety Features**
   - Backup tools-manifest.csv before updating
   - Dry-run mode (show changes without applying)
   - Validation: ensure all versions exist before committing
   - Generate changelog of version updates

**Implementation**:
```bash
# Check for outdated versions
python3 scripts/update_tool_versions.py --check

# Update all tools
python3 scripts/update_tool_versions.py --update

# Update specific tool
python3 scripts/update_tool_versions.py --tool checkstyle --update

# Verify current versions exist
python3 scripts/update_tool_versions.py --verify
```

**Files**:
- `scripts/update_tool_versions.py` - Main updater script
- `scripts/version_checkers/` - Per-platform version checkers
  - `github_checker.py` - GitHub releases
  - `npm_checker.py` - npm registry
  - `pypi_checker.py` - PyPI API
  - `winget_checker.py` - Winget manifests

**Dependencies**:
- `requests` - HTTP requests (already dependency)
- GitHub personal access token (optional, for rate limiting)
- PyPI/npm APIs (public, no auth required)

**Success Criteria**:
- ✅ Detects all 49 tools' latest versions
- ✅ Updates tools-manifest.csv correctly
- ✅ Regenerates tool-versions.lock via generate_tool_manifest.py
- ✅ Validates versions exist before updating
- ✅ Runs in CI/CD pipeline weekly

**Future Enhancements**:
- GitHub Action to auto-create PR with version updates
- Dependency vulnerability scanning integration
- Tool deprecation detection
- Breaking change warnings (major version bumps)

---

## v2026.1.0 (Planned - Q1 2026)

### Paid Version Launch
- Commercial licensing model
- Premium features
- Enterprise support

---

## Backlog

### High Priority
- Rubocop gem PATH fix after Ruby install
- Java auto-install evaluation

### Medium Priority
- Auto version pin updater script
- Enhanced error reporting
- macOS universal binary support

### Low Priority
- GUI interface
- IDE plugin improvements
- Cloud scanning support

---

**Last Updated**: 2025-11-28
**Current Version**: v2025.8.0.0
