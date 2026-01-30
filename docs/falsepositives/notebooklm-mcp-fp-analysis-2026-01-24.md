# False Positive Analysis: notebooklm-mcp-secure

**Date:** 2026-01-24
**MEDUSA Version:** 2026.1.0
**Project:** notebooklm-mcp-secure
**Files Scanned:** 103
**Lines Scanned:** 27,212

## Summary

| Metric | Value |
|--------|-------|
| Total Findings | 6 |
| True Positives | 0 |
| False Positives | 6 |
| **FP Rate** | **100%** |

---

## Finding #1: Over-privileged MCP tool access

**Scanner:** mcpserverscanner
**File:** `src/index.ts:142`
**Severity:** MEDIUM
**Rule ID:** (needs identification)

### Flagged Code
```typescript
log.info(`🔧 [MCP] Tool call: ${name}`);
```

### Why It's a False Positive
This is simply logging which MCP tool is being called. The `name` variable is the tool name (e.g., "ask_question", "get_health"), not sensitive data or over-privileged access.

### Root Cause
Rule is too broad - matching any log statement that contains "tool" + variable interpolation.

### Suggested Fix
- Add negative lookahead for `log\.(info|debug|warn)` contexts
- Require actual privilege indicators like `admin`, `root`, `sudo`, `elevated`

---

## Finding #2: Sensitive data in MCP logs

**Scanner:** mcpserverscanner
**File:** `src/index.ts:150`
**Severity:** MEDIUM
**Rule ID:** MCP-RUNTIME-OUTPUT-002 or similar

### Flagged Code
```typescript
log.warning(`🔒 [MCP] Authentication failed for tool: ${name}`);
```

### Why It's a False Positive
This logs authentication failure status - a standard security practice. It logs the tool name, not credentials, tokens, or sensitive user data.

### Root Cause
Rule matches `auth` + `log` without distinguishing between:
- Logging auth status (safe)
- Logging auth credentials (dangerous)

### Suggested Fix
- Require actual credential patterns: `token`, `password`, `key`, `secret` + value
- Exclude status words: `failed`, `success`, `enabled`, `disabled`, `required`

---

## Finding #3: Sensitive data in MCP logs

**Scanner:** mcpserverscanner
**File:** `src/index.ts:669`
**Severity:** MEDIUM
**Rule ID:** MCP-RUNTIME-OUTPUT-002 or similar

### Flagged Code
```typescript
log.info(`  MCP Authentication: ${authStatus.enabled ? 'enabled' : 'disabled'}`);
```

### Why It's a False Positive
This logs whether authentication is enabled/disabled - a boolean status. No sensitive data is exposed.

### Root Cause
Same as Finding #2 - rule matches `auth` in log context without semantic analysis.

### Suggested Fix
Same as Finding #2 - exclude boolean status patterns.

---

## Finding #4: Roleplay injection pattern - identity override

**Scanner:** mcpserverscanner
**File:** `src/tools/definitions/ask-question.ts:38`
**Severity:** MEDIUM
**Rule ID:** JB-RUNTIME-ROLE-001 or similar

### Flagged Code
```typescript
// Tool description containing:
"After every NotebookLM answer: pause, compare with the user's goal, and only respond if you are 100% sure the information is complete."
```

### Why It's a False Positive
This is MCP tool description text - instructions for how Claude should behave when using the tool. It's not an attack payload; it's legitimate tool documentation.

### Root Cause
Rule matches instruction-like text ("respond", "you are", etc.) without distinguishing:
- Tool descriptions (safe - defining expected behavior)
- User input (potentially dangerous)

### Suggested Fix
- Add exception for `description:` fields in tool definitions
- Add exception for files matching `*/tools/definitions/*.ts`
- Require jailbreak-specific keywords: `ignore`, `bypass`, `override`, `DAN`, `jailbreak`

---

## Finding #5: MCP server without authentication

**Scanner:** mcpserverscanner
**File:** `src/tools/definitions/system.ts:13`
**Severity:** MEDIUM
**Rule ID:** MEDUSA-AGENT-MCP-006 or similar

### Flagged Code
```typescript
// Tool description containing:
"If authenticated=false and having persistent issues:\n" +
"Consider running cleanup_data(preserve_library=true) + setup_auth for fresh start"
```

### Why It's a False Positive
This is help text describing what to do when authentication fails - troubleshooting documentation. The server DOES have authentication; this text is explaining how to fix auth problems.

### Root Cause
Rule matches `authenticated=false` or `no.*authentication` without context:
- Troubleshooting docs (safe)
- Actual missing auth config (dangerous)

### Suggested Fix
- Require config file context (`.json`, `.yaml`, `.toml`)
- Exclude string literals and documentation
- Look for actual config patterns: `auth: false`, `"authentication": false`

---

## Finding #6: Command injection (child_process)

**Scanner:** semgrepscanner
**File:** `src/utils/file-permissions.ts:179`
**Severity:** CRITICAL
**Rule ID:** javascript.lang.security.audit.child-process-injection

### Flagged Code
```typescript
execSync(
  `icacls "${normalizedPath}" /inheritance:r /grant:r "${username}:(F)" /q`,
  { stdio: "pipe" }
);
```

### Why It's a False Positive
This is an internal utility function for setting Windows file permissions:
1. `normalizedPath` is internally generated, not user input
2. The path is properly quoted with double quotes
3. `icacls` is a Windows-specific command with limited injection surface
4. The function is called only for internal file operations

### Root Cause
Semgrep rule flags any `execSync` with template literals, regardless of:
- Whether input is user-controlled
- Whether values are properly quoted/escaped
- Whether it's an internal utility

### Suggested Fix (FP Filter)
- Add pattern for quoted paths in system commands
- Add exception for `utils/` or `internal/` directories
- Check if variable comes from user input vs internal logic

---

## Pattern Summary

| FP Category | Count | Root Cause |
|-------------|-------|------------|
| Logging status messages | 3 | Rules match keyword without semantic context |
| Tool descriptions | 2 | Rules match instruction text in docs |
| Internal utilities | 1 | Rules flag all exec regardless of input source |

## Recommended Rule Changes

### 1. Sensitive Data in Logs (Findings #1-3)
**File:** `medusa/rules/ai_security/mcp_security_runtime.yaml`

Current pattern matches `log.*auth|token|key` too broadly.

**Fix:** Require actual value exposure, not status messages:
```yaml
# Bad: log.*auth  (matches "auth failed")
# Good: log.*(token|key|secret)\s*[:=]\s*[^(status|enabled|disabled|failed|success)]
```

### 2. Roleplay/Instruction Patterns (Finding #4)
**File:** `medusa/rules/ai_security/jailbreaking_runtime.yaml`

**Fix:** Add tool description exception:
```yaml
# Exclude: description: "..." in tool definitions
# Exclude: files in */tools/definitions/*
```

### 3. Authentication Config (Finding #5)
**File:** `medusa/rules/agent_security/tool_attacks.yaml`

**Fix:** Require config file context:
```yaml
# Only match in .json, .yaml, .toml, .env files
# Exclude string literals and documentation
```

### 4. Command Injection (Finding #6)
**File:** FP filter addition

**Fix:** Add pattern for quoted internal paths:
```python
FPPattern(
    name="exec_quoted_internal_path",
    scanner="semgrepscanner",
    pattern=r'execSync\s*\(\s*`[^`]*"\$\{[^}]+\}"',
    context_pattern=r'(utils|internal|helpers)',
    reason=FPReason.SAFE_PATTERN,
    confidence=0.85,
)
```

---

## Test Commands

```bash
# Re-scan after fixes
medusa scan /home/ross-churchill/Documents/notebooklm-mcp-secure --format json

# Expected result: 0 findings (or only true positives)
```

## Cross-Reference

This document should be used when reviewing:
- `medusa/rules/ai_security/mcp_security_runtime.yaml`
- `medusa/rules/ai_security/jailbreaking_runtime.yaml`
- `medusa/rules/agent_security/tool_attacks.yaml`
- `medusa/core/fp_filter.py`
