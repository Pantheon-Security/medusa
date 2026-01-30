# Repo Analysis: DamnVulnerableLLMProject

**Date:** 2026-01-24
**Before Rule Fixes:** 20 findings, ~70% FALSE POSITIVE rate
**After Rule Fixes:** 8 findings, 87-100% TRUE POSITIVE rate

---

## Final Verified Findings

| File | Line | Severity | Issue | Verdict |
|------|------|----------|-------|---------|
| process.py | 19 | MEDIUM | Shell=True with user input | TRUE POSITIVE |
| process.py | 31 | MEDIUM | File open with filepath variable | BORDERLINE |
| process.py | 73 | CRITICAL | pickle.load() | TRUE POSITIVE |
| server.py | 15 | CRITICAL | pickle.load() | TRUE POSITIVE |
| server.py | 26 | MEDIUM | API without rate limiting | TRUE POSITIVE |
| server.py | 30 | MEDIUM | API without rate limiting | TRUE POSITIVE |
| server.py | 66 | LOW | Localhost binding (0.0.0.0) | TRUE POSITIVE |
| server.py | 66 | MEDIUM | Insecure transport | TRUE POSITIVE |

---

## Rules Fixed During Analysis

### 1. Command Injection (agent_patterns.yaml)
**Problem:** Pattern `os\.system\s*\(` matched ALL os.system calls including hardcoded strings like `os.system('clear')`

**Fix:** Changed to only match with user input indicators:
- `os\.system\s*\([^)]*\+` (concatenation)
- `os\.system\s*\(\s*f["']` (f-string)
- `os\.system\s*\([^)]*\.format\s*\(` (format)
- `os\.system\s*\(\s*\w+\s*\)` (variable)

### 2. Glob Patterns (mcp_server_patterns.yaml)
**Problem:** Pattern `glob\s*\([^)]*["\'][*]` matched all glob calls with wildcards

**Fix:** Changed to only match with user input:
- `glob\s*\(\s*f["']` (f-string)
- `glob\s*\([^)]*\+` (concatenation)
- `glob\s*\(\s*[a-z_]\w+\s*\)` (variable)

### 3. Path Traversal F-string (mcp_server_patterns.yaml)
**Problem:** Pattern `f["\'][^"\']*\{(file_?path|path|filename|input)` matched ANY f-string with `path` variable, including print statements

**Fix:** Changed to only match in file operation context:
- `open\s*\(\s*f["\'][^"\']*\{`
- `Path\s*\(\s*f["\'][^"\']*\{`
- `(read|write)File(Sync)?\s*\(\s*f["\']`

### 4. pickle.dump() (mcp_server_scanner.py)
**Problem:** Pattern flagged pickle.dump() as dangerous

**Fix:** Removed - creating pickles is safe, only loading them is dangerous

---

## False Positives Eliminated

| Original Line | Original Issue | Reason for FP |
|---------------|----------------|---------------|
| main.py:23,43,54,57 | subprocess with shell=True | `os.system('clear')` - hardcoded string |
| process.py:39 | Glob pattern enumeration | Hardcoded path `Path("training/facts/")` |
| process.py:66 | pickle.dump() | Creating pickles is safe |
| process.py:97 | Path traversal f-string | `print(f"...")` - not a file operation |

---

## Remaining Real Vulnerabilities

1. **RCE via Shell Injection (CRITICAL)**
   - process.py:19 - User input flows directly to subprocess
   - Flow: `input()` → `execute_commands()` → `subprocess.check_output(shell=True)`

2. **Unsafe Deserialization (CRITICAL)**
   - process.py:73, server.py:15 - pickle.load() can execute arbitrary code

3. **Missing Rate Limiting (MEDIUM)**
   - server.py:26,30 - API endpoints have no rate limiting

4. **Network Exposure (MEDIUM)**
   - server.py:66 - Bound to 0.0.0.0 without HTTPS

---

*Analysis complete - Rule fixes applied*
