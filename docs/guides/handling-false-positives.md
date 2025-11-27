# Handling False Positives in MEDUSA

This guide shows you how to intelligently handle false positives (FPs) in MEDUSA scan results, reducing noise from 70+ findings to just the real issues.

## The Problem

Security scanners like Bandit use pattern matching, which can flag legitimate code as vulnerable. For example:

- A CLI tool that uses `subprocess` to run commands
- A test file using `assert` statements
- A `.env.example` file with placeholder values

These are **false positives** - they match a pattern but aren't actual vulnerabilities.

## Quick Solution: .bandit Config

Create a `.bandit` file in your project root:

```yaml
# .bandit - Bandit configuration for this project
skips:
  - B404  # import subprocess - legitimate for CLI tools
  - B603  # subprocess call - safe when not using shell=True
  - B607  # partial executable path - tools validated before use
  - B101  # assert in tests - standard pytest practice

exclude_dirs:
  - .venv
  - node_modules
  - dist
```

Then run MEDUSA again:

```bash
medusa scan .
```

## Understanding Common False Positives

### B404: Import Subprocess

**What triggers it:** `import subprocess`

**Why it's usually a FP:** CLI tools, installers, and build scripts legitimately need subprocess to run external commands.

**When it's real:** Never - importing subprocess isn't a vulnerability, only how you use it.

**Solution:** Add `B404` to `.bandit` skips.

---

### B603: Subprocess Call Without Shell

**What triggers it:** `subprocess.run(['cmd', 'arg'], ...)`

**Why it's usually a FP:** Using subprocess with a list of arguments (not `shell=True`) is the **safe** way to run commands.

**When it's real:** Never - this is the secure pattern.

**Solution:** Add `B603` to `.bandit` skips.

---

### B602: Shell=True

**What triggers it:** Any code containing `shell=` keyword

**Why it's often a FP:** Bandit triggers on `shell=variable` even when the variable isn't `True`. For example:
```python
shell=self._detect_shell()  # FP - this is an attribute assignment!
```

**When it's real:** `subprocess.run(cmd, shell=True)` with user-controlled input.

**Solution:** Review each B602 finding. If it's `shell=True` with hardcoded commands or attribute assignments, add `B602` to skips.

---

### B607: Partial Executable Path

**What triggers it:** `subprocess.run(['npm', 'install'])`

**Why it's usually a FP:** Using tool names without full paths is standard practice. The tools are found via PATH.

**When it's real:** Rarely - only if an attacker can modify PATH.

**Solution:** Add `B607` to `.bandit` skips.

---

### B101: Assert Statement

**What triggers it:** `assert something`

**Why it's usually a FP:** Assert statements in test files are standard pytest practice.

**When it's real:** Using assert for input validation in production code (asserts are stripped in optimized Python).

**Solution:** Add `B101` to `.bandit` skips for test-heavy projects.

---

### Secret Detection FPs

**What triggers it:** Patterns matching API keys in `.env.example` files

**Why it's a FP:** Example/template files contain placeholders like:
```
API_KEY=your-api-key-here
SECRET=xxxxxxxxxxxxxxxx
```

**When it's real:** Actual high-entropy strings that look like real tokens.

**Solution:** Add `.env.example` patterns to `.medusa.yml` exclude:
```yaml
exclude:
  files:
    - "*.example"
    - ".env.example"
```

## Real Issues to Always Fix

These are **never** false positives:

| Issue | Example | Why It's Dangerous |
|-------|---------|-------------------|
| shell=True + user input | `subprocess.run(user_cmd, shell=True)` | Command injection |
| SQL concatenation | `f"SELECT * FROM users WHERE id={user_id}"` | SQL injection |
| eval/exec + external data | `eval(request.data)` | Code execution |
| Real API keys | `sk-proj-abc123...` (high entropy) | Credential leak |
| Hardcoded passwords | `password = "admin123"` | Credential leak |

## Step-by-Step Triage Process

### 1. Run Initial Scan

```bash
medusa scan .
```

### 2. Review Findings by Category

```bash
# View JSON report
cat .medusa/reports/medusa-scan-*.json | python -c "
import json, sys
d = json.load(sys.stdin)
for f in d['findings']:
    print(f\"{f['severity']}: {f['file'].split('/')[-1]}:{f['line']} - {f['issue'][:60]}\")
"
```

### 3. Identify Patterns

Group findings by rule ID (B404, B603, etc.). If you see 50+ subprocess findings in a CLI tool, that's a clear FP pattern.

### 4. Create .bandit Config

```yaml
# Start with common FPs for your project type
skips:
  - B404  # CLI tool uses subprocess
  - B603  # Safe subprocess usage
```

### 5. Re-scan and Verify

```bash
medusa scan .
```

You should see a dramatic reduction in findings.

### 6. Review Remaining Issues

The remaining issues are likely real. Fix them or document why they're acceptable.

## Project-Specific Configurations

### CLI Tools / Build Scripts

```yaml
skips:
  - B404  # import subprocess
  - B603  # subprocess without shell
  - B607  # partial path
  - B602  # shell=True (if audited)
```

### Web Applications

```yaml
skips:
  - B101  # assert in tests
# Keep SQL and XSS checks enabled!
```

### Test-Heavy Projects

```yaml
skips:
  - B101  # assert statements
  - B105  # hardcoded passwords in test fixtures
```

## Using AI for Triage

MEDUSA integrates with AI IDEs (Claude Code, Gemini, Copilot) that can intelligently triage findings. When you run `medusa init`, it creates context files that teach the AI:

- Which patterns are typically FPs
- Which issues are real and need fixing
- How to create appropriate `.bandit` configs

## Best Practices

1. **Never blindly suppress** - Understand each finding before skipping
2. **Document your skips** - Add comments explaining why each rule is skipped
3. **Review periodically** - As code changes, FP patterns may change
4. **Keep real checks enabled** - Don't skip SQL injection or XSS checks
5. **Use project-wide config** - `.bandit` file is better than inline `# nosec` comments

## Example: Before and After

**Before (72 findings):**
```
CRITICAL: 0, HIGH: 2, MEDIUM: 70, LOW: 0
- 65 subprocess warnings (FPs in CLI tool)
- 2 assert warnings (FPs in tests)
- 2 YAML formatting (real - fixed)
- 2 shell=True (1 FP, 1 real but audited)
- 1 .env secret (local dev file)
```

**After .bandit config (2 findings):**
```
CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 0
- 1 .env secret (expected - gitignored)
- 1 shell=True FP (attribute assignment)
```

**Result:** 97% noise reduction, only real issues remain.

## Further Reading

- [Bandit Documentation](https://bandit.readthedocs.io/)
- [MEDUSA Configuration Guide](../configuration.md)
- [IDE Integration Guide](./ide-integration.md)
