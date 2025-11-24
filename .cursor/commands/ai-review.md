# MEDUSA AI Security Review

Run intelligent security scan with AI-powered false positive filtering and explanations.

## What This Does

1. **Fast Traditional Scan** - Runs all 43+ MEDUSA scanners (5-10 seconds)
2. **AI Analysis** - Claude analyzes each finding for false positives
3. **Smart Filtering** - Removes low-confidence issues (<70% confidence)
4. **Contextual Explanations** - Explains WHY code is vulnerable
5. **Fix Suggestions** - Provides secure code alternatives

## Usage

```bash
@medusa ai-review
```

In Cursor chat, just type:
```
@medusa ai-review
```

## Output

```
✅ Scanned 1,247 files with 43+ analyzers (6.3s)
🤖 AI analyzed 52 findings...

📊 Security Analysis Results:

CRITICAL (3 issues - 100% confidence):
  1. [B201] SQL Injection in api/users.py:156
     └─ Using string formatting with user input
     └─ Fix: Use parameterized queries

  2. [B608] Hardcoded Password in config/db.py:22
     └─ Database credentials in source code
     └─ Fix: Use environment variables

  3. [CWE-79] XSS Vulnerability in views/profile.py:89
     └─ Unescaped user input in template
     └─ Fix: Use auto-escaping template engine

HIGH (2 issues - 85% confidence):
  4. [B104] Weak Binding in server.py:45
     └─ Server binds to 0.0.0.0 (all interfaces)
     └─ Consider: Bind to localhost only

  5. [B603] subprocess.call without shell=False
     └─ Potential command injection risk
     └─ Fix: Use subprocess.run with list args

✅ Filtered 47 false positives:
  - 23 test file warnings (expected in tests)
  - 12 example code (not production)
  - 8 properly sanitized inputs
  - 4 library code (out of scope)

💡 AI Confidence Legend:
  100% = Definitely vulnerable
  85-99% = Very likely vulnerable
  70-84% = Probably vulnerable
  <70% = Likely false positive (filtered)
```

## Next Steps

- Review critical/high findings: `@medusa ai-explain <id>`
- Get secure fixes: `@medusa fix <id>`
- Ask questions: `@medusa ask "question"`
- Dismiss false positives: Run `medusa dismiss <id>` in terminal

## How It Works

1. **Traditional Scan**: MEDUSA runs bandit, eslint, shellcheck, etc.
2. **Context Gathering**: Reads surrounding code for each finding
3. **AI Analysis**: Claude evaluates:
   - Is this production code or test/example?
   - Is user input properly sanitized?
   - Are there mitigating controls?
   - What's the actual exploit scenario?
4. **Confidence Scoring**: 0-100% based on analysis
5. **Smart Filtering**: Remove <70% confidence findings
6. **Explanation Generation**: Plain English vulnerability descriptions

## Configuration

Edit `.medusa.yml` to customize:

```yaml
ide:
  cursor:
    enabled: true
    ai_analysis:
      enabled: true
      confidence_threshold: 0.7  # 70%
      explain_findings: true
      suggest_fixes: true
      filter_test_files: true
```

Or use `.cursor/settings.json`:

```json
{
  "medusa": {
    "aiAnalysis": {
      "enabled": true,
      "confidenceThreshold": 0.7,
      "features": {
        "falsePositiveDetection": true,
        "contextualExplanations": true
      }
    }
  }
}
```

## Cost Note

AI analysis uses Claude API (or local if configured). Typical costs:
- Small project (50 findings): ~$0.10
- Medium project (200 findings): ~$0.40
- Large project (500 findings): ~$1.00

To skip AI and just run traditional scan:
```bash
medusa scan .
```

Or in Cursor terminal:
```
@medusa scan
```
