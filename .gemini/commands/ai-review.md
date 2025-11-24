# medusa ai-review - AI Security Review

Run intelligent security scan with AI-powered false positive filtering and explanations.

## Usage

```bash
medusa ai-review [options]
```

## What This Does

1. **Fast Traditional Scan** - Runs all 43+ MEDUSA scanners (5-10 seconds)
2. **AI Analysis** - Gemini analyzes each finding for false positives
3. **Smart Filtering** - Removes low-confidence issues (<70% confidence)
4. **Contextual Explanations** - Explains WHY code is vulnerable
5. **Fix Suggestions** - Provides secure code alternatives

## Example Output

```bash
$ medusa ai-review

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

💡 Next Steps:
  - Explain finding: medusa ai-explain B201
  - Generate fix: medusa fix B201
  - Ask question: medusa ask "your question"
```

## Options

```bash
# Scan specific directory
medusa ai-review src/

# Adjust confidence threshold
medusa ai-review --confidence 0.8

# Save report to file
medusa ai-review -o .medusa/ai-report.json

# Verbose output
medusa ai-review --verbose

# Quiet mode (only show issues)
medusa ai-review --quiet
```

## How It Works

1. **Traditional Scan**: Runs bandit, eslint, shellcheck, etc.
2. **Context Gathering**: Reads surrounding code for each finding
3. **AI Analysis**: Gemini evaluates:
   - Is this production code or test/example?
   - Is user input properly sanitized?
   - Are there mitigating controls?
   - What's the actual exploit scenario?
4. **Confidence Scoring**: 0-100% based on analysis
5. **Smart Filtering**: Remove <70% confidence findings
6. **Explanation Generation**: Plain English vulnerability descriptions

## Configuration

`.gemini/config.yaml`:

```yaml
medusa:
  ai_analysis:
    enabled: true
    provider: google
    model: gemini-pro
    confidence_threshold: 0.7
    features:
      false_positive_detection: true
      contextual_explanations: true
```

## Cost Estimate

Using Gemini API (50-70% cheaper than Claude):
- Small project (50 findings): ~$0.05-0.08
- Medium project (200 findings): ~$0.20-0.30
- Large project (500 findings): ~$0.50-0.75

To skip AI and use traditional scan:
```bash
medusa scan
```

## Compare with Traditional Scan

```bash
# Traditional scan (fast, high FP rate)
medusa scan

# AI review (slower, <15% FP rate)
medusa ai-review
```

**Traditional scan:** 52 findings (91% FP rate)
**AI review:** 5 findings (100% real vulnerabilities)

## See Also

- `medusa ai-explain` - Explain specific finding
- `medusa fix` - Generate secure code fix
- `medusa ask` - Natural language queries
