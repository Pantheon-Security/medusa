# medusa ask - Natural Language Security Queries

Ask Gemini security questions about your codebase using natural language.

## Usage

```bash
medusa ask "<your security question>"
```

## Example Questions

### General Security Assessment
```bash
medusa ask "What are my most critical security issues?"
medusa ask "Is my application secure?"
medusa ask "What should I fix first?"
medusa ask "Give me a security summary"
```

### Specific Vulnerabilities
```bash
medusa ask "Do I have any SQL injection vulnerabilities?"
medusa ask "Where are my XSS risks?"
medusa ask "Are there hardcoded secrets in the code?"
medusa ask "Do I have authentication issues?"
```

### Code-Specific Questions
```bash
medusa ask "Is auth.py secure?"
medusa ask "What's wrong with the login function?"
medusa ask "Should I worry about the B608 warning?"
medusa ask "Is this SQL injection real or false positive?"
```

### Fix Guidance
```bash
medusa ask "How do I fix the XSS in views.py?"
medusa ask "What's the secure way to handle user input?"
medusa ask "How should I store passwords?"
medusa ask "Best practices for API authentication?"
```

### Architecture Questions
```bash
medusa ask "Where is user input validated?"
medusa ask "How is authentication implemented?"
medusa ask "What security controls are in place?"
medusa ask "Which files handle sensitive data?"
```

## How It Works

1. **Context Loading** - Reads latest scan results
2. **Intelligent Search** - Finds related code and findings
3. **AI Analysis** - Gemini examines codebase
4. **Smart Response** - Plain English with code references

## Example Interaction

```bash
$ medusa ask "Do I have SQL injection vulnerabilities?"

🔍 Analyzing SQL injection risks in your codebase...

Found 3 potential SQL injection vulnerabilities:

1. ❌ CRITICAL: api/users.py:156
   ```python
   query = f"SELECT * FROM users WHERE username = '{username}'"
   ```
   **Issue:** Using f-strings with user input
   **Risk:** Attacker can inject: `' OR '1'='1' --`
   **Fix:** Use parameterized queries

2. ⚠️ HIGH: api/posts.py:89
   ```python
   db.query("SELECT * FROM posts WHERE id = " + post_id)
   ```
   **Issue:** String concatenation with input
   **Risk:** Numeric SQL injection possible
   **Fix:** Use %s parameter marker

3. ✅ FALSE POSITIVE: api/comments.py:45
   ```python
   db.execute("SELECT * FROM comments WHERE id = %s", (id,))
   ```
   **Status:** Already using parameterized query - SECURE ✓

📊 Summary:
- 2 real SQL injection vulnerabilities (CRITICAL/HIGH)
- 1 false positive (already secure)
- Recommendation: Fix api/users.py and api/posts.py immediately

💡 Next Steps:
1. Run: medusa fix B201 (secure code generation)
2. Review all database queries for similar patterns
3. Consider using an ORM (SQLAlchemy, Django ORM)
```

## Interactive Mode

For multi-turn conversations:

```bash
$ medusa ask --interactive

🤖 MEDUSA Security Assistant (powered by Gemini)
Type 'exit' to quit, 'help' for commands

You: What are my critical security issues?

Gemini: Found 3 critical issues:
1. SQL Injection in api/users.py:156
2. Hardcoded password in config/db.py:22
3. XSS in views/profile.py:89

You: Tell me more about the SQL injection

Gemini: The SQL injection in api/users.py occurs because...
[detailed explanation]

You: How do I fix it?

Gemini: Here's a secure fix:
[code example with explanation]

You: Can you show me test cases?

Gemini: Here are 3 test cases to verify the fix:
[test code examples]

You: exit

Goodbye!
```

## Options

```bash
# Interactive mode
medusa ask --interactive

# Save conversation to file
medusa ask "question" -o conversation.txt

# JSON output
medusa ask "question" --format json

# Verbose mode (show reasoning)
medusa ask "question" --verbose

# Search specific directory
medusa ask "question" --path src/
```

## Best Practices

**DO:**
- ✅ Ask specific questions
- ✅ Reference file names or finding IDs
- ✅ Ask for explanations and fixes
- ✅ Use for security learning

**DON'T:**
- ❌ Ask non-security questions
- ❌ Expect code generation (use `medusa fix` for that)
- ❌ Ask about non-scanned files
- ❌ Rely solely on AI (always verify)

## Configuration

`.gemini/config.yaml`:

```yaml
medusa:
  commands:
    ask:
      enabled: true
      interactive_mode: true
      max_context_files: 10
      include_scan_results: true
```

## Privacy Note

Your code and security findings are sent to Gemini API for analysis.
For sensitive projects, consider:
- Self-hosted models
- Using traditional `medusa scan` without AI
- Setting `privacy_mode: true` in config

## Cost Estimate

Using Gemini API (50-70% cheaper than alternatives):
- Simple queries: ~$0.005-0.01
- Complex analysis: ~$0.015-0.025
- Deep codebase review: ~$0.05-0.10
- Interactive sessions: ~$0.10-0.20

## See Also

- `medusa ai-explain` - Detailed vulnerability explanations
- `medusa fix` - Generate secure code fixes
- `medusa ai-review` - Full AI security review
