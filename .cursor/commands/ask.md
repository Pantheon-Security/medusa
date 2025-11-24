# MEDUSA Ask - Natural Language Security Queries

Ask Claude security questions about your codebase using natural language.

## Usage

```bash
@medusa ask "<your security question>"
```

In Cursor chat, just type:
```
@medusa ask "Do I have SQL injection vulnerabilities?"
```

## Example Questions

### General Security Assessment
```bash
@medusa ask "What are my most critical security issues?"
@medusa ask "Is my application secure?"
@medusa ask "What should I fix first?"
@medusa ask "Give me a security summary"
```

### Specific Vulnerabilities
```bash
@medusa ask "Do I have any SQL injection vulnerabilities?"
@medusa ask "Where are my XSS risks?"
@medusa ask "Are there hardcoded secrets in the code?"
@medusa ask "Do I have authentication issues?"
```

### Code-Specific Questions
```bash
@medusa ask "Is auth.py secure?"
@medusa ask "What's wrong with the login function?"
@medusa ask "Should I worry about the B608 warning?"
@medusa ask "Is this SQL injection real or false positive?"
```

### Fix Guidance
```bash
@medusa ask "How do I fix the XSS in views.py?"
@medusa ask "What's the secure way to handle user input?"
@medusa ask "How should I store passwords?"
@medusa ask "Best practices for API authentication?"
```

### Architecture Questions
```bash
@medusa ask "Where is user input validated?"
@medusa ask "How is authentication implemented?"
@medusa ask "What security controls are in place?"
@medusa ask "Which files handle sensitive data?"
```

## How It Works

1. **Context Loading**
   - Reads latest MEDUSA scan results
   - Indexes codebase structure
   - Identifies relevant files

2. **Intelligent Search**
   - Finds related code and findings
   - Gathers security context
   - Loads relevant documentation

3. **AI Analysis**
   - Claude analyzes your question
   - Searches through scan results
   - Examines actual source code
   - Provides contextual answer

4. **Smart Response**
   - Plain English explanation
   - File:line references
   - Code snippets
   - Fix suggestions

## Example Interaction

```
You: @medusa ask "Do I have SQL injection vulnerabilities?"

Claude:
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
1. Run `@medusa fix B201` for secure code fixes
2. Review all database queries for similar patterns
3. Consider using an ORM (SQLAlchemy, Django ORM)
```

## Best Practices

**DO:**
- ✅ Ask specific questions
- ✅ Reference file names or finding IDs
- ✅ Ask for explanations and fixes
- ✅ Use for security learning

**DON'T:**
- ❌ Ask non-security questions
- ❌ Expect code generation (use `@medusa fix` for that)
- ❌ Ask about non-scanned files
- ❌ Rely solely on AI (always verify fixes)

## Configuration

Requires AI analysis enabled in `.medusa.yml`:

```yaml
ide:
  cursor:
    enabled: true
    ai_analysis:
      enabled: true
      natural_language_queries: true
```

Or in `.cursor/settings.json`:

```json
{
  "medusa": {
    "aiAnalysis": {
      "enabled": true,
      "features": {
        "naturalLanguageQueries": true
      }
    }
  }
}
```

## Privacy Note

Your code and security findings are sent to Claude API for analysis.
For sensitive projects, consider:
- Self-hosted Claude (if available)
- Using traditional `medusa scan` without AI
- Reviewing privacy settings in `.medusa.yml`

## Cost Estimate

Typical costs per question:
- Simple queries: ~$0.01-0.02
- Complex analysis: ~$0.03-0.05
- Deep codebase review: ~$0.10-0.15

These are approximations and may vary based on:
- Project size
- Question complexity
- Amount of code analyzed
