# medusa ai-explain - Explain Security Finding

Get detailed explanation of a specific security finding with context and fix suggestions.

## Usage

```bash
medusa ai-explain <finding-id>
```

## Examples

```bash
# Explain Bandit finding B201
medusa ai-explain B201

# Explain ESLint finding
medusa ai-explain no-eval

# Explain by file:line
medusa ai-explain auth.py:156

# Explain with full code context
medusa ai-explain B201 --context=full
```

## What You Get

Gemini analyzes the finding and provides:

1. **Vulnerability Explanation** - Plain English description
2. **Code Context Analysis** - Reads actual code
3. **Risk Assessment** - Exploitability + impact
4. **Secure Fix** - Before/after comparison
5. **References** - OWASP/CWE links

## Example Output

```bash
$ medusa ai-explain B201

🔍 Analyzing Finding: B201 (SQL Injection)

📍 Location: api/users.py:156

📄 Vulnerable Code:
```python
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)
```

⚠️ Vulnerability: SQL Injection (CWE-89)

**What's Wrong:**
This code uses Python f-strings to construct an SQL query with
user input (`username`). An attacker can inject malicious SQL
by providing input like: `' OR '1'='1' --`

**Attack Scenario:**
```python
# Attacker input:
username = "admin' OR '1'='1' --"

# Resulting query:
"SELECT * FROM users WHERE username = 'admin' OR '1'='1' --'"
# This returns ALL users, bypassing authentication
```

**Risk Level:** CRITICAL
- Exploitability: High (easy to exploit)
- Impact: Critical (full database access)
- Scope: All user accounts at risk

✅ Secure Fix:
```python
def get_user(username):
    # Use parameterized query (prepared statement)
    query = "SELECT * FROM users WHERE username = %s"
    return db.execute(query, (username,))

    # Alternative: Use ORM
    return User.query.filter_by(username=username).first()
```

**Why This Works:**
Parameterized queries keep SQL and data separate. The database
driver handles escaping automatically, making injection impossible.

📚 References:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- Python DB-API 2.0: https://peps.python.org/pep-0249/

💡 Next Steps:
1. Apply the secure fix above
2. Run: medusa fix B201 (automated fix generation)
3. Verify: medusa scan api/users.py
```

## Options

```bash
# Show more code context
medusa ai-explain B201 --context=full

# Interactive mode (ask follow-up questions)
medusa ai-explain B201 --interactive

# Save explanation to file
medusa ai-explain B201 -o explanation.md

# Output as JSON
medusa ai-explain B201 --format json
```

## False Positive Detection

If Gemini determines it's a false positive:

```bash
$ medusa ai-explain B201

🔍 Analysis: B201 (SQL Injection)

✅ FALSE POSITIVE

**Why This Is Safe:**
Your code at api/users.py:156 already uses parameterized
queries correctly:

```python
db.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

The `%s` placeholder is NOT Python string formatting - it's
PostgreSQL's parameter marker. The database driver handles
this securely.

**Recommendation:**
This is a scanner false positive. You can safely dismiss it.

💡 To suppress this warning:
echo "B201:api/users.py:156" >> .medusa/.medusaignore
```

## Configuration

`.gemini/config.yaml`:

```yaml
medusa:
  commands:
    ai_explain:
      enabled: true
      show_full_context: true
      include_references: true
      interactive_mode: false
```

## Cost Estimate

Using Gemini API:
- Simple explanation: ~$0.005-0.01
- Complex analysis: ~$0.015-0.025
- Full context mode: ~$0.025-0.05

## See Also

- `medusa fix` - Generate automated secure fix
- `medusa ask` - Ask natural language questions
- `medusa ai-review` - Full AI security review
