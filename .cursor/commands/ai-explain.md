# MEDUSA AI Explain

Get detailed explanation of a specific security finding with context and fix suggestions.

## Usage

```bash
@medusa ai-explain <finding-id>
```

## Examples

```bash
# Explain Bandit finding B201
@medusa ai-explain B201

# Explain ESLint finding
@medusa ai-explain no-eval

# Explain by line number
@medusa ai-explain auth.py:156
```

## What You Get

Claude will analyze the finding and provide:

1. **Vulnerability Explanation**
   - What the issue is in plain English
   - Why it's dangerous
   - Common attack scenarios

2. **Code Context Analysis**
   - Reads your actual code
   - Identifies the vulnerable pattern
   - Checks for mitigating controls

3. **Risk Assessment**
   - Severity justification
   - Exploitability assessment
   - Impact analysis

4. **Secure Fix**
   - Before/after code comparison
   - Step-by-step fix instructions
   - Best practice recommendations

5. **References**
   - OWASP guidelines
   - CWE/CVE references
   - Security documentation

## Example Output

```
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
2. Audit other database queries in the codebase
3. Consider adding input validation
4. Run `@medusa scan` to verify fix
```

## For False Positives

If Claude determines it's a false positive:

```
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

**To prevent this warning:**
Add a comment for other developers:
```python
# Using DB-API parameterized query (secure)
db.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```
```

## Integration

Works with scan results from:
- `@medusa ai-review` (AI-powered scan)
- `medusa scan` (traditional scan in terminal)
- Reads from `.medusa/reports/*.json`

## Privacy Note

Your code snippet (10-20 lines around the finding) is sent to Claude API for analysis.
For sensitive projects, consider:
- Self-hosted Claude (if available)
- Using traditional `medusa scan` without AI
- Reviewing privacy settings in `.medusa.yml`

## Cost Estimate

Typical costs per explanation:
- Simple vulnerability: ~$0.01-0.02
- Complex analysis: ~$0.03-0.05
- Deep codebase context: ~$0.05-0.10
