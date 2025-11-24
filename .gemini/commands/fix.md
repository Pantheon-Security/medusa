# medusa fix - Generate Secure Code Fix

Get AI-generated secure code fixes for specific security vulnerabilities.

## Usage

```bash
medusa fix <finding-id> [options]
```

## Examples

```bash
# Fix specific scanner finding
medusa fix B201
medusa fix no-eval
medusa fix CWE-89

# Fix by file:line
medusa fix auth.py:156

# Interactive fix (asks questions)
medusa fix B608 --interactive

# Auto-apply fix with backup
medusa fix B201 --apply --backup

# Preview only (no changes)
medusa fix B201 --dry-run
```

## What This Generates

1. **Vulnerability Analysis** - What's wrong + attack scenarios
2. **Secure Code Alternative** - Drop-in replacement
3. **Before/After Comparison** - Side-by-side view
4. **Testing Guidance** - Test cases to verify fix
5. **Best Practices** - Additional recommendations

## Example Output

```bash
$ medusa fix B201

🔧 Generating Secure Fix for: B201 (SQL Injection)

📍 Location: api/users.py:156-158

❌ VULNERABLE CODE:
```python
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)
```

**Problem:**
- Using f-string with untrusted input
- No input validation or escaping
- Direct SQL string construction

**Attack Example:**
```python
username = "admin' OR '1'='1' --"
# Results in: SELECT * FROM users WHERE username = 'admin' OR '1'='1' --'
# Returns all users!
```

---

✅ SECURE FIX:
```python
def get_user(username):
    """
    Retrieve user by username using parameterized query.

    Security: Uses DB-API parameter substitution to prevent SQL injection.
    The database driver handles escaping automatically.
    """
    # Option 1: Parameterized query (RECOMMENDED)
    query = "SELECT * FROM users WHERE username = %s"
    return db.execute(query, (username,))

    # Option 2: ORM (even better)
    # return User.query.filter_by(username=username).first()
```

**Why This Fix Works:**
1. ✅ Database driver handles parameter escaping
2. ✅ SQL structure is fixed at compile time
3. ✅ User input is treated as pure data, not code
4. ✅ Injection becomes impossible

**Changes Made:**
- Replaced f-string with %s parameter marker
- Added tuple with parameters: (username,)
- Added security-focused docstring
- Included ORM alternative as best practice

---

🧪 TESTING YOUR FIX:

**Test Case 1: Normal Input**
```python
result = get_user("john_doe")
assert result['username'] == 'john_doe'
```

**Test Case 2: SQL Injection Attempt (should fail safely)**
```python
# This should return None, NOT all users
result = get_user("admin' OR '1'='1' --")
assert result is None or result['username'] != 'admin'
```

**Test Case 3: Special Characters**
```python
# Should handle quotes and special chars safely
result = get_user("O'Brien")
assert result['username'] == "O'Brien"
```

---

📚 ADDITIONAL SECURITY RECOMMENDATIONS:

1. **Input Validation** (Defense in Depth)
   ```python
   import re

   def validate_username(username):
       if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
           raise ValueError("Invalid username format")
       return username

   def get_user(username):
       username = validate_username(username)
       query = "SELECT * FROM users WHERE username = %s"
       return db.execute(query, (username,))
   ```

2. **Use an ORM** (Best Practice)
   ```python
   from sqlalchemy.orm import Session
   from models import User

   def get_user(username: str, db: Session):
       return db.query(User).filter(User.username == username).first()
   ```

3. **Audit All Queries**
   ```bash
   grep -r "f\".*SELECT" .
   grep -r "query.*\\+" .
   ```

4. **Enable Query Logging**
   ```python
   import logging
   logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
   ```

---

✅ VERIFICATION:

After applying the fix:
1. Run tests: pytest tests/test_users.py
2. Run scan: medusa scan api/users.py
3. Expected: No B201 warning

---

📋 CHECKLIST:

- [ ] Applied secure code fix
- [ ] Added test cases
- [ ] Verified no B201 warning
- [ ] Audited similar code patterns
- [ ] Updated documentation
- [ ] Reviewed by security-aware teammate

💡 Apply this fix automatically?
    Run: medusa fix B201 --apply --backup
```

## Options

```bash
# Interactive mode (asks context questions)
medusa fix B608 --interactive

# Auto-apply fix
medusa fix B201 --apply

# Auto-apply with backup
medusa fix B201 --apply --backup

# Dry run (preview only)
medusa fix B201 --dry-run

# Multiple fix options
medusa fix B201 --show-alternatives

# Save fix to file
medusa fix B201 -o fix-b201.patch

# JSON output
medusa fix B201 --format json
```

## Interactive Mode

For complex fixes requiring context:

```bash
$ medusa fix B608 --interactive

🔧 Generating fix for B608 (Hardcoded Password)

Let me ask a few questions to provide the best fix:

1. What database are you using?
   [1] PostgreSQL [2] MySQL [3] SQLite [4] Other
   > 1

2. Are you using any environment variable management?
   [1] python-dotenv [2] os.environ [3] django-environ [4] None
   > 1

3. Do you need backward compatibility?
   [Y/n] n

4. Should I generate a .env.example file?
   [Y/n] y

Generating custom fix...

[Tailored fix based on your answers]
```

## Auto-Apply

```bash
# Preview first (recommended)
medusa fix B201

# Then apply with backup
medusa fix B201 --apply --backup

# Backup saved to: api/users.py.bak
# Fix applied to: api/users.py
# Verification: No B201 warning ✅
```

⚠️ **Warning:** Always review AI-generated fixes before applying!

## Configuration

`.gemini/config.yaml`:

```yaml
medusa:
  commands:
    fix:
      enabled: true
      create_backup: true
      require_confirmation: true
      show_alternatives: true
      generate_tests: true
```

## Limitations

**AI-Generated Fixes CAN:**
- ✅ Replace vulnerable patterns with secure alternatives
- ✅ Explain what changed and why
- ✅ Provide multiple fix options
- ✅ Generate test cases

**AI-Generated Fixes CANNOT:**
- ❌ Understand your entire application architecture
- ❌ Handle complex business logic automatically
- ❌ Replace human security review
- ❌ Guarantee 100% correctness

**Always:**
- Review generated code carefully
- Test thoroughly
- Have security-aware team member review
- Consider broader architectural implications

## Cost Estimate

Using Gemini API (50-70% cheaper than alternatives):
- Simple fix: ~$0.025-0.05
- Complex fix with tests: ~$0.075-0.125
- Interactive mode: ~$0.10-0.20

Still much cheaper than manual security consultation! 💰

## See Also

- `medusa ai-explain` - Understand the vulnerability first
- `medusa ask` - Ask questions about the fix
- `medusa scan` - Verify the fix worked
