# MEDUSA Fix - AI-Generated Secure Code

Get AI-generated secure code fixes for specific security vulnerabilities.

## Usage

```bash
@medusa fix <finding-id>
```

In Cursor chat, type:
```
@medusa fix B201
```

## Examples

```bash
# Fix specific scanner finding
@medusa fix B201
@medusa fix no-eval
@medusa fix CWE-89

# Fix by file:line
@medusa fix auth.py:156

# Interactive fix (asks questions)
@medusa fix B608 --interactive
```

## What This Generates

1. **Vulnerability Analysis**
   - Current vulnerable code
   - What makes it insecure
   - Attack scenarios

2. **Secure Code Alternative**
   - Drop-in replacement code
   - Explanation of changes
   - Why the fix works

3. **Before/After Comparison**
   - Side-by-side code view
   - Highlighted changes
   - Comments explaining security improvements

4. **Testing Guidance**
   - How to test the fix
   - Edge cases to verify
   - Security test cases

5. **Best Practices**
   - Additional hardening recommendations
   - Related security patterns
   - Prevention strategies

## Example Output

```
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
       username = validate_username(username)  # Validate first
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
   Search for similar patterns:
   ```bash
   grep -r "f\".*SELECT" .
   grep -r "query.*\\+" .
   ```

4. **Enable Query Logging**
   ```python
   # In development, log all queries to catch mistakes
   import logging
   logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
   ```

---

✅ VERIFICATION:

After applying the fix:
1. Run unit tests: `pytest tests/test_users.py`
2. Run MEDUSA: `medusa scan api/users.py`
3. Expected: No B201 warning

---

📋 CHECKLIST:

- [ ] Applied secure code fix
- [ ] Added test cases
- [ ] Verified no B201 warning
- [ ] Audited similar code patterns
- [ ] Updated documentation
- [ ] Reviewed by security-aware teammate

💡 Run `@medusa scan` after applying fixes to verify!
```

## Interactive Mode

For complex fixes requiring context:

```bash
@medusa fix B608 --interactive
```

Claude will ask:
- What database are you using?
- What ORM (if any)?
- Performance requirements?
- Backward compatibility needed?

Then generates a custom fix for your specific situation.

## Apply Fix Automatically

```bash
# Preview fix first (recommended)
@medusa fix B201

# Auto-apply fix (be careful!)
@medusa fix B201 --apply

# Create backup before applying
@medusa fix B201 --apply --backup
```

⚠️ **Warning:** Always review AI-generated fixes before applying!

## Configuration

```yaml
ide:
  cursor:
    ai_analysis:
      auto_fix:
        enabled: true
        create_backup: true
        require_confirmation: true
```

Or in `.cursor/settings.json`:

```json
{
  "medusa": {
    "commands": {
      "@medusa fix": {
        "enabled": true,
        "createBackup": true,
        "requireConfirmation": true
      }
    }
  }
}
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

## Cost Note

Fix generation is more expensive than simple queries:
- Simple fix: ~$0.05-0.10
- Complex fix with tests: ~$0.15-0.25
- Interactive mode: ~$0.20-0.40

But still much cheaper than manual security consultation! 💰
