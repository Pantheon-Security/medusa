# Vulnerable Flask LLM App

**DO NOT DEPLOY — intentionally vulnerable for MEDUSA demonstration.**

## Vulnerabilities Present

| # | Category | Location | MEDUSA Rule |
|---|----------|----------|-------------|
| 1 | Hardcoded Secrets | `app.py:22-24` | Secrets detection |
| 2 | Prompt Injection | `app.py:44-55` | Prompt injection (unsanitized user input to LLM) |
| 3 | SQL Injection | `app.py:72-74` | SQL injection via f-string |
| 4 | RAG Poisoning | `app.py:80-85` | RAG context injection without sanitization |
| 5 | Unsafe Deserialization | `app.py:110` | pickle.loads on untrusted data (RCE) |
| 6 | SSRF | `app.py:107` | Unvalidated URL fetch from user input |
| 7 | Code Injection | `app.py:122` | eval() on user-controlled input |
| 8 | Command Injection | `app.py:141` | os.system() with user-controlled args |
| 9 | Missing Auth | `app.py:128-133` | Admin endpoint without authentication |
| 10 | Debug in Production | `app.py:31` | Flask debug mode enabled |

## Scan This Example

```bash
medusa scan examples/vulnerable-apps/flask-llm-app/
```

## What You'll Learn

This example demonstrates why AI applications need specialized security scanning:

1. **Traditional SAST catches** (#3, #7, #8): SQL injection, eval, os.system
2. **AI-specific issues** (#2, #4): Prompt injection and RAG poisoning are invisible to traditional scanners
3. **Secrets management** (#1): API keys in source code
4. **ML pipeline risks** (#5, #6): Loading untrusted models enables RCE
