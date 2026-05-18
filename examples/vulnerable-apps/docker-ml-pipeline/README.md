# Vulnerable Docker ML Pipeline

**DO NOT DEPLOY — intentionally vulnerable for MEDUSA demonstration.**

## Vulnerabilities Present

### Dockerfile Issues

| # | Category | Issue |
|---|----------|-------|
| 1 | Unpinned Base Image | `python:latest` — not reproducible |
| 2 | Running as Root | No `USER` directive |
| 3 | Hardcoded Secrets | AWS keys and tokens as build ARGs (visible in history) |
| 4 | Insecure pip | `--trusted-host` bypasses TLS verification |
| 5 | Secrets in Image | `.env` and `credentials.json` copied into layers |

### Docker Compose Issues

| # | Category | Issue |
|---|----------|-------|
| 6 | Privileged Container | `privileged: true` — host escape |
| 7 | Docker Socket Mount | Container can control host Docker daemon |
| 8 | Host FS Mount | `/:/host-root` exposes entire host filesystem |
| 9 | No Auth on Services | Jupyter (no token), Redis (no password), ChromaDB, MLflow |
| 10 | Exposed Ports | Services bound to `0.0.0.0` — accessible from network |
| 11 | No Resource Limits | Containers can consume all host resources |
| 12 | Hardcoded API Keys | OpenAI, HuggingFace, W&B keys in environment |

### Model Serving Issues

| # | Category | Issue |
|---|----------|-------|
| 13 | Unsafe Deserialization | `pickle.load` on model files (RCE) |
| 14 | SSRF | Arbitrary URL model loading |
| 15 | Code Execution | `exec()` on user-provided eval code |

## Scan This Example

```bash
medusa scan examples/vulnerable-apps/docker-ml-pipeline/
```

## Key Lessons

1. **ML model files are code** — pickle/joblib models can execute arbitrary code on load
2. **Docker privileged + socket = game over** — container escape is trivial
3. **Internal services need auth too** — Jupyter, Redis, MLflow all need access control
4. **Secrets in Docker layers persist** — use multi-stage builds and runtime secrets
