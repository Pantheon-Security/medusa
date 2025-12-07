# MEDUSA Scanner Documentation

Documentation for adding and maintaining MEDUSA scanners.

## Guides

| Document | Description |
|----------|-------------|
| [Adding New Linters](./ADDING_NEW_LINTERS.md) | Complete onboarding process for new linters |
| [Windows Linter Guide](./WINDOWS_LINTER_GUIDE.md) | Windows-specific installation and troubleshooting |

## Quick Links

- **Scanner code:** `medusa/scanners/`
- **Installer code:** `medusa/platform/installers/`
- **Version pins:** `medusa/tool-versions.lock`

## Current Scanner Count

MEDUSA has **64 scanners** covering:
- 42+ programming languages
- 18 AI/LLM security scanners
- CVE detection (React2Shell, Next.js vulnerabilities)
- Docker, Kubernetes, Terraform
- And more...

Run `medusa scanners` to see the full list.
