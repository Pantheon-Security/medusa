# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.9.x   | :white_check_mark: |
| < 0.9   | :x:                |

## Reporting a Vulnerability

**Please DO NOT file public GitHub issues for security vulnerabilities.**

We take security seriously at Pantheon Security. If you discover a security vulnerability in MEDUSA, please report it to us privately.

### How to Report

**Email**: security@pantheonsecurity.io

**PGP Key**: Coming soon

### What to Include

Please include the following information in your report:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Any suggested fixes (optional)
- Your name/handle for acknowledgment (optional)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - **Critical**: 1-7 days
  - **High**: 7-30 days  
  - **Medium**: 30-90 days
  - **Low**: Best effort

### Disclosure Policy

- We request that you give us reasonable time to fix the issue before public disclosure
- We will acknowledge your contribution in our security advisories (unless you prefer to remain anonymous)
- We may provide a CVE if the issue warrants one

## Security Updates

To receive security updates:

1. Watch this repository on GitHub (Releases only)
2. Subscribe to our security mailing list (coming soon)
3. Follow [@PantheonSec](https://twitter.com/PantheonSec) on Twitter

## Supported Features

MEDUSA scans code for security issues but does not:
- Execute code from scanned projects
- Send data to external servers (all scanning is local)
- Require network access (except for tool installation)

## Known Limitations

- MEDUSA relies on external security tools (listed in `tool-versions.lock`)
- We cannot guarantee 100% accuracy (false positives/negatives may occur)
- Tool versions are pinned for reproducibility but may lag behind latest versions

## Security Best Practices

When using MEDUSA:

1. **Keep MEDUSA updated** to the latest version
2. **Review scan results** - don't blindly trust all findings
3. **Use pinned tool versions** for production CI/CD
4. **Report false positives** to help us improve

## Bug Bounty

We currently do not offer a bug bounty program but deeply appreciate responsible disclosure.

---

**Last Updated**: 2024-11-16  
**Contact**: security@pantheonsecurity.io
