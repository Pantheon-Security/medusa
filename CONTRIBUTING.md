# Contributing to MEDUSA

Thank you for your interest in contributing to MEDUSA! We welcome contributions from the community.

## Ways to Contribute

- 🐛 **Bug Reports** - Found a bug? Open an issue
- ✨ **Feature Requests** - Have an idea? We'd love to hear it
- 📖 **Documentation** - Help improve our docs
- 🔧 **Code** - Submit a pull request
- 🧪 **Testing** - Help test on different platforms

## Getting Started

### Prerequisites

- Python 3.10+
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Pantheon-Security/medusa.git
cd medusa

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install in development mode
pip install -e ".[dev]"

# Verify installation
medusa --version
```

### Running Tests

```bash
pytest tests/ -v
```

### Code Style

We use standard Python conventions:

- Follow PEP 8
- Use type hints where practical
- Keep functions focused and small
- Write descriptive commit messages

## Submitting Changes

### For Bug Fixes

1. Open an issue describing the bug (if not already reported)
2. Fork the repository
3. Create a branch: `git checkout -b fix/issue-description`
4. Make your changes
5. Test your changes: `medusa scan .`
6. Submit a pull request

### For New Features

1. **Open an issue first** to discuss the feature
2. Wait for feedback before starting work
3. Fork and create a branch: `git checkout -b feat/feature-name`
4. Implement with tests
5. Submit a pull request

### For New Scanners

Adding a new language scanner? Great! Here's the pattern:

```python
# medusa/scanners/mylang_scanner.py
from medusa.scanners.base import BaseScanner, ScanResult

class MyLangScanner(BaseScanner):
    name = "MyLangScanner"
    tool = "mylang-lint"
    file_patterns = ["*.mylang"]

    def scan(self, file_path: str) -> list[ScanResult]:
        # Implementation
        pass
```

See existing scanners in `medusa/scanners/` for examples.

### Fixing a False Positive

A rule fired on benign code. There are **three** places to fix it, and picking the
wrong one either misses the fix or hides real detections. Use this decision tree:

```
Is the rule PATTERN itself wrong (too broad — bare acronym, missing \b, over-broad .*)?
│   e.g.  PLA|...  matching "temPLAte";  \.filename  matching every attribute access
├─ YES → EDIT THE RULE. Tighten the pattern (word boundaries, required context,
│        anchor the acronym). ReDoS-safe: bounded quantifiers only.
│        File: the rule's YAML under medusa/rules/<category>/
│
└─ NO — the pattern is correct, it matched a real construct that's benign HERE.
    │
    Does it fire because of the FILE / CODE class (an AI rule firing on non-AI code,
    a web rule on non-web code, a signature in a doc/comment)?
    ├─ YES → ADD/EXTEND A CONTEXT GATE. Gate the scanner on context.
    │        Files: medusa/scanners/_ml_context.py (AI/LLM context),
    │        _web_context.py (web code), _signature_context.py (docs/prose).
    │        (Harvested "mention" rules are already screening-only — see PR-013.)
    │
    └─ NO — pattern right, context right, this specific match is a known benign class
             (test fixtures, example placeholders, MEDUSA's own signatures).
         → ADD AN FP-FILTER ENTRY. File: medusa/core/fp_filter.py
             NEVER FP-filter a malice signal (CC-/MEDUSA-SKILL-/MCP-POISON-/TAINT-).
```

**Every FP fix MUST be two-sided and benchmark-verified:**

1. Show the benign case no longer fires (add a test).
2. Show a crafted **true positive** for the rule's real intent STILL fires (add a test).
3. `python3 -m pytest tests/test_regression.py -q -o addopts=""` — the native benchmark
   (354) must not drop a real detection. If it moves, you dropped a corpus true positive
   — do **not** re-baseline around it; fix the fix.

New detection rules must also pass the corpus lint gate (`tests/test_rule_corpus_lint.py`):
no bare short-acronym alternates, `file_types` on harvested rules, CRITICAL only on
curated provenance.

## Pull Request Guidelines

- Keep PRs focused on a single change
- Update documentation if needed
- Add tests for new functionality
- Ensure all tests pass
- Follow existing code style

### PR Title Format

```
type: brief description

Examples:
- fix: Resolve false positive in Python scanner
- feat: Add Ruby scanner support
- docs: Update installation guide
- chore: Update dependencies
```

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## Questions?

- Open a [Discussion](https://github.com/Pantheon-Security/medusa/discussions)
- Check existing [Issues](https://github.com/Pantheon-Security/medusa/issues)

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.

---

Thank you for helping make MEDUSA better! 🐍
