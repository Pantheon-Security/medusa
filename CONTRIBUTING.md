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
