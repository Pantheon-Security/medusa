---
description: Bump MEDUSA version across all project files
---

You are helping to bump the version number for the MEDUSA project.

## Your Task

1. Ask the user what type of version bump they want:
   - **major** (X.0.0.0) - Breaking changes, major new features
   - **minor** (0.X.0.0) - New features, backward compatible
   - **patch** (0.0.X.0) - Bug fixes, minor improvements
   - **build** (0.0.0.X) - Build/metadata changes
   - **custom** - Specify exact version (e.g., 1.0.0.0)

2. Run the version bump script:
   ```bash
   python3 scripts/bump_version.py [major|minor|patch|build]
   # OR for custom version:
   python3 scripts/bump_version.py --version X.Y.Z.W
   ```

3. Show the user what was changed:
   ```bash
   git diff
   ```

4. Ask if they want to commit the changes. If yes:
   ```bash
   git add -u
   git commit -m "Version bump: [old] → [new]

   [Brief description of changes in this version]

   🤖 Generated with [Claude Code](https://claude.com/claude-code)

   Co-Authored-By: Claude <noreply@anthropic.com>"
   git push
   ```

5. Optionally create a git tag:
   ```bash
   git tag v[new-version]
   git push --tags
   ```

## Version Numbering Guide

MEDUSA uses semantic versioning with 4 parts: `MAJOR.MINOR.PATCH.BUILD`

- **MAJOR**: Incompatible API changes, major rewrites
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, small improvements
- **BUILD**: Build metadata, docs, tests

## Example

```
User: "I want to bump to the next minor version"

1. Run: python3 scripts/bump_version.py minor
2. Current: 0.8.0.0 → New: 0.9.0.0
3. Files updated:
   - medusa/__init__.py
   - pyproject.toml
   - Dockerfile
   - .claude/claude.md
4. Commit and push
```
