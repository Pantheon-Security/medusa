# MEDUSA v0.11.1 - Production Ready 🎉

**Full Windows Support** ✅ | **Multi-Format Reports** 📊 | **1,600+ Downloads** 📈

---

## 🐛 Critical Windows Fix

**Fixed:** Unicode encoding error on Windows when generating reports

**Error:** `UnicodeEncodeError: 'charmap' codec can't encode character '\U0001f40d'`

**Solution:** Added explicit UTF-8 encoding to all file writes in the reporter module. Reports now generate flawlessly on Windows!

---

## ✨ What's New in v0.11.x

### 📊 Multi-Format Reports (v0.11.0)

Export security scan results in your preferred format:

```bash
# JSON - Machine-readable for CI/CD
medusa scan . --format json

# HTML - Beautiful glassmorphism UI
medusa scan . --format html

# Markdown - Documentation-friendly
medusa scan . --format markdown

# All formats at once
medusa scan . --format all
```

**Report Features:**
- Executive summary with security score
- Severity breakdown with percentages
- Detailed findings with CWE links
- File and line number references
- Scanner attribution

---

## 🪟 Windows Support Journey

The 0.10.x series brought **full native Windows support**:

### Auto-Installation (v0.10.0)
- ✅ Winget integration
- ✅ Chocolatey support
- ✅ npm tools via Node.js
- ✅ Automatic PATH refresh

### Tool Detection Fixes (v0.10.9, v0.10.10)
- ✅ Fixed reinstall loops
- ✅ Reliable PATH-based detection
- ✅ Consistent behavior across all package managers

### Scanner Transparency (v0.10.8)
- ✅ "Scanners used" output line
- ✅ Verify which tools actually ran

---

## 📦 Installation

```powershell
# Windows
pip install medusa-security

# Verify
py -m medusa --version
# MEDUSA v0.11.1

# Run your first scan
py -m medusa scan .
```

```bash
# macOS/Linux
pip install medusa-security

# Verify
medusa --version
# MEDUSA v0.11.1

# Run your first scan
medusa scan .
```

---

## 🚀 Key Features

- 🔍 **40+ Specialized Scanners** - Comprehensive language coverage
- ⚡ **Parallel Processing** - 10-40× faster than sequential scanning
- 📦 **Auto-Installer** - One-command setup on Windows, macOS, and Linux
- 📊 **Multi-Format Reports** - JSON, HTML, and Markdown exports
- 🔄 **Smart Caching** - Skip unchanged files for instant rescans
- 🌍 **Cross-Platform** - Native support for all major platforms
- 🎯 **Zero Config** - Works out of the box with sensible defaults

---

## 📈 Growing Fast

- **1,600+ Downloads** in first week
- **40+ Security Tools** integrated
- **42 Programming Languages** supported
- **3 Platforms** fully supported

---

## 🔗 Links

- **PyPI**: https://pypi.org/project/medusa-security/
- **Documentation**: https://github.com/Pantheon-Security/medusa
- **Report Issues**: https://github.com/Pantheon-Security/medusa/issues

---

## 💙 Thank You

Thank you to everyone who downloaded, tested, and provided feedback! Your support helps make MEDUSA better for the entire community.

Special shoutout to our Windows testers for helping identify and fix the encoding bug! 🙏

---

**Full Changelog**: https://github.com/Pantheon-Security/medusa/blob/main/CHANGELOG.md
