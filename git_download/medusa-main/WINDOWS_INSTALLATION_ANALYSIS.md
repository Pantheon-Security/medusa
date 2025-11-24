# Windows Installation Analysis - MEDUSA v0.12.9

## 📊 Overall Status

**MEDUSA supports 44 total scanners**

### ✅ Currently Working (7 scanners)
1. **PythonScanner** (bandit) → .py
2. **BashScanner** (shellcheck) → .sh, .bash, .ksh, .zsh
3. **BatScanner** (blinter) → .bat, .cmd  ⚠️ **BUT blinter failed to install on Windows!**
4. **YAMLScanner** (yamllint) → .yml, .yaml
5. **DockerComposeScanner** (docker-compose) → .yml, .yaml
6. **JavaScriptScanner** (eslint) → .js, .jsx, .ts, .tsx
7. **JSONScanner** (python) → .json

### ❌ Missing Tools (37 scanners)

Of the 37 missing tools, user attempted to install 15 on Windows. Let's analyze those 15:

---

## 🔍 Analysis of 15 Tools Attempted on Windows

Out of 15 tools that failed to install, here's the breakdown:

---

## 🔧 Category 1: CAN BE FIXED - Add winget/choco Support (9 tools)

### 1. **blinter** 🚨 CRITICAL BUG
- **Status**: "No installer available for this platform"
- **Issue**: BatScanner shows as "Available" in `medusa config` but blinter fails to install on Windows!
- **Root Cause**: Missing from PYTHON_TOOLS list in base.py (line 176)
- **Impact**: Users can't scan .bat/.cmd files on Windows even though scanner is "available"
- **Fix**: Add 'blinter' to PYTHON_TOOLS set
- **Action**: `pip install Blinter` (note capital B in package name)

### 2. **rubocop**
- **Status**: "Looking for gem... Not found"
- **Current mapping**: `'winget': 'RubyInstallerTeam.Ruby'` (installs Ruby, not rubocop)
- **Fix**: Install Ruby via winget, then `gem install rubocop`
- **Action**: Need two-step install process

### 3. **phpstan**
- **Status**: Custom installer shows manual instructions
- **Current mapping**: Only brew, choco removed
- **Available on winget**: Need to check `winget search phpstan`
- **Action**: Add winget mapping if available, or use composer

### 4. **ktlint**
- **Status**: Custom installer shows manual instructions
- **Current mapping**: Only brew, choco removed
- **Available on winget**: Need to check `winget search ktlint`
- **Action**: Add winget mapping if available

### 5. **checkstyle**
- **Status**: Custom installer shows manual instructions
- **Current mapping**: Has apt/yum/brew, choco removed (404 error)
- **Available on winget**: Need to check `winget search checkstyle`
- **Action**: Add winget mapping if available

### 6. **clj-kondo**
- **Status**: Tried chocolatey but user doesn't have choco installed
- **Current mapping**: Only brew
- **Available on**: Scoop, winget (need to check)
- **Action**: Try winget first, then fall back to scoop instructions

### 7. **perlcritic**
- **Status**: "Looking for cpan... Not found"
- **Current mapping**: apt, brew, manual (cpan)
- **Available on winget**: `winget search perl` → Strawberry Perl
- **Action**: Install Strawberry Perl via winget, then `cpan Perl::Critic`

### 8. **mix** (Elixir)
- **Status**: "Looking for elixir... Not found"
- **Current mapping**: apt, yum, dnf, pacman, brew
- **Available on winget**: Need to check `winget search elixir`
- **Action**: Add winget mapping if available

### 9. **checkmake**
- **Status**: Custom installer shows manual instructions
- **Current mapping**: brew, manual (go install)
- **Available**: Can use `go install github.com/mrtazz/checkmake/cmd/checkmake@latest`
- **Action**: Detect if Go is installed, use ecosystem detection

---

## 🔍 Category 2: ECOSYSTEM DEPENDENT - Already Correct (4 tools)

### 10. **taplo**
- **Status**: Cargo found, installation failed (user reported internet issues)
- **Current mapping**: Uses cargo via EcosystemDetector
- **Fix**: NOT A BUG - User's internet was down
- **Action**: User should retry when internet is stable

### 11. **luacheck**
- **Status**: "Looking for luarocks... Not found"
- **Current mapping**: brew, manual (luarocks)
- **Fix**: Need Lua + luarocks installed first
- **Action**: Could add winget mapping for Lua if available

### 12. **hlint**
- **Status**: "Looking for stack... Not found"
- **Current mapping**: apt, pacman, brew, manual (cabal)
- **Fix**: Need Haskell Stack or Cabal installed first
- **Action**: Could add winget mapping for Haskell Platform

### 13. **scalastyle**
- **Status**: Custom installer shows manual instructions
- **Current mapping**: brew, manual
- **Fix**: Scala linter - need Scala/sbt installed
- **Action**: Add winget mapping if available

---

## ⛔ Category 3: PLATFORM INCOMPATIBLE - Cannot Fix (2 tools)

### 14. **swiftlint**
- **Status**: "No installer available for this platform"
- **Platform**: macOS only (Swift is Apple's language)
- **Fix**: NONE - This is correct behavior
- **Action**: Document that Swift scanning requires macOS

### 15. **codenarc**
- **Status**: Custom installer shows manual instructions
- **Current mapping**: brew, manual (Groovy/Gradle)
- **Platform**: Groovy linter - requires JVM
- **Fix**: Could add winget mapping for Groovy if available
- **Action**: Check winget for Groovy

---

## 📊 Summary

### Failed Installation Breakdown
| Category | Count | Action Required |
|----------|-------|-----------------|
| **Can be fixed** | 9 | Add winget/choco mappings |
| **Ecosystem dependent** | 4 | Already working correctly (need parent tools) |
| **Platform incompatible** | 2 | Expected behavior |

### Tools Successfully Working on Linux (7/44)
| Scanner | Tool | Status | Platform |
|---------|------|--------|----------|
| PythonScanner | bandit | ✅ Working | All |
| BashScanner | shellcheck | ✅ Working | All |
| BatScanner | blinter | ⚠️ BROKEN on Windows | Windows only |
| YAMLScanner | yamllint | ✅ Working | All |
| DockerComposeScanner | docker-compose | ✅ Working | All |
| JavaScriptScanner | eslint | ✅ Working | All |
| JSONScanner | python | ✅ Working | All |

### Windows Installation Success Rate
- **Current**: 6/7 scanners working (blinter is broken)
- **After fixes**: Could potentially support 15-20 additional scanners

---

## 🎯 Recommended Fixes (Priority Order)

### HIGH PRIORITY
1. **blinter** - CRITICAL: This is MEDUSA's own dependency!
   - Add to PYTHON_TOOLS set
   - Add to TOOL_PACKAGES with pip mapping

### MEDIUM PRIORITY
2. **clj-kondo** - Try winget before chocolatey
3. **rubocop** - Improve Ruby installation flow
4. **phpstan** - Add winget mapping
5. **ktlint** - Add winget mapping
6. **checkstyle** - Add winget mapping
7. **checkmake** - Use Go ecosystem detection

### LOW PRIORITY
8. **perlcritic** - Add Strawberry Perl via winget
9. **mix** - Add Elixir via winget
10. **luacheck** - Add Lua via winget
11. **hlint** - Add Haskell Platform via winget
12. **scalastyle** - Add Scala via winget

---

## 🔍 Next Steps

1. Research winget package availability:
   ```powershell
   winget search phpstan
   winget search ktlint
   winget search checkstyle
   winget search clj-kondo
   winget search elixir
   winget search perl
   winget search lua
   winget search haskell
   winget search scala
   ```

2. Update `medusa/platform/installers/base.py`:
   - Add 'blinter' to PYTHON_TOOLS (line 176)
   - Add winget mappings to TOOL_PACKAGES for available tools

3. Test on Windows with `medusa install --all --debug`

4. Release as v0.12.10 with improved Windows support
