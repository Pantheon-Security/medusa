# Windows Tool Installation Research - v0.12.11

## 📊 Current Status (v0.12.10)
- **Successfully Installed**: 7/15 tools (47%)
- **Failed**: 8/15 tools (53%)

---

## ✅ Successfully Installed Tools (No Changes Needed)

1. **blinter** → `pip install Blinter` ✅ CRITICAL FIX WORKING
2. **scalastyle** → `choco install scala` ✅
3. **perlcritic** → `choco install strawberryperl` ✅
4. **luacheck** → `choco install lua` ✅
5. **mix** → `choco install elixir` ✅
6. **hlint** → `choco install ghc` ✅
7. **codenarc** → `choco install groovy` ✅

---

## 🔍 Research Findings for Failed Tools

### 1. **clj-kondo** ⚠️ INCORRECT MAPPING
**Current**: `'choco': 'clj-kondo'` (DOESN'T EXIST!)
**Actual**: Available via **Scoop** only

**Installation Options:**
- **Scoop**: `scoop bucket add scoop-clojure && scoop install clj-kondo` ✅
- **Manual**: Download exe from GitHub releases
- **NOT available**: Chocolatey, Winget

**Recommendation**: Add scoop mapping, remove choco mapping

---

### 2. **rubocop** (Ruby Linter)
**Current Status**: Looking for gem, not found (no Ruby installed)

**Installation Options:**
- **Method 1**: `winget install RubyInstallerTeam.RubyWithDevKit.3.2` → `gem install rubocop` ✅
- **Method 2**: `choco install ruby` → `gem install rubocop` ✅
- **Chocolatey Ruby**: v3.4.7.1 (approved Oct 10, 2025)

**Current Mapping**: `'winget': 'RubyInstallerTeam.Ruby'` ✅ (correct, but incomplete)

**Recommendation**: Keep winget mapping, add note that gem install is required after

---

### 3. **phpstan** (PHP Static Analyzer)
**Current Status**: No installer available

**Installation Options:**
- **Composer** (official): `composer require --dev phpstan/phpstan` ✅ (v2.1.32)
- **NOT available**: Chocolatey, Winget, Scoop

**Current Mapping**: Only brew

**Recommendation**: Keep as manual install via Composer (can't automate without PHP)

---

### 4. **ktlint** (Kotlin Linter)
**Current Status**: No installer available

**Installation Options:**
- **Scoop**: `scoop install ktlint` ✅ (v1.7.0 in Main bucket)
- **NOT available**: Chocolatey, Winget

**Current Mapping**: Only brew

**Recommendation**: Add scoop mapping

---

### 5. **checkstyle** (Java Linter)
**Current Status**: No installer available

**Installation Options:**
- **Chocolatey**: `choco install checkstyle` ⚠️ (VERY OUTDATED - v6.18 vs latest 12.1.2)
- **NOT available**: Winget (policy prohibits .bat/.cmd)
- **Maven Plugin**: Better option for Java projects

**Current Mapping**: Has apt/yum/brew, choco was removed (404 error)

**Recommendation**: Could add choco mapping but warn it's outdated, or keep as manual

---

### 6. **taplo** (TOML Formatter)
**Current Status**: Cargo found but installation failed (network issue)

**Installation Options:**
- **Cargo**: `cargo install taplo-cli` ✅ (official method)
- **NOT available**: Chocolatey, Winget, Scoop

**Current Mapping**: Ecosystem detection via cargo ✅ (correct)

**Recommendation**: No change needed - was just a network issue

---

### 7. **checkmake** (Makefile Linter)
**Current Status**: Go not found

**Installation Options:**
- **Go Install**: `go install github.com/checkmake/checkmake/cmd/checkmake@latest` ✅
- **Manual**: Download prebuilt Windows binary from GitHub releases
- **NOT available**: Chocolatey, Winget, Scoop

**Current Mapping**: Only brew, manual (go install)

**Recommendation**: Add Go to ecosystem detection (if Go found, suggest go install)

---

### 8. **swiftlint** (Expected Failure)
**Platform**: macOS only
**Status**: ✅ Correctly shows as unavailable on Windows

---

## 📦 Recommended Mapping Updates

### High Priority - Add Scoop Support

1. **clj-kondo**:
```python
'clj-kondo': {
    'brew': 'borkdude/brew/clj-kondo',
    'scoop': 'clj-kondo',  # Requires: scoop bucket add scoop-clojure
    'manual': 'bash <(curl -s https://raw.githubusercontent.com/clj-kondo/clj-kondo/master/script/install-clj-kondo)',
},
```

2. **ktlint**:
```python
'ktlint': {
    'brew': 'ktlint',
    'scoop': 'ktlint',
    'manual': 'curl -sSLO https://github.com/pinterest/ktlint/releases/latest/download/ktlint && chmod a+x ktlint && sudo mv ktlint /usr/local/bin/',
},
```

### Low Priority - Keep as Manual

3. **rubocop**: Already has winget for Ruby, gem install is manual step ✅

4. **phpstan**: Composer-based, can't automate without PHP ecosystem ✅

5. **checkstyle**: Outdated choco package, better via Maven for Java projects ✅

6. **checkmake**: Could add to ecosystem detection for Go ⚠️

7. **taplo**: Already correct via cargo ecosystem ✅

---

## 📊 Potential Impact

### Before v0.12.11
- **Installed**: 7/15 (47%)
- **Failed**: 8/15 (53%)

### After v0.12.11 (with Scoop support)
- **Installable via package managers**: 9/15 (60%)
  - 7 via Chocolatey (existing)
  - 2 via Scoop (new: clj-kondo, ktlint)
- **Manual/Ecosystem**: 5/15 (33%)
  - rubocop (gem after Ruby)
  - phpstan (composer)
  - checkstyle (maven/manual)
  - checkmake (go install)
  - taplo (cargo)
- **Unavailable**: 1/15 (7%)
  - swiftlint (macOS only)

**Improvement**: 47% → 60% installation success rate (+13%) 🚀

---

## 🎯 Action Plan

1. ✅ **Remove**: clj-kondo choco mapping (doesn't exist)
2. ⏳ **Add**: clj-kondo scoop mapping
3. ⏳ **Add**: ktlint scoop mapping
4. ⏳ **Enhance**: Scoop installer class (if not exists)
5. ⏳ **Document**: Users need to add scoop-clojure bucket for clj-kondo

---

## 💡 Notes

### About Scoop
- User-level installs (no admin required)
- Clean PATH management
- Popular for developer CLI tools
- Smaller package library than Chocolatey
- Requires bucket system (clj-kondo needs scoop-clojure bucket)

### Installation Command
```powershell
# Install Scoop
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression

# Add clojure bucket for clj-kondo
scoop bucket add scoop-clojure https://github.com/littleli/scoop-clojure

# Install tools
scoop install clj-kondo
scoop install ktlint
```
