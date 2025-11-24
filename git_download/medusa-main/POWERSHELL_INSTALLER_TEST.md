# PowerShell Installer - Proof of Concept

## 🎯 Goal
Replace .cmd installers (antivirus false positives) with PowerShell scripts (.ps1)

## ✅ What We Did

### 1. Created PowerShell Installer
**File**: `medusa/platform/installers/windows_scripts/install-clj-kondo.ps1`

**Features**:
- Downloads latest clj-kondo from GitHub releases API
- Extracts to `%LOCALAPPDATA%\clj-kondo`
- Verifies installation
- Clean error handling with fallback instructions
- Debug mode support
- No hardcoded versions (uses GitHub API for latest)

**Advantages over .cmd**:
- ✅ Less likely to trigger antivirus (PowerShell is Windows-native)
- ✅ Better error handling
- ✅ Can use GitHub API (not just static URLs)
- ✅ More powerful scripting capabilities
- ✅ Proper exit codes

---

### 2. Updated WindowsCustomInstaller Class
**File**: `medusa/platform/installers/windows.py`

**Changes**:
- Renamed from "runs bundled .bat scripts" → "runs bundled PowerShell scripts"
- Updated `SUPPORTED_TOOLS` to use `.ps1` extension
- Removed clj-kondo from `CHOCOLATEY_PACKAGES` (doesn't exist in choco)
- New `install()` method that:
  1. Extracts .ps1 script from package using `importlib.resources`
  2. Writes to temp file
  3. Runs with `powershell -ExecutionPolicy Bypass`
  4. Cleans up temp file
  5. Falls back to manual instructions on failure

---

### 3. Updated Packaging
**Files**: `pyproject.toml`, `MANIFEST.in`

**Changes**:
- Added `*.ps1` to package-data
- Added `recursive-include medusa *.ps1` to MANIFEST.in
- .cmd files still excluded (antivirus issue)

---

## 🧪 Testing Plan

### On Windows (v0.12.11 build):

1. **Build and install**:
```powershell
pip install --upgrade medusa-security
```

2. **Run with debug**:
```powershell
py -m medusa install --all --debug
```

3. **Expected behavior for clj-kondo**:
```
Installing clj-kondo...
  → Using custom Windows installer...
[DEBUG] Running PowerShell installer: install-clj-kondo.ps1
[DEBUG] Script written to: C:\Users\...\AppData\Local\Temp\tmp....ps1
[DEBUG] Running: powershell -NoProfile -ExecutionPolicy Bypass -File ...
Downloading clj-kondo v2025.xx.xx...
Extracting files...

✅ clj-kondo installed successfully!
   Location: C:\Users\...\AppData\Local\clj-kondo\clj-kondo.exe
   Version: 2025.xx.xx

[DEBUG] Successfully installed clj-kondo via PowerShell script
  ✅ Installed successfully
```

4. **Verify clj-kondo works**:
```powershell
C:\Users\...\AppData\Local\clj-kondo\clj-kondo.exe --version
```

---

## 🔍 What to Watch For

### Success Indicators:
- ✅ PowerShell script runs without errors
- ✅ clj-kondo.exe downloaded and extracted
- ✅ No antivirus alerts (Bitdefender, Windows Defender)
- ✅ Tool works after installation

### Potential Issues:
- ⚠️ PowerShell execution policy errors
  - **Fix**: Script uses `-ExecutionPolicy Bypass` flag
- ⚠️ Antivirus still flags .ps1
  - **Next step**: Would need to fall back to Python-based downloader
- ⚠️ importlib.resources fails
  - **Fix**: Already has Python 3.8 fallback in code
- ⚠️ GitHub API rate limiting
  - **Impact**: Would see 403 errors
  - **Fix**: Script falls back to manual instructions

---

## 📊 Success Metrics

### Before (v0.12.10):
- **clj-kondo**: ❌ Failed (tried choco, doesn't exist)
- **Installation success**: 7/15 (47%)

### After (v0.12.11) - if PowerShell approach works:
- **clj-kondo**: ✅ Installed via PowerShell script
- **Installation success**: 8/15 (53%)

---

## 🚀 Next Steps (if successful)

If clj-kondo PowerShell installer works without antivirus issues:

1. **Create more PowerShell installers**:
   - `install-ktlint.ps1` (download JAR from GitHub)
   - `install-checkstyle.ps1` (download JAR from GitHub)
   - `install-phpstan.ps1` (download PHAR from GitHub)

2. **Potential improvements**:
   - Add version pinning support
   - Add SHA256 verification
   - Add PATH management (auto-add to user PATH)
   - Add upgrade detection

3. **Release as v0.12.11**

---

## ❌ Alternative if PowerShell Also Triggers Antivirus

If PowerShell scripts also trigger antivirus:

**Plan B**: Python-based downloader
- Use MEDUSA's own Python to download/extract
- No external scripts needed
- Guaranteed to work (Python is already trusted)
- Example implementation in `WINDOWS_TOOL_RESEARCH.md` (Option C)

---

## 📝 Notes

### Why PowerShell vs .cmd?
- PowerShell is signed by Microsoft
- Native Windows scripting language
- More trusted by antivirus software
- Better error handling and scripting capabilities
- Can parse JSON (GitHub API responses)

### Why not Python directly?
- Wanted to test PowerShell approach first (simpler)
- PowerShell can handle PATH management better
- If this works, easier for users to inspect/modify scripts
- Python approach is Plan B if PowerShell fails

---

## 🎯 Decision Point

After testing on Windows:
- ✅ **If works**: Create more .ps1 installers for other tools
- ❌ **If antivirus flags it**: Switch to Python-based downloader approach
