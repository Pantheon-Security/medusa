# Medusa False Positive Analysis Handover

**Project Scanned**: [gtsteffaniak/filebrowser](https://github.com/gtsteffaniak/filebrowser)
**Medusa Version**: 2025.9.0.6
**Scan Date**: 2026-01-04
**Analyst**: Claude Code Security Review

---

## Executive Summary

- **Total Findings**: 24
- **CRITICAL**: 13 (11 are False Positives = **84.6% FP rate**)
- **MEDIUM**: 9 (7 are context-dependent for test files)
- **LOW**: 2

---

## CRITICAL Findings - False Positive Analysis

### FP-1: SHA1 in `file_cache.go:109`

**Flagged Code**:
```go
func (f *FileCache) getFileName(key string) string {
    hasher := sha1.New()
    _, _ = hasher.Write([]byte(key))
    hash := hex.EncodeToString(hasher.Sum(nil))
    return filepath.Join(f.dir, fmt.Sprintf("%s/%s/%s", hash[:1], hash[1:3], hash))
}
```

**Why False Positive**:
SHA1 generates a well-distributed directory structure for cache files (similar to git's object storage). NOT used for cryptographic security. Collision resistance is irrelevant - worst case is a cache miss, not a security breach.

**Suggested FP Filter Pattern**:
- Hash output used in `filepath.Join()`
- Directory sharding patterns: `hash[:1]`, `hash[1:3]`
- Cache/storage path construction context

---

### FP-2 & FP-3: MD5/SHA1 in `file.go:26-27`

**Flagged Code**:
```go
func GetChecksum(fullPath, algo string) (string, error) {
    hashFuncs := map[string]hash.Hash{
        "md5":    md5.New(),
        "sha1":   sha1.New(),
        "sha256": sha256.New(),
        "sha512": sha512.New(),
    }
    h, ok := hashFuncs[algo]
    // ...
}
```

**Why False Positive**:
This is a user-requested checksum feature. Users choose the algorithm. The function explicitly offers SHA256/SHA512 as options. This is a legitimate file integrity feature, not a vulnerability.

**Suggested FP Filter Pattern**:
- Algorithm passed as parameter (user choice)
- Function offers multiple algorithms including SHA256/SHA512
- Function names: `*Checksum*`, `*Hash*` for file verification
- Map/switch containing multiple hash algorithms

---

### FP-4: math/rand in `main.go:8`

**Flagged Code**:
```go
import (
    "crypto/rand"  // Line 4 - SECURE rand for GenerateKey()
    math "math/rand"  // Line 8 - Explicitly aliased
)

func GenerateKey() string {
    b := make([]byte, 64)
    _, err := rand.Read(b)  // Uses crypto/rand correctly
    // ...
}

func InsecureRandomIdentifier(length int) string {  // Self-documenting name
    math.New(math.NewSource(time.Now().UnixNano()))
    // ...
}
```

**Why False Positive**:
The function is **explicitly named "InsecureRandomIdentifier"** - self-documenting that this is not for security. The same file correctly uses `crypto/rand` for `GenerateKey()`. This is intentional design separation.

**Suggested FP Filter Pattern**:
- Function name contains `Insecure`, `NonSecure`, `Weak`
- Same file also imports and uses `crypto/rand`
- Function used for non-sensitive identifiers (logging, display)

---

### FP-5: math/rand in `mocks.go:6`

**Flagged Code**:
```go
// File: backend/common/utils/mocks.go
package utils

import "math/rand"

func GenerateRandomPath(levels int) string { ... }
func GetRandomTerm() string { ... }
func GetRandomExtension() string { ... }
```

**Why False Positive**:
File is named `mocks.go` - these are test utilities for generating random test data. Using `math/rand` in test infrastructure is completely appropriate.

**Suggested FP Filter Pattern**:
- Filename matches: `*mock*.go`, `*_mock.go`, `mock_*.go`
- Directory: `mocks/`, `testdata/`, `fixtures/`
- Package name contains `mock`, `test`, `fake`

---

### FP-6: math/rand in `indexing/mock.go:4`

**Flagged Code**:
```go
// File: backend/indexing/mock.go
func (idx *Index) CreateMockData(numDirs, numFilesPerDir int) { ... }
func CreateMockData(numDirs, numFilesPerDir int) iteminfo.FileInfo { ... }
```

**Why False Positive**:
Same as FP-5. File named `mock.go`, functions named `CreateMockData`. Clearly test infrastructure, not production security code.

**Suggested FP Filter Pattern**:
- Function names: `*Mock*`, `*Fake*`, `*Stub*`
- Used for generating test fixtures

---

### FP-7: MD5 in `duplicates.go:441`

**Flagged Code**:
```go
func calculatePartialChecksum(filePath string, size int64) (string, error) {
    hash := md5.New()
    buf := make([]byte, 8192) // 8KB buffer

    // Samples: first 8KB + middle 8KB + last 8KB
    n, _ := io.ReadFull(file, buf)
    hash.Write(buf[:n])

    if size > 24576 {
        // Sample middle and end portions...
    }

    checksum := fmt.Sprintf("%x", hash.Sum(nil))
    checksumCache.Set(cacheKey, checksum)
    return checksum, nil
}
```

**Why False Positive**:
MD5 is used for **fast file similarity comparison** in duplicate detection, not cryptographic verification:
- Speed matters when comparing many large files
- False positives acceptable (shows as duplicate candidate for user review)
- Collision attacks irrelevant - attacker gains nothing from creating colliding files
- Partial file sampling (first/middle/last 8KB) - clearly optimization, not security

**Suggested FP Filter Pattern**:
- Function/file names: `*Duplicate*`, `*Dedup*`, `*Similar*`
- Partial file reading patterns (seeking, sampling)
- Size-based pre-filtering nearby
- Cache storage of results

---

### FP-8: MD5 in `resource.go:336`

**Flagged Code**:
```go
func resourcePostHandler(...) {
    // Create unique temp file for chunked uploads
    hasher := md5.New()
    hasher.Write([]byte(realPath))  // Hashing FILE PATH, not content
    uploadID := hex.EncodeToString(hasher.Sum(nil))
    tempFilePath := filepath.Join(settings.Config.Server.CacheDir, "uploads", uploadID)
}
```

**Why False Positive**:
MD5 hashes the **file path string** (not file content or secrets) to generate a deterministic temp filename for tracking chunked upload progress. This is purely internal file naming for resumable uploads.

**Suggested FP Filter Pattern**:
- Hashing path strings, not file content
- Result used in temp file path construction
- Variable names: `*uploadID*`, `*tempFile*`, `*chunkID*`
- Context: upload handling, chunked transfers

---

### FP-9 through FP-13: MD5 in `preview.go` (lines 143, 148, 184, 281, 324)

**Flagged Code**:
```go
// Line 143-151: Cache album art
hasher := md5.New()
_, _ = hasher.Write([]byte(file.Metadata.AlbumArt))
cacheHash = hex.EncodeToString(hasher.Sum(nil))

// Line 148-151: Cache file metadata
cacheString := fmt.Sprintf("%s:%d:%s", file.RealPath, file.Size, file.ModTime.Format(time.RFC3339Nano))
hasher.Write([]byte(cacheString))

// Line 164 - EXPLICIT COMMENT IN CODE:
// Note: fileMD5 is actually a cache hash (metadata-based), not a true file content MD5
```

**Why False Positive**:
All MD5 usage in preview.go is for **cache key generation** from file metadata. The code itself documents this at line 164. Cache keys from metadata (path + size + modtime) have no security implications.

**Suggested FP Filter Pattern**:
- File/function names: `*preview*`, `*thumbnail*`, `*cache*`
- Variables: `*cacheKey*`, `*cacheHash*`, `*CacheKey*`
- Hashing metadata strings (path + size + modtime patterns)
- Result used with cache storage APIs

---

## MEDIUM Findings - Context Analysis

### Docker Root User (2 findings)

| File | Line | Verdict |
|------|------|---------|
| `Dockerfile` | 46 | **TRUE POSITIVE** - Production, should consider non-root |
| `Dockerfile.slim` | 38 | **TRUE POSITIVE** - Production, should consider non-root |

**Note**: File browsers often intentionally run as root to access all mounted files. Consider adding documentation that this is intentional, or implementing user namespace remapping.

### Unpinned :latest Tags (7 findings)

| File | Verdict | Reasoning |
|------|---------|-----------|
| `Dockerfile.playwright-general` | **Context-Dependent FP** | Test Dockerfile |
| `Dockerfile.playwright-no-config` | **Context-Dependent FP** | Test Dockerfile |
| `Dockerfile.playwright-noauth` | **Context-Dependent FP** | Test Dockerfile |
| `Dockerfile.playwright-oidc` | **Context-Dependent FP** | Test Dockerfile |
| `Dockerfile.playwright-proxy` | **Context-Dependent FP** | Test Dockerfile |
| `Dockerfile.playwright-settings` | **Context-Dependent FP** | Test Dockerfile |
| `Dockerfile.playwright-sharing` | **Context-Dependent FP** | Test Dockerfile |

**Suggested FP Filter Pattern**:
- Dockerfile names containing `test`, `playwright`, `dev`, `ci`
- Dockerfiles in `test/`, `tests/`, `e2e/` directories
- Consider reducing severity for non-production Dockerfiles

---

## LOW Findings

| File | Line | Issue | Verdict |
|------|------|-------|---------|
| `Dockerfile` | 26 | `:latest` tag | TRUE POSITIVE |
| `Dockerfile.slim` | 24 | `:latest` tag | TRUE POSITIVE |

---

## Recommended FP Filter Improvements

### 1. Cache/Storage Context Detection
```yaml
fp_patterns:
  - name: "hash_for_cache_key"
    indicators:
      - hash_output_in: ["filepath.Join", "cache.Store", "cache.Set"]
      - variable_names: ["*cacheKey*", "*cacheHash*", "*uploadID*"]
      - directory_sharding: ["hash[:1]", "hash[1:3]"]
```

### 2. Test/Mock File Detection
```yaml
fp_patterns:
  - name: "test_mock_files"
    file_patterns:
      - "*mock*.go"
      - "*_mock.go"
      - "*_test.go"
      - "*fake*.go"
    directories:
      - "test/"
      - "tests/"
      - "testdata/"
      - "mocks/"
    function_names:
      - "*Mock*"
      - "*Fake*"
      - "*Stub*"
      - "Create*Data"
```

### 3. Self-Documenting Insecure Usage
```yaml
fp_patterns:
  - name: "intentionally_insecure"
    function_names:
      - "*Insecure*"
      - "*NonSecure*"
      - "*Weak*"
      - "*Fast*"  # When paired with secure alternative
    conditions:
      - same_file_uses_crypto_rand: true
```

### 4. User-Selectable Algorithm Detection
```yaml
fp_patterns:
  - name: "multi_algorithm_choice"
    indicators:
      - algorithm_parameter: true
      - offers_sha256_or_sha512: true
      - function_names: ["*Checksum*", "*Hash*", "*Digest*"]
```

### 5. Duplicate Detection Context
```yaml
fp_patterns:
  - name: "duplicate_detection"
    indicators:
      - partial_file_reading: true
      - file_size_comparisons: true
      - function_names: ["*Duplicate*", "*Dedup*", "*Similar*"]
```

### 6. Test Dockerfile Detection
```yaml
fp_patterns:
  - name: "test_dockerfiles"
    file_patterns:
      - "Dockerfile.*test*"
      - "Dockerfile.*playwright*"
      - "Dockerfile.*dev*"
      - "Dockerfile.*ci*"
    action: reduce_severity
```

---

## Attachments

- `filebrowser-security-report.json/` - Original Medusa scan results
- FileBrowser source: https://github.com/gtsteffaniak/filebrowser

---

## Contact

This analysis was performed as part of a security review for potential fork contribution. The FP patterns identified here should help improve Medusa's accuracy for Go codebases, particularly those involving:
- File management applications
- Caching systems
- Upload/download handlers
- Preview/thumbnail generation
