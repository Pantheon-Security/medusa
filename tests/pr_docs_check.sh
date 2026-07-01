#!/usr/bin/env bash
# pr_docs_check.sh — doc-honesty gate for the product-review DOC tickets
# (PR-007, PR-009, PR-010, PR-011 doc-half, PR-012, PR-013).
#
# Pure grep assertions against README.md + CLAUDE.md. No medusa runtime needed.
# Exit non-zero if ANY assertion fails (was RED before the doc fixes, GREEN after).
#
# Usage:  bash tests/pr_docs_check.sh
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
README="$REPO_ROOT/README.md"
CLAUDE="$REPO_ROOT/CLAUDE.md"

fails=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fails=$((fails + 1)); }

# assert_grep   <desc> <pattern> <file>     -> pattern MUST be present
assert_grep() { if grep -q -- "$2" "$3"; then pass "$1"; else fail "$1"; fi; }
# assert_absent <desc> <pattern> <file>     -> pattern MUST be absent
assert_absent() { if grep -q -- "$2" "$3"; then fail "$1"; else pass "$1"; fi; }

echo "== PR-009: flagship 'medusa vet' documented in README =="
assert_grep  "README documents 'medusa vet'"                 "medusa vet" "$README"
assert_grep  "README shows the DO_NOT_INSTALL verdict"       "DO_NOT_INSTALL" "$README"
assert_grep  "README states the vet exit-code contract"      "Exit codes" "$README"

echo "== PR-010: broken --ai-only example removed =="
assert_absent "README no longer references the nonexistent --ai-only flag" "--ai-only" "$README"

echo "== PR-007: PreToolUse claim narrowed to URL-based installs =="
assert_grep  "README qualifies the hook (registry-name resolution on roadmap)" "registry-name resolution" "$README"
assert_grep  "CLAUDE.md qualifies the hook (registry-name resolution)"          "registry-name resolution" "$CLAUDE"

echo "== PR-011 (doc half): OSV egress disclosed + --offline opt-out =="
assert_grep  "README discloses OSV.dev egress (api.osv.dev)" "api.osv.dev" "$README"
assert_grep  "README documents the --offline opt-out"        "--offline" "$README"

echo "== PR-012: real scan flags present in README =="
for f in --baseline --write-baseline --llm-triage --llm-backend --offline; do
    assert_grep "README documents $f" "$f" "$README"
done

echo "== PR-013: doc-drift fixes =="
assert_absent "README no longer says .cursor/mcp-config.json"   "mcp-config.json" "$README"
assert_absent "CLAUDE.md no longer cites the stale 133 CVE count" "133 Critical CVEs" "$CLAUDE"
assert_grep   "README cites the verified 265 CVE count"          "265" "$README"
assert_grep   "CLAUDE.md cites the verified 265 CVE count"       "265" "$CLAUDE"

echo
if [ "$fails" -eq 0 ]; then
    printf '\033[32mALL DOC CHECKS PASSED\033[0m\n'
    exit 0
fi
printf '\033[31m%d DOC CHECK(S) FAILED\033[0m\n' "$fails"
exit 1
