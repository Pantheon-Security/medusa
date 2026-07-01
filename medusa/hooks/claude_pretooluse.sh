#!/usr/bin/env bash
#
# MEDUSA Claude Code PreToolUse "vet before install" hook.
#
# Claude Code invokes this with the tool-call JSON on stdin and BLOCKS the tool
# call ONLY when the hook exits 2 (exit 1 fails OPEN — the call still runs). This
# script therefore:
#
#   * fails CLOSED (exit 2) if `medusa` is not available — an install command we
#     cannot vet must not be green-lit;
#   * matches a broad set of fetch/install commands (git/gh clone, curl|sh,
#     wget, pip/pip3/pipx/uv pip install, npm install, poetry add, cargo/go
#     install);
#   * extracts EVERY http(s)/git URL in the command and vets each one;
#   * on ANY finding or vetting failure, prints a reason to stderr and exits 2;
#   * otherwise exits 0 and the command proceeds.
#
# This file is a FIXED, MEDUSA-authored constant: it never interpolates
# untrusted data into itself. The scanned command is only ever passed as a
# quoted argument to `medusa`, never evaluated.
set -u

# Explicit, documented escape hatch. Setting MEDUSA_HOOK_BYPASS=1 (alias:
# MEDUSA_HOOK_DISABLE=1) lets this ONE install proceed WITHOUT vetting — the
# intended alternative to deleting the hook entirely when medusa is temporarily
# unreachable or a verdict is a known false alarm. The default stays fail-closed:
# with neither var set, a missing medusa or a non-SAFE verdict still blocks
# (exit 2). This only ever fails OPEN when the user explicitly opts in.
if [ "${MEDUSA_HOOK_BYPASS:-}" = "1" ] || [ "${MEDUSA_HOOK_DISABLE:-}" = "1" ]; then
    echo "MEDUSA vet bypassed (MEDUSA_HOOK_BYPASS=1) — this command was NOT vetted." >&2
    exit 0
fi

# Read tool_input.command from the stdin JSON (best effort; empty on any error).
cmd=$(python3 -c 'import sys, json; print(json.load(sys.stdin).get("tool_input", {}).get("command", ""))' 2>/dev/null)

block() {
    echo "MEDUSA blocked: $1" >&2
    echo "  To retry: re-run the command once MEDUSA is reachable." >&2
    echo "  To override this one command (false alarm / offline): prefix it with MEDUSA_HOOK_BYPASS=1" >&2
    exit 2
}

# Fail CLOSED: if we cannot run medusa we cannot vouch for anything. This is a
# "could not run" case (distinct from a finding) but still blocks by default.
command -v medusa >/dev/null 2>&1 || block "medusa not found — cannot vet (fail closed)"

# `uv pip install` is matched by the `pip install` substring pattern below (kept
# as one pattern to stay shellcheck-clean — SC2221/SC2222).
case "$cmd" in
    *"git clone"* | *"gh repo clone"* | *curl* | *wget* | \
    *"pip install"* | *"pip3 install"* | *"pipx install"* | \
    *"npm install"* | *"poetry add"* | *"cargo install"* | *"go install"*)
        # Vet every extracted URL. `grep -oE` prints one match per line; a
        # `while read` loop keeps this shellcheck-clean (no word-split of $()).
        while IFS= read -r url; do
            [ -n "$url" ] || continue
            # `medusa vet` is the single verdict model shared with the MCP
            # gatekeeper (SkillSpector thresholds). It exits 0 only on SAFE;
            # CAUTION (1) and DO_NOT_INSTALL (2) are non-SAFE verdicts; any other
            # non-zero means vetting could not run. Both block by default, but we
            # word the reason differently so the user knows which happened.
            medusa vet "$url"
            rc=$?
            if [ "$rc" -eq 1 ] || [ "$rc" -eq 2 ]; then
                block "$url failed vetting (non-SAFE verdict)"
            elif [ "$rc" -ne 0 ]; then
                block "could not vet $url (medusa error, exit $rc)"
            fi
        done < <(printf '%s' "$cmd" | grep -oE '(https?://|git@)[^ ]+')

        # Also catch credentials being staged alongside the install.
        medusa secrets scan || block "secrets detected"
        ;;
    *)
        exit 0
        ;;
esac

exit 0
