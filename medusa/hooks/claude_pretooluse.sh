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

# Read tool_input.command from the stdin JSON (best effort; empty on any error).
cmd=$(python3 -c 'import sys, json; print(json.load(sys.stdin).get("tool_input", {}).get("command", ""))' 2>/dev/null)

block() {
    echo "MEDUSA blocked: $1" >&2
    exit 2
}

# Fail CLOSED: if we cannot run medusa we cannot vouch for anything.
command -v medusa >/dev/null 2>&1 || block "medusa not found (fail closed)"

# `uv pip install` is matched by the `pip install` substring pattern below (kept
# as one pattern to stay shellcheck-clean — SC2221/SC2222).
case "$cmd" in
    *"git clone"* | *"gh repo clone"* | *curl*sh* | *wget* | \
    *"pip install"* | *"pip3 install"* | *"pipx install"* | \
    *"npm install"* | *"poetry add"* | *"cargo install"* | *"go install"*)
        # Vet every extracted URL. `grep -oE` prints one match per line; a
        # `while read` loop keeps this shellcheck-clean (no word-split of $()).
        while IFS= read -r url; do
            [ -n "$url" ] || continue
            # TODO CR-022: switch to `medusa vet "$url"` once that command lands
            # (single verdict model shared with the MCP gatekeeper).
            medusa scan --git "$url" --fail-on high --yes --no-prompt \
                || block "$url failed vetting"
        done < <(printf '%s' "$cmd" | grep -oE '(https?://|git@)[^ ]+')

        # Also catch credentials being staged alongside the install.
        medusa secrets scan || block "secrets detected"
        ;;
    *)
        exit 0
        ;;
esac

exit 0
