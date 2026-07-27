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
    *"git clone"* | *"gh repo clone"* | *"gh gist clone"* | *curl* | *wget* | \
    *"pip install"* | *"pip3 install"* | *"pipx install"* | \
    *"uv add"* | *uvx* | *"npm install"* | *"npm i "* | *npx* | *"pnpm add"* | \
    *"pnpm dlx"* | *"yarn add"* | *bunx* | *"bun add"* | \
    *"poetry add"* | *"cargo install"* | *"go install"* | *"deno run"* | *"deno install"*)
        # NB: `uv pip install` / `pnpm install` are intentionally NOT listed —
        # they are already matched by the `pip install` / `npm install` substring
        # patterns above (kept implicit to stay shellcheck-clean, SC2221/SC2222).
        # FIRST catch a credential embedded in the install COMMAND itself — a token
        # in a clone URL (`git clone https://user:ghp_…@host`) or pasted into the
        # command. Runs BEFORE URL vetting so a leaked token is caught up front and
        # is never handed to `medusa vet` (which would clone WITH the token in the
        # URL). This scans the actual TARGET present at hook time (the command
        # string), NOT the user's $HOME chat/shell history — the bare
        # `medusa secrets scan` default, which fired on unrelated host artefacts and,
        # lacking --exit-code, returned 0 so it never actually blocked (dead line).
        # `--exit-code` makes a real detection non-zero; temp file is 0600, removed
        # immediately.
        _sec_tmp="$(mktemp "${TMPDIR:-/tmp}/medusa_hook_cmd.XXXXXX")" || _sec_tmp=""
        if [ -n "$_sec_tmp" ]; then
            chmod 600 "$_sec_tmp" 2>/dev/null
            printf '%s' "$cmd" > "$_sec_tmp"
            medusa secrets scan --path "$_sec_tmp" --exit-code
            _sec_rc=$?
            rm -f "$_sec_tmp"
            [ "$_sec_rc" -eq 0 ] || block "a credential is embedded in the command (e.g. a token in the URL)"
        fi

        # Extract the URLs to vet with the precise per-segment parser packaged
        # alongside this hook (`_vet_url_extract.py`): it only vets a URL whose
        # statement's LEADING command is a real fetch (git clone / gh repo clone /
        # pip|npm|… install / curl|wget piped into a shell). This stops the
        # compound-command URL bleed (`git clone X && az … https://dev.azure.com`),
        # substring/echo matches (`echo "pip install …"`), greedy-regex junk
        # (`https://x.git;cd`) and plain-download FPs — while still emitting every
        # real clone/dropper target. If the helper is unavailable it falls back to
        # the old greedy grep (fail SAFE — over-vet rather than under-vet).
        _hook_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
        urls="$(printf '%s' "$cmd" | python3 "$_hook_dir/_vet_url_extract.py" 2>/dev/null)"
        parser_rc=$?
        if [ "$parser_rc" -ne 0 ]; then
            urls="$(printf '%s' "$cmd" | grep -oE '(https?://|git@)[^ ]+')"
        fi
        # Vet every extracted URL. `medusa vet` is the single verdict model shared
        # with the MCP gatekeeper (SkillSpector thresholds): exit 0 = SAFE, 1 =
        # CAUTION, 2 = DO_NOT_INSTALL, any other non-zero = could-not-vet. All
        # non-SAFE outcomes block by default; the reason is worded per case.
        while IFS= read -r url; do
            [ -n "$url" ] || continue
            medusa vet "$url"
            rc=$?
            if [ "$rc" -eq 1 ] || [ "$rc" -eq 2 ]; then
                block "$url failed vetting (non-SAFE verdict)"
            elif [ "$rc" -ne 0 ]; then
                block "could not vet $url (medusa error, exit $rc)"
            fi
        done < <(printf '%s\n' "$urls")
        # Fail CLOSED: a clone command whose target we could not turn into a
        # vettable URL (ext::/file:///scp/local) must not slip through un-vetted.
        # Scoped to clone patterns only — bare-name installs (pip install requests)
        # legitimately have no URL and must NOT be blocked here.
        case "$cmd" in
            *"git clone"* | *"gh repo clone"*)
                [ -n "${urls//[[:space:]]/}" ] || \
                    block "clone target could not be identified for vetting (fail closed)"
                ;;
        esac
        ;;
    *)
        exit 0
        ;;
esac

exit 0
