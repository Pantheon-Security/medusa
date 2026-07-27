#!/usr/bin/env python3
"""Extract the URLs a PreToolUse install/clone command should have vetted.

The old hook `grep`ed every ``http(s)://``/``git@`` token out of the WHOLE command
string and vetted each as a clone target. That produced false BLOCKS:

  * compound-command URL bleed — ``git clone X && az repos --org https://dev.azure.com``
    vetted the ``az`` URL as a clone target;
  * substring matching — ``echo "remember to pip install black"`` entered the vet branch;
  * greedy regex — ``https://x.git;cd`` / a trailing quote produced a malformed URL that
    errored → fail-closed BLOCK;
  * plain ``curl``/``wget`` downloads (not repos) vetted as repos → error → BLOCK.

This module parses the command properly: shell-tokenise (quotes respected), split into
STATEMENTS on ``&& || ; &`` / newlines (pipes stay within a statement), and only emit
URLs from a statement whose LEADING command (argv[0], after env-assignments / ``sudo``)
is a real fetch:

  * ``git clone`` / ``gh repo clone``            -> the URL(s) in that statement
  * ``pip|pip3|pipx|uv|npm|pnpm|yarn|poetry|cargo|go`` install/add -> URL(s) present
  * ``curl`` / ``wget`` ONLY when the statement pipes into a shell (``| sh`` / ``| bash``)
    — the canonical dropper; a plain download/API call is not a repo and is skipped
  * ``sh -c "<subcommand>"`` -> recurse into the quoted sub-command

Security note: this only makes matching MORE PRECISE (fewer spurious vets); every real
clone/curl|bash target is still emitted and still vetted by the caller (fail-closed on a
non-SAFE verdict). It is a parser — it never executes the command.
"""
from __future__ import annotations

import re
import shlex
import sys
from typing import List

_STATEMENT_SEPS = {"&&", "||", ";", "&", "\n"}
_CMD_PREFIXES = {"sudo", "doas", "env", "command", "nohup", "time", "exec", "then", "do"}
_INSTALL_CMDS = {"pip", "pip3", "pipx", "uv", "npm", "pnpm", "yarn", "poetry", "cargo", "go"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
# A dropper can pipe a fetched script into ANY interpreter, not just a shell
# (`curl URL | python3`). _pipes_to_shell checks this superset.
_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh",
                 "python", "python2", "python3", "perl", "ruby", "node", "php"}

# Set True when _tokenize falls back to a naive split (degraded parse) so main()
# signals the shell to over-vet via grep instead of trusting an under-emitted list.
_DEGRADED = False


def _tokenize(cmd: str) -> List[str]:
    """Shell-tokenise, keeping shell operators (&& || ; | & > …) as their own tokens."""
    global _DEGRADED
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        # unbalanced quotes etc. — fall back to a naive split (still no execution)
        _DEGRADED = True
        return cmd.split()


def _split_statements(tokens: List[str]) -> List[List[str]]:
    statements, cur = [], []
    for t in tokens:
        if t in _STATEMENT_SEPS:
            if cur:
                statements.append(cur)
                cur = []
        else:
            cur.append(t)
    if cur:
        statements.append(cur)
    return statements


def _argv(stmt: List[str]) -> List[str]:
    """Drop leading ``NAME=value`` env-assignments and command prefixes (sudo/env/…)."""
    i = 0
    while i < len(stmt):
        t = stmt[i]
        if "=" in t and not t.startswith("-") and t.split("=", 1)[0].isidentifier():
            i += 1
            continue
        if t in _CMD_PREFIXES:
            i += 1
            continue
        break
    return stmt[i:]


_URL_PREFIXES = ("http://", "https://", "git@",
                 "git+http://", "git+https://", "git+ssh://")


def _is_url(tok: str) -> bool:
    return tok.startswith(_URL_PREFIXES)


def _clean_url(tok: str) -> str:
    """Strip trailing shell punctuation and a ``git+`` VCS prefix (pip install form)."""
    tok = tok.rstrip(";,)")
    if tok.startswith(("git+http://", "git+https://", "git+ssh://")):
        tok = tok[4:]
    return tok


def _pipes_to_shell(stmt: List[str]) -> bool:
    # A pipe into ANY interpreter (shell OR python/perl/ruby/node/php) is a dropper.
    return "|" in stmt and any(t.rsplit("/", 1)[-1] in _INTERPRETERS for t in stmt)


def urls_to_vet(cmd: str) -> List[str]:
    """Return the ordered, de-duplicated URLs that should be vetted for ``cmd``."""
    urls: List[str] = []
    # Process each physical line independently. shlex(whitespace_split=True) treats
    # "\n" as whitespace, so _split_statements never sees the newline separator and a
    # multi-line command collapses into ONE statement (later-line curl|bash / git
    # clone dropped). Splitting on newlines first restores per-line classification.
    statements = []
    for _line in cmd.splitlines() or [cmd]:
        statements.extend(_split_statements(_tokenize(_line)))
    for stmt in statements:
        argv = _argv(stmt)
        if not argv:
            continue
        cmd0 = argv[0]
        sub = argv[1] if len(argv) > 1 else ""
        seg_urls = [_clean_url(t) for t in stmt if _is_url(t)]

        if cmd0 == "git" and sub == "clone":
            urls += seg_urls
        elif cmd0 == "gh" and sub == "repo" and len(argv) > 2 and argv[2] == "clone":
            if seg_urls:
                urls += seg_urls
            else:
                for t in argv[3:]:                       # gh repo clone owner/repo
                    if re.match(r"^[\w.-]+/[\w.-]+$", t):
                        urls.append(f"https://github.com/{t}")
                        break
        elif cmd0 in _INSTALL_CMDS:                      # pip/npm/… install <url>
            urls += seg_urls
        elif cmd0 in ("curl", "wget"):                  # only the dropper form
            if _pipes_to_shell(stmt):
                urls += seg_urls
        elif cmd0 in _SHELLS:                            # sh -c "<subcommand>"
            for j, t in enumerate(argv):
                if t == "-c" and j + 1 < len(argv):
                    urls += urls_to_vet(argv[j + 1])
        # anything else (az, echo, grep, kubectl, …) -> not a fetch -> skip

    seen, out = set(), []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def main() -> int:
    global _DEGRADED
    _DEGRADED = False
    cmd = sys.stdin.read()
    urls = urls_to_vet(cmd)
    for u in urls:
        print(u)
    fetch_kw = any(k in cmd for k in ("git clone", "gh repo clone", "curl", "wget",
                                      "pip install", "npm install"))
    # Signal "over-vet via grep" to the shell when the parse degraded or a fetch
    # keyword produced no vettable URL. The exit code is the signal; stdout stays
    # URLs-only.
    return 1 if (_DEGRADED or (fetch_kw and not urls)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
