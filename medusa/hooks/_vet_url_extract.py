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

import shlex
import sys
from typing import List

_STATEMENT_SEPS = {"&&", "||", ";", "&", "\n"}
_CMD_PREFIXES = {"sudo", "doas", "env", "command", "nohup", "time", "exec", "then", "do"}
_INSTALL_CMDS = {"pip", "pip3", "pipx", "uv", "npm", "pnpm", "yarn", "poetry", "cargo", "go"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}


def _tokenize(cmd: str) -> List[str]:
    """Shell-tokenise, keeping shell operators (&& || ; | & > …) as their own tokens."""
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        # unbalanced quotes etc. — fall back to a naive split (still no execution)
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
    return "|" in stmt and any(t in _SHELLS for t in stmt)


def urls_to_vet(cmd: str) -> List[str]:
    """Return the ordered, de-duplicated URLs that should be vetted for ``cmd``."""
    urls: List[str] = []
    for stmt in _split_statements(_tokenize(cmd)):
        argv = _argv(stmt)
        if not argv:
            continue
        cmd0 = argv[0]
        sub = argv[1] if len(argv) > 1 else ""
        seg_urls = [_clean_url(t) for t in stmt if _is_url(t)]

        if cmd0 == "git" and sub == "clone":
            urls += seg_urls
        elif cmd0 == "gh" and sub == "repo":            # gh repo clone
            urls += seg_urls
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
    cmd = sys.stdin.read()
    for u in urls_to_vet(cmd):
        print(u)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
