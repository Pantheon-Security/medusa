#!/usr/bin/env python3
"""MEDUSA corpus-validation gate.

The gate that must run before a launch. Measures the two numbers that decide
whether the flagship `medusa vet` verdict is trustworthy, against a REAL corpus:

  1. FALSE-BLOCK RATE  — every KNOWN-GOOD repo must come back SAFE. A blocking
                         CAUTION/DO_NOT_INSTALL on benign code is a false positive.
  2. DETECTION RATE    — every KNOWN-VULN repo must NOT come back SAFE.

Plus the regressions the Mac shakedown surfaced:
  3. PER-RULE FP RANK  — which rules drive the false blocks (targeted fixes).
  4. DEDUP             — the same (rule,file,line) counted once, not 6x.
  5. TMP/BUILD SCANNED — findings under tmp/ , build/, dist/, zip-extract/ etc.
                         mean the scanner walked throwaway dirs it should skip.
  6. EMPTY-DIR HONESTY — a 0-file target must NOT read as SAFE with no signal.

Rerunnable on any machine that has `medusa` + the corpus. Exit 0 = GATE PASS
(zero false blocks, all vuln repos detected, no dedup/tmp regressions);
exit 1 = GATE FAIL, with the table explaining why.

Usage:
  corpus_gate.py --good ~/Documents ~/dev --vuln ~/test-repos/vuln \
                 [--medusa /path/to/medusa] [--out report.json] [--max-depth 3]
  # or explicit repo lists:
  corpus_gate.py --good-repos a b c --vuln-repos x y
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

# Findings whose path contains any of these are scanning throwaway trees.
_TMP_MARKERS = re.compile(
    r"(^|/)(tmp|temp|\.tmp|build|dist|\.cache|node_modules|\.venv|venv|"
    r"zip-?extract|zip\d+|__pycache__|\.git|site-packages)(/|$)", re.IGNORECASE
)
# Severities that can drive a blocking verdict (CAUTION/DO_NOT_INSTALL).
_BLOCK_SEV = {"CRITICAL", "HIGH"}
_CODE_EXT = (".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java",
             ".sh", ".yaml", ".yml", ".json", ".md", ".toml")


def discover_repos(roots, max_depth):
    repos = []
    for root in roots:
        root = os.path.expanduser(root)
        if not os.path.isdir(root):
            continue
        # A git repo, or a leaf project dir with code in it.
        for dirpath, dirnames, _ in os.walk(root):
            depth = dirpath[len(root):].count(os.sep)
            if depth > max_depth:
                dirnames[:] = []
                continue
            if ".git" in dirnames:
                repos.append(dirpath)
                dirnames[:] = []  # don't descend into a repo
    # de-dup, keep order
    seen, out = set(), []
    for r in repos:
        if r not in seen:
            seen.add(r); out.append(r)
    return out


def _rel(path, repo):
    """Path relative to the repo root, so the tmp/build exclusion matches
    throwaway SUBdirs — not because the repo itself lives under e.g. /tmp."""
    try:
        return os.path.relpath(str(path), repo)
    except Exception:
        return str(path)


def count_code_files(repo):
    n = 0
    for dp, dn, fn in os.walk(repo):
        rel = _rel(dp, repo)
        if rel != "." and _TMP_MARKERS.search(rel):
            dn[:] = []          # prune throwaway subtree, don't descend
            continue
        n += sum(1 for f in fn if f.endswith(_CODE_EXT))
    return n


def run(cmd, timeout=600):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def vet_repo(medusa, repo):
    """Return the authoritative verdict dict from `medusa vet --json`."""
    rc, out, _ = run([medusa, "vet", repo, "--json"])
    try:
        return json.loads(out), rc
    except Exception:
        return {"verdict": "ERROR", "score": None, "_parse_error": out[:200]}, rc


def scan_findings(medusa, repo):
    """Full findings list via `medusa scan --format json` (rule-level detail)."""
    with tempfile.TemporaryDirectory() as td:
        rc, out, err = run([medusa, "scan", repo, "--format", "json",
                            "--yes", "-o", td])
        # find the report json the scanner wrote
        cand = [p for p in Path(td).glob("medusa-scan-*.json")
                if "raw-payload" not in p.name and "history" not in p.name]
        if not cand:
            return []
        try:
            data = json.loads(cand[0].read_text())
        except Exception:
            return []
        return data.get("findings", []) or []


def analyse(repo, verdict, findings):
    blocking = [f for f in findings
                if str(f.get("severity", "")).upper() in _BLOCK_SEV]
    # dedup key: same rule at same file:line seen more than once
    keyed = Counter((f.get("rule_id"),
                     os.path.basename(str(f.get("file", ""))),
                     f.get("line")) for f in findings)
    dup_inflation = sum(c - 1 for c in keyed.values() if c > 1)
    tmp_hits = [f for f in findings
                if _TMP_MARKERS.search(_rel(f.get("file", ""), repo))]
    return {
        "repo": repo,
        "verdict": verdict.get("verdict"),
        "score": verdict.get("score"),
        "code_files": count_code_files(repo),
        "total_findings": len(findings),
        "blocking_findings": len(blocking),
        "blocking_rules": Counter(f.get("rule_id") for f in blocking),
        "dup_inflation": dup_inflation,      # extra copies of an identical finding
        "tmp_findings": len(tmp_hits),       # findings under throwaway dirs
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--good", nargs="*", default=[], help="roots to discover known-GOOD repos")
    ap.add_argument("--vuln", nargs="*", default=[], help="roots to discover known-VULN repos")
    ap.add_argument("--good-repos", nargs="*", default=[], help="explicit known-GOOD repo paths")
    ap.add_argument("--vuln-repos", nargs="*", default=[], help="explicit known-VULN repo paths")
    ap.add_argument("--medusa", default="medusa", help="path to the medusa executable")
    ap.add_argument("--max-depth", type=int, default=3)
    ap.add_argument("--out", default=None, help="write full JSON report here")
    args = ap.parse_args()

    good = args.good_repos + discover_repos(args.good, args.max_depth)
    vuln = args.vuln_repos + discover_repos(args.vuln, args.max_depth)
    if not good and not vuln:
        print("ERROR: no repos found. Pass --good/--vuln roots or --good-repos/--vuln-repos.")
        return 2

    print(f"Corpus: {len(good)} known-good, {len(vuln)} known-vuln repos "
          f"(medusa: {args.medusa})\n")

    fp_repos, fp_rule_counts = [], Counter()
    dedup_offenders, tmp_offenders, empty_offenders = [], [], []
    rows = []

    for repo in good:
        verdict, _ = vet_repo(args.medusa, repo)
        findings = scan_findings(args.medusa, repo)
        a = analyse(repo, verdict, findings)
        rows.append(("good", a))
        # empty-dir honesty: 0 code files must not read as a plain SAFE
        if a["code_files"] == 0 and a["verdict"] == "SAFE":
            empty_offenders.append(repo)
        # false block: benign repo returned a blocking verdict
        if a["verdict"] in ("CAUTION", "DO_NOT_INSTALL"):
            fp_repos.append((repo, a["verdict"], a["score"]))
            fp_rule_counts.update(a["blocking_rules"])
        if a["dup_inflation"] > 0:
            dedup_offenders.append((repo, a["dup_inflation"]))
        if a["tmp_findings"] > 0:
            tmp_offenders.append((repo, a["tmp_findings"]))

    missed = []
    for repo in vuln:
        verdict, _ = vet_repo(args.medusa, repo)
        findings = scan_findings(args.medusa, repo)
        a = analyse(repo, verdict, findings)
        rows.append(("vuln", a))
        if a["verdict"] == "SAFE":
            missed.append(repo)

    # ---- report ----
    n_good, n_vuln = len(good), len(vuln)
    fp_rate = (len(fp_repos) / n_good * 100) if n_good else 0.0
    det_rate = ((n_vuln - len(missed)) / n_vuln * 100) if n_vuln else None

    print("=" * 64)
    print("MEDUSA CORPUS-VALIDATION GATE")
    print("=" * 64)
    print(f"  FALSE-BLOCK RATE (known-good): {len(fp_repos)}/{n_good} "
          f"= {fp_rate:.1f}%   (target 0%)")
    if det_rate is not None:
        print(f"  DETECTION RATE  (known-vuln): {n_vuln-len(missed)}/{n_vuln} "
              f"= {det_rate:.1f}%   (target 100%)")
    print(f"  DEDUP inflation:  {sum(d for _,d in dedup_offenders)} extra dup findings "
          f"across {len(dedup_offenders)} repos   (target 0)")
    print(f"  TMP/BUILD scanned: {sum(t for _,t in tmp_offenders)} findings in throwaway dirs "
          f"across {len(tmp_offenders)} repos   (target 0)")
    print(f"  EMPTY-DIR-as-SAFE: {len(empty_offenders)} repos   (target 0)")

    if fp_repos:
        print("\n  Known-good repos FALSELY BLOCKED:")
        for repo, v, s in fp_repos:
            print(f"    [{v}] score {s}  {repo}")
    if fp_rule_counts:
        print("\n  PER-RULE false-positive ranking (blocking hits on good code):")
        for rule, c in fp_rule_counts.most_common(15):
            print(f"    {c:4d}  {rule}")
    if missed:
        print("\n  Known-vuln repos MISSED (returned SAFE):")
        for r in missed:
            print(f"    {r}")

    passed = (len(fp_repos) == 0 and not missed and not dedup_offenders
              and not tmp_offenders and not empty_offenders)
    print("\n" + ("GATE PASS" if passed else "GATE FAIL") +
          f"  ({len(fp_repos)} false blocks, {len(missed)} missed, "
          f"{len(dedup_offenders)} dedup, {len(tmp_offenders)} tmp, "
          f"{len(empty_offenders)} empty-safe)")

    if args.out:
        Path(args.out).write_text(json.dumps({
            "fp_rate": fp_rate, "detection_rate": det_rate,
            "false_blocked": [{"repo": r, "verdict": v, "score": s} for r, v, s in fp_repos],
            "per_rule_fp": dict(fp_rule_counts),
            "missed_vuln": missed,
            "dedup_offenders": dedup_offenders, "tmp_offenders": tmp_offenders,
            "empty_as_safe": empty_offenders,
            "rows": [{"class": c, **{k: (dict(v) if isinstance(v, Counter) else v)
                                     for k, v in a.items()}} for c, a in rows],
        }, indent=2))
        print(f"\nJSON report -> {args.out}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
