#!/usr/bin/env python3
"""MEDUSA corpus audit harness — robust, resumable, checkpointed.

Runs MEDUSA against the labelled benchmark corpus and records, per repo:
detection (vuln repos must not be SAFE), false-block (clean repos must not
DO_NOT_INSTALL), and the per-rule / per-provenance breakdown of what drove each
verdict. Built for a machine that may lock up mid-run:

  * ONE result file per repo, written the instant that repo finishes
    (results/<repo>.json). A crash costs the in-flight repo only.
  * On restart it SKIPS repos that already have a result file — so re-running
    resumes exactly where it stopped. `--redo` forces a fresh pass.
  * Fresh scan per repo: --no-cache (the result cache is content-keyed, not
    scanner-version-keyed) + --screening (matches how `vet` runs the corpus).

Designed to run inside the Docker sandbox (see Dockerfile) so scanning
deliberately-malicious repos never touches the host, but it runs bare too.

Usage:
    audit.py --corpus /corpus --labels /corpus/benchmark_repos.csv \
             --out results/ [--only rampart garak] [--redo] [--vuln-vet-only]
    report.py results/            # aggregate the checkpoints into the tables
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

_TMP_MARKERS = re.compile(
    r"(^|/)(tmp|temp|\.tmp|build|dist|\.cache|node_modules|\.venv|venv|"
    r"zip-?extract|zip\d+|__pycache__|\.git|site-packages)(/|$)", re.IGNORECASE)
_BLOCK_SEV = {"CRITICAL", "HIGH"}
_CLEAN_CATS = {"Reference", "LLM Firewall", "Agent Security"}


def label_of(row):
    """clean (must-not-hard-block) vs vuln (must-detect), from the catalog row."""
    ev = (row.get("expected_vulnerabilities") or "").lower()
    if "not a vuln" in ev or "not vuln" in ev or "tool framework" in ev:
        return "clean"
    return "clean" if row.get("category") in _CLEAN_CATS else "vuln"


def load_labels(labels_csv):
    out = {}
    if labels_csv and os.path.exists(labels_csv):
        for r in csv.DictReader(open(labels_csv)):
            out[r["repo"]] = {"label": label_of(r), "category": r.get("category", "?")}
    return out


def find_repos(corpus, only):
    """name -> path for every git repo under corpus (depth <= 3)."""
    repos = {}
    corpus = os.path.abspath(corpus)
    for dp, dns, _ in os.walk(corpus):
        if dp[len(corpus):].count(os.sep) > 3:
            dns[:] = []
            continue
        if ".git" in dns:
            repos.setdefault(os.path.basename(dp), dp)
            dns[:] = []
    if only:
        repos = {k: v for k, v in repos.items() if k in set(only)}
    return repos


def _run(cmd, timeout):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def vet(medusa, repo, timeout, network):
    cmd = [medusa, "vet", repo, "--json"]
    rc, out, _ = _run(cmd, timeout)
    if rc == 124:
        return {"verdict": "TIMEOUT", "score": None}
    try:
        return json.loads(out)
    except Exception:
        return {"verdict": "ERROR", "score": None}


def scan_rules(medusa, repo, timeout):
    """Full screening findings for the per-rule breakdown (clean repos only)."""
    with tempfile.TemporaryDirectory() as td:
        rc, _, _ = _run([medusa, "scan", repo, "--format", "json",
                         "--screening", "--yes", "--no-cache", "-o", td], timeout)
        cand = [p for p in Path(td).glob("medusa-scan-*.json")
                if "raw-payload" not in p.name and "history" not in p.name]
        if not cand:
            return []
        try:
            return json.loads(cand[0].read_text()).get("findings", []) or []
        except Exception:
            return []


def _rel(path, repo):
    try:
        return os.path.relpath(str(path), repo)
    except Exception:
        return str(path)


def analyse_clean(repo, findings):
    blocking = [f for f in findings
                if str(f.get("severity", "")).upper() in _BLOCK_SEV]
    keyed = Counter((f.get("rule_id"), os.path.basename(str(f.get("file", ""))),
                     f.get("line")) for f in findings)
    return {
        "blocking_rules": dict(Counter(f.get("rule_id") for f in blocking)),
        "dup_inflation": sum(c - 1 for c in keyed.values() if c > 1),
        "tmp_findings": sum(1 for f in findings
                            if _TMP_MARKERS.search(_rel(f.get("file", ""), repo))),
        "total_findings": len(findings),
    }


def safe_name(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--labels", default=None)
    ap.add_argument("--out", default="results")
    ap.add_argument("--medusa", default="medusa")
    ap.add_argument("--only", nargs="*", default=None)
    ap.add_argument("--redo", action="store_true", help="ignore existing checkpoints")
    ap.add_argument("--vuln-vet-only", action="store_true",
                    help="skip the per-rule scan on vuln repos (detection only)")
    ap.add_argument("--timeout", type=int, default=420)
    ap.add_argument("--network", default="none")
    args = ap.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    labels = load_labels(args.labels)
    repos = find_repos(args.corpus, args.only)
    total = len(repos)
    print(f"corpus: {total} repos | labels: {len(labels)} | out: {outdir}", flush=True)

    done = 0
    for i, (name, path) in enumerate(sorted(repos.items()), 1):
        cp = outdir / f"{safe_name(name)}.json"
        if cp.exists() and not args.redo:
            done += 1
            continue
        label = labels.get(name, {}).get("label", "unknown")
        category = labels.get(name, {}).get("category", "?")
        t0 = time.time()
        v = vet(args.medusa, path, args.timeout, args.network)
        verdict = v.get("verdict")
        rec = {"repo": name, "path": path, "label": label, "category": category,
               "verdict": verdict, "score": v.get("score"),
               "blocking_findings": v.get("blocking_findings"),
               "counts_by_severity": v.get("counts_by_severity"),
               "top_findings": [{"rule_id": f.get("rule_id"),
                                 "severity": f.get("severity"),
                                 "file": f.get("file"), "line": f.get("line")}
                                for f in (v.get("top_findings") or [])]}
        # per-rule breakdown for clean repos (or all, unless vuln-vet-only)
        if label == "clean" or not args.vuln_vet_only:
            rec.update(analyse_clean(path, scan_rules(args.medusa, path, args.timeout)))
        rec["seconds"] = round(time.time() - t0, 1)
        cp.write_text(json.dumps(rec, indent=2))          # checkpoint NOW
        done += 1
        print(f"[{i}/{total}] {label:7} {verdict:16} {name}  ({rec['seconds']}s)",
              flush=True)

    print(f"\ndone: {done}/{total} checkpoints in {outdir}. Run report.py {outdir}.",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
