#!/usr/bin/env python3
"""Aggregate audit.py per-repo checkpoints into the audit tables.

Reads results/*.json (each written by audit.py the moment a repo finished) and
prints: detection rate on vuln repos, HARD (DO_NOT_INSTALL) vs SOFT (CAUTION)
false-block rate on clean repos, and the per-rule false-block ranking split into
HARVESTED (screening-corpus cap fixes these) vs CURATED (hand-tune). Reads only
the checkpoint files, so it works on a partial (crash-interrupted) run too.

Usage: report.py results/ [--json report.json]
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def harvested_ids():
    try:
        from medusa.rules import RuleLoader, is_screening_only
        return frozenset(rid for r in RuleLoader().load_all_rules()
                         if (rid := getattr(r, "id", None)) and is_screening_only(r))
    except Exception as e:
        print(f"  (provenance split unavailable: {e})")
        return frozenset()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    recs = []
    for p in sorted(Path(args.results).glob("*.json")):
        try:
            recs.append(json.loads(p.read_text()))
        except Exception:
            pass
    if not recs:
        print("no checkpoints found in", args.results)
        return 2

    harv = harvested_ids()
    clean = [r for r in recs if r.get("label") == "clean"]
    vuln = [r for r in recs if r.get("label") == "vuln"]

    hard = [r for r in clean if r.get("verdict") == "DO_NOT_INSTALL"]
    soft = [r for r in clean if r.get("verdict") == "CAUTION"]
    missed = [r for r in vuln if r.get("verdict") == "SAFE"]
    timeouts = [r for r in recs if r.get("verdict") in ("TIMEOUT", "ERROR")]

    fp_harv, fp_cur = Counter(), Counter()
    for r in clean:
        if r.get("verdict") in ("DO_NOT_INSTALL", "CAUTION"):
            for rid, n in (r.get("blocking_rules") or {}).items():
                (fp_harv if rid in harv else fp_cur)[rid] += n
    dedup = [(r["repo"], r.get("dup_inflation", 0)) for r in clean
             if r.get("dup_inflation", 0) > 0]
    tmp = [(r["repo"], r.get("tmp_findings", 0)) for r in clean
           if r.get("tmp_findings", 0) > 0]

    nc, nv = len(clean), len(vuln)
    print("=" * 66)
    print(f"MEDUSA CORPUS AUDIT   ({len(recs)} repos scored"
          f"{', ' + str(len(timeouts)) + ' timeout/error' if timeouts else ''})")
    print("=" * 66)
    if nc:
        print(f"  HARD-BLOCK (DO_NOT_INSTALL) on clean: {len(hard)}/{nc} "
              f"= {100*len(hard)/nc:.1f}%   (target 0%)")
        print(f"  SOFT-BLOCK (CAUTION) on clean:        {len(soft)}/{nc}   (advisory)")
    if nv:
        print(f"  DETECTION on vuln:                    {nv-len(missed)}/{nv} "
              f"= {100*(nv-len(missed))/nv:.1f}%   (target 100%)")
    print(f"  DEDUP inflation:  {sum(d for _, d in dedup)} across {len(dedup)} repos")
    print(f"  TMP/BUILD scanned: {sum(t for _, t in tmp)} across {len(tmp)} repos")

    if hard:
        print("\n  HARD-BLOCKED clean repos (worst first):")
        for r in sorted(hard, key=lambda x: -(x.get("score") or 0)):
            print(f"    score {str(r.get('score')):>7}  [{r.get('category')}] {r['repo']}")
    if missed:
        print("\n  MISSED vuln repos (returned SAFE):")
        for r in missed:
            print(f"    [{r.get('category')}] {r['repo']}")

    def rank(counter, title):
        if counter:
            print(f"\n  {title}  ({sum(counter.values())} hits, {len(counter)} rules):")
            for rid, n in counter.most_common(25):
                print(f"    {n:4d}  {rid}")
    rank(fp_cur, "CURATED false-block drivers  [hand-tune]")
    rank(fp_harv, "HARVESTED false-block drivers  [screening cap]")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "clean": nc, "vuln": nv,
            "hard_block": [{"repo": r["repo"], "score": r.get("score"),
                            "category": r.get("category")} for r in hard],
            "caution": [r["repo"] for r in soft],
            "missed": [r["repo"] for r in missed],
            "detection_rate": (100*(nv-len(missed))/nv) if nv else None,
            "hard_block_rate": (100*len(hard)/nc) if nc else None,
            "curated_fp": dict(fp_cur), "harvested_fp": dict(fp_harv),
            "timeouts": [r["repo"] for r in timeouts],
        }, indent=2))
        print(f"\nJSON -> {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
