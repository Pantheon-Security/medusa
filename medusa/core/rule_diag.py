"""
Rule diagnostics — opt-in trace + per-rule timing.

With 40k+ rules, when a rule fires a false positive, misses, or hangs a scan via
catastrophic regex backtracking, there is otherwise no way to see which rule did
what to which content. Enable via `medusa scan --trace-rules` (or the env var
MEDUSA_TRACE_RULES=1), which forces a SERIAL in-process scan so this collector
gathers everything in one process. Writes two artifacts to the report dir:

  - rule-trace.jsonl : one record per rule firing (provenance: which rule, file,
    line, matched snippet) — answers "why did this fire?".
  - slow_rules.csv   : per-rule wall time, sorted by worst single-file cost —
    names a slow/ReDoS rule in one scan.

Zero-cost when disabled: the scan loop only touches this when the module-level
`_DIAG` is set, and it times per-RULE (not per-search), so normal scans are
unaffected.
"""
import csv
import json
from pathlib import Path
from typing import Optional


class RuleDiagnostics:
    SNIPPET_LEN = 160

    def __init__(self):
        self._trace = []                      # list of trace records
        self._timings = {}                    # (rule_id, scanner) -> [total_ms, calls, max_ms, worst_file]

    def trace(self, rule_id, scanner, file_path, line_no, line_text, pattern_idx, severity=None):
        self._trace.append({
            "rule_id": rule_id,
            "scanner": scanner,
            "file": str(file_path),
            "line": line_no,
            "pattern_idx": pattern_idx,
            "severity": getattr(severity, "value", severity),
            "snippet": (line_text or "")[:self.SNIPPET_LEN].strip(),
        })

    def record_time(self, rule_id, scanner, file_path, ms):
        key = (rule_id, scanner)
        t = self._timings.get(key)
        if t is None:
            self._timings[key] = [ms, 1, ms, str(file_path)]
        else:
            t[0] += ms
            t[1] += 1
            if ms > t[2]:
                t[2] = ms
                t[3] = str(file_path)

    def write(self, output_dir: Path):
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        trace_path = output_dir / "rule-trace.jsonl"
        with open(trace_path, "w", encoding="utf-8") as f:
            for rec in self._trace:
                f.write(json.dumps(rec) + "\n")
        slow_path = output_dir / "slow_rules.csv"
        rows = sorted(
            ([rid, sc, round(t[0], 2), t[1], round(t[2], 3), t[3]]
             for (rid, sc), t in self._timings.items()),
            key=lambda r: r[4], reverse=True,   # by worst single-file ms
        )
        with open(slow_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["rule_id", "scanner", "total_ms", "calls", "max_ms_single_file", "worst_file"])
            w.writerows(rows)
        return trace_path, slow_path, len(self._trace), len(self._timings)


# Module-level singleton; None when diagnostics are off (the scan loop checks this).
_DIAG: Optional[RuleDiagnostics] = None


def enable() -> RuleDiagnostics:
    global _DIAG
    _DIAG = RuleDiagnostics()
    return _DIAG


def get() -> Optional[RuleDiagnostics]:
    return _DIAG


def disable() -> None:
    global _DIAG
    _DIAG = None
