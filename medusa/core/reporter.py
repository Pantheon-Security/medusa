#!/usr/bin/env python3
"""
MEDUSA Security Report Generator
Generates beautiful JSON/HTML security reports from MEDUSA scan results
"""

import hashlib
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict

from medusa import __version__

# Pre-compiled regex patterns for SARIF rule ID sanitisation (used per-finding)
_SARIF_RULE_ID_SANITIZE = re.compile(r'[^a-zA-Z0-9-]')
_SARIF_RULE_ID_COLLAPSE = re.compile(r'-+')

# Pre-compiled tag patterns for _generate_sarif_tags (used per-finding)
_SARIF_TAG_PATTERNS: List[tuple] = [
    ('sql', re.compile(r'\bsql\b', re.IGNORECASE)),
    ('injection', re.compile(r'\binjection\b', re.IGNORECASE)),
    ('xss', re.compile(r'\bxss\b', re.IGNORECASE)),
    ('cross-site-scripting', re.compile(r'\bcross.?site.?script', re.IGNORECASE)),
    ('prompt-injection', re.compile(r'\bprompt.?injection\b', re.IGNORECASE)),
    ('llm', re.compile(r'\bllm\b', re.IGNORECASE)),
    ('secrets', re.compile(r'\bsecret|api.?key|password|credential', re.IGNORECASE)),
    ('cryptography', re.compile(r'\bcrypto|hash|cipher|encrypt', re.IGNORECASE)),
    ('jailbreak', re.compile(r'\bjailbreak\b', re.IGNORECASE)),
    ('ai-security', re.compile(r'\bai\b|\bml\b|\bmodel\b', re.IGNORECASE)),
]

class MedusaReportGenerator:
    """Generate comprehensive security reports from MEDUSA scans"""

    SEVERITY_WEIGHTS = {
        'CRITICAL': 10,
        'HIGH': 5,
        'MEDIUM': 2,
        'LOW': 1,
        'UNDEFINED': 0
    }

    SEVERITY_COLORS = {
        'CRITICAL': '#dc3545',  # Red
        'HIGH': '#fd7e14',      # Orange
        'MEDIUM': '#ffc107',    # Yellow
        'LOW': '#0dcaf0',       # Cyan
        'UNDEFINED': '#6c757d'  # Gray
    }

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path.cwd() / ".medusa" / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = self.output_dir / "scan_history.json"

    def calculate_security_score(self, findings: List[Dict]) -> float:
        """Calculate security score (0-100, higher is better)"""
        if not findings:
            return 100.0

        # Calculate weighted issue score
        total_weight = sum(
            self.SEVERITY_WEIGHTS.get(f['severity'], 0)
            for f in findings
        )

        # Penalty: -1 point per weighted issue, minimum 0
        score = max(0, 100 - total_weight)

        return round(score, 2)

    def calculate_risk_level(self, score: float) -> str:
        """Determine risk level from security score"""
        if score >= 95:
            return "EXCELLENT"
        elif score >= 85:
            return "GOOD"
        elif score >= 70:
            return "MODERATE"
        elif score >= 50:
            return "CONCERNING"
        else:
            return "CRITICAL"

    def aggregate_findings(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate findings by severity, file, scanner"""
        findings = scan_results.get('findings', [])

        by_severity = defaultdict(list)
        by_file = defaultdict(list)
        by_scanner = defaultdict(list)

        for finding in findings:
            by_severity[finding['severity']].append(finding)
            by_file[finding['file']].append(finding)
            by_scanner[finding['scanner']].append(finding)

        return {
            'by_severity': dict(by_severity),
            'by_file': dict(by_file),
            'by_scanner': dict(by_scanner)
        }

    def generate_json_report(self, scan_results: Dict[str, Any], output_path: Path = None, ai_safe: bool = False) -> Path:
        """Generate JSON report"""
        timestamp = datetime.now().isoformat()
        findings = list(scan_results.get('findings', []))

        # Apply AI-safe obfuscation if requested
        obfuscator = None
        if ai_safe:
            obfuscator = PayloadObfuscator()
            findings = obfuscator.obfuscate_findings(findings)

        # FP stats
        fp_stats = scan_results.get('fp_stats')
        likely_fps = scan_results.get('likely_fps', [])

        report = {
            'timestamp': timestamp,
            'medusa_version': __version__,
            'scanner': {
                'name': 'MEDUSA',
                'version': __version__,
                'analyzers': 76,
                'rules': '3,000+',
                'url': 'https://medusa-security.dev',
            },
            'scan_summary': {
                'total_issues': len(findings),
                'files_scanned': scan_results.get('files_scanned', 0),
                'lines_scanned': scan_results.get('total_lines_scanned', 0),
                'security_score': self.calculate_security_score(findings),
                'risk_level': self.calculate_risk_level(self.calculate_security_score(findings)),
                'false_positives_filtered': len(likely_fps),
                'missing_linters': scan_results.get('missing_linters', []),
            },
            'severity_breakdown': {
                severity: len([f for f in findings if f['severity'] == severity])
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNDEFINED']
            },
            'findings': findings,
            'aggregations': self.aggregate_findings({'findings': findings})
        }

        if fp_stats:
            report['fp_stats'] = fp_stats

        if ai_safe:
            report['ai_safe_mode'] = True

        # Save report
        output_path = output_path or self.output_dir / f"medusa-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        # Save raw payloads alongside report when ai_safe is enabled
        if ai_safe and obfuscator is not None:
            obfuscator.save_raw_payloads(output_path)

        # Update history
        self._update_history(report)

        return output_path

    def _update_history(self, report: Dict[str, Any]):
        """Update scan history for trend analysis"""
        history = []
        if self.history_file.exists():
            with open(self.history_file) as f:
                history = json.load(f)

        history.append({
            'timestamp': report['timestamp'],
            'security_score': report['scan_summary']['security_score'],
            'risk_level': report['scan_summary']['risk_level'],
            'total_issues': report['scan_summary']['total_issues'],
            'severity_breakdown': report['severity_breakdown']
        })

        # Keep last 100 scans
        history = history[-100:]

        with open(self.history_file, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2)

    def generate_html_report(self, json_report_path: Path, output_path: Path = None) -> Path:
        """Generate beautiful HTML report from JSON"""
        with open(json_report_path) as f:
            report = json.load(f)

        output_path = output_path or json_report_path.with_suffix('.html')

        html = self._build_html_report(report)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        return output_path

    def generate_markdown_report(self, scan_results: Dict[str, Any], output_path: Path = None, ai_safe: bool = False) -> Path:
        """Generate Markdown report from scan results"""
        timestamp = datetime.now().isoformat()
        findings = list(scan_results.get('findings', []))

        # Apply AI-safe obfuscation if requested
        obfuscator = None
        if ai_safe:
            obfuscator = PayloadObfuscator()
            findings = obfuscator.obfuscate_findings(findings)

        # Calculate metrics
        security_score = self.calculate_security_score(findings)
        risk_level = self.calculate_risk_level(security_score)

        severity_breakdown = {
            severity: len([f for f in findings if f['severity'] == severity])
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNDEFINED']
        }

        # Build markdown content
        md = f"""# MEDUSA Security Scan Report

**Generated:** {datetime.fromisoformat(timestamp).strftime('%B %d, %Y at %H:%M:%S')}
**MEDUSA Version:** {__version__}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Security Score** | **{security_score}/100** |
| **Risk Level** | **{risk_level}** |
| **Total Issues** | {len(findings)} |
| **Files Scanned** | {scan_results.get('files_scanned', 0)} |
| **Lines Scanned** | {scan_results.get('total_lines_scanned', 0):,} |

---

## Severity Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
"""

        # Add severity rows
        total_issues = len(findings) if findings else 1  # Avoid division by zero
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_breakdown.get(severity, 0)
            if count > 0:
                percentage = (count / total_issues) * 100
                emoji = {'CRITICAL': '🚨', 'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🔵'}.get(severity, '⚪')
                md += f"| {emoji} **{severity}** | {count} | {percentage:.1f}% |\n"

        md += "\n---\n\n"

        # Add detailed findings
        if findings:
            md += "## Detailed Findings\n\n"

            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNDEFINED': 4}
            sorted_findings = sorted(findings, key=lambda f: severity_order.get(f['severity'], 99))

            for i, finding in enumerate(sorted_findings, 1):
                severity = finding['severity']
                emoji = {'CRITICAL': '🚨', 'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🔵', 'UNDEFINED': '⚪'}.get(severity, '⚪')

                md += f"### {i}. {emoji} {severity}: {finding['issue']}\n\n"
                md += f"**File:** `{finding['file']}:{finding['line']}`  \n"
                md += f"**Scanner:** {finding['scanner']}  \n"
                md += f"**Confidence:** {finding.get('confidence', 'N/A')}  \n"

                cwe = finding.get('cwe')
                if cwe and str(cwe).isdigit():
                    md += f"**CWE:** [CWE-{cwe}](https://cwe.mitre.org/data/definitions/{cwe}.html)  \n"

                if finding.get('code'):
                    md += f"\n**Code:**\n```\n{finding['code']}\n```\n"

                md += "\n---\n\n"
        else:
            md += "## Detailed Findings\n\n✨ **No security issues found!** Your code is excellent!\n\n---\n\n"

        # Missing linters note
        missing_linters = scan_results.get('missing_linters', [])
        if missing_linters:
            linter_list = ', '.join(missing_linters[:8])
            if len(missing_linters) > 8:
                linter_list += f' (+{len(missing_linters) - 8} more)'
            md += f"""## Coverage Note

> **{len(missing_linters)} external linter(s) not installed:** {linter_list}
>
> For fuller coverage, install these tools and re-scan. Run `medusa install --check` for details.

---

"""

        # Footer
        md += f"""## About MEDUSA

MEDUSA is an AI-first security scanner with 76 analyzers and 3,000+ detection rules for AI/ML, LLM agents, and MCP servers.

**Learn more:** [MEDUSA Security](https://medusa-security.dev)

---

*Report generated by MEDUSA v{__version__}*
"""

        # Save markdown report
        output_path = output_path or self.output_dir / f"medusa-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)

        # Save raw payloads alongside report when ai_safe is enabled
        if ai_safe and obfuscator is not None:
            obfuscator.save_raw_payloads(output_path)

        return output_path

    def generate_sarif_report(self, scan_results: Dict[str, Any], output_path: Path = None, ai_safe: bool = False) -> Path:
        """Generate SARIF 2.1.0 report for GitHub Code Scanning integration"""
        findings = list(scan_results.get('findings', []))

        # Apply AI-safe obfuscation if requested
        obfuscator = None
        if ai_safe:
            obfuscator = PayloadObfuscator()
            findings = obfuscator.obfuscate_findings(findings)

        # Severity to SARIF level mapping
        severity_to_level = {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'note',
            'INFO': 'note',
            'UNDEFINED': 'note',
        }

        # Severity to security-severity score (for GitHub)
        severity_to_score = {
            'CRITICAL': '9.0',
            'HIGH': '7.0',
            'MEDIUM': '4.0',
            'LOW': '1.0',
            'INFO': '0.5',
            'UNDEFINED': '0.0',
        }

        # Build rules and results
        rules: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []
        seen_rule_ids: Dict[str, int] = {}

        for finding in findings:
            # Determine rule ID
            cwe = finding.get('cwe')
            if cwe and str(cwe).isdigit():
                rule_id = f"CWE-{cwe}"
            else:
                cwe = None  # Clear invalid CWE
                # Sanitize issue text into a rule ID
                rule_id = _SARIF_RULE_ID_SANITIZE.sub('-', finding.get('issue', 'unknown'))
                rule_id = _SARIF_RULE_ID_COLLAPSE.sub('-', rule_id).strip('-')

            # Track rule index for ruleIndex reference
            if rule_id not in seen_rule_ids:
                rule_index = len(rules)
                seen_rule_ids[rule_id] = rule_index

                # Build rule definition
                rule_def: Dict[str, Any] = {
                    'id': rule_id,
                    'name': finding.get('issue', 'Unknown Issue'),
                    'shortDescription': {
                        'text': finding.get('issue', 'Unknown Issue'),
                    },
                    'fullDescription': {
                        'text': finding.get('issue', 'Unknown Issue'),
                    },
                    'properties': {
                        'security-severity': severity_to_score.get(finding.get('severity', 'UNDEFINED'), '0.0'),
                        'tags': self._generate_sarif_tags(finding),
                    },
                }

                # Add CWE help URI
                if cwe:
                    rule_def['helpUri'] = f"https://cwe.mitre.org/data/definitions/{cwe}.html"

                rules.append(rule_def)
            else:
                rule_index = seen_rule_ids[rule_id]

            # Build fingerprint
            fingerprint_input = f"{rule_id}:{finding.get('file', '')}:{finding.get('line', '')}:{finding.get('issue', '')}"
            fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()

            # Build location
            region: Dict[str, Any] = {
                'startLine': finding.get('line', 1),
            }
            if finding.get('code'):
                region['snippet'] = {'text': finding['code']}

            location = {
                'physicalLocation': {
                    'artifactLocation': {
                        'uri': finding.get('file', 'unknown'),
                        'uriBaseId': '%SRCROOT%',
                    },
                    'region': region,
                }
            }

            # Build result
            result: Dict[str, Any] = {
                'ruleId': rule_id,
                'ruleIndex': rule_index,
                'level': severity_to_level.get(finding.get('severity', 'UNDEFINED'), 'note'),
                'message': {
                    'text': finding.get('issue', 'Unknown Issue'),
                },
                'locations': [location],
                'fingerprints': {
                    'medusa/v1': fingerprint,
                },
                'properties': {
                    'security-severity': severity_to_score.get(finding.get('severity', 'UNDEFINED'), '0.0'),
                    'tags': self._generate_sarif_tags(finding),
                },
            }

            results.append(result)

        # Build SARIF document
        sarif = {
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
            'version': '2.1.0',
            'runs': [
                {
                    'tool': {
                        'driver': {
                            'name': 'MEDUSA',
                            'semanticVersion': __version__,
                            'informationUri': 'https://medusa-security.dev',
                            'rules': rules,
                        }
                    },
                    'results': results,
                    'invocations': [
                        {
                            'executionSuccessful': True,
                            'toolExecutionNotifications': [],
                        }
                    ],
                }
            ],
        }

        # Save SARIF report
        output_path = output_path or self.output_dir / f"medusa-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.sarif"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2)

        # Save raw payloads alongside report when ai_safe is enabled
        if ai_safe and obfuscator is not None:
            obfuscator.save_raw_payloads(output_path)

        return output_path

    def _generate_sarif_tags(self, finding: Dict[str, Any]) -> List[str]:
        """Generate tags for a SARIF rule based on finding content."""
        tags = ['security']
        issue = finding.get('issue', '').lower()
        code = finding.get('code', '').lower()
        text = f"{issue} {code}"

        for tag, compiled in _SARIF_TAG_PATTERNS:
            if compiled.search(text):
                tags.append(tag)

        # Add CWE tag if present
        cwe = finding.get('cwe')
        if cwe:
            tags.append(f"external/cwe/cwe-{cwe}")

        return tags

    def _build_html_report(self, report: Dict[str, Any]) -> str:
        """Build professional, clean HTML security report"""
        from medusa import __version__

        summary = report['scan_summary']
        severity_breakdown = report['severity_breakdown']
        findings = report['findings']

        # Calculate actual severity counts from findings
        actual_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in findings:
            sev = f.get('severity', 'LOW').upper()
            if sev in actual_counts:
                actual_counts[sev] += 1

        # Scanner summary: count findings per scanner
        scanner_counts = defaultdict(int)
        for f in findings:
            scanner_counts[f.get('scanner', 'unknown')] += 1

        # FP stats from report
        fp_filtered = summary.get('false_positives_filtered', 0)

        # Get score color based on value
        score = summary['security_score']
        if score >= 90:
            score_color = '#22c55e'  # Green
        elif score >= 70:
            score_color = '#eab308'  # Yellow
        elif score >= 50:
            score_color = '#f97316'  # Orange
        else:
            score_color = '#ef4444'  # Red

        # Build scanner summary rows
        scanner_rows = ''
        for scanner_name, count in sorted(scanner_counts.items(), key=lambda x: x[1], reverse=True):
            scanner_rows += f'''
                <tr>
                    <td style="padding: 10px 16px; border-bottom: 1px solid var(--border);">{scanner_name}</td>
                    <td style="padding: 10px 16px; border-bottom: 1px solid var(--border); text-align: right; font-weight: 600;">{count}</td>
                </tr>'''

        # Missing linters banner
        missing_linters = summary.get('missing_linters', [])
        linter_banner = ''
        if missing_linters:
            linter_list = ', '.join(missing_linters[:8])
            if len(missing_linters) > 8:
                linter_list += f' (+{len(missing_linters) - 8} more)'
            linter_banner = f'''
        <div style="background: #1c1f26; border: 1px solid #d29922; border-radius: 12px; padding: 20px; margin-bottom: 24px;">
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                <span style="font-size: 20px;">&#9888;</span>
                <span style="font-size: 16px; font-weight: 600; color: #d29922;">{len(missing_linters)} External Linter(s) Not Installed</span>
            </div>
            <p style="color: var(--text-muted); margin-bottom: 8px; font-size: 14px;">
                For fuller coverage, install these tools and re-scan: <span style="color: var(--text);">{linter_list}</span>
            </p>
            <p style="color: var(--text-muted); font-size: 13px;">
                Run <code style="background: var(--bg); padding: 2px 6px; border-radius: 4px; color: var(--primary);">medusa install --check</code> for details and install instructions.
            </p>
        </div>'''

        # FP stats section
        fp_section = ''
        if fp_filtered > 0:
            fp_section = f'''
        <div class="summary-card" style="border-left: 3px solid var(--success);">
            <div class="summary-label">FPs Filtered</div>
            <div class="summary-value" style="color: var(--success);">{fp_filtered}</div>
        </div>'''

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MEDUSA Security Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        :root {{
            /* MEDUSA Security Brand Colors */
            --bg: #0d1117;
            --bg-card: #161b22;
            --bg-card-hover: #21262d;
            --border: #30363d;
            --text: #e6edf3;
            --text-muted: #8b949e;
            --primary: #00CED1;          /* Cyan - brand primary */
            --primary-dark: #123B70;     /* Dark blue */
            --accent: #98FB92;           /* Electric green */
            --critical: #f85149;
            --high: #db6d28;
            --medium: #d29922;
            --low: #00CED1;              /* Use brand cyan for low */
            --info: #8b949e;             /* Gray for info */
            --success: #98FB92;          /* Brand green */
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 24px;
        }}

        /* Header */
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 48px;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border);
        }}

        .logo {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}

        .logo-icon {{
            height: 48px;
            flex-shrink: 0;
        }}

        .logo-text {{
            font-size: 28px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}

        .logo-subtitle {{
            font-size: 13px;
            color: var(--text-muted);
            font-weight: 400;
        }}

        .report-meta {{
            text-align: right;
            color: var(--text-muted);
            font-size: 14px;
        }}

        .report-meta .version-badge {{
            display: inline-block;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 2px 10px;
            font-size: 12px;
            font-weight: 600;
            color: var(--primary);
            margin-top: 6px;
        }}

        /* Summary Cards */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }}

        .summary-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
        }}

        .summary-card.score {{
            grid-column: span 2;
            display: flex;
            align-items: center;
            gap: 24px;
        }}

        .score-circle {{
            position: relative;
            width: 100px;
            height: 100px;
            flex-shrink: 0;
        }}

        .score-circle svg {{
            transform: rotate(-90deg);
            width: 100%;
            height: 100%;
        }}

        .score-bg {{
            fill: none;
            stroke: var(--border);
            stroke-width: 8;
        }}

        .score-progress {{
            fill: none;
            stroke: {score_color};
            stroke-width: 8;
            stroke-linecap: round;
            stroke-dasharray: 251;
            stroke-dashoffset: {251 - (251 * score / 100)};
        }}

        .score-value {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 28px;
            font-weight: 700;
            color: {score_color};
        }}

        .score-info h3 {{
            font-size: 14px;
            color: var(--text-muted);
            font-weight: 500;
            margin-bottom: 4px;
        }}

        .score-info .risk {{
            font-size: 24px;
            font-weight: 600;
        }}

        .summary-label {{
            font-size: 13px;
            color: var(--text-muted);
            margin-bottom: 8px;
            font-weight: 500;
        }}

        .summary-value {{
            font-size: 32px;
            font-weight: 700;
        }}

        /* Severity Breakdown */
        .severity-section {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }}

        .section-title {{
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 16px;
        }}

        .severity-item {{
            background: var(--bg);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}

        .severity-count {{
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 4px;
        }}

        .severity-count.critical {{ color: var(--critical); }}
        .severity-count.high {{ color: var(--high); }}
        .severity-count.medium {{ color: var(--medium); }}
        .severity-count.low {{ color: var(--low); }}
        .severity-count.info {{ color: var(--info); }}

        .severity-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .severity-label.critical {{ color: var(--critical); }}
        .severity-label.high {{ color: var(--high); }}
        .severity-label.medium {{ color: var(--medium); }}
        .severity-label.low {{ color: var(--low); }}
        .severity-label.info {{ color: var(--info); }}

        /* Scanner Summary */
        .scanner-section {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }}

        .scanner-table {{
            width: 100%;
            border-collapse: collapse;
        }}

        .scanner-table th {{
            text-align: left;
            padding: 10px 16px;
            border-bottom: 2px solid var(--border);
            color: var(--text-muted);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .scanner-table th:last-child {{
            text-align: right;
        }}

        .scanner-table td {{
            color: var(--text);
            font-size: 14px;
        }}

        /* Findings */
        .findings-section {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
        }}

        .finding {{
            background: var(--bg);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
            border-left: 4px solid var(--border);
        }}

        .finding:last-child {{
            margin-bottom: 0;
        }}

        .finding.critical {{ border-left-color: var(--critical); }}
        .finding.high {{ border-left-color: var(--high); }}
        .finding.medium {{ border-left-color: var(--medium); }}
        .finding.low {{ border-left-color: var(--low); }}
        .finding.info {{ border-left-color: var(--info); }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
            gap: 16px;
        }}

        .finding-location {{
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 13px;
            color: var(--text-muted);
            background: var(--bg-card);
            padding: 4px 10px;
            border-radius: 4px;
            word-break: break-all;
        }}

        .finding-badge {{
            font-size: 11px;
            font-weight: 600;
            padding: 4px 10px;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            flex-shrink: 0;
        }}

        .finding-badge.critical {{ background: var(--critical); color: white; }}
        .finding-badge.high {{ background: var(--high); color: white; }}
        .finding-badge.medium {{ background: var(--medium); color: #1e293b; }}
        .finding-badge.low {{ background: var(--low); color: white; }}
        .finding-badge.info {{ background: var(--info); color: white; }}

        .finding-message {{
            font-size: 15px;
            color: var(--text);
            margin-bottom: 12px;
            line-height: 1.5;
        }}

        .finding-code {{
            background: #0d1117;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 14px;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 13px;
            color: #e6edf3;
            overflow-x: auto;
            margin-bottom: 12px;
        }}

        .finding-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            font-size: 13px;
            color: var(--text-muted);
        }}

        .finding-meta a {{
            color: var(--primary);
            text-decoration: none;
        }}

        .finding-meta a:hover {{
            text-decoration: underline;
        }}

        .no-findings {{
            text-align: center;
            padding: 60px 20px;
            color: var(--success);
        }}

        .no-findings-icon {{
            font-size: 48px;
            margin-bottom: 16px;
        }}

        .no-findings-text {{
            font-size: 18px;
            font-weight: 500;
        }}

        /* Footer */
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 24px;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 14px;
        }}

        .footer a {{
            color: var(--primary);
            text-decoration: none;
        }}

        @media (max-width: 768px) {{
            .summary-grid {{
                grid-template-columns: 1fr;
            }}
            .summary-card.score {{
                grid-column: span 1;
            }}
            .severity-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            .header {{
                flex-direction: column;
                gap: 16px;
                text-align: center;
            }}
            .report-meta {{
                text-align: center;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo">
                <img class="logo-icon" src="{self._get_logo_data_uri()}" alt="Pantheon Security"/>
                <div>
                    <div class="logo-text">MEDUSA</div>
                    <div class="logo-subtitle">76 Analyzers &bull; 3,000+ Detection Rules</div>
                </div>
            </div>
            <div class="report-meta">
                <div>Security Scan Report</div>
                <div>{datetime.fromisoformat(report['timestamp']).strftime('%B %d, %Y at %H:%M')}</div>
                <div class="version-badge">v{__version__}</div>
            </div>
        </header>

        <div class="summary-grid">
            <div class="summary-card score">
                <div class="score-circle">
                    <svg viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="40" class="score-bg"/>
                        <circle cx="50" cy="50" r="40" class="score-progress"/>
                    </svg>
                    <div class="score-value">{int(score)}</div>
                </div>
                <div class="score-info">
                    <h3>Security Score</h3>
                    <div class="risk" style="color: {score_color}">{summary['risk_level']}</div>
                </div>
            </div>
            <div class="summary-card">
                <div class="summary-label">Total Issues</div>
                <div class="summary-value">{summary['total_issues']}</div>
            </div>
            <div class="summary-card">
                <div class="summary-label">Files Scanned</div>
                <div class="summary-value">{summary['files_scanned']}</div>
            </div>
            <div class="summary-card">
                <div class="summary-label">Lines Scanned</div>
                <div class="summary-value">{summary.get('lines_scanned', 0):,}</div>
            </div>
        </div>

        <div class="severity-section">
            <h2 class="section-title">Severity Breakdown</h2>
            <div class="severity-grid">
                <div class="severity-item">
                    <div class="severity-count critical">{actual_counts['CRITICAL']}</div>
                    <div class="severity-label critical">Critical</div>
                </div>
                <div class="severity-item">
                    <div class="severity-count high">{actual_counts['HIGH']}</div>
                    <div class="severity-label high">High</div>
                </div>
                <div class="severity-item">
                    <div class="severity-count medium">{actual_counts['MEDIUM']}</div>
                    <div class="severity-label medium">Medium</div>
                </div>
                <div class="severity-item">
                    <div class="severity-count low">{actual_counts['LOW']}</div>
                    <div class="severity-label low">Low</div>
                </div>
                <div class="severity-item">
                    <div class="severity-count info">{actual_counts['INFO']}</div>
                    <div class="severity-label info">Info</div>
                </div>
            </div>
        </div>

        <div class="scanner-section">
            <h2 class="section-title">Scanner Summary</h2>
            <table class="scanner-table">
                <thead>
                    <tr>
                        <th>Scanner</th>
                        <th>Findings</th>
                    </tr>
                </thead>
                <tbody>{scanner_rows}
                </tbody>
            </table>
        </div>

        {linter_banner}

        <div class="findings-section">
            <h2 class="section-title">Findings ({len(findings)})</h2>
            {self._build_professional_findings_html(findings)}
        </div>

        <footer class="footer">
            <p>Generated by <strong>MEDUSA</strong> v{__version__} &mdash; 76 Analyzers &bull; 3,000+ Rules &bull; AI Security Detection</p>
            <p><a href="https://medusa-security.dev">medusa-security.dev</a></p>
        </footer>
    </div>
</body>
</html>"""

        return html

    def _build_professional_findings_html(self, findings: List[Dict]) -> str:
        """Build professional findings list"""
        if not findings:
            return '''
            <div class="no-findings">
                <div class="no-findings-icon">&#10003;</div>
                <div class="no-findings-text">No security issues found</div>
            </div>
            '''

        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4, 'UNDEFINED': 5}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get('severity', 'LOW').upper(), 99))

        import html as html_lib

        html_parts = []
        for finding in sorted_findings:
            severity = finding.get('severity', 'LOW').upper()
            severity_class = severity.lower()

            # Escape HTML in user content
            issue = html_lib.escape(finding.get('issue', 'Unknown issue'))
            file_path = html_lib.escape(str(finding.get('file', 'Unknown')))
            line = finding.get('line', '?')
            code = html_lib.escape(finding.get('code', '')) if finding.get('code') else ''
            scanner = html_lib.escape(finding.get('scanner', 'unknown'))
            confidence = html_lib.escape(str(finding.get('confidence', 'N/A')))
            cwe = finding.get('cwe')

            code_block = f'<pre class="finding-code">{code}</pre>' if code else ''

            # Only render CWE link if it's a valid numeric ID
            cwe_link = ''
            if cwe and str(cwe).isdigit():
                cwe_link = f'<span>CWE-{cwe}: <a href="https://cwe.mitre.org/data/definitions/{cwe}.html" target="_blank">Details</a></span>'

            # FP analysis badge
            fp_analysis = finding.get('fp_analysis', {})
            fp_badge = ''
            if fp_analysis.get('is_likely_fp'):
                fp_badge = '<span style="color: var(--medium);">Likely FP</span>'

            html_parts.append(f'''
            <div class="finding {severity_class}">
                <div class="finding-header">
                    <span class="finding-location">{file_path}:{line}</span>
                    <span class="finding-badge {severity_class}">{severity}</span>
                </div>
                <div class="finding-message">{issue}</div>
                {code_block}
                <div class="finding-meta">
                    <span>Scanner: {scanner}</span>
                    <span>Confidence: {confidence}</span>
                    {cwe_link}
                    {fp_badge}
                </div>
            </div>
            ''')

        return ''.join(html_parts)

    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level badge"""
        colors = {
            'EXCELLENT': '#28a745',
            'GOOD': '#20c997',
            'MODERATE': '#ffc107',
            'CONCERNING': '#fd7e14',
            'CRITICAL': '#dc3545'
        }
        return colors.get(risk_level, '#6c757d')

    def _get_risk_gradient(self, risk_level: str) -> str:
        """Get gradient for risk level badge"""
        gradients = {
            'EXCELLENT': 'linear-gradient(135deg, #10b981, #059669)',
            'GOOD': 'linear-gradient(135deg, #3b82f6, #2563eb)',
            'MODERATE': 'linear-gradient(135deg, #f59e0b, #d97706)',
            'CONCERNING': 'linear-gradient(135deg, #f97316, #ea580c)',
            'CRITICAL': 'linear-gradient(135deg, #ef4444, #dc2626)'
        }
        return gradients.get(risk_level, 'linear-gradient(135deg, #6b7280, #4b5563)')

    def _get_risk_shadow(self, risk_level: str) -> str:
        """Get shadow color for risk level badge"""
        shadows = {
            'EXCELLENT': 'rgba(16, 185, 129, 0.4)',
            'GOOD': 'rgba(59, 130, 246, 0.4)',
            'MODERATE': 'rgba(245, 158, 11, 0.4)',
            'CONCERNING': 'rgba(249, 115, 22, 0.4)',
            'CRITICAL': 'rgba(239, 68, 68, 0.4)'
        }
        return shadows.get(risk_level, 'rgba(107, 114, 128, 0.4)')

    def _get_logo_data_uri(self) -> str:
        """Return the Pantheon Security logo as a base64 data URI for HTML embedding"""
        from medusa.core.report_assets import LOGO_DATA_URI
        return LOGO_DATA_URI

    def _build_modern_severity_bars(self, severity_breakdown: Dict[str, int], total: int) -> str:
        """Build modern severity bars with gradients and animations"""
        if total == 0:
            return '<p style="text-align: center; color: var(--success); font-size: 1.2em; padding: 40px;">✨ No security issues found! Your code is excellent!</p>'

        severity_config = {
            'CRITICAL': {'icon': '🚨', 'color_start': '#ef4444', 'color_end': '#dc2626'},
            'HIGH': {'icon': '🔴', 'color_start': '#f97316', 'color_end': '#ea580c'},
            'MEDIUM': {'icon': '🟡', 'color_start': '#f59e0b', 'color_end': '#d97706'},
            'LOW': {'icon': '🔵', 'color_start': '#3b82f6', 'color_end': '#2563eb'}
        }

        bars = []
        for severity, config in severity_config.items():
            count = severity_breakdown.get(severity, 0)
            if count == 0:
                continue

            percentage = (count / total) * 100 if total > 0 else 0

            bars.append(f"""
            <div class="severity-bar">
                <div class="severity-header">
                    <div class="severity-name">
                        <span>{config['icon']}</span>
                        <span>{severity}</span>
                    </div>
                    <div class="severity-count">{count} issue{'s' if count != 1 else ''}</div>
                </div>
                <div class="bar-track">
                    <div class="bar-progress" style="width: {percentage}%; --color-start: {config['color_start']}; --color-end: {config['color_end']};"></div>
                </div>
            </div>
            """)

        return ''.join(bars)

    def _build_modern_findings_html(self, findings: List[Dict]) -> str:
        """Build modern findings cards with hover effects"""
        if not findings:
            return '<p style="text-align: center; color: var(--success); font-size: 1.2em; padding: 40px;">✨ No security issues found! Your code is excellent!</p>'

        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNDEFINED': 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f['severity'], 99))

        severity_colors = {
            'CRITICAL': '#ef4444',
            'HIGH': '#f97316',
            'MEDIUM': '#f59e0b',
            'LOW': '#3b82f6',
            'UNDEFINED': '#6b7280'
        }

        severity_shadows = {
            'CRITICAL': 'rgba(239, 68, 68, 0.3)',
            'HIGH': 'rgba(249, 115, 22, 0.3)',
            'MEDIUM': 'rgba(245, 158, 11, 0.3)',
            'LOW': 'rgba(59, 130, 246, 0.3)',
            'UNDEFINED': 'rgba(107, 114, 128, 0.3)'
        }

        cards = []
        for finding in sorted_findings:
            severity = finding['severity']
            color = severity_colors.get(severity, '#6b7280')
            shadow = severity_shadows.get(severity, 'rgba(107, 114, 128, 0.3)')

            cards.append(f"""
            <div class="finding-card" style="--severity-color: {color}; --severity-shadow: {shadow};">
                <div class="finding-header">
                    <div class="finding-file">📁 {finding['file']}:{finding['line']}</div>
                    <div class="severity-badge" style="--severity-color: {color}; --severity-shadow: {shadow};">
                        {severity}
                    </div>
                </div>
                <div class="finding-issue">{finding['issue']}</div>
                {f'<div class="finding-code">{finding.get("code", "")}</div>' if finding.get('code') else ''}
                <div class="finding-meta">
                    <div class="meta-item">🔍 Scanner: <strong>{finding['scanner']}</strong></div>
                    <div class="meta-item">📊 Confidence: <strong>{finding.get('confidence', 'N/A')}</strong></div>
                    {f'<div class="meta-item">🔗 <a href="https://cwe.mitre.org/data/definitions/{finding["cwe"]}.html" target="_blank" style="color: var(--primary);">CWE-{finding["cwe"]}</a></div>' if finding.get('cwe') else ''}
                </div>
            </div>
            """)

        return ''.join(cards)

    def _build_severity_bars(self, severity_breakdown: Dict[str, int], total: int) -> str:
        """Build severity bar charts HTML (legacy fallback)"""
        if total == 0:
            return '<p style="text-align: center; color: #28a745; font-size: 1.2em;">✅ No security issues found!</p>'

        bars = []
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_breakdown.get(severity, 0)
            if count == 0:
                continue

            percentage = (count / total) * 100 if total > 0 else 0
            color = self.SEVERITY_COLORS[severity]

            bars.append(f"""
            <div class="severity-bar">
                <div class="severity-label">
                    <span>{severity}</span>
                    <span>{count} issue{'s' if count != 1 else ''}</span>
                </div>
                <div class="bar-container">
                    <div class="bar-fill" style="width: {percentage}%; background: {color};">
                        {percentage:.1f}%
                    </div>
                </div>
            </div>
            """)

        return ''.join(bars)

    def _build_findings_html(self, findings: List[Dict]) -> str:
        """Build findings cards HTML"""
        if not findings:
            return '<p style="text-align: center; color: #28a745; font-size: 1.2em;">✅ No security issues found!</p>'

        # Sort by severity (CRITICAL first)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNDEFINED': 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f['severity'], 99))

        cards = []
        for finding in sorted_findings:
            severity = finding['severity']
            color = self.SEVERITY_COLORS[severity]

            cards.append(f"""
            <div class="finding-card" style="border-left-color: {color};">
                <div class="finding-header">
                    <div>
                        <div class="finding-file">📁 {finding['file']}:{finding['line']}</div>
                    </div>
                    <span class="severity-badge" style="background: {color};">{severity}</span>
                </div>
                <div class="finding-issue">
                    <strong>{finding['issue']}</strong>
                </div>
                {f'<div class="finding-code">{finding.get("code", "")}</div>' if finding.get('code') else ''}
                <div style="margin-top: 10px; font-size: 0.85em; color: #6c757d;">
                    Scanner: {finding['scanner']} | Confidence: {finding.get('confidence', 'N/A')}
                    {f' | CWE-{finding["cwe"]}' if finding.get('cwe') else ''}
                </div>
            </div>
            """)

        return ''.join(cards)


class PayloadObfuscator:
    """Obfuscate dangerous payloads (prompt injection, jailbreaks) in scan reports.

    Prevents prompt injection payloads found during scanning from being passed
    through to AI agents or downstream consumers that read the reports.
    """

    DANGEROUS_ISSUE_PATTERNS = [
        re.compile(r'PI-.*\d', re.IGNORECASE),
        re.compile(r'JB-.*\d', re.IGNORECASE),
        re.compile(r'RAG-.*\d', re.IGNORECASE),
        re.compile(r'prompt.?injection', re.IGNORECASE),
        re.compile(r'jailbreak', re.IGNORECASE),
        re.compile(r'MCP.*manipulation', re.IGNORECASE),
    ]

    DANGEROUS_CODE_PATTERNS = [
        re.compile(r'ignore\s+(all\s+)?previous\s+instructions', re.IGNORECASE),
        re.compile(r'you\s+are\s+now\s+', re.IGNORECASE),
        re.compile(r'bypass\s+guardrail', re.IGNORECASE),
        re.compile(r'DAN\s+mode', re.IGNORECASE),
        re.compile(r'override\s+all\s+previous', re.IGNORECASE),
        re.compile(r'system:\s*override', re.IGNORECASE),
        re.compile(r'ignores?\s+safety', re.IGNORECASE),
    ]

    ATTACK_CATEGORIES = [
        (re.compile(r'PI-|prompt.?inject', re.IGNORECASE), 'Prompt Injection'),
        (re.compile(r'JB-|jailbreak|DAN\s+mode', re.IGNORECASE), 'Jailbreak Attempt'),
        (re.compile(r'bypass.?guardrail|guardrail', re.IGNORECASE), 'Guardrail Bypass'),
        (re.compile(r'RAG-|RAG', re.IGNORECASE), 'RAG Attack'),
        (re.compile(r'MCP|tool.?manipulat', re.IGNORECASE), 'MCP/Tool Manipulation'),
    ]

    def __init__(self):
        self._raw_payloads: Dict[str, Dict[str, Any]] = {}

    def should_obfuscate(self, finding: Dict[str, Any]) -> bool:
        """Check if a finding contains dangerous patterns that should be obfuscated."""
        issue = finding.get('issue', '')
        code = finding.get('code', '')

        for pattern in self.DANGEROUS_ISSUE_PATTERNS:
            if pattern.search(issue):
                return True

        for pattern in self.DANGEROUS_CODE_PATTERNS:
            if pattern.search(code):
                return True

        return False

    def obfuscate_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Obfuscate a finding if it contains dangerous content."""
        if not self.should_obfuscate(finding):
            return finding

        result = dict(finding)
        ref_hash = hashlib.sha256(
            f"{finding.get('code', '')}{finding.get('file', '')}{finding.get('line', '')}".encode()
        ).hexdigest()[:12]

        self._raw_payloads[ref_hash] = {
            'original_code': finding.get('code', ''),
            'original_issue': finding.get('issue', ''),
            'file': finding.get('file', ''),
            'line': finding.get('line', 0),
            'category': self._categorize_attack(finding),
        }

        result['code'] = f'[PAYLOAD OBFUSCATED] (ref:{ref_hash})'
        return result

    def obfuscate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Obfuscate a batch of findings."""
        return [self.obfuscate_finding(f) for f in findings]

    def get_raw_payloads(self) -> Dict[str, Dict[str, Any]]:
        """Return stored raw payloads for human review."""
        return dict(self._raw_payloads)

    def save_raw_payloads(self, report_path: Path) -> Path:
        """Save raw payloads to a separate file alongside the report."""
        if not self._raw_payloads:
            return None

        raw_path = report_path.parent / f"{report_path.stem}-raw-payloads.json"
        data = {
            'warning': 'RAW PAYLOADS - Contains unobfuscated attack content. For human review only.',
            'generated': datetime.now().isoformat(),
            'payloads': self._raw_payloads,
        }
        with open(raw_path, 'w') as f:
            json.dump(data, f, indent=2)

        return raw_path

    def _categorize_attack(self, finding: Dict[str, Any]) -> str:
        """Categorize the type of attack in a finding."""
        text = f"{finding.get('issue', '')} {finding.get('code', '')}"

        for pattern, category in self.ATTACK_CATEGORIES:
            if pattern.search(text):
                return category

        return 'Unknown Attack'
