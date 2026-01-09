#!/usr/bin/env python3
"""
MEDUSA Security Report Generator
Generates beautiful JSON/HTML security reports from MEDUSA scan results
"""

import json
import sys
import webbrowser
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict

from medusa import __version__

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

    def parse_bandit_json(self, bandit_json_path: Path) -> Dict[str, Any]:
        """Parse Bandit JSON output"""
        with open(bandit_json_path) as f:
            bandit_data = json.load(f)

        findings = []
        for result in bandit_data.get('results', []):
            findings.append({
                'scanner': 'bandit',
                'file': result['filename'],
                'line': result['line_number'],
                'severity': result['issue_severity'],
                'confidence': result['issue_confidence'],
                'issue': result['issue_text'],
                'cwe': result.get('issue_cwe', {}).get('id'),
                'code': result.get('code', '').strip()
            })

        metrics = bandit_data.get('metrics', {})
        total_lines = sum(m.get('loc', 0) for m in metrics.values() if isinstance(m, dict))

        return {
            'findings': findings,
            'total_lines_scanned': total_lines,
            'files_scanned': len(metrics) - 1,  # Exclude '_totals' key
            'scanner_version': 'bandit'
        }

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

    def generate_json_report(self, scan_results: Dict[str, Any], output_path: Path = None) -> Path:
        """Generate JSON report"""
        timestamp = datetime.now().isoformat()
        findings = scan_results.get('findings', [])

        report = {
            'timestamp': timestamp,
            'medusa_version': __version__,
            'scan_summary': {
                'total_issues': len(findings),
                'files_scanned': scan_results.get('files_scanned', 0),
                'lines_scanned': scan_results.get('total_lines_scanned', 0),
                'security_score': self.calculate_security_score(findings),
                'risk_level': self.calculate_risk_level(self.calculate_security_score(findings))
            },
            'severity_breakdown': {
                severity: len([f for f in findings if f['severity'] == severity])
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNDEFINED']
            },
            'findings': findings,
            'aggregations': self.aggregate_findings(scan_results)
        }

        # Save report
        output_path = output_path or self.output_dir / f"medusa-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

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

    def generate_markdown_report(self, scan_results: Dict[str, Any], output_path: Path = None) -> Path:
        """Generate Markdown report from scan results"""
        timestamp = datetime.now().isoformat()
        findings = scan_results.get('findings', [])

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

                if finding.get('cwe'):
                    md += f"**CWE:** [{finding['cwe']}](https://cwe.mitre.org/data/definitions/{finding['cwe']}.html)  \n"

                if finding.get('code'):
                    md += f"\n**Code:**\n```\n{finding['code']}\n```\n"

                md += "\n---\n\n"
        else:
            md += "## Detailed Findings\n\n✨ **No security issues found!** Your code is excellent!\n\n---\n\n"

        # Footer
        md += """## About MEDUSA

MEDUSA is a multi-language security scanner with 40+ specialized analyzers for all platforms.

**Learn more:** [Pantheon Security](https://pantheonsecurity.io)

---

*Report generated by MEDUSA v{__version__}*
"""

        # Save markdown report
        output_path = output_path or self.output_dir / f"medusa-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)

        return output_path

    def _build_html_report(self, report: Dict[str, Any]) -> str:
        """Build professional, clean HTML security report"""
        from medusa import __version__

        summary = report['scan_summary']
        severity_breakdown = report['severity_breakdown']
        findings = report['findings']

        # Calculate actual severity counts from findings
        actual_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            sev = f.get('severity', 'LOW').upper()
            if sev in actual_counts:
                actual_counts[sev] += 1

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
            /* Pantheon Security Brand Colors */
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
            gap: 12px;
        }}

        .logo-icon {{
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }}

        .logo-text {{
            font-size: 28px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}

        .logo-version {{
            font-size: 14px;
            color: var(--text-muted);
            font-weight: 400;
        }}

        .report-meta {{
            text-align: right;
            color: var(--text-muted);
            font-size: 14px;
        }}

        /* Summary Cards */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 40px;
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
            margin-bottom: 40px;
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
            grid-template-columns: repeat(4, 1fr);
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
            gap: 20px;
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
                <div class="logo-icon">🐍</div>
                <div>
                    <div class="logo-text">MEDUSA</div>
                    <div class="logo-version">v{__version__}</div>
                </div>
            </div>
            <div class="report-meta">
                <div>Security Scan Report</div>
                <div>{datetime.fromisoformat(report['timestamp']).strftime('%B %d, %Y at %H:%M')}</div>
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
        </div>

        <div class="severity-section">
            <h2 class="section-title">Issue Breakdown</h2>
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
            </div>
        </div>

        <div class="findings-section">
            <h2 class="section-title">Findings ({len(findings)})</h2>
            {self._build_professional_findings_html(findings)}
        </div>

        <footer class="footer">
            <p>Generated by <strong>MEDUSA</strong> v{__version__} • 64 Security Analyzers</p>
            <p><a href="https://pantheonsecurity.io">Pantheon Security</a></p>
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
                <div class="no-findings-icon">✓</div>
                <div class="no-findings-text">No security issues found</div>
            </div>
            '''

        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNDEFINED': 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get('severity', 'LOW').upper(), 99))

        html_parts = []
        for finding in sorted_findings:
            severity = finding.get('severity', 'LOW').upper()
            severity_class = severity.lower()

            # Escape HTML in user content
            import html as html_lib
            issue = html_lib.escape(finding.get('issue', 'Unknown issue'))
            file_path = html_lib.escape(str(finding.get('file', 'Unknown')))
            line = finding.get('line', '?')
            code = html_lib.escape(finding.get('code', '')) if finding.get('code') else ''
            scanner = html_lib.escape(finding.get('scanner', 'unknown'))
            confidence = html_lib.escape(str(finding.get('confidence', 'N/A')))
            cwe = finding.get('cwe')

            code_block = f'<pre class="finding-code">{code}</pre>' if code else ''
            cwe_link = f'<span>CWE: <a href="https://cwe.mitre.org/data/definitions/{cwe}.html" target="_blank">{cwe}</a></span>' if cwe else ''

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


def main():
    """CLI entry point"""
    if len(sys.argv) < 2:
        print("Usage: medusa-report.py <bandit-json-file> [output-dir]")
        sys.exit(1)

    bandit_json = Path(sys.argv[1])
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    if not bandit_json.exists():
        print(f"Error: {bandit_json} not found")
        sys.exit(1)

    print("🐍 MEDUSA Report Generator v0.7.0")
    print("=" * 60)

    generator = MedusaReportGenerator(output_dir)

    # Parse Bandit results
    print(f"📊 Parsing Bandit results from {bandit_json}...")
    scan_results = generator.parse_bandit_json(bandit_json)

    print(f"✅ Found {len(scan_results['findings'])} issues in {scan_results['files_scanned']} files")
    print(f"📝 Scanned {scan_results['total_lines_scanned']:,} lines of code")

    # Generate JSON report
    print("\n📄 Generating JSON report...")
    json_path = generator.generate_json_report(scan_results)
    print(f"✅ JSON report saved: {json_path}")

    # Generate HTML report
    print("\n🎨 Generating HTML report...")
    html_path = generator.generate_html_report(json_path)
    print(f"✅ HTML report saved: {html_path}")

    # Calculate security score
    score = generator.calculate_security_score(scan_results['findings'])
    risk_level = generator.calculate_risk_level(score)

    print("\n" + "=" * 60)
    print(f"🎯 SECURITY SCORE: {score}/100")
    print(f"⚠️  RISK LEVEL: {risk_level}")
    print("=" * 60)

    # Auto-open HTML report in browser
    print(f"\n🌐 Opening report in browser...")
    webbrowser.open(f"file://{html_path.absolute()}")

    print(f"📂 Report location: {html_path.absolute()}")


if __name__ == '__main__':
    main()
