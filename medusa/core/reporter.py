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
            'medusa_version': '6.0.0',
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
        with open(output_path, 'w') as f:
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

        with open(self.history_file, 'w') as f:
            json.dump(history, f, indent=2)

    def generate_html_report(self, json_report_path: Path, output_path: Path = None) -> Path:
        """Generate beautiful HTML report from JSON"""
        with open(json_report_path) as f:
            report = json.load(f)

        output_path = output_path or json_report_path.with_suffix('.html')

        html = self._build_html_report(report)

        with open(output_path, 'w') as f:
            f.write(html)

        return output_path

    def _build_html_report(self, report: Dict[str, Any]) -> str:
        """Build stunning modern HTML report with glassmorphism and animations"""
        summary = report['scan_summary']
        severity_breakdown = report['severity_breakdown']
        findings = report['findings']

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MEDUSA Security Report - {report['timestamp']}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        :root {{
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --bg-dark: #0f172a;
            --bg-card: rgba(255, 255, 255, 0.05);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --glass-bg: rgba(255, 255, 255, 0.08);
            --glass-border: rgba(255, 255, 255, 0.18);
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            background-attachment: fixed;
            min-height: 100vh;
            padding: 0;
            color: var(--text-primary);
        }}

        /* Animated background particles */
        body::before {{
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image:
                radial-gradient(circle at 20% 50%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(255, 119, 255, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 40% 20%, rgba(138, 180, 248, 0.3) 0%, transparent 50%);
            animation: float 20s ease-in-out infinite;
            pointer-events: none;
            z-index: 0;
        }}

        @keyframes float {{
            0%, 100% {{ transform: translateY(0) rotate(0deg); }}
            50% {{ transform: translateY(-20px) rotate(5deg); }}
        }}

        .container {{
            max-width: 1400px;
            margin: 40px auto;
            position: relative;
            z-index: 1;
        }}

        /* Glass morphism header */
        .header {{
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 24px;
            padding: 60px 40px;
            text-align: center;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }}

        .header h1 {{
            font-size: 3.5em;
            font-weight: 800;
            background: linear-gradient(135deg, #fff 0%, #a78bfa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 15px;
            letter-spacing: -2px;
        }}

        .header .subtitle {{
            font-size: 1.3em;
            color: var(--text-secondary);
            font-weight: 400;
        }}

        .header .timestamp {{
            margin-top: 15px;
            font-size: 0.95em;
            color: rgba(255, 255, 255, 0.6);
            font-weight: 300;
        }}

        /* Dashboard grid */
        .dashboard {{
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 30px;
            margin-bottom: 30px;
        }}

        /* Score card with animated ring */
        .score-card {{
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 24px;
            padding: 40px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            position: relative;
            overflow: hidden;
        }}

        .score-card::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: pulse 4s ease-in-out infinite;
        }}

        @keyframes pulse {{
            0%, 100% {{ transform: scale(1); opacity: 0.5; }}
            50% {{ transform: scale(1.1); opacity: 0.8; }}
        }}

        .score-ring {{
            position: relative;
            width: 240px;
            height: 240px;
        }}

        .score-ring svg {{
            transform: rotate(-90deg);
            width: 100%;
            height: 100%;
        }}

        .score-ring-bg {{
            fill: none;
            stroke: rgba(255, 255, 255, 0.1);
            stroke-width: 16;
        }}

        .score-ring-progress {{
            fill: none;
            stroke: url(#scoreGradient);
            stroke-width: 16;
            stroke-linecap: round;
            stroke-dasharray: 628;
            stroke-dashoffset: {628 - (628 * summary['security_score'] / 100)};
            animation: fillRing 2s ease-out forwards;
        }}

        @keyframes fillRing {{
            from {{ stroke-dashoffset: 628; }}
        }}

        .score-content {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }}

        .score-value {{
            font-size: 4em;
            font-weight: 800;
            background: linear-gradient(135deg, #10b981 0%, #3b82f6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            line-height: 1;
            margin-bottom: 8px;
        }}

        .score-label {{
            font-size: 0.9em;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }}

        .risk-badge {{
            margin-top: 25px;
            padding: 12px 32px;
            border-radius: 100px;
            font-size: 1.1em;
            font-weight: 700;
            background: {self._get_risk_gradient(summary['risk_level'])};
            color: white;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: 0 8px 24px {self._get_risk_shadow(summary['risk_level'])};
        }}

        /* Stats grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
        }}

        .stat-card {{
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 30px;
            transition: all 0.3s ease;
            cursor: default;
            position: relative;
            overflow: hidden;
        }}

        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, var(--primary), var(--success));
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.2);
        }}

        .stat-card:hover::before {{
            transform: scaleX(1);
        }}

        .stat-icon {{
            font-size: 2.5em;
            margin-bottom: 15px;
            opacity: 0.8;
        }}

        .stat-value {{
            font-size: 3em;
            font-weight: 800;
            background: linear-gradient(135deg, #fff 0%, #a78bfa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
            line-height: 1;
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.95em;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        /* Severity section */
        .severity-section {{
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 24px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }}

        h2 {{
            font-size: 1.8em;
            font-weight: 700;
            margin-bottom: 30px;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        h2::before {{
            content: '';
            width: 4px;
            height: 30px;
            background: linear-gradient(180deg, var(--primary), var(--success));
            border-radius: 4px;
        }}

        .severity-bars {{
            display: grid;
            gap: 20px;
        }}

        .severity-bar {{
            position: relative;
        }}

        .severity-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }}

        .severity-name {{
            font-weight: 600;
            font-size: 1.05em;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .severity-count {{
            background: rgba(255, 255, 255, 0.1);
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.9em;
            font-weight: 600;
        }}

        .bar-track {{
            height: 12px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 100px;
            overflow: hidden;
            position: relative;
        }}

        .bar-progress {{
            height: 100%;
            border-radius: 100px;
            background: linear-gradient(90deg, var(--color-start), var(--color-end));
            transition: width 1s ease-out;
            position: relative;
            overflow: hidden;
        }}

        .bar-progress::after {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            bottom: 0;
            right: 0;
            background: linear-gradient(90deg,
                transparent,
                rgba(255, 255, 255, 0.3),
                transparent
            );
            animation: shimmer 2s infinite;
        }}

        @keyframes shimmer {{
            0% {{ transform: translateX(-100%); }}
            100% {{ transform: translateX(100%); }}
        }}

        /* Findings section */
        .findings-section {{
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 24px;
            padding: 40px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }}

        .finding-card {{
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-left: 4px solid var(--severity-color);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
        }}

        .finding-card:hover {{
            background: rgba(255, 255, 255, 0.06);
            transform: translateX(8px);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 16px;
        }}

        .finding-file {{
            font-family: 'SF Mono', 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
            color: var(--text-secondary);
            background: rgba(255, 255, 255, 0.05);
            padding: 6px 12px;
            border-radius: 8px;
        }}

        .severity-badge {{
            padding: 6px 16px;
            border-radius: 100px;
            font-size: 0.75em;
            font-weight: 700;
            color: white;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background: var(--severity-color);
            box-shadow: 0 4px 12px var(--severity-shadow);
        }}

        .finding-issue {{
            color: var(--text-primary);
            font-size: 1.05em;
            font-weight: 500;
            margin-bottom: 12px;
            line-height: 1.6;
        }}

        .finding-code {{
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 16px;
            font-family: 'SF Mono', 'Monaco', 'Courier New', monospace;
            font-size: 0.85em;
            overflow-x: auto;
            margin-top: 12px;
            color: #e2e8f0;
        }}

        .finding-meta {{
            margin-top: 12px;
            font-size: 0.85em;
            color: var(--text-secondary);
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }}

        .meta-item {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        /* Footer */
        .footer {{
            background: var(--glass-bg);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 24px;
            padding: 30px;
            text-align: center;
            margin-top: 30px;
            color: var(--text-secondary);
        }}

        .footer-title {{
            font-size: 1.2em;
            font-weight: 700;
            margin-bottom: 8px;
            color: var(--text-primary);
        }}

        @media (max-width: 1024px) {{
            .dashboard {{ grid-template-columns: 1fr; }}
            .stats-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🐍 MEDUSA</h1>
            <div class="subtitle">Security Analysis Dashboard</div>
            <div class="timestamp">Generated {datetime.fromisoformat(report['timestamp']).strftime('%B %d, %Y at %H:%M:%S')}</div>
        </div>

        <div class="dashboard">
            <div class="score-card">
                <div class="score-ring">
                    <svg viewBox="0 0 200 200">
                        <defs>
                            <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" style="stop-color:#10b981;stop-opacity:1" />
                                <stop offset="100%" style="stop-color:#3b82f6;stop-opacity:1" />
                            </linearGradient>
                        </defs>
                        <circle cx="100" cy="100" r="90" class="score-ring-bg"></circle>
                        <circle cx="100" cy="100" r="90" class="score-ring-progress"></circle>
                    </svg>
                    <div class="score-content">
                        <div class="score-value">{summary['security_score']}</div>
                        <div class="score-label">Security Score</div>
                    </div>
                </div>
                <div class="risk-badge">{summary['risk_level']}</div>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon">🎯</div>
                    <div class="stat-value">{summary['total_issues']}</div>
                    <div class="stat-label">Security Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">📂</div>
                    <div class="stat-value">{summary['files_scanned']}</div>
                    <div class="stat-label">Files Scanned</div>
                </div>
                <div class="stat-card" style="grid-column: span 2;">
                    <div class="stat-icon">📊</div>
                    <div class="stat-value">{summary['lines_scanned']:,}</div>
                    <div class="stat-label">Lines of Code Analyzed</div>
                </div>
            </div>
        </div>

        <div class="severity-section">
            <h2>Issue Distribution</h2>
            <div class="severity-bars">
                {self._build_modern_severity_bars(severity_breakdown, summary['total_issues'])}
            </div>
        </div>

        <div class="findings-section">
            <h2>Detailed Findings</h2>
            {self._build_modern_findings_html(findings)}
        </div>

        <div class="footer">
            <div class="footer-title">MEDUSA v0.7.0</div>
            <div>The 42-Headed Security Guardian • Project Chimera</div>
        </div>
    </div>
</body>
</html>"""

        return html

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
