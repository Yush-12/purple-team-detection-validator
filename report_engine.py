import os
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger(__name__)

class ReportEngine:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def generate(self, run_results: List[Dict]) -> Dict[str, Path]:
        """
        Generates both JSON and HTML coverage reports.
        
        Args:
            run_results: List of dictionaries combining execution and SIEM query results.
        """
        data = self._compile_report_data(run_results)
        
        # Output reports
        json_path = self._write_json(data)
        html_path = self._write_html(data)
        
        # Display elegant console summary
        self._print_console_summary(data)
        
        return {
            "json": json_path,
            "html": html_path
        }

    def _compile_report_data(self, results: List[Dict]) -> Dict:
        total = len(results)
        fully_detected = sum(1 for r in results if r.get("siem", {}).get("detection_fired", False))
        telemetry_ingested = sum(1 for r in results if r.get("siem", {}).get("log_visible", False))
        
        gaps = total - fully_detected
        coverage_rate = (fully_detected / total * 100) if total > 0 else 0.0
        
        compiled_techniques = []
        for r in results:
            exec_res = r.get("execution", {})
            siem_res = r.get("siem", {})
            
            # Status resolution
            if siem_res.get("detection_fired"):
                status = "Fully Covered"
            elif siem_res.get("log_visible"):
                status = "Telemetry Only"
            else:
                status = "No Coverage"
                
            compiled_techniques.append({
                "id": exec_res["technique_id"],
                "name": exec_res["technique_name"],
                "tactic": exec_res["tactic"],
                "command": exec_res["command"],
                "success": exec_res["success"],
                "log_visible": siem_res.get("log_visible", False),
                "detection_fired": siem_res.get("detection_fired", False),
                "status": status,
                "notes": siem_res.get("notes", ""),
                "remediation": r.get("remediation", {})
            })

        return {
            "report_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_techniques": total,
            "fully_detected": fully_detected,
            "telemetry_ingested": telemetry_ingested,
            "gaps": gaps,
            "coverage_rate_pct": round(coverage_rate, 1),
            "techniques": compiled_techniques
        }

    def _print_console_summary(self, data: Dict) -> None:
        print("\n" + "=" * 70)
        print("  === PURPLE TEAM DETECTION COVERAGE DASHBOARD ===")
        print("=" * 70)
        print(f"  Techniques Tested  : {data['total_techniques']}")
        print(f"  Log Ingested (ES)  : {data['telemetry_ingested']}")
        print(f"  Alerts Fired (SIEM): {data['fully_detected']}")
        print(f"  Remediation Gaps   : {data['gaps']}")
        print(f"  SIEM Coverage Rate : {data['coverage_rate_pct']}%")
        print("-" * 70)
        
        for t in data["techniques"]:
            if t["status"] == "Fully Covered":
                status_str = "\033[92m[FULL COVERAGE]\033[0m" # Green
            elif t["status"] == "Telemetry Only":
                status_str = "\033[93m[TELEMETRY ONLY]\033[0m" # Yellow
            else:
                status_str = "\033[91m[NO COVERAGE]\033[0m" # Red
                
            print(f"  {status_str:<25} {t['id']:<10} {t['name']}")
        print("=" * 70 + "\n")

    def _write_json(self, data: Dict) -> Path:
        json_file = self.output_dir / f"coverage_{self.timestamp}.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info(f"[REPORTER] JSON coverage report created: {json_file}")
        return json_file

    def _write_html(self, data: Dict) -> Path:
        html_file = self.output_dir / f"coverage_{self.timestamp}.html"
        
        rows = ""
        for t in data["techniques"]:
            # Setup class and badge for status
            if t["status"] == "Fully Covered":
                status_class = "status-full"
                status_badge = "✓ Fully Covered"
            elif t["status"] == "Telemetry Only":
                status_class = "status-telemetry"
                status_badge = "⚠ Telemetry Only"
            else:
                status_class = "status-none"
                status_badge = "✗ No Coverage"
                
            exec_badge = "Success" if t["success"] else "Failed"
            exec_class = "exec-success" if t["success"] else "exec-failed"
            
            remediation_block = ""
            if t["remediation"]:
                rem = t["remediation"]
                remediation_block = f"""
                <div class="remediation-box">
                    <p class="rem-gap"><strong>Remediation Gap:</strong> {rem.get('gap_description')}</p>
                    <p class="rem-fix"><strong>Fix Action:</strong> {rem.get('recommendation')}</p>
                    <a href="{rem.get('reference')}" target="_blank" class="rem-link">MITRE ATT&CK reference ↗</a>
                </div>
                """
            
            rows += f"""
            <tr class="{status_class}">
                <td><code class="tech-id">{t['id']}</code></td>
                <td>
                    <div class="tech-name">{t['name']}</div>
                    <div class="tech-tactic">{t['tactic']}</div>
                </td>
                <td>
                    <span class="badge {exec_class}">{exec_badge}</span>
                </td>
                <td>
                    <div class="log-indicator">
                        <span class="dot {'dot-green' if t['log_visible'] else 'dot-red'}"></span>
                        <span>{'Ingested' if t['log_visible'] else 'Missing'}</span>
                    </div>
                </td>
                <td>
                    <span class="status-badge">{status_badge}</span>
                    {f'<div class="error-msg">{t["notes"]}</div>' if t["notes"] else ""}
                </td>
                <td>
                    {remediation_block or '—'}
                </td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Purple Team Coverage Report — {self.timestamp}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=Space+Grotesk:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-deep: #080c14;
            --bg-card: rgba(22, 28, 45, 0.4);
            --bg-card-hover: rgba(22, 28, 45, 0.6);
            --border-glow: rgba(139, 92, 246, 0.15);
            --border-glow-active: rgba(139, 92, 246, 0.3);
            
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --text-muted: #6b7280;
            
            --accent-purple: #8b5cf6;
            --accent-blue: #3b82f6;
            
            --color-success: #10b981;
            --color-warning: #f59e0b;
            --color-danger: #ef4444;
            
            --font-main: 'Outfit', sans-serif;
            --font-mono: 'Space Grotesk', monospace;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            background-color: var(--bg-deep);
            color: var(--text-primary);
            font-family: var(--font-main);
            padding: 3rem 1.5rem;
            min-height: 100vh;
            background-image: 
                radial-gradient(at 10% 10%, rgba(139, 92, 246, 0.08) 0px, transparent 50%),
                radial-gradient(at 90% 10%, rgba(59, 82, 246, 0.08) 0px, transparent 50%);
            background-attachment: fixed;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        header {{
            margin-bottom: 3rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }}
        
        h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            letter-spacing: -0.05em;
            background: linear-gradient(135deg, #fff 30%, #a78bfa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        
        .subtitle {{
            color: var(--text-secondary);
            font-size: 1.1rem;
        }}
        
        .timestamp {{
            font-family: var(--font-mono);
            color: var(--text-muted);
            font-size: 0.9rem;
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3.5rem;
        }}
        
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-glow);
            border-radius: 16px;
            padding: 1.5rem 2rem;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            backdrop-filter: blur(12px);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
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
            background: transparent;
        }}
        
        .stat-card.purple::before {{ background: var(--accent-purple); }}
        .stat-card.blue::before {{ background: var(--accent-blue); }}
        .stat-card.green::before {{ background: var(--color-success); }}
        .stat-card.yellow::before {{ background: var(--color-warning); }}
        .stat-card.red::before {{ background: var(--color-danger); }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            border-color: var(--border-glow-active);
            box-shadow: 0 12px 40px 0 rgba(139, 92, 246, 0.1);
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.95rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}
        
        .stat-value {{
            font-size: 3rem;
            font-weight: 700;
            font-family: var(--font-mono);
            line-height: 1.1;
        }}
        
        .stat-desc {{
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 0.5rem;
        }}
        
        /* Table styles */
        .table-container {{
            background: var(--bg-card);
            border: 1px solid var(--border-glow);
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(12px);
            margin-bottom: 2rem;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        
        th {{
            background: rgba(10, 15, 30, 0.8);
            padding: 1.25rem 1.5rem;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text-secondary);
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            font-weight: 600;
        }}
        
        td {{
            padding: 1.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            vertical-align: top;
        }}
        
        tr {{
            transition: background-color 0.2s ease;
        }}
        
        tr:hover {{
            background-color: var(--bg-card-hover);
        }}
        
        /* Badges and tags */
        .tech-id {{
            background: rgba(139, 92, 246, 0.15);
            color: #c084fc;
            padding: 0.3rem 0.6rem;
            border-radius: 6px;
            font-family: var(--font-mono);
            font-weight: 600;
            font-size: 0.85rem;
            border: 1px solid rgba(139, 92, 246, 0.3);
        }}
        
        .tech-name {{
            font-weight: 600;
            font-size: 1.1rem;
            margin-bottom: 0.25rem;
        }}
        
        .tech-tactic {{
            color: var(--text-muted);
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }}
        
        .exec-success {{
            background: rgba(16, 185, 129, 0.1);
            color: var(--color-success);
            border: 1px solid rgba(16, 185, 129, 0.25);
        }}
        
        .exec-failed {{
            background: rgba(239, 68, 68, 0.1);
            color: var(--color-danger);
            border: 1px solid rgba(239, 68, 68, 0.25);
        }}
        
        /* Status styling */
        .log-indicator {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.95rem;
            font-weight: 600;
        }}
        
        .dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
        }}
        
        .dot-green {{
            background-color: var(--color-success);
            box-shadow: 0 0 8px var(--color-success);
        }}
        
        .dot-red {{
            background-color: var(--color-danger);
            box-shadow: 0 0 8px var(--color-danger);
        }}
        
        .status-badge {{
            font-weight: 700;
            font-size: 0.9rem;
            padding: 0.4rem 0.8rem;
            border-radius: 8px;
            display: inline-block;
        }}
        
        .status-full .status-badge {{
            background: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}
        
        .status-telemetry .status-badge {{
            background: rgba(245, 158, 11, 0.15);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }}
        
        .status-none .status-badge {{
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}
        
        .error-msg {{
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.4rem;
            max-width: 250px;
        }}
        
        /* Remediation Box */
        .remediation-box {{
            background: rgba(0, 0, 0, 0.2);
            border-radius: 12px;
            padding: 1rem;
            border: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 0.9rem;
            line-height: 1.4rem;
            max-width: 450px;
        }}
        
        .rem-gap {{
            color: var(--text-primary);
            margin-bottom: 0.4rem;
        }}
        
        .rem-fix {{
            color: var(--text-secondary);
            margin-bottom: 0.6rem;
        }}
        
        .rem-link {{
            color: var(--accent-purple);
            text-decoration: none;
            font-weight: 600;
            font-size: 0.85rem;
            transition: color 0.2s ease;
        }}
        
        .rem-link:hover {{
            color: #c084fc;
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>🟣 Purple Team Coverage Report</h1>
                <div class="subtitle">ATT&CK Technique Simulation & SIEM Validation Dashboard</div>
            </div>
            <div class="timestamp">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
        </header>
        
        <!-- Summary metrics -->
        <section class="stats-grid">
            <div class="stat-card purple">
                <div class="stat-label">Coverage Rate</div>
                <div class="stat-value">{data['coverage_rate_pct']}%</div>
                <div class="stat-desc">Fully Alerting Rules in Kibana</div>
            </div>
            
            <div class="stat-card blue">
                <div class="stat-label">Simulations Run</div>
                <div class="stat-value">{data['total_techniques']}</div>
                <div class="stat-desc">MITRE ATT&CK techniques tested</div>
            </div>
            
            <div class="stat-card green">
                <div class="stat-label">Ingested Logs</div>
                <div class="stat-value">{data['telemetry_ingested']} / {data['total_techniques']}</div>
                <div class="stat-desc">Raw logs visible in Elasticsearch</div>
            </div>
            
            <div class="stat-card yellow">
                <div class="stat-label">Detection Alerts</div>
                <div class="stat-value">{data['fully_detected']}</div>
                <div class="stat-desc">KQL rules triggered alerts</div>
            </div>
            
            <div class="stat-card red">
                <div class="stat-label">Detection Gaps</div>
                <div class="stat-value">{data['gaps']}</div>
                <div class="stat-desc">Techniques requiring remediation</div>
            </div>
        </section>
        
        <!-- Results Table -->
        <section class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Technique ID</th>
                        <th>Technique Name</th>
                        <th>Host Execution</th>
                        <th>Log Ingestion</th>
                        <th>SIEM Alert</th>
                        <th>Gap & Remediation Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </section>
    </div>
</body>
</html>
"""
        html_file.write_text(html_content, encoding="utf-8")
        logger.info(f"[REPORTER] Premium HTML coverage dashboard created: {html_file}")
        return html_file
