"""
reporting/coverage_report.py
------------------------------
Generates the detection coverage report from a completed RunSummary.

Outputs:
    - Console summary table (always)
    - JSON report   (reports/coverage_YYYYMMDD_HHMMSS.json)
    - HTML report   (reports/coverage_YYYYMMDD_HHMMSS.html)

Detection gap remediation recommendations are defined per technique
in the REMEDIATION_MAP below. Expand this as you add techniques.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from simulator.runner import RunSummary

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path("reports")

# Per-technique remediation recommendations for gaps
REMEDIATION_MAP: dict[str, dict] = {
    "T1059": {
        "gap_description": "Command execution not detected",
        "recommendation": (
            "Enable process creation logging (auditd or Sysmon). "
            "Create Elastic rule: process.name in (sh, bash, python) "
            "with unusual parent processes."
        ),
        "reference": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1046": {
        "gap_description": "Network scanning not detected",
        "recommendation": (
            "Enable network flow logs. Create threshold rule: "
            ">10 unique destination ports from a single source IP "
            "within 60 seconds."
        ),
        "reference": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1003": {
        "gap_description": "Credential access artifacts not detected",
        "recommendation": (
            "Monitor for .dmp file creation, access to /etc/passwd, "
            "and /proc/*/mem access. Audit rule: -w /etc/passwd -p r."
        ),
        "reference": "https://attack.mitre.org/techniques/T1003/",
    },
    "T1078": {
        "gap_description": "Account abuse not detected",
        "recommendation": (
            "Enable auth log ingestion. Create rules for: "
            ">5 auth failures in 60s (brute force), "
            "same account from >2 source IPs in 5 min (lateral movement)."
        ),
        "reference": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1566": {
        "gap_description": "Phishing artifacts not detected",
        "recommendation": (
            "Alert on double-extension files (.pdf.sh, .docx.exe) dropped "
            "to ~/Downloads. Monitor for Office/PDF apps spawning shells "
            "via process ancestry rules."
        ),
        "reference": "https://attack.mitre.org/techniques/T1566/",
    },
}


class CoverageReport:
    def __init__(self, summary: RunSummary, output_dir: Path = OUTPUT_DIR):
        self.summary = summary
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def generate(self, fmt: str = "both") -> dict[str, Path]:
        """
        Generate report(s).

        Args:
            fmt: "json" | "html" | "both"

        Returns:
            Dict of format → output path.
        """
        data = self._build_report_data()
        self._print_console_summary(data)

        outputs = {}
        if fmt in ("json", "both"):
            outputs["json"] = self._write_json(data)
        if fmt in ("html", "both"):
            outputs["html"] = self._write_html(data)
        return outputs

    # ── Internal ────────────────────────────────────────────────────────────

    def _build_report_data(self) -> dict:
        technique_results = []
        for report in self.summary.reports:
            tid = report.technique_id
            remediation = None
            if not report.detected:
                remediation = REMEDIATION_MAP.get(tid, {
                    "gap_description": "No remediation guidance available",
                    "recommendation": "Review detection coverage for this technique.",
                    "reference": f"https://attack.mitre.org/techniques/{tid}/",
                })

            technique_results.append({
                "technique_id": tid,
                "technique_name": report.simulation.technique_name,
                "tactic": report.simulation.tactic,
                "simulated": report.simulation.success,
                "detected": report.detected,
                "matched_keywords": (
                    report.detection.matched_keywords if report.detection else []
                ),
                "remediation": remediation,
            })

        return {
            "report_timestamp": self._timestamp,
            "total_techniques": self.summary.total,
            "detected": self.summary.detected_count,
            "missed": self.summary.gap_count,
            "detection_rate_pct": round(self.summary.detection_rate, 1),
            "techniques": technique_results,
        }

    def _print_console_summary(self, data: dict) -> None:
        print("\n" + "=" * 60)
        print("  PURPLE TEAM DETECTION COVERAGE REPORT")
        print("=" * 60)
        print(f"  Techniques simulated : {data['total_techniques']}")
        print(f"  Detected             : {data['detected']}")
        print(f"  Missed (gaps)        : {data['missed']}")
        print(f"  Detection rate       : {data['detection_rate_pct']}%")
        print("-" * 60)
        for t in data["techniques"]:
            status = "[OK] DETECTED" if t["detected"] else "[GAP] MISSED  "
            print(f"  {status}  {t['technique_id']:<8} {t['technique_name']}")
        print("=" * 60 + "\n")

    def _write_json(self, data: dict) -> Path:
        path = self.output_dir / f"coverage_{self._timestamp}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info(f"[REPORT] JSON report written: {path}")
        return path

    def _write_html(self, data: dict) -> Path:
        path = self.output_dir / f"coverage_{self._timestamp}.html"
        html = self._render_html(data)
        path.write_text(html, encoding="utf-8")
        logger.info(f"[REPORT] HTML report written: {path}")
        return path

    def _render_html(self, data: dict) -> str:
        rows = ""
        for t in data["techniques"]:
            status_class = "detected" if t["detected"] else "missed"
            status_label = "✓ Detected" if t["detected"] else "✗ Missed"
            remediation_html = ""
            if t["remediation"]:
                r = t["remediation"]
                remediation_html = f"""
                <div class="remediation">
                    <strong>Gap:</strong> {r['gap_description']}<br>
                    <strong>Fix:</strong> {r['recommendation']}<br>
                    <a href="{r['reference']}" target="_blank">ATT&CK Reference ↗</a>
                </div>"""
            rows += f"""
            <tr class="{status_class}">
                <td><code>{t['technique_id']}</code></td>
                <td>{t['technique_name']}</td>
                <td>{t['tactic']}</td>
                <td class="status">{status_label}</td>
                <td>{remediation_html or "—"}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Detection Coverage Report — {data['report_timestamp']}</title>
<style>
  body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  h1 {{ color: #58a6ff; }}
  .summary {{ background: #161b22; border: 1px solid #30363d; padding: 1rem; margin-bottom: 2rem; border-radius: 6px; }}
  .rate {{ font-size: 2rem; font-weight: bold; color: #3fb950; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #21262d; padding: 0.6rem 1rem; text-align: left; border-bottom: 1px solid #30363d; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid #21262d; vertical-align: top; }}
  tr.detected td {{ border-left: 3px solid #3fb950; }}
  tr.missed td {{ border-left: 3px solid #f85149; }}
  .status {{ font-weight: bold; }}
  tr.detected .status {{ color: #3fb950; }}
  tr.missed .status {{ color: #f85149; }}
  .remediation {{ font-size: 0.85rem; color: #8b949e; margin-top: 0.3rem; }}
  .remediation a {{ color: #58a6ff; }}
  code {{ background: #21262d; padding: 0.1rem 0.3rem; border-radius: 3px; }}
</style>
</head>
<body>
<h1>🟣 Purple Team — Detection Coverage Report</h1>
<div class="summary">
  <div class="rate">{data['detection_rate_pct']}% detected</div>
  <div>{data['detected']} of {data['total_techniques']} simulated techniques triggered an alert</div>
  <div style="margin-top:0.5rem; color:#f85149">{data['missed']} detection gap(s) identified</div>
  <div style="margin-top:0.3rem; color:#8b949e">Generated: {data['report_timestamp']}</div>
</div>
<table>
  <thead>
    <tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Detection</th><th>Remediation</th></tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
</body>
</html>"""
