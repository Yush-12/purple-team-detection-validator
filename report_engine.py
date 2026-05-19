"""
report_engine.py — Coverage reporting engine for purple team detection validation.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from siem_querier import DetectionResult

logger = logging.getLogger(__name__)

REMEDIATION_MAP: Dict[str, Dict[str, str]] = {
    "T1046": {
        "root_cause": "No detection rule for network scanning activity. Nmap produces no syslog entries by default on Linux.",
        "fix": "Enable auditd with a rule watching execve for nmap binary. Alternatively, monitor outbound ICMP/SYN floods at network level.",
        "reference": "https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_nmap.yml",
        "priority": "MEDIUM",
    },
    "T1105": {
        "root_cause": "curl-based downloads produce no default log entries unless proxy logging is enabled.",
        "fix": "Deploy a web proxy with TLS inspection or enable auditd execve monitoring for curl/wget.",
        "reference": "https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_curl_download.yml",
        "priority": "HIGH",
    },
    "T1078": {
        "root_cause": "Failed SSH logins appear in auth.log but no alerting threshold is set. Single failed logins are noise; patterns are not aggregated.",
        "fix": "Write a detection rule that fires on 5+ auth failures from the same source within 60 seconds. Implement fail2ban as a compensating control.",
        "reference": "https://github.com/SigmaHQ/sigma/blob/master/rules/linux/builtin/auth/lnx_auth_brute_force.yml",
        "priority": "HIGH",
    },
    "T1070.004": {
        "root_cause": "File deletion leaves no log entry unless auditd is configured with -a always,exit -F arch=b64 -S unlink rules.",
        "fix": "Add auditd rules for unlink, unlinkat syscalls on sensitive directories.",
        "reference": "https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_delete_logs.yml",
        "priority": "HIGH",
    },
    "T1059.004": {
        "root_cause": "Base64-encoded command execution is not detectable from bash history or syslog without shell auditing enabled.",
        "fix": "Enable bash audit logging via auditd execve rules or deploy a HIDS that captures command arguments.",
        "reference": "https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_base64_execution.yml",
        "priority": "CRITICAL",
    },
}

STATUS_ICONS: Dict[str, str] = {
    "DETECTED": "✅",
    "NOT_DETECTED": "⚠️",
    "LOG_PIPELINE_ERROR": "❌",
}


def calculate_metrics(results: List[DetectionResult]) -> Dict[str, Any]:
    """Calculate aggregate detection metrics from a list of DetectionResults."""
    total = len(results)
    detected_count = sum(1 for r in results if r.detection_status == "DETECTED")
    not_detected_count = sum(1 for r in results if r.detection_status == "NOT_DETECTED")
    pipeline_error_count = sum(1 for r in results if r.detection_status == "LOG_PIPELINE_ERROR")
    detection_rate = round((detected_count / total) * 100, 1) if total > 0 else 0.0

    critical_gaps: List[str] = []
    for r in results:
        if r.detection_status != "DETECTED":
            remediation = REMEDIATION_MAP.get(r.technique_id, {})
            priority = remediation.get("priority", "UNKNOWN")
            if priority in ("CRITICAL", "HIGH"):
                critical_gaps.append(r.technique_id)

    return {
        "total": total,
        "detected_count": detected_count,
        "not_detected_count": not_detected_count,
        "pipeline_error_count": pipeline_error_count,
        "detection_rate": detection_rate,
        "critical_gaps": critical_gaps,
    }


def generate_markdown_report(
    results: List[DetectionResult],
    metrics: Dict[str, Any],
    run_metadata: Dict[str, str],
) -> str:
    """Generate a full Markdown coverage report."""
    lines: List[str] = []

    lines.append("# Purple Team Detection Validation Report")
    lines.append("")
    lines.append(f"**Date:** {run_metadata.get('date', 'N/A')}")
    lines.append(f"**Machine:** {run_metadata.get('hostname', 'N/A')}")
    lines.append(f"**Operator:** {run_metadata.get('operator', 'N/A')}")
    lines.append(f"**Framework Version:** {run_metadata.get('version', '1.0.0')}")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Techniques Tested:** {metrics['total']}")
    lines.append(f"- **Detection Rate:** {metrics['detection_rate']}%")
    lines.append(f"- **Detected:** {metrics['detected_count']}")
    lines.append(f"- **Not Detected:** {metrics['not_detected_count']}")
    lines.append(f"- **Pipeline Errors:** {metrics['pipeline_error_count']}")
    lines.append(f"- **Critical/High Gaps:** {len(metrics['critical_gaps'])}")
    lines.append("")

    if metrics["detection_rate"] >= 80:
        risk_statement = "Detection coverage is strong. Address remaining gaps to achieve full visibility."
    elif metrics["detection_rate"] >= 40:
        risk_statement = "Significant detection gaps exist. Adversary techniques may go unnoticed in production."
    else:
        risk_statement = "Critical detection deficit. Most simulated adversary techniques were invisible to the SIEM."

    lines.append(f"> **Risk Assessment:** {risk_statement}")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Coverage Matrix")
    lines.append("")
    lines.append("| Status | ID | Name | Tactic | Priority |")
    lines.append("|--------|----|------|--------|----------|")

    for r in results:
        icon = STATUS_ICONS.get(r.detection_status, "?")
        priority = REMEDIATION_MAP.get(r.technique_id, {}).get("priority", "N/A")
        lines.append(f"| {icon} | {r.technique_id} | {r.technique_name} | {r.tactic} | {priority} |")

    lines.append("")

    gap_results = [r for r in results if r.detection_status != "DETECTED"]
    if gap_results:
        lines.append("---")
        lines.append("")
        lines.append("## Gap Analysis")
        lines.append("")

        for r in gap_results:
            remediation = REMEDIATION_MAP.get(r.technique_id, {})
            lines.append(f"### {r.technique_id} — {r.technique_name}")
            lines.append("")
            lines.append(f"- **Status:** {r.detection_status}")
            lines.append(f"- **Tactic:** {r.tactic}")
            lines.append(f"- **Priority:** {remediation.get('priority', 'N/A')}")
            lines.append(f"- **Root Cause:** {remediation.get('root_cause', 'No remediation data available.')}")
            lines.append(f"- **Recommended Fix:** {remediation.get('fix', 'N/A')}")
            lines.append(f"- **Sigma Rule Reference:** [{remediation.get('reference', '')}]({remediation.get('reference', '')})")
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append("This report was generated by a single-machine purple team validation framework.")
    lines.append("Each MITRE ATT&CK technique was executed via local subprocess on the test host.")
    lines.append("Structured JSON events were written to `/tmp/purpleteam/events.log` and ingested")
    lines.append("by Filebeat into a local Elasticsearch 8.x instance.")
    lines.append("")
    lines.append('**What "DETECTED" means in this lab:** A technique is marked DETECTED if the')
    lines.append("Elasticsearch query against the expected index returns at least one matching")
    lines.append("document within the configured time window. This validates **raw log visibility**,")
    lines.append("not alerting rule firing. In a production environment, detection would additionally")
    lines.append("require a SIEM correlation rule or Elastic Security alert to trigger.")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Appendix: Elasticsearch Queries Used")
    lines.append("")

    for r in results:
        lines.append(f"### {r.technique_id} — {r.technique_name}")
        lines.append("")
        lines.append(f"**Index:** `{r.log_source_checked}`")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(r.query_used, indent=2))
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def save_reports(
    results: List[DetectionResult],
    metrics: Dict[str, Any],
    run_metadata: Dict[str, str],
    output_dir: str = "reports",
) -> Dict[str, Path]:
    """Save Markdown and JSON reports to disk. Print summary table to stdout."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    md_file = out_path / f"report_{timestamp_str}.md"
    json_file = out_path / f"report_{timestamp_str}.json"

    markdown_content = generate_markdown_report(results, metrics, run_metadata)
    md_file.write_text(markdown_content, encoding="utf-8")
    logger.info("[REPORTER] Markdown report saved: %s", md_file)

    json_data = {
        "run_metadata": run_metadata,
        "metrics": metrics,
        "results": [
            {
                "technique_id": r.technique_id,
                "technique_name": r.technique_name,
                "tactic": r.tactic,
                "log_source_checked": r.log_source_checked,
                "raw_log_visible": r.raw_log_visible,
                "matching_doc_count": r.matching_doc_count,
                "detection_status": r.detection_status,
                "query_used": r.query_used,
                "execution_time": r.execution_time.isoformat(),
                "query_time": r.query_time.isoformat(),
                "remediation": REMEDIATION_MAP.get(r.technique_id, {}),
            }
            for r in results
        ],
    }

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)
    logger.info("[REPORTER] JSON report saved: %s", json_file)

    _print_console_summary(results, metrics)

    return {"markdown": md_file, "json": json_file}


def _print_console_summary(results: List[DetectionResult], metrics: Dict[str, Any]) -> None:
    """Print a formatted summary table to stdout using manual string padding."""
    print("")
    print("=" * 90)
    print("  PURPLE TEAM DETECTION COVERAGE REPORT")
    print("=" * 90)
    print(f"  Techniques Tested : {metrics['total']}")
    print(f"  Detection Rate    : {metrics['detection_rate']}%")
    print(f"  Detected          : {metrics['detected_count']}")
    print(f"  Not Detected      : {metrics['not_detected_count']}")
    print(f"  Pipeline Errors   : {metrics['pipeline_error_count']}")
    print(f"  Critical Gaps     : {', '.join(metrics['critical_gaps']) or 'None'}")
    print("-" * 90)

    header = (
        "  "
        + "STATUS".ljust(18)
        + "ID".ljust(14)
        + "NAME".ljust(42)
        + "PRIORITY".ljust(10)
    )
    print(header)
    print("  " + "-" * 82)

    for r in results:
        priority = REMEDIATION_MAP.get(r.technique_id, {}).get("priority", "N/A")

        if r.detection_status == "DETECTED":
            status_label = "[DETECTED]"
        elif r.detection_status == "NOT_DETECTED":
            status_label = "[NOT DETECTED]"
        else:
            status_label = "[PIPELINE ERROR]"

        row = (
            "  "
            + status_label.ljust(18)
            + r.technique_id.ljust(14)
            + r.technique_name[:40].ljust(42)
            + priority.ljust(10)
        )
        print(row)

    print("=" * 90)
    print("")
