"""
orchestrator.py — CLI entrypoint for the Purple Team Detection Validation Framework.
"""

import argparse
import json
import logging
import os
import platform
import sys
import time
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from technique_schema import Technique, load_all_techniques, load_technique
from executor import TechniqueExecutor, ExecutionResult
from siem_querier import SIEMQuerier, DetectionResult
from report_engine import calculate_metrics, save_reports

logger = logging.getLogger("purpleteam")


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Load framework configuration from YAML file."""
    path = Path(config_path)
    if not path.exists():
        logger.error("Configuration file not found: %s", config_path)
        sys.exit(1)

    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def setup_logging(log_dir: str = "logs") -> None:
    """Configure dual logging: INFO to console, DEBUG to timestamped log file."""
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_file = log_path / f"run_{timestamp}.log"

    root_logger = logging.getLogger("purpleteam")
    root_logger.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    console_handler.setFormatter(console_fmt)

    file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s — %(message)s")
    file_handler.setFormatter(file_fmt)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    logger.info("Log file: %s", log_file)


def filter_techniques(
    techniques: List[Technique],
    technique_id: Optional[str],
    tactic: Optional[str],
) -> List[Technique]:
    """Apply optional technique ID or tactic filters."""
    filtered = techniques

    if technique_id:
        filtered = [t for t in filtered if t.technique_id == technique_id]
        if not filtered:
            logger.error("No technique found matching ID: %s", technique_id)
            sys.exit(1)

    if tactic:
        filtered = [t for t in filtered if t.tactic.lower() == tactic.lower()]
        if not filtered:
            logger.error("No techniques found matching tactic: %s", tactic)
            sys.exit(1)

    return filtered


def print_run_plan(techniques: List[Technique]) -> bool:
    """Print the list of techniques about to execute and ask user to confirm."""
    print("")
    print("=" * 70)
    print("  RUN PLAN")
    print("=" * 70)
    print(f"  Techniques to execute: {len(techniques)}")
    print("-" * 70)

    for i, t in enumerate(techniques, start=1):
        print(f"  {i}. [{t.technique_id}] {t.name} ({t.tactic})")
        print(f"     Commands: {len(t.commands)}, Cleanup: {len(t.cleanup_commands)}, Log: {t.log_source}")

    print("-" * 70)
    print("")

    try:
        answer = input("  Proceed with execution? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("")
        return False

    return answer in ("y", "yes")


def countdown(seconds: int, label: str = "Waiting for log ingestion") -> None:
    """Print a countdown timer to stdout."""
    for remaining in range(seconds, 0, -1):
        sys.stdout.write(f"\r  {label}... {remaining}s remaining  ")
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write(f"\r  {label}... done.                      \n")
    sys.stdout.flush()


def run(args: argparse.Namespace) -> None:
    """Main execution flow: load, execute, query, report."""
    config = load_config(args.config)

    es_config = config.get("elasticsearch", {})
    fw_config = config.get("framework", {})

    techniques_dir = fw_config.get("techniques_dir", "./techniques/")
    output_dir = fw_config.get("output_dir", "./reports/")
    post_delay = fw_config.get("post_execution_delay", 25)
    es_url = es_config.get("url", "http://localhost:9200")
    time_window = es_config.get("time_window_seconds", 120)

    logger.info("Loading techniques from: %s", techniques_dir)
    techniques = load_all_techniques(techniques_dir)
    logger.info("Loaded %d technique(s)", len(techniques))

    techniques = filter_techniques(techniques, args.technique, args.tactic)

    if not print_run_plan(techniques):
        logger.info("Execution cancelled by user.")
        sys.exit(0)

    Path("/tmp/purpleteam").mkdir(parents=True, exist_ok=True)

    executor = TechniqueExecutor(timeout=30)
    querier = SIEMQuerier(es_url=es_url, time_window_seconds=time_window)

    execution_results: List[ExecutionResult] = []
    detection_results: List[DetectionResult] = []

    for i, technique in enumerate(techniques, start=1):
        print("")
        logger.info(
            "[%d/%d] [%s] %s — executing...",
            i, len(techniques), technique.technique_id, technique.name,
        )

        exec_result = executor.execute(technique)
        execution_results.append(exec_result)

        if exec_result.success:
            logger.info(
                "[%s] Execution completed — %d/%d commands succeeded",
                technique.technique_id, exec_result.commands_run, exec_result.commands_run,
            )
        else:
            logger.warning(
                "[%s] Execution had failures — %d/%d commands failed: %s",
                technique.technique_id,
                exec_result.commands_failed,
                exec_result.commands_run,
                exec_result.error,
            )

        countdown(post_delay, f"[{technique.technique_id}] Waiting for log ingestion")

        logger.info("[%s] Querying Elasticsearch for detection...", technique.technique_id)
        detection = querier.check_visibility(technique, exec_result.start_time)
        detection_results.append(detection)

        if detection.detection_status == "DETECTED":
            logger.info("[%s] DETECTED — %d matching document(s)", technique.technique_id, detection.matching_doc_count)
        elif detection.detection_status == "NOT_DETECTED":
            logger.warning("[%s] NOT DETECTED — 0 matching documents", technique.technique_id)
        else:
            logger.error("[%s] LOG PIPELINE ERROR — query failed", technique.technique_id)

    run_metadata: Dict[str, str] = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "hostname": platform.node(),
        "operator": os.getenv("USER", os.getenv("USERNAME", "unknown")),
        "version": "1.0.0",
        "config": str(Path(args.config).resolve()),
    }

    metrics = calculate_metrics(detection_results)
    report_paths = save_reports(detection_results, metrics, run_metadata, output_dir)

    print("")
    logger.info("Reports saved:")
    for fmt, path in report_paths.items():
        logger.info("  %s: %s", fmt.upper(), path)


def report(args: argparse.Namespace) -> None:
    """Regenerate reports from a previously saved JSON results file."""
    json_path = Path(args.input)
    if not json_path.exists():
        logger.error("Input JSON file not found: %s", args.input)
        sys.exit(1)

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results: List[DetectionResult] = []
    for r in data.get("results", []):
        results.append(DetectionResult(
            technique_id=r["technique_id"],
            technique_name=r["technique_name"],
            tactic=r["tactic"],
            log_source_checked=r["log_source_checked"],
            raw_log_visible=r["raw_log_visible"],
            matching_doc_count=r["matching_doc_count"],
            detection_status=r["detection_status"],
            query_used=r["query_used"],
            execution_time=datetime.fromisoformat(r["execution_time"]),
            query_time=datetime.fromisoformat(r["query_time"]),
        ))

    run_metadata = data.get("run_metadata", {})
    run_metadata["regenerated_from"] = str(json_path.resolve())
    run_metadata["regenerated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    config = load_config(args.config)
    output_dir = config.get("framework", {}).get("output_dir", "./reports/")

    metrics = calculate_metrics(results)
    report_paths = save_reports(results, metrics, run_metadata, output_dir)

    print("")
    logger.info("Regenerated reports saved:")
    for fmt, path in report_paths.items():
        logger.info("  %s: %s", fmt.upper(), path)


def main() -> None:
    """Parse CLI arguments and dispatch to the appropriate command."""
    parser = argparse.ArgumentParser(
        description="Purple Team Detection Validation Framework",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config.yaml (default: config.yaml)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Execute techniques and validate detections")
    run_parser.add_argument("--technique", default=None, help="Run a single technique by ID (e.g. T1046)")
    run_parser.add_argument("--tactic", default=None, help="Filter techniques by tactic (e.g. Discovery)")

    report_parser = subparsers.add_parser("report", help="Regenerate report from a previous JSON output")
    report_parser.add_argument("--input", required=True, help="Path to a previously saved report JSON file")

    args = parser.parse_args()

    setup_logging()

    if args.command == "run":
        run(args)
    elif args.command == "report":
        report(args)


if __name__ == "__main__":
    main()
