"""
main.py — CLI entry point for the Purple Team Detection Validator

Usage:
    python main.py                              # run all techniques, Elastic SIEM
    python main.py --dry-run                    # simulate without executing or querying
    python main.py --mock-siem                  # run sims, skip real SIEM query
    python main.py --techniques T1059,T1046     # run subset
    python main.py --config path/to/config.yaml
    python main.py --report-format html         # html | json | both
"""

import argparse
import logging
import sys
from pathlib import Path

import yaml

from detection.siem_query import ElasticSiemQuery, MockSiemQuery
from simulator.runner import SimulationRunner
from reporting.coverage_report import CoverageReport

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def load_config(config_path: str) -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)


def build_siem_query(cfg: dict, mock: bool):
    if mock:
        logger.info("[MAIN] Using MockSiemQuery — no SIEM connection required")
        return MockSiemQuery(always_detected=False)

    siem_cfg = cfg.get("siem", {})
    siem_type = siem_cfg.get("type", "elastic")

    if siem_type == "elastic":
        return ElasticSiemQuery(
            host=siem_cfg.get("host", "http://localhost:9200"),
            index_pattern=siem_cfg.get("index_pattern", "logs-*"),
            api_key=siem_cfg.get("api_key"),
            username=siem_cfg.get("username"),
            password=siem_cfg.get("password"),
        )
    else:
        raise ValueError(f"Unsupported SIEM type: {siem_type}")


def main():
    parser = argparse.ArgumentParser(
        description="Purple Team Detection Validation Framework"
    )
    parser.add_argument(
        "--config",
        default="config/siem_config.yaml",
        help="Path to SIEM config YAML (default: config/siem_config.yaml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log intended actions but do not execute simulations",
    )
    parser.add_argument(
        "--mock-siem",
        action="store_true",
        help="Skip real SIEM queries (useful for offline dev/testing)",
    )
    parser.add_argument(
        "--techniques",
        default=None,
        help="Comma-separated technique IDs to run (e.g. T1059,T1046). "
             "Default: all registered techniques.",
    )
    parser.add_argument(
        "--report-format",
        choices=["json", "html", "both"],
        default="both",
        help="Report output format (default: both)",
    )
    args = parser.parse_args()

    # Load config
    config_path = Path(args.config)
    if not config_path.exists():
        logger.error(f"Config not found: {config_path}")
        sys.exit(1)
    cfg = load_config(str(config_path))

    # Build SIEM query client
    siem_query = build_siem_query(cfg, mock=args.mock_siem or args.dry_run)

    # Resolve technique filter
    technique_filter = None
    if args.techniques:
        technique_filter = [t.strip().upper() for t in args.techniques.split(",")]

    # Run simulations
    runner_cfg = cfg.get("runner", {})
    runner = SimulationRunner(
        siem_query=siem_query,
        delay_seconds=runner_cfg.get("delay_after_sim_seconds", 5),
        dry_run=args.dry_run,
        technique_filter=technique_filter,
    )
    summary = runner.run_all()

    # Generate report
    report_cfg = cfg.get("reporting", {})
    reporter = CoverageReport(
        summary=summary,
        output_dir=Path(report_cfg.get("output_dir", "reports/")),
    )
    outputs = reporter.generate(fmt=args.report_format)

    for fmt, path in outputs.items():
        print(f"  [{fmt.upper()}] Report saved: {path}")

    # Exit non-zero if detection gaps exist (useful for CI)
    if summary.gap_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
