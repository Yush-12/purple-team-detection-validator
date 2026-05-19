import os
import sys
import time
import argparse
import logging
import yaml
from pathlib import Path
from typing import List, Optional

from executor import TechniqueExecutor
from siem_querier import SiemQuerier
from report_engine import ReportEngine

logger = logging.getLogger(__name__)

SUPPORTED_TECHNIQUES = ["T1046", "T1105", "T1078", "T1070.004", "T1059.004"]


def load_yaml_config(config_path: str) -> dict:
    """Loads SIEM config YAML."""
    if not os.path.exists(config_path):
        logger.error(f"Configuration file not found: {config_path}")
        raise FileNotFoundError(f"Config path {config_path} does not exist.")
        
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_orchestration(
    config_path: str = "config/siem_config.yaml",
    dry_run: bool = False,
    mock_siem: bool = False,
    techniques_filter: Optional[List[str]] = None,
    report_dir: str = "reports"
) -> int:
    """
    Core execution routine. Orchestrates provisioning, execution, querying, and reporting.
    """
    logger.info("=" * 60)
    logger.info("=== PURPLE TEAM DETECTION VALIDATION FRAMEWORK STARTING ===")
    logger.info("=" * 60)

    # 1. Load configuration
    try:
        config = load_yaml_config(config_path)
    except Exception as e:
        logger.critical(f"Failed to load configuration: {e}")
        return 1

    # 2. Initialize SIEM Querier
    querier = SiemQuerier(config)
    
    # 3. Resolve techniques to run
    to_run = []
    filter_set = set(t.strip().upper() for t in techniques_filter) if techniques_filter else None
    
    # Instantiate executor to load the techniques YAML definitions
    executor = TechniqueExecutor(dry_run=dry_run)
    
    tech_definitions = []
    for tid in SUPPORTED_TECHNIQUES:
        try:
            tech_def = executor.load_technique(tid)
            tech_definitions.append(tech_def)
            
            # Filter matches
            if filter_set:
                if tid.upper() in filter_set or tid.replace(".", "_").upper() in filter_set:
                    to_run.append(tid)
            else:
                to_run.append(tid)
        except Exception as e:
            logger.error(f"Failed to load technique definition for {tid}: {e}")

    if not to_run:
        logger.error("[ORCHESTRATOR] No valid techniques identified to execute. Exiting.")
        return 1

    logger.info(f"[ORCHESTRATOR] Resolved {len(to_run)} technique(s) to execute: {', '.join(to_run)}")

    # 4. Programmatic Kibana Detection Rules Setup
    if not dry_run and not mock_siem:
        # Test SIEM cluster connection first
        if querier.test_connection():
            logger.info("[ORCHESTRATOR] Connected to ELK stack. Deploying detection rules...")
            # We provision rules based on all supported techniques
            querier.provision_rules(tech_definitions)
        else:
            logger.warning("[ORCHESTRATOR] SIEM cluster connection failed. Skipping rule provisioning.")

    # 5. Execute Techniques
    execution_results = []
    for tid in to_run:
        try:
            exec_res = executor.execute(tid)
            execution_results.append(exec_res)
        except Exception as e:
            logger.error(f"[ORCHESTRATOR] Execution failed for technique {tid}: {e}")

    # 6. Wait for Filebeat log harvesting and ingestion
    delay_seconds = config.get("runner", {}).get("delay_after_sim_seconds", 5)
    if not dry_run:
        logger.info(f"[ORCHESTRATOR] Waiting {delay_seconds}s for Filebeat ingestion and ES indexing...")
        time.sleep(delay_seconds)

    # 7. Query SIEM for log visibility & rule fires
    full_report_results = []
    
    for exec_res in execution_results:
        tid = exec_res["technique_id"]
        tech_def = executor.load_technique(tid)
        
        siem_outcome = {
            "technique_id": tid,
            "log_visible": False,
            "detection_fired": False,
            "matched_docs": 0,
            "notes": ""
        }

        if dry_run:
            siem_outcome["notes"] = "Dry run mode. Verification skipped."
        elif mock_siem:
            siem_outcome["notes"] = "Mock SIEM mode. Verification skipped."
            # Set artificial visibility for mock dashboard demo if execution succeeded
            if exec_res["success"]:
                siem_outcome["log_visible"] = True
                siem_outcome["detection_fired"] = True
        else:
            try:
                siem_outcome = querier.query_verification(tech_def, exec_res["timestamp"])
            except Exception as e:
                siem_outcome["notes"] = f"SIEM query error: {e}"
                logger.error(f"[ORCHESTRATOR] Error verifying {tid}: {e}")

        full_report_results.append({
            "execution": exec_res,
            "siem": siem_outcome,
            "remediation": tech_def.get("remediation", {})
        })

    # 8. Generate Reports
    reporter = ReportEngine(output_dir=report_dir)
    outputs = reporter.generate(full_report_results)
    
    logger.info("[ORCHESTRATOR] All operations complete.")
    for fmt, path in outputs.items():
        logger.info(f"[ORCHESTRATOR] [{fmt.upper()}] Report saved: {path}")

    # Return exit code: non-zero if gaps exist and not running mock/dry
    gaps = sum(1 for r in full_report_results if not r["siem"]["detection_fired"])
    if gaps > 0 and not dry_run and not mock_siem:
        logger.warning(f"[ORCHESTRATOR] {gaps} detection gaps identified.")
        return 1
        
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Purple Team Detection Validation Framework (Realistic Edition)"
    )
    parser.add_argument(
        "--config",
        default="config/siem_config.yaml",
        help="Path to SIEM config YAML (default: config/siem_config.yaml)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate execution without modifying system state or running shell queries"
    )
    parser.add_argument(
        "--mock-siem",
        action="store_true",
        help="Skip SIEM connectivity queries and return mock detection events"
    )
    parser.add_argument(
        "--techniques",
        default=None,
        help="Comma-separated technique IDs to run (e.g. T1046,T1105). Default runs all 5."
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to save report outputs (default: reports)"
    )
    
    args = parser.parse_args()
    
    # Set up basic logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

    techs_filter = None
    if args.techniques:
        techs_filter = [t.strip() for t in args.techniques.split(",")]

    exit_code = run_orchestration(
        config_path=args.config,
        dry_run=args.dry_run,
        mock_siem=args.mock_siem,
        techniques_filter=techs_filter,
        report_dir=args.output_dir
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
