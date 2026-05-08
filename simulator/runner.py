"""
simulator/runner.py
--------------------
Orchestrates the full purple team simulation run.

Flow per technique:
    1. Instantiate the technique class
    2. Call .run() — executes simulate() + cleanup()
    3. Wait delay_after_sim_seconds (let logs flush to SIEM)
    4. Hand SimulationResult to detection/siem_query.py
    5. Aggregate into a DetectionSummary for reporting

Usage (CLI entry point defined in main.py):
    python main.py --config config/siem_config.yaml
    python main.py --dry-run
    python main.py --techniques T1059,T1046
"""

import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from techniques import TECHNIQUE_REGISTRY
from techniques.base import SimulationResult
from detection.siem_query import SiemQuery, DetectionOutcome

logger = logging.getLogger(__name__)

DEFAULT_DELAY_SECONDS = 5


@dataclass
class TechniqueReport:
    """Combined sim result + detection outcome for one technique."""
    simulation: SimulationResult
    detection: Optional[DetectionOutcome] = None

    @property
    def detected(self) -> bool:
        return self.detection is not None and self.detection.alert_fired

    @property
    def technique_id(self) -> str:
        return self.simulation.technique_id


@dataclass
class RunSummary:
    """Aggregated results for the full simulation run."""
    start_time: datetime
    end_time: Optional[datetime] = None
    reports: list[TechniqueReport] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.reports)

    @property
    def detected_count(self) -> int:
        return sum(1 for r in self.reports if r.detected)

    @property
    def detection_rate(self) -> float:
        return (self.detected_count / self.total * 100) if self.total else 0.0

    @property
    def gap_count(self) -> int:
        return self.total - self.detected_count


class SimulationRunner:
    def __init__(
        self,
        siem_query: SiemQuery,
        delay_seconds: int = DEFAULT_DELAY_SECONDS,
        dry_run: bool = False,
        technique_filter: Optional[list[str]] = None,
    ):
        self.siem_query = siem_query
        self.delay_seconds = delay_seconds
        self.dry_run = dry_run
        self.technique_filter = technique_filter  # e.g. ["T1059", "T1046"]

    def run_all(self) -> RunSummary:
        summary = RunSummary(start_time=datetime.now(timezone.utc))

        techniques_to_run = self._resolve_techniques()
        logger.info(
            f"[RUNNER] Starting simulation run — "
            f"{len(techniques_to_run)} technique(s), dry_run={self.dry_run}"
        )

        for technique_id, technique_cls in techniques_to_run.items():
            report = self._run_one(technique_id, technique_cls)
            summary.reports.append(report)

        summary.end_time = datetime.now(timezone.utc)
        logger.info(
            f"[RUNNER] Run complete — "
            f"{summary.detected_count}/{summary.total} detected "
            f"({summary.detection_rate:.1f}%)"
        )
        return summary

    def _run_one(self, technique_id: str, technique_cls) -> TechniqueReport:
        logger.info(f"[RUNNER] -- {technique_id} ----------------------")

        # Execute simulation
        instance = technique_cls(dry_run=self.dry_run)
        sim_result = instance.run()

        # Wait for SIEM to ingest
        if not self.dry_run:
            logger.info(
                f"[RUNNER] Waiting {self.delay_seconds}s for SIEM ingestion..."
            )
            time.sleep(self.delay_seconds)

        # Query SIEM for detection
        detection = None
        try:
            detection = self.siem_query.check_detection(sim_result)
            status = "DETECTED [OK]" if detection.alert_fired else "MISSED [GAP]"
            logger.info(f"[RUNNER] {technique_id} - {status}")
        except Exception as exc:
            logger.warning(f"[RUNNER] SIEM query failed for {technique_id}: {exc}")

        return TechniqueReport(simulation=sim_result, detection=detection)

    def _resolve_techniques(self) -> dict:
        if not self.technique_filter:
            return TECHNIQUE_REGISTRY
        filtered = {}
        for tid in self.technique_filter:
            tid = tid.upper()
            if tid in TECHNIQUE_REGISTRY:
                filtered[tid] = TECHNIQUE_REGISTRY[tid]
            else:
                logger.warning(f"[RUNNER] Unknown technique ID: {tid} — skipping")
        return filtered
