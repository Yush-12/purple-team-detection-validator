"""
techniques/base.py
------------------
Abstract base class for all ATT&CK technique simulations.

Every technique module inherits from TechniqueBase and must implement:
    - simulate()  : performs the safe, log-generating action
    - cleanup()   : reverses or removes any artifacts created
    - metadata    : ATT&CK ID, name, tactic, expected log signatures
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class SimulationResult:
    """Returned by every technique's simulate() call."""
    technique_id: str
    technique_name: str
    tactic: str
    timestamp: datetime
    success: bool                          # did the simulation run cleanly?
    artifacts_generated: list[str]         # log lines / file paths / proc names created
    expected_alert_keywords: list[str]     # what the SIEM rule should key on
    notes: str = ""
    error: Optional[str] = None


class TechniqueBase(ABC):
    """
    Abstract base for all technique simulations.

    Subclasses must populate class-level metadata and implement
    simulate() and cleanup().
    """

    # --- Override these in each subclass ---
    TECHNIQUE_ID: str = ""          # e.g. "T1059.001"
    TECHNIQUE_NAME: str = ""        # e.g. "PowerShell"
    TACTIC: str = ""                # e.g. "Execution"
    REFERENCE_URL: str = ""         # ATT&CK URL for this technique
    SAFE_TO_RUN: bool = True        # set False for any destructive sim

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._start_time: Optional[datetime] = None

    def run(self) -> SimulationResult:
        """
        Orchestration wrapper — call this, not simulate() directly.
        Handles timing, dry_run, logging, and cleanup.
        """
        if not self.SAFE_TO_RUN:
            raise RuntimeError(
                f"{self.TECHNIQUE_ID} is marked SAFE_TO_RUN=False. "
                "Review the implementation before enabling."
            )

        self._start_time = datetime.now(timezone.utc)
        logger.info(f"[SIM] Starting {self.TECHNIQUE_ID} — {self.TECHNIQUE_NAME}")

        if self.dry_run:
            logger.info(f"[DRY RUN] Would execute {self.TECHNIQUE_ID} — skipping.")
            return SimulationResult(
                technique_id=self.TECHNIQUE_ID,
                technique_name=self.TECHNIQUE_NAME,
                tactic=self.TACTIC,
                timestamp=self._start_time,
                success=True,
                artifacts_generated=[],
                expected_alert_keywords=self._expected_keywords(),
                notes="dry_run=True — no actions taken",
            )

        try:
            result = self.simulate()
            logger.info(f"[SIM] Completed {self.TECHNIQUE_ID}")
            return result
        except Exception as exc:
            logger.error(f"[SIM] {self.TECHNIQUE_ID} failed: {exc}")
            return SimulationResult(
                technique_id=self.TECHNIQUE_ID,
                technique_name=self.TECHNIQUE_NAME,
                tactic=self.TACTIC,
                timestamp=self._start_time,
                success=False,
                artifacts_generated=[],
                expected_alert_keywords=self._expected_keywords(),
                error=str(exc),
            )
        finally:
            self.cleanup()

    @abstractmethod
    def simulate(self) -> SimulationResult:
        """
        Execute the safe simulation and return a SimulationResult.
        Must NOT perform destructive or irreversible actions.
        """
        ...

    def cleanup(self) -> None:
        """
        Remove any artifacts or state created by simulate().
        Override in subclasses that create files, processes, etc.
        Default is a no-op.
        """
        pass

    def _expected_keywords(self) -> list[str]:
        """
        Return the log keywords a SIEM rule should match.
        Override in each subclass with technique-specific terms.
        """
        return []
