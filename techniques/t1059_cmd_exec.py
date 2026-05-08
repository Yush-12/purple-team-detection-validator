import subprocess
from datetime import datetime, timezone
from techniques.base import TechniqueBase, SimulationResult

class T1059CmdExec(TechniqueBase):
    TECHNIQUE_ID = "T1059"
    TECHNIQUE_NAME = "Command and Scripting Interpreter"
    TACTIC = "Execution"
    REFERENCE_URL = "https://attack.mitre.org/techniques/T1059/"

    def simulate(self) -> SimulationResult:
        """
        Runs benign shell commands to generate process execution telemetry.
        """
        # Benign commands that should be logged
        cmd = ["whoami"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        return SimulationResult(
            technique_id=self.TECHNIQUE_ID,
            technique_name=self.TECHNIQUE_NAME,
            tactic=self.TACTIC,
            timestamp=datetime.now(timezone.utc),
            success=True,
            artifacts_generated=[f"Process: {' '.join(cmd)}", f"Output: {result.stdout.strip()}"],
            expected_alert_keywords=self._expected_keywords(),
        )

    def _expected_keywords(self) -> list[str]:
        return ["whoami", "process.name"]
