import os
import subprocess
from datetime import datetime, timezone
from techniques.base import TechniqueBase, SimulationResult

class T1566PhishingArtifact(TechniqueBase):
    TECHNIQUE_ID = "T1566"
    TECHNIQUE_NAME = "Phishing"
    TACTIC = "Initial Access"
    REFERENCE_URL = "https://attack.mitre.org/techniques/T1566/"

    def simulate(self) -> SimulationResult:
        """
        Drops a double-extension file and spawns a simulated shell child process.
        """
        # 1. Drop double-extension file
        malicious_file = "invoice_2024.pdf.sh"
        with open(malicious_file, "w") as f:
            f.write("#!/bin/bash\necho 'Mock malicious payload'")
        
        # 2. Spawn a simulated shell child process (benign but shows lineage)
        # We'll just run a simple command via a shell
        cmd = ["sh", "-c", "echo 'Phishing simulation active'"]
        subprocess.run(cmd, capture_output=True)

        return SimulationResult(
            technique_id=self.TECHNIQUE_ID,
            technique_name=self.TECHNIQUE_NAME,
            tactic=self.TACTIC,
            timestamp=datetime.now(timezone.utc),
            success=True,
            artifacts_generated=[f"Dropped file: {malicious_file}", f"Spawned child process: sh -c ..."],
            expected_alert_keywords=self._expected_keywords(),
        )

    def cleanup(self) -> None:
        if os.path.exists("invoice_2024.pdf.sh"):
            os.remove("invoice_2024.pdf.sh")

    def _expected_keywords(self) -> list[str]:
        return [".pdf.sh", "invoice", "shell"]
