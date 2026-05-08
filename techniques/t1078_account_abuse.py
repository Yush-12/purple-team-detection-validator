import os
from datetime import datetime, timezone
from techniques.base import TechniqueBase, SimulationResult

class T1078AccountAbuse(TechniqueBase):
    TECHNIQUE_ID = "T1078"
    TECHNIQUE_NAME = "Valid Accounts"
    TACTIC = "Defense Evasion"
    REFERENCE_URL = "https://attack.mitre.org/techniques/T1078/"

    def simulate(self) -> SimulationResult:
        """
        Writes structured auth failure events to a local log file.
        """
        log_file = "auth_simulation.log"
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        
        events = [
            f"{timestamp} server-01 sshd[1234]: Failed password for root from 192.168.1.100 port 5678 ssh2",
            f"{timestamp} server-01 sshd[1234]: Failed password for admin from 192.168.1.100 port 5679 ssh2",
            f"{timestamp} server-01 sshd[1234]: Failed password for invaliduser from 192.168.1.100 port 5680 ssh2"
        ]
        
        with open(log_file, "a") as f:
            for event in events:
                f.write(event + "\n")
                
        return SimulationResult(
            technique_id=self.TECHNIQUE_ID,
            technique_name=self.TECHNIQUE_NAME,
            tactic=self.TACTIC,
            timestamp=datetime.now(timezone.utc),
            success=True,
            artifacts_generated=[f"Logs written to {log_file}", f"Sample: {events[0]}"],
            expected_alert_keywords=self._expected_keywords(),
        )

    def cleanup(self) -> None:
        if os.path.exists("auth_simulation.log"):
            os.remove("auth_simulation.log")

    def _expected_keywords(self) -> list[str]:
        return ["Failed password", "sshd", "ssh2"]
