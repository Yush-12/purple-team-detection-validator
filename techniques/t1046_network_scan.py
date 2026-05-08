import socket
from datetime import datetime, timezone
from techniques.base import TechniqueBase, SimulationResult

class T1046NetworkScan(TechniqueBase):
    TECHNIQUE_ID = "T1046"
    TECHNIQUE_NAME = "Network Service Discovery"
    TACTIC = "Discovery"
    REFERENCE_URL = "https://attack.mitre.org/techniques/T1046/"

    def simulate(self) -> SimulationResult:
        """
        TCP connect probe on localhost across common ports.
        """
        target = "127.0.0.1"
        ports = [22, 80, 443, 8080]
        results = []
        
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                result = s.connect_ex((target, port))
                status = "open" if result == 0 else "closed"
                results.append(f"{target}:{port} - {status}")
        
        return SimulationResult(
            technique_id=self.TECHNIQUE_ID,
            technique_name=self.TECHNIQUE_NAME,
            tactic=self.TACTIC,
            timestamp=datetime.now(timezone.utc),
            success=True,
            artifacts_generated=[f"TCP Scanned: {', '.join(results)}"],
            expected_alert_keywords=self._expected_keywords(),
        )

    def _expected_keywords(self) -> list[str]:
        return ["network.connection", "destination.port"]
