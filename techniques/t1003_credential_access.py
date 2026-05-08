import os
import platform
from datetime import datetime, timezone
from techniques.base import TechniqueBase, SimulationResult

class T1003CredentialAccess(TechniqueBase):
    TECHNIQUE_ID = "T1003"
    TECHNIQUE_NAME = "OS Credential Dumping"
    TACTIC = "Credential Access"
    REFERENCE_URL = "https://attack.mitre.org/techniques/T1003/"

    def simulate(self) -> SimulationResult:
        """
        Reads sensitive files or creates dmp artifacts.
        """
        artifacts = []
        
        # 1. Read /etc/passwd (Linux) or equivalent
        if platform.system() == "Linux":
            try:
                with open("/etc/passwd", "r") as f:
                    _ = f.read(10)
                artifacts.append("Read /etc/passwd")
            except Exception as e:
                artifacts.append(f"Failed to read /etc/passwd: {e}")
        
        # 2. Create a .dmp canary file
        dmp_file = "lsass_mock.dmp"
        with open(dmp_file, "w") as f:
            f.write("MOCK DMP CONTENT")
        artifacts.append(f"Created {dmp_file}")
        
        # 3. Access /proc/self/maps (Linux)
        if platform.system() == "Linux":
            try:
                with open("/proc/self/maps", "r") as f:
                    _ = f.read(10)
                artifacts.append("Accessed /proc/self/maps")
            except Exception as e:
                artifacts.append(f"Failed to access /proc/self/maps: {e}")

        return SimulationResult(
            technique_id=self.TECHNIQUE_ID,
            technique_name=self.TECHNIQUE_NAME,
            tactic=self.TACTIC,
            timestamp=datetime.now(timezone.utc),
            success=True,
            artifacts_generated=artifacts,
            expected_alert_keywords=self._expected_keywords(),
        )

    def cleanup(self) -> None:
        if os.path.exists("lsass_mock.dmp"):
            os.remove("lsass_mock.dmp")

    def _expected_keywords(self) -> list[str]:
        return ["/etc/passwd", ".dmp", "lsass"]
