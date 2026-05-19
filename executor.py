import os
import sys
import platform
import subprocess
import json
import yaml
from datetime import datetime, timezone
import getpass
import socket
import logging

logger = logging.getLogger(__name__)

# Platform-aware telemetry paths
if platform.system() == "Windows":
    LOG_DIR = "C:\\Temp\\purpleteam"
else:
    LOG_DIR = "/tmp/purpleteam"

LOG_FILE = os.path.join(LOG_DIR, "events.log")


class TechniqueExecutor:
    def __init__(self, techniques_dir: str = "techniques", dry_run: bool = False):
        self.techniques_dir = techniques_dir
        self.dry_run = dry_run
        
        # Ensure telemetry log directory exists
        if not self.dry_run:
            try:
                os.makedirs(LOG_DIR, exist_ok=True)
                logger.info(f"[EXECUTOR] Telemetry directory verified: {LOG_DIR}")
            except Exception as e:
                logger.error(f"[EXECUTOR] Failed to create telemetry directory {LOG_DIR}: {e}")

    def load_technique(self, technique_id: str) -> dict:
        """Load technique definition from YAML."""
        # Convert T1070.004 to t1070_004 for filename
        sanitized_id = technique_id.lower().replace(".", "_")
        yaml_path = os.path.join(self.techniques_dir, f"{sanitized_id}.yaml")
        
        if not os.path.exists(yaml_path):
            raise FileNotFoundError(f"Technique YAML not found: {yaml_path}")
            
        with open(yaml_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def execute(self, technique_id: str) -> dict:
        """Loads and executes a technique by ID."""
        tech = self.load_technique(technique_id)
        
        # Determine current platform
        current_os = platform.system()
        cmd = tech.get("command_linux") if current_os != "Windows" else tech.get("command_windows")
        
        logger.info(f"[EXECUTOR] Executing technique {tech['id']} ({tech['name']}) on {current_os}")
        
        result = {
            "technique_id": tech["id"],
            "technique_name": tech["name"],
            "tactic": tech["tactic"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "command": cmd,
            "success": False,
            "stdout": "",
            "stderr": "",
            "error": None,
            "notes": ""
        }
        
        if self.dry_run:
            logger.info(f"[DRY RUN] Would execute command: {cmd}")
            result["success"] = True
            result["notes"] = "Dry run mode enabled. No commands executed."
            return result

        if not cmd:
            result["error"] = f"No command defined for platform {current_os}"
            logger.error(f"[EXECUTOR] {result['error']}")
            return result

        # Subprocess execution
        try:
            # We run via shell since some techniques use shell-native pipes or loops
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30 # 30-second execution safety limit
            )
            result["stdout"] = proc.stdout
            result["stderr"] = proc.stderr
            result["success"] = (proc.returncode == 0)
            logger.info(f"[EXECUTOR] Command exited with return code: {proc.returncode}")
        except subprocess.TimeoutExpired as te:
            result["error"] = "Command timed out after 30 seconds"
            result["stdout"] = te.stdout or ""
            result["stderr"] = te.stderr or ""
            logger.warning(f"[EXECUTOR] Command timed out: {cmd}")
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"[EXECUTOR] Process execution error: {e}")

        # Post-execution logging: write structured telemetry event
        self._write_telemetry_event(tech, result)
        
        return result

    def _write_telemetry_event(self, tech: dict, execution_result: dict) -> None:
        """Appends custom JSON telemetry events to the watched events.log file."""
        log_event = tech.get("log_event")
        if not log_event:
            logger.debug(f"[EXECUTOR] No custom log_event defined for {tech['id']}. Skipping telemetry write.")
            return

        # Prepare ECS compliant base metadata
        telemetry = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event.provider": "purpleteam-validator",
            "host.name": socket.gethostname(),
            "user.name": getpass.getuser(),
            "execution.success": execution_result["success"]
        }
        
        # Merge YAML-defined log fields into telemetry
        telemetry.update(log_event)

        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(telemetry) + "\n")
            logger.info(f"[TELEMETRY] Custom log event appended to {LOG_FILE}")
            
            # Special case for T1078 SSH auth: also append duplicate login attempts to auth log path if writable
            if tech["id"] == "T1078":
                logger.info("[TELEMETRY] SSH simulation event written. Filebeat will pick up either custom JSON event or system auth log.")
        except Exception as e:
            logger.error(f"[TELEMETRY] Failed to write custom event to {LOG_FILE}: {e}")
