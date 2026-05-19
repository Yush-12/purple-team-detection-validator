"""
executor.py — Subprocess execution engine for purple team technique simulation.
"""

import subprocess
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from technique_schema import Technique

logger = logging.getLogger(__name__)

PURPLETEAM_DIR = Path("/tmp/purpleteam")


@dataclass
class ExecutionResult:
    technique_id: str
    success: bool
    commands_run: int
    commands_failed: int
    stdout_lines: List[str]
    stderr_lines: List[str]
    start_time: datetime
    end_time: datetime
    error: Optional[str]


class TechniqueExecutor:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def execute(self, technique: Technique) -> ExecutionResult:
        """Execute all commands for a technique sequentially, then run cleanup."""
        PURPLETEAM_DIR.mkdir(parents=True, exist_ok=True)

        start_time = datetime.now(timezone.utc)
        stdout_lines: List[str] = []
        stderr_lines: List[str] = []
        commands_run = 0
        commands_failed = 0
        errors: List[str] = []

        logger.info(
            "[EXECUTOR] Running technique %s (%s) — %d command(s)",
            technique.technique_id,
            technique.name,
            len(technique.commands),
        )

        for i, cmd in enumerate(technique.commands, start=1):
            logger.info("[EXECUTOR] [%d/%d] %s", i, len(technique.commands), cmd[:120])
            success, stdout, stderr = self._run_single_command(cmd)
            commands_run += 1

            if stdout:
                stdout_lines.extend(stdout.splitlines())
            if stderr:
                stderr_lines.extend(stderr.splitlines())

            if not success:
                commands_failed += 1
                error_msg = f"Command {i} failed: {stderr.strip()[:200]}"
                errors.append(error_msg)
                logger.warning("[EXECUTOR] %s", error_msg)

        for j, cleanup_cmd in enumerate(technique.cleanup_commands, start=1):
            logger.info("[EXECUTOR] [cleanup %d/%d] %s", j, len(technique.cleanup_commands), cleanup_cmd[:120])
            cleanup_ok, _, cleanup_stderr = self._run_single_command(cleanup_cmd)
            if not cleanup_ok:
                logger.warning("[EXECUTOR] Cleanup command %d failed: %s", j, cleanup_stderr.strip()[:200])

        end_time = datetime.now(timezone.utc)
        overall_success = commands_failed == 0

        result = ExecutionResult(
            technique_id=technique.technique_id,
            success=overall_success,
            commands_run=commands_run,
            commands_failed=commands_failed,
            stdout_lines=stdout_lines,
            stderr_lines=stderr_lines,
            start_time=start_time,
            end_time=end_time,
            error="; ".join(errors) if errors else None,
        )

        logger.info(
            "[EXECUTOR] Technique %s finished — success=%s, ran=%d, failed=%d",
            technique.technique_id,
            overall_success,
            commands_run,
            commands_failed,
        )

        return result

    def _run_single_command(self, cmd: str) -> Tuple[bool, str, str]:
        """Run a single shell command. Never raises — always returns (success, stdout, stderr)."""
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return (proc.returncode == 0, proc.stdout, proc.stderr)

        except subprocess.TimeoutExpired:
            return (False, "", f"Command timed out after {self.timeout}s: {cmd[:100]}")

        except FileNotFoundError as e:
            return (False, "", f"Command not found: {e}")

        except Exception as e:
            return (False, "", f"Unexpected error: {e}")
