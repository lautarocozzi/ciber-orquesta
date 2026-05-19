"""
main_manager.py — Sub-process lifecycle manager with 3-tier rollback.

Launches MAIN (Managed Arbitrary INvocation) sub-processes from skill definitions,
tracks PIDs via state files, and implements a 3-tier retry strategy:

- Tier 1: Direct retry (up to 3 immediate attempts)
- Tier 2: Escalate — fall back to sub-process alternatives
- Tier 3: Record failure with error context
"""

import asyncio
import json
import logging
import os
import signal
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_STATE_DIR = Path(os.environ.get("STATE_DIR", "state"))


class RetryTier(Enum):
    """3-tier rollback levels."""
    TIER1_RETRY = "tier1_retry"          # Immediate re-execution
    TIER2_ESCALATE = "tier2_escalate"    # Fall back to alternative sub-process
    TIER3_FAILURE = "tier3_failure"      # Record failure, do not retry


class ProcessStatus(Enum):
    """Execution status for a managed sub-process."""
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ProcessResult:
    """Outcome of a managed process execution."""
    scan_id: str
    skill: str
    target: str
    sub_process: str
    status: ProcessStatus
    return_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    retry_tier: Optional[RetryTier] = None
    error_context: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0


class MainManager:
    """Manages sub-process lifecycle with PID tracking and 3-tier rollback."""

    def __init__(self, max_tier1_retries: int = 3):
        self.max_tier1_retries = max_tier1_retries
        self._running_pids: dict[str, int] = {}  # key: f"{scan_id}/{sub_process}"

    async def run_sub_process(
        self,
        scan_id: str,
        skill: str,
        target: str,
        sub_process_path: str,
        parameters: Optional[dict[str, Any]] = None,
    ) -> ProcessResult:
        """Execute a sub-process MAIN with 3-tier rollback.

        Args:
            scan_id: Unique scan identifier.
            skill: Skill name (e.g. "nmap").
            target: Target IP or hostname.
            sub_process_path: Path to the sub-process executable/script.
            parameters: Optional dict of parameters passed as env vars.

        Returns:
            ProcessResult with final status and error context.
        """
        started = time.monotonic()
        process_key = f"{scan_id}/{sub_process_path}"
        params = parameters or {}

        # Tier 1: Direct retry
        last_error: Optional[str] = None
        for attempt in range(1, self.max_tier1_retries + 1):
            logger.info(
                "Tier 1: Attempt %d/%d for %s (%s)",
                attempt, self.max_tier1_retries, sub_process_path, target,
            )
            result = await self._execute_process(
                scan_id, skill, target, sub_process_path, params, process_key,
            )
            if result.status == ProcessStatus.DONE:
                result.retry_tier = RetryTier.TIER1_RETRY if attempt > 1 else None
                result.duration_ms = (time.monotonic() - started) * 1000
                return result

            last_error = result.stderr or result.error_context.get("error", "unknown")
            logger.warning(
                "Attempt %d failed for %s: %s",
                attempt, sub_process_path, last_error,
            )

            if attempt < self.max_tier1_retries:
                await asyncio.sleep(1 * attempt)  # Backoff: 1s, 2s, 3s

        # Tier 2: Escalate — look for sub-process alternatives
        logger.info(
            "Tier 2: Escalating %s after %d failed attempts",
            sub_process_path, self.max_tier1_retries,
        )
        tier2_result = await self._try_sub_process_alternatives(
            scan_id, skill, target, sub_process_path, params,
        )
        if tier2_result.status == ProcessStatus.DONE:
            tier2_result.retry_tier = RetryTier.TIER2_ESCALATE
            tier2_result.duration_ms = (time.monotonic() - started) * 1000
            return tier2_result

        # Tier 3: Record failure
        logger.error(
            "Tier 3: All retry strategies exhausted for %s (%s)",
            sub_process_path, target,
        )
        failed_result = ProcessResult(
            scan_id=scan_id,
            skill=skill,
            target=target,
            sub_process=sub_process_path,
            status=ProcessStatus.FAILED,
            retry_tier=RetryTier.TIER3_FAILURE,
            error_context={
                "last_attempt_error": last_error,
                "tier2_outcome": tier2_result.stderr,
                "total_attempts": self.max_tier1_retries + 1,
            },
            stderr=last_error or "",
        )
        failed_result.duration_ms = (time.monotonic() - started) * 1000
        return failed_result

    async def _execute_process(
        self,
        scan_id: str,
        skill: str,
        target: str,
        sub_process_path: str,
        parameters: dict[str, Any],
        process_key: str,
    ) -> ProcessResult:
        """Low-level process execution with PID tracking."""
        env = dict(os.environ)
        env.update({
            "SCAN_ID": scan_id,
            "SKILL": skill,
            "TARGET": target,
            "SUB_PROCESS": sub_process_path,
        })
        for k, v in parameters.items():
            env[f"PARAM_{k.upper()}"] = str(v)

        try:
            proc = await asyncio.create_subprocess_exec(
                sub_process_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError:
            return ProcessResult(
                scan_id=scan_id,
                skill=skill,
                target=target,
                sub_process=sub_process_path,
                status=ProcessStatus.FAILED,
                error_context={"error": f"Executable not found: {sub_process_path}"},
            )

        self._running_pids[process_key] = proc.pid if proc.pid else 0

        try:
            stdout, stderr = await proc.communicate()
        except asyncio.CancelledError:
            self._kill_process(process_key)
            return ProcessResult(
                scan_id=scan_id,
                skill=skill,
                target=target,
                sub_process=sub_process_path,
                status=ProcessStatus.CANCELLED,
            )
        finally:
            self._running_pids.pop(process_key, None)

        status = ProcessStatus.DONE if proc.returncode == 0 else ProcessStatus.FAILED

        self._write_pid_record(scan_id, skill, sub_process_path, proc.returncode)

        return ProcessResult(
            scan_id=scan_id,
            skill=skill,
            target=target,
            sub_process=sub_process_path,
            status=status,
            return_code=proc.returncode,
            stdout=stdout.decode("utf-8", errors="replace") if stdout else "",
            stderr=stderr.decode("utf-8", errors="replace") if stderr else "",
        )

    async def _try_sub_process_alternatives(
        self,
        scan_id: str,
        skill: str,
        target: str,
        sub_process_path: str,
        parameters: dict[str, Any],
    ) -> ProcessResult:
        """Tier 2: Search for alternative sub-process scripts.

        Checks the same skill's ``sub_processes/`` directory for variant names
        (e.g. ``nmap-light``, ``quick-scan``).
        """
        base_dir = Path(sub_process_path).parent
        base_name = Path(sub_process_path).stem

        # Look for alternative scripts in the same directory
        alternatives = list(base_dir.glob("*.sh")) + list(base_dir.glob("*.py"))
        # Exclude the original
        alternatives = [a for a in alternatives if str(a) != sub_process_path]
        # Prioritise names containing "quick", "light", "fallback"
        alternatives.sort(
            key=lambda p: (
                0 if any(kw in p.stem for kw in ["quick", "light", "fallback"]) else 1,
                p.stem,
            )
        )

        for alt in alternatives:
            logger.info("Tier 2: Trying alternative %s", alt)
            alt_result = await self._execute_process(
                scan_id, skill, target, str(alt), parameters, f"{scan_id}/{alt}",
            )
            if alt_result.status == ProcessStatus.DONE:
                return alt_result

        return ProcessResult(
            scan_id=scan_id,
            skill=skill,
            target=target,
            sub_process=sub_process_path,
            status=ProcessStatus.FAILED,
            error_context={"error": "No alternative sub-process succeeded"},
        )

    def _write_pid_record(
        self,
        scan_id: str,
        skill: str,
        sub_process_path: str,
        return_code: Optional[int],
    ) -> None:
        """Write a PID record to state/ for observability."""
        record_dir = _STATE_DIR / skill / scan_id
        record_dir.mkdir(parents=True, exist_ok=True)

        record = {
            "scan_id": scan_id,
            "skill": skill,
            "sub_process": sub_process_path,
            "return_code": return_code,
            "timestamp": time.time(),
        }
        pid_file = record_dir / "pid_record.json"
        try:
            if pid_file.exists():
                with open(pid_file) as f:
                    existing = json.load(f)
                if not isinstance(existing, list):
                    existing = [existing]
            else:
                existing = []
            existing.append(record)
            with open(pid_file, "w") as f:
                json.dump(existing, f, indent=2)
        except OSError as exc:
            logger.warning("Failed to write PID record: %s", exc)

    def _kill_process(self, process_key: str) -> None:
        """Send SIGTERM to a tracked process, then SIGKILL after 5s."""
        pid = self._running_pids.get(process_key)
        if pid and pid > 0:
            try:
                os.kill(pid, signal.SIGTERM)
                # Allow 5s grace period
                time.sleep(5)
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as exc:
                logger.warning("Failed to kill process %d: %s", pid, exc)
            finally:
                self._running_pids.pop(process_key, None)

    def cancel_scan(self, scan_id: str) -> int:
        """Cancel all running processes for a given scan_id.

        Args:
            scan_id: The scan identifier to cancel.

        Returns:
            Number of processes cancelled.
        """
        count = 0
        for process_key in list(self._running_pids.keys()):
            if process_key.startswith(f"{scan_id}/"):
                self._kill_process(process_key)
                count += 1
        return count

    @property
    def running_count(self) -> int:
        """Number of currently tracked running processes."""
        return len(self._running_pids)

    def cleanup_zombie_pids(self) -> int:
        """Clean up PID records where the process no longer exists.

        Returns:
            Number of stale records cleaned.
        """
        cleaned = 0
        for process_key in list(self._running_pids.keys()):
            pid = self._running_pids[process_key]
            if pid and pid > 0:
                try:
                    os.kill(pid, 0)  # Test if process exists
                except OSError:
                    self._running_pids.pop(process_key, None)
                    cleaned += 1
        return cleaned
