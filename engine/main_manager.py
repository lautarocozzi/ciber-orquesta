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
        self._running_pids: dict[str, tuple[int, float]] = {}  # key: f"{scan_id}/{sub_process}" → (pid, start_time_ns)

    async def run_sub_process(
        self,
        scan_id: str,
        skill: str,
        target: str,
        sub_process_path: str,
        parameters: Optional[dict[str, Any]] = None,
        timeout: Optional[int] = None,
        env_overrides: Optional[dict[str, str]] = None,
    ) -> ProcessResult:
        """Execute a sub-process MAIN with 3-tier rollback.

        Args:
            scan_id: Unique scan identifier.
            skill: Skill name (e.g. "nmap").
            target: Target IP or hostname.
            sub_process_path: Path to the sub-process executable/script.
            parameters: Optional dict of parameters passed as env vars.
            timeout: Optional timeout in seconds for the sub-process.

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
                timeout=timeout, env_overrides=env_overrides,
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
            env_overrides=env_overrides,
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
        timeout: Optional[int] = None,
        env_overrides: Optional[dict[str, str]] = None,
    ) -> ProcessResult:
        """Low-level process execution with PID tracking."""
        env = dict(os.environ)
        env.update({
            "SCAN_ID": scan_id,
            "SKILL": skill,
            "TARGET": target,
            "SUB_PROCESS": sub_process_path,
            "STATE_DIR": os.environ.get("STATE_DIR", str(_STATE_DIR)),
            "REPORTS_DIR": os.environ.get("REPORTS_DIR", "reports"),
        })
        if env_overrides:
            env.update(env_overrides)
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

        pid = proc.pid if proc.pid else 0
        start_time_ns = 0.0
        if pid > 0:
            try:
                start_time_ns = os.stat(f'/proc/{pid}').st_ctime_ns
            except OSError:
                pass  # /proc inaccessible or process already gone
        self._running_pids[process_key] = (pid, start_time_ns)

        try:
            if timeout is not None:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout,
                )
            else:
                stdout, stderr = await proc.communicate()
        except asyncio.TimeoutError:
            await self._kill_process(process_key)
            return ProcessResult(
                scan_id=scan_id,
                skill=skill,
                target=target,
                sub_process=sub_process_path,
                status=ProcessStatus.FAILED,
                error_context={
                    "error": f"Process timed out after {timeout}s",
                    "timeout": timeout,
                },
            )
        except asyncio.CancelledError:
            await self._kill_process(process_key)
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

        await asyncio.to_thread(
            self._write_pid_record, scan_id, skill, sub_process_path, proc.returncode,
        )

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
        env_overrides: Optional[dict[str, str]] = None,
    ) -> ProcessResult:
        """Tier 2: Search for alternative sub-process scripts.

        Looks for scripts with ``fallback``, ``light``, or ``quick`` in the
        name within the same directory (e.g. ``port-discovery-fallback.sh``).
        Avoids grabbing unrelated sibling scripts.
        """
        base_dir = Path(sub_process_path).parent
        base_name = Path(sub_process_path).stem

        # Only look for named fallback/light/quick variants of the same sub-process
        alternatives = []
        search_dirs = [base_dir, base_dir / "sub-processes"]
        for search_dir in search_dirs:
            for suffix in ["fallback", "light", "quick"]:
                candidates = (
                    list(search_dir.glob(f"{base_name}-{suffix}.sh")) +
                    list(search_dir.glob(f"{base_name}-{suffix}.py"))
                )
                alternatives.extend(candidates)

        for alt in alternatives:
            logger.info("Tier 2: Trying alternative %s", alt)
            alt_result = await self._execute_process(
                scan_id, skill, target, str(alt), parameters, f"{scan_id}/{alt}",
                env_overrides=env_overrides,
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

    async def _kill_process(self, process_key: str) -> None:
        """Send SIGTERM to a tracked process, then SIGKILL after 5s.

        Uses process start time (from /proc/{pid}) to detect PID recycling:
        before sending SIGKILL, verifies the process at that PID is still the
        same one we spawned. Falls back to basic existence check if start time
        was not recorded (/proc unavailable).
        """
        entry = self._running_pids.get(process_key)
        if not entry:
            return
        pid, start_time_ns = entry
        if pid <= 0:
            return

        try:
            os.kill(pid, signal.SIGTERM)
            # Allow 5s grace period — use asyncio.sleep to avoid blocking
            await asyncio.sleep(5)

            # Check if process still exists AND hasn't been PID-recycled.
            # Use os.stat on /proc/{pid} to get current start_time for comparison.
            if start_time_ns > 0:
                # We have a recorded start time — verify it matches
                try:
                    current_ctime = os.stat(f'/proc/{pid}').st_ctime_ns
                    if current_ctime != start_time_ns:
                        logger.warning(
                            "PID %d start time changed (%.0f \u2192 %.0f) \u2014 "
                            "process recycled, skipping SIGKILL",
                            pid, start_time_ns, current_ctime,
                        )
                        return
                except OSError:
                    # /proc/{pid} doesn't exist — process exited during grace period
                    return
                # Start time matches — process is the same one, send SIGKILL
                os.kill(pid, signal.SIGKILL)
            else:
                # Fallback: no recorded start time (/proc was unavailable),
                # use basic existence check
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    # Process exited gracefully during grace period
                    return
                os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            logger.warning("Failed to kill process %d: %s", pid, exc)
        finally:
            self._running_pids.pop(process_key, None)

    async def cancel_scan(self, scan_id: str) -> int:
        """Cancel all running processes for a given scan_id.

        Args:
            scan_id: The scan identifier to cancel.

        Returns:
            Number of processes cancelled.
        """
        count = 0
        for process_key in list(self._running_pids.keys()):
            if process_key.startswith(f"{scan_id}/"):
                await self._kill_process(process_key)
                count += 1
        return count

    @property
    def running_count(self) -> int:
        """Number of currently tracked running processes."""
        return len(self._running_pids)

    def cleanup_zombie_pids(self) -> int:
        """Clean up PID records where the process no longer exists.

        Uses start-time comparison (when available) to detect PID recycling:
        if the process at the tracked PID has a different start time, the
        original process is gone and the PID was reused.

        Returns:
            Number of stale records cleaned.
        """
        cleaned = 0
        for process_key in list(self._running_pids.keys()):
            pid, start_time_ns = self._running_pids[process_key]
            if pid <= 0:
                self._running_pids.pop(process_key, None)
                cleaned += 1
                continue

            stale = False
            try:
                os.kill(pid, 0)  # Test if process exists
            except OSError:
                stale = True

            if not stale and start_time_ns > 0:
                # Process exists — verify it's the same one
                try:
                    current_ctime = os.stat(f'/proc/{pid}').st_ctime_ns
                    if current_ctime != start_time_ns:
                        stale = True
                except OSError:
                    stale = True  # /proc inaccessible, assume stale

            if stale:
                self._running_pids.pop(process_key, None)
                cleaned += 1

        return cleaned
