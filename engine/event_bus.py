"""
event_bus.py — Filesystem event bus with inotify + polling fallback.

Writes scan events as JSON to ``events/{skill}/{scan_id}.json`` and provides
an async watcher that monitors ``state/`` for completion by polling or inotify.

Event file TTL cleanup is configurable (default 24h).
"""

import asyncio
import json
import logging
import os
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

_EVENTS_DIR = Path(os.environ.get("EVENTS_DIR", "events"))
_STATE_DIR = Path(os.environ.get("STATE_DIR", "state"))
_DEFAULT_TTL_HOURS = 24
_POLL_INTERVAL = 5  # seconds


def write_event(
    skill: str,
    scan_id: str,
    target: str,
    parameters: Optional[dict[str, Any]] = None,
) -> str:
    """Write a scan event to ``events/{skill}/{scan_id}.json``.

    Args:
        skill: Skill name (e.g. "nmap").
        scan_id: Unique scan identifier.
        target: Target IP or hostname.
        parameters: Optional dict of scan parameters.

    Returns:
        The absolute path of the written event file.
    """
    event_dir = _EVENTS_DIR / skill
    event_dir.mkdir(parents=True, exist_ok=True)

    event = {
        "skill": skill,
        "target": target,
        "scan_id": scan_id,
        "parameters": parameters or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    event_path = event_dir / f"{scan_id}.json"
    with open(event_path, "w") as f:
        json.dump(event, f, indent=2, default=str)

    logger.info("Event written: %s", event_path)
    return str(event_path)


async def wait_for_completion(
    scan_id: str,
    skill: str = "nmap",
    poll_interval: float = _POLL_INTERVAL,
    timeout: Optional[float] = None,
) -> dict[str, Any]:
    """Wait for a scan to complete by monitoring its state file.

    Uses inotify if available (via ``watchfiles`` or ``pyinotify``), otherwise
    polls ``state/{skill}/{scan_id}/status.json`` every *poll_interval* seconds.

    Args:
        scan_id: Unique scan identifier.
        skill: Skill name.
        poll_interval: Seconds between polls (default 5).
        timeout: Maximum seconds to wait (None = no limit).

    Returns:
        The parsed status dict from the state file.

    Raises:
        TimeoutError: If *timeout* seconds elapse without completion.
    """
    state_status_path = _STATE_DIR / skill / scan_id / "status.json"
    started = time.monotonic()

    # Try inotify-based watching first
    inotify_available = await _try_inotify_watch(state_status_path, timeout)
    if inotify_available:
        # If inotify succeeded, file exists and should have final status
        pass

    # Polling fallback
    while True:
        if state_status_path.exists():
            try:
                with open(state_status_path) as f:
                    status: dict[str, Any] = json.load(f)
                if status.get("status") in ("done", "failed", "degraded", "cancelled"):
                    logger.info(
                        "Scan %s/%s completed with status: %s",
                        skill, scan_id, status.get("status"),
                    )
                    return status
            except (json.JSONDecodeError, OSError):
                pass

        if timeout is not None and (time.monotonic() - started) > timeout:
            raise TimeoutError(
                f"Timed out waiting for {skill}/{scan_id} after {timeout}s"
            )

        await asyncio.sleep(poll_interval)


async def _try_inotify_watch(
    path: Path, timeout: Optional[float]
) -> bool:
    """Attempt to use inotify to watch *path* for changes.

    Falls back silently if inotify libraries are not available.

    Returns:
        True if inotify detected the file completion, False to fall back to polling.
    """
    try:
        import watchfiles
    except ImportError:
        logger.debug("watchfiles not available; using polling fallback")
        return False

    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)

    async def _wait_for_change() -> bool:
        async for changes in watchfiles.awatch(
            str(path.parent), stop_event=None,
        ):
            for _change_type, changed_path in changes:
                if str(changed_path) == str(path):
                    return True
        return False

    try:
        result = await asyncio.wait_for(
            _wait_for_change(), timeout=timeout or 30,
        )
        return result
    except asyncio.TimeoutError:
        logger.debug("inotify watch timed out; using polling fallback")
        return False
    except Exception as exc:
        logger.debug("inotify watch failed (%s); using polling fallback", exc)
        return False


def cleanup_old_events(ttl_hours: int = _DEFAULT_TTL_HOURS) -> int:
    """Remove event files older than *ttl_hours*.

    Args:
        ttl_hours: Age threshold in hours (default 24).

    Returns:
        Number of deleted files.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)
    deleted = 0
    if not _EVENTS_DIR.exists():
        return 0

    for event_file in _EVENTS_DIR.rglob("*.json"):
        try:
            mtime = datetime.fromtimestamp(event_file.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                event_file.unlink()
                deleted += 1
        except OSError:
            continue
    return deleted


class EventWatcher:
    """Async context manager that watches ``state/`` for status changes.

    Calls *callback(skill, scan_id, status)* when a scan completes.
    """

    def __init__(
        self,
        callback: Callable[[str, str, dict[str, Any]], None],
        poll_interval: float = _POLL_INTERVAL,
    ):
        self.callback = callback
        self.poll_interval = poll_interval
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Begin watching the state directory tree."""
        self._running = True
        self._task = asyncio.create_task(self._watch_loop())
        logger.info("EventWatcher started (poll interval: %ss)", self.poll_interval)

    async def stop(self) -> None:
        """Stop watching."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _watch_loop(self) -> None:
        """Main loop: scan ``state/`` for new/changed status.json files."""
        known_states: OrderedDict[str, str] = OrderedDict()
        _MAX_KNOWN = 1000
        while self._running:
            await self._scan_state_dir(known_states)
            # Evict oldest entries when over max size
            while len(known_states) > _MAX_KNOWN:
                known_states.popitem(last=False)
            await asyncio.sleep(self.poll_interval)

    async def _scan_state_dir(
        self, known_states: dict[str, str]
    ) -> None:
        """Walk ``state/`` and look for completion status files."""
        if not _STATE_DIR.exists():
            return

        for skill_dir in _STATE_DIR.iterdir():
            if not skill_dir.is_dir():
                continue
            for scan_dir in skill_dir.iterdir():
                if not scan_dir.is_dir():
                    continue
                status_file = scan_dir / "status.json"
                if not status_file.exists():
                    continue

                key = f"{skill_dir.name}/{scan_dir.name}"
                prev_status = known_states.get(key)
                try:
                    with open(status_file) as f:
                        status: dict[str, Any] = json.load(f)
                except (json.JSONDecodeError, OSError):
                    continue

                current_status = status.get("status", "unknown")
                known_states[key] = current_status

                if current_status in ("done", "failed", "degraded", "cancelled"):
                    if prev_status != current_status:
                        try:
                            self.callback(
                                skill_dir.name, scan_dir.name, status
                            )
                        except Exception as exc:
                            logger.error(
                                "EventWatcher callback error: %s", exc
                            )
