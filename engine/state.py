"""
state.py — Concurrent-safe state file read/write with flock and atomic rename.

Provides read_state() and write_state() for JSON state files under state/.
Uses POSIX flock for exclusive write locking and atomic rename (write tmp → mv)
to prevent partial reads by concurrent processes.
"""

import fcntl
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

_STATE_DIR = Path(os.environ.get("STATE_DIR", "state"))
_LOCK_RETRIES = 3
_LOCK_BACKOFF_MS = 100  # milliseconds


def _ensure_dir(path: Path) -> None:
    """Create parent directories for *path* if they don't exist."""
    path.parent.mkdir(parents=True, exist_ok=True)


def _lock_file(fd: int, exclusive: bool = True) -> bool:
    """Acquire a POSIX flock on an open file descriptor.

    Args:
        fd: Open file descriptor.
        exclusive: If True, acquire exclusive (write) lock; else shared lock.

    Returns:
        True if lock acquired, False otherwise.
    """
    op = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    try:
        fcntl.flock(fd, op | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def write_state(scan_id: str, data: dict[str, Any], skill: str = "engine") -> str:
    """Write *data* as JSON to ``state/{skill}/{scan_id}.json``.

    Uses flock + atomic rename:

    1. Write to a temporary file in the same directory.
    2. Acquire exclusive flock on the target file (creates if missing).
    3. Rename (atomic on POSIX) temp → target.
    4. Release lock (fd close).

    Args:
        scan_id: Unique scan/workflow identifier.
        data: Serializable dictionary to persist.
        skill: Skill namespace (default "engine").

    Returns:
        The absolute path of the written state file.

    Raises:
        IOError: If the file cannot be written after retries.
    """
    target = _STATE_DIR / skill / f"{scan_id}.json"
    _ensure_dir(target)

    # Retry loop for lock contention
    for attempt in range(1, _LOCK_RETRIES + 1):
        # Open target for locking (O_CREAT ensures the file exists)
        lock_fd: Optional[int] = None
        try:
            lock_fd = os.open(str(target), os.O_CREAT | os.O_RDWR, 0o644)
            if _lock_file(lock_fd, exclusive=True):
                # Lock acquired — write to tmp, then rename
                tmp_fd, tmp_path = tempfile.mkstemp(
                    dir=str(target.parent),
                    prefix=f".{scan_id}.tmp.",
                )
                try:
                    with os.fdopen(tmp_fd, "w") as tmp_file:
                        json.dump(data, tmp_file, indent=2, default=str)
                        tmp_file.flush()
                        os.fsync(tmp_fd)
                    os.rename(tmp_path, str(target))
                except Exception:
                    # Clean up temp file on failure
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                    raise
                return str(target)
        except OSError:
            if attempt < _LOCK_RETRIES:
                time.sleep(_LOCK_BACKOFF_MS / 1000)
            else:
                raise IOError(
                    f"Could not acquire lock on {target} after {_LOCK_RETRIES} attempts"
                )
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
    raise IOError(f"Failed to write {target}")  # unreachable, but satisfy type


def read_state(scan_id: str, skill: str = "engine") -> dict[str, Any]:
    """Read JSON state from ``state/{skill}/{scan_id}.json``.

    Uses a shared (read) flock to ensure consistency during concurrent writes.

    Args:
        scan_id: Unique scan/workflow identifier.
        skill: Skill namespace (default "engine").

    Returns:
        Deserialized dictionary.

    Raises:
        FileNotFoundError: If the state file does not exist.
        json.JSONDecodeError: If the file contains invalid JSON.
    """
    target = _STATE_DIR / skill / f"{scan_id}.json"
    if not target.exists():
        raise FileNotFoundError(f"State file not found: {target}")

    fd = os.open(str(target), os.O_RDONLY)
    try:
        _lock_file(fd, exclusive=False)
        with os.fdopen(fd, "r") as f:
            return dict(json.load(f))
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def delete_state(scan_id: str, skill: str = "engine") -> None:
    """Remove a state file.

    Args:
        scan_id: Unique scan/workflow identifier.
        skill: Skill namespace (default "engine").
    """
    target = _STATE_DIR / skill / f"{scan_id}.json"
    if target.exists():
        target.unlink()
