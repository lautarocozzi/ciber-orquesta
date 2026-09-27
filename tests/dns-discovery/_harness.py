#!/usr/bin/env python3
"""Shared bootstrap for the offline dns-discovery verification harnesses.

Every portability rule is enforced HERE, once, so no individual harness has to
remember it:

* ``PROJECT`` is derived from this file's location -- never hardcoded. The
  harnesses therefore keep working when the repo is cloned, moved or renamed.
* Each run gets a fresh ``tempfile.mkdtemp()`` work dir OUTSIDE the repo
  working tree, removed on exit unless ``KEEP_TEST_WORKDIR=1``. Nothing is
  ever written into the checkout.
* ``STATE_DIR`` / ``REPORTS_DIR`` / ``WORKFLOW_SHARED_DIR`` point at that work
  dir, so the real ``state/`` and ``reports/`` are never written to. The
  ``assert_repo_untouched()`` check proves that claim instead of asserting it.

Offline by construction: no harness here reaches the network or runs a real
scanner. See README.md for why that matters when reading the results.
"""
from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

# <repo>/tests/dns-discovery/_harness.py -> <repo>
PROJECT = Path(__file__).resolve().parents[2]

# Repo dirs a test run must never write to. Fingerprinted on import.
GENERATED_DIRS = ("state", "reports", "events", "notifications")

# Sanity markers: if these are missing, this file is not inside the repo.
_REPO_MARKERS = ("engine", "skills", "workflows", "run-workflow.sh")


def _fatal(msg: str) -> None:
    print(f"  FATAL  {msg}", file=sys.stderr)
    raise SystemExit(2)


if any(not (PROJECT / m).exists() for m in _REPO_MARKERS):
    _fatal(
        f"project root {PROJECT} does not look like the repo "
        f"(missing {[m for m in _REPO_MARKERS if not (PROJECT / m).exists()]}). "
        f"These tests must live at <repo>/tests/dns-discovery/."
    )


# ---------------------------------------------------------------------------
# Repo write-protection
# ---------------------------------------------------------------------------
def _fingerprint_generated_dirs() -> dict[str, tuple]:
    out: dict[str, tuple] = {}
    for name in GENERATED_DIRS:
        d = PROJECT / name
        if not d.is_dir():
            continue
        entries = []
        for p in sorted(d.rglob("*")):
            try:
                st = p.stat()
            except OSError:
                continue
            entries.append((str(p.relative_to(d)), st.st_size, int(st.st_mtime_ns)))
        out[name] = tuple(entries)
    return out


_BASELINE = _fingerprint_generated_dirs()


def assert_repo_untouched() -> bool:
    """True when the run left the real state/reports/events/notifications alone.

    Call this LAST. A False result is a harness bug, not a product bug: some
    code path resolved a generated dir relative to the repo instead of honouring
    STATE_DIR/REPORTS_DIR.
    """
    now = _fingerprint_generated_dirs()
    dirty = sorted(k for k in set(_BASELINE) | set(now) if now.get(k) != _BASELINE.get(k))
    if dirty:
        print(
            "  FATAL  run wrote to the real " + ", ".join(dirty) + " dir(s) -- "
            "state isolation is broken",
            file=sys.stderr,
        )
        return False
    print("  info  repo " + "/".join(GENERATED_DIRS) + " untouched")
    return True


# ---------------------------------------------------------------------------
# Isolated work dir
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Workspace:
    """A throwaway work dir. ``root`` is the sandbox boundary for a harness."""

    name: str
    root: Path

    @property
    def bin(self) -> Path:
        return self.root / "bin"

    @property
    def state(self) -> Path:
        return self.root / "state"

    @property
    def reports(self) -> Path:
        return self.root / "reports"

    @property
    def shared(self) -> Path:
        return self.root / "shared"

    def reset(self, *dirs: Path) -> None:
        """Wipe the sandbox and recreate *dirs* (default: all four)."""
        shutil.rmtree(self.root, ignore_errors=True)
        for d in dirs or (self.bin, self.state, self.reports, self.shared):
            d.mkdir(parents=True, exist_ok=True)

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    @property
    def str(self) -> str:
        return str(self.root)


def new_workspace(name: str) -> Workspace:
    """mkdtemp under $TMPDIR -- never inside the repo, so nothing to gitignore."""
    ws = Workspace(name=name, root=Path(tempfile.mkdtemp(prefix=f"ciber-{name}-")))
    if os.environ.get("KEEP_TEST_WORKDIR") == "1":
        print(f"  info  KEEP_TEST_WORKDIR=1 -> leaving {ws.root} behind")
    else:
        atexit.register(shutil.rmtree, ws.root, True)
    return ws


# ---------------------------------------------------------------------------
# Engine env
# ---------------------------------------------------------------------------
def activate_engine_env(state_dir: Path) -> None:
    """Point an in-process engine at this repo and an isolated state dir.

    MUST run before importing anything under ``engine.*``: workflow.py captures
    ``$WORKFLOWS_DIR`` into a module-level constant at import time and its
    default is the RELATIVE path ``workflows``. A harness that just relied on
    "cd to the repo first" was the original portability bug; the absolute path
    below fixes it properly instead of re-encoding the accident.
    """
    os.environ["WORKFLOWS_DIR"] = str(PROJECT / "workflows")
    os.environ["SKILLS_DIR"] = str(PROJECT / "skills")
    os.environ["STATE_DIR"] = str(state_dir)
    os.environ["REPORTS_DIR"] = str(state_dir.parent / "reports")
    os.chdir(PROJECT)


# ---------------------------------------------------------------------------
# Check reporting
# ---------------------------------------------------------------------------
class Reporter:
    """Accumulates named checks and renders the summary the runner parses."""

    def __init__(self, title: str) -> None:
        self.title = title
        self.passed: list[str] = []
        self.failed: list[str] = []

    def ck(self, name: str, cond: Any, detail: str = "") -> bool:
        ok = bool(cond)
        (self.passed if ok else self.failed).append(name)
        suffix = f"   [{detail}]" if detail else ""
        print(("  PASS  " if ok else "  FAIL  ") + name + suffix)
        return ok

    def section(self, title: str) -> None:
        print(f"\n=== {title} ===")

    def info(self, msg: str) -> None:
        print("  info  " + msg)

    def finish(self) -> int:
        total = len(self.passed) + len(self.failed)
        print(
            f"\n=== RESULT: {len(self.passed)} passed, {len(self.failed)} failed "
            f"({total} checks) ==="
        )
        for name in self.failed:
            print("  FAILED: " + name)
        print(f"  {'HARNESS FAILED' if self.failed else 'HARNESS OK'}: {self.title}")
        return 1 if self.failed else 0


def finish(reporter: Reporter) -> None:
    """Standard epilogue: summary, then the repo-write guarantee, then exit."""
    rc = reporter.finish()
    if not assert_repo_untouched():
        rc = 2
    raise SystemExit(rc)


# ---------------------------------------------------------------------------
# Small helpers shared by the harnesses
# ---------------------------------------------------------------------------
def run_bash(script_rel: str, env: dict[str, str], *, timeout: int = 300,
             cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run a repo-relative bash script with *env* layered over os.environ."""
    merged = dict(os.environ)
    merged.update(env)
    return subprocess.run(
        ["bash", script_rel],
        cwd=str(cwd or PROJECT),
        env=merged,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def jload(path: Path) -> Any:
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return None


def write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(0o755)


def assert_bash_syntax(path: Path) -> None:
    """Fail loudly on a broken stub instead of letting it fail as a product bug."""
    p = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
    if p.returncode != 0:
        _fatal(f"stub {path.name} has a shell syntax error: {p.stderr.strip()}")


def tool_present(name: str) -> bool:
    from shutil import which
    return which(name) is not None


def main(fn: Callable[[], int], reporter: Reporter) -> None:
    """Run *fn*, print an unexpected-exception banner, and exit non-zero."""
    try:
        fn()
    except Exception:  # noqa: BLE001 - a crashing harness is a failing harness
        import traceback
        traceback.print_exc()
        reporter.ck("harness completed without an unhandled exception", False,
                    "see traceback above")
    finish(reporter)


__all__ = [
    "PROJECT", "GENERATED_DIRS", "Workspace", "Reporter", "new_workspace",
    "activate_engine_env", "assert_repo_untouched", "assert_bash_syntax",
    "finish", "jload", "main", "run_bash", "tool_present", "write_executable",
]
