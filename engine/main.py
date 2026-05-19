#!/usr/bin/env python3
"""
main.py — Engine entry point.

CLI interface for loading skills, resolving workflows, and executing scans.

Usage:
    python3 engine/main.py --target <IP|hostname> --workflow <name>
    python3 engine/main.py --target 10.0.0.1 --workflow recon-inicial
    python3 engine/main.py --list-skills
    python3 engine/main.py --list-workflows
"""

import sys
import os

# Ensure the repo root is on sys.path so package imports resolve
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from engine.event_bus import write_event, EventWatcher
from engine.main_manager import MainManager
from engine.skill_loader import SkillLoader, SkillValidationError, SkillDependencyError
from engine.state import read_state, write_state
from engine.workflow import WorkflowEngine, load_workflow

logger = logging.getLogger("engine.main")


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with structured output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="engine",
        description="core-engine: Attack vector orchestration engine",
        epilog="Example: python3 engine/main.py --target 10.0.0.1 --workflow recon-inicial",
    )
    parser.add_argument(
        "--target",
        type=str,
        help="Target IP address or hostname to scan",
    )
    parser.add_argument(
        "--workflow",
        type=str,
        help="Workflow name to execute (e.g. 'recon-inicial')",
    )
    parser.add_argument(
        "--list-skills",
        action="store_true",
        help="List all loaded skills and exit",
    )
    parser.add_argument(
        "--list-workflows",
        action="store_true",
        help="List available workflows and exit",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug-level logging",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load and validate everything but do not execute",
    )
    return parser


def list_skills(skill_loader: SkillLoader) -> None:
    """Display loaded skills."""
    skills = skill_loader.load_all()
    if not skills:
        print("No skills loaded.")
        if skill_loader._load_errors:
            print("\nLoad errors:")
            for err in skill_loader._load_errors:
                print(f"  • {err}")
        sys.exit(1)

    print(f"\nLoaded skills ({len(skills)}):")
    print(f"{'Name':<20} {'Version':<12} {'Deps':<30}")
    print("-" * 62)
    for name, skill in sorted(skills.items()):
        deps = ", ".join(skill.dependencies) if skill.dependencies else "(none)"
        print(f"{name:<20} {skill.version:<12} {deps:<30}")

    if skill_loader._load_errors:
        print("\nSkipped skills:")
        for err in skill_loader._load_errors:
            print(f"  • {err}")
        print()


def list_workflows() -> None:
    """Display available workflow files."""
    workflows_dir = Path("workflows")
    if not workflows_dir.exists():
        print("Workflows directory not found.")
        sys.exit(1)

    yaml_files = list(workflows_dir.glob("*.yaml")) + list(workflows_dir.glob("*.yml"))
    if not yaml_files:
        print("No workflow files found in workflows/.")
        sys.exit(1)

    print(f"\nAvailable workflows ({len(yaml_files)}):")
    for wf in sorted(yaml_files):
        print(f"  • {wf.stem}")
    print()


def _resolve_workflow_target(workflow, target: str) -> None:
    """Resolve ``{{ target }}`` template variables in workflow steps.

    Modifies each step's targets list in-place, replacing any occurrence
    of ``{{ target }}`` with the actual *target* string from the CLI arg.
    """
    for step in workflow.steps:
        step.targets = [
            t.replace("{{ target }}", target) if isinstance(t, str) else t
            for t in step.targets
        ]


async def run_scan(
    target: str,
    workflow_name: str,
    skill_loader: SkillLoader,
    manager: MainManager,
    verbose: bool = False,
    dry_run: bool = False,
) -> int:
    """Execute a scan against *target* using *workflow_name*.

    Returns:
        Exit code (0 = success, 1 = degraded, 2 = failure).
    """
    # Load the workflow
    try:
        workflow = load_workflow(workflow_name)
    except FileNotFoundError as exc:
        logger.error("Workflow load failed: %s", exc)
        return 2

    logger.info(
        "Starting scan | target=%s workflow=%s profile=%s",
        target, workflow.name, workflow.scan_profile,
    )

    # Generate scan ID
    import uuid
    scan_id = str(uuid.uuid4())[:8]

    # Resolve template variables in workflow steps
    _resolve_workflow_target(workflow, target)

    # Write initial event
    write_event(
        skill="engine",
        scan_id=scan_id,
        target=target,
        parameters={"workflow": workflow.name, "profile": workflow.scan_profile},
    )
    write_state(
        scan_id=scan_id,
        data={"target": target, "workflow": workflow.name, "status": "running"},
        skill="engine",
    )

    if dry_run:
        logger.info("DRY RUN: workflow validated, would execute %d steps", len(workflow.steps))
        print(f"\nDRY RUN — {workflow.name}")
        print(f"  Target: {target}")
        print(f"  Profile: {workflow.scan_profile}")
        print(f"  Steps ({len(workflow.steps)}):")
        for step in workflow.steps:
            deps = f" (after: {', '.join(step.depends_on)})" if step.depends_on else ""
            print(f"    {step.id}: {step.skill}/{step.sub_process} -> {step.targets}{deps}")
        return 0

    # Execute
    engine = WorkflowEngine(
        main_manager=manager,
        skill_loader=skill_loader,
        base_scan_id=scan_id,
    )

    # Set up event watcher for progress callbacks
    if verbose:
        watcher = EventWatcher(
            callback=lambda s, sid, status: logger.info(
                "Event: skill=%s scan=%s status=%s", s, sid, status.get("status"),
            )
        )
        await watcher.start()

    try:
        results = await engine.execute(workflow)
    finally:
        if verbose:
            await watcher.stop()

    # Report outcomes
    failed = {sid: r for sid, r in results.items() if r.status.value != "done"}
    if failed:
        logger.warning(
            "Completed with %d failed step(s): %s",
            len(failed),
            {sid: r.status.value for sid, r in failed.items()},
        )
        for sid, result in failed.items():
            logger.warning("  %s: %s", sid, result.error_context.get("error", "unknown"))

    # Print summary
    print(f"\n{'='*50}")
    print(f"Scan {scan_id} — {workflow.name}")
    print(f"{'='*50}")
    for step_id, result in results.items():
        icon = "✓" if result.status.value == "done" else "✗"
        print(f"  {icon} {step_id}: {result.status.value}")
    print(f"{'='*50}\n")

    # Write final state
    overall = "done"
    if failed:
        overall = "degraded" if len(failed) < len(results) else "failed"

    write_state(
        scan_id=scan_id,
        data={
            "target": target,
            "workflow": workflow.name,
            "status": overall,
            "results": {
                sid: {
                    "status": r.status.value,
                    "return_code": r.return_code,
                    "retry_tier": r.retry_tier.value if r.retry_tier else None,
                }
                for sid, r in results.items()
            },
        },
        skill="engine",
    )

    return 0 if overall == "done" else (1 if overall == "degraded" else 2)


async def amain() -> int:
    """Async main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)

    skill_loader = SkillLoader()
    manager = MainManager()

    # List modes
    if args.list_skills:
        list_skills(skill_loader)
        return 0

    if args.list_workflows:
        list_workflows()
        return 0

    # Validate required args for scan mode
    if not args.target and not args.workflow:
        parser.print_help()
        print("\nError: --target and --workflow are required (or use --list-skills / --list-workflows)")
        return 2

    if not args.target:
        parser.print_help()
        print("\nError: --target is required")
        return 2

    if not args.workflow:
        parser.print_help()
        print("\nError: --workflow is required")
        return 2

    return await run_scan(
        target=args.target,
        workflow_name=args.workflow,
        skill_loader=skill_loader,
        manager=manager,
        verbose=args.verbose,
        dry_run=args.dry_run,
    )


def main() -> None:
    """Synchronous entry point for CLI."""
    exit_code = asyncio.run(amain())
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
