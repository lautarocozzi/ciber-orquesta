"""
workflow.py — Workflow DAG resolver and step dispatcher.

Reads workflow YAML definitions from workflows/, resolves the dependency DAG
using topological sort, and dispatches each step through the MainManager.
"""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

import yaml

from engine.main_manager import MainManager, ProcessResult, ProcessStatus
from engine.skill_loader import SkillLoader
from engine.state import read_state, write_state

logger = logging.getLogger(__name__)

_WORKFLOWS_DIR = Path(os.environ.get("WORKFLOWS_DIR", "workflows"))


class WorkflowValidationError(Exception):
    """Raised when a workflow YAML fails validation."""


class WorkflowStep:
    """A single step in a workflow DAG."""

    def __init__(self, data: dict[str, Any]):
        self.id: str = data["id"]
        self.skill: str = data.get("skill", "")
        self.targets: list[str] = data.get("targets", [])
        self.sub_process: str = data.get("sub_process", "")
        self.parameters: dict[str, Any] = data.get("parameters", {})
        self.depends_on: list[str] = data.get("depends_on", [])
        self.timeout: Optional[int] = data.get("timeout")
        self.condition: Optional[str] = data.get("condition")  # e.g. "prev.success"
        self.metadata: dict[str, Any] = data.get("metadata", {})

    def __repr__(self) -> str:
        return f"WorkflowStep(id='{self.id}', skill='{self.skill}')"


class Workflow:
    """A loaded and validated workflow definition."""

    def __init__(self, data: dict[str, Any], source: Path):
        self.name: str = data.get("name", source.stem)
        self.description: str = data.get("description", "")
        self.scan_profile: str = data.get("scan_profile", "default")
        self.steps: list[WorkflowStep] = [
            WorkflowStep(s) for s in data.get("steps", [])
        ]
        self.source: Path = source
        self.global_params: dict[str, Any] = data.get("parameters", {})

    def get_step(self, step_id: str) -> Optional[WorkflowStep]:
        """Look up a step by its ID."""
        for step in self.steps:
            if step.id == step_id:
                return step
        return None


class WorkflowEngine:
    """Resolves workflow DAGs and dispatches steps through MainManager."""

    def __init__(
        self,
        main_manager: MainManager,
        skill_loader: SkillLoader,
        base_scan_id: str,
        skill_name: str = "engine",
    ):
        self.manager = main_manager
        self.skill_loader = skill_loader
        self.base_scan_id = base_scan_id
        self.skill_name = skill_name
        self._results: dict[str, ProcessResult] = {}

    async def execute(self, workflow: Workflow) -> dict[str, ProcessResult]:
        """Execute all steps in a workflow respecting DAG dependencies.

        Args:
            workflow: A loaded Workflow instance.

        Returns:
            Dict of {step_id: ProcessResult} with all outcomes.
        """
        # Topological sort
        order = self._resolve_dag(workflow)
        logger.info(
            "Workflow '%s': DAG resolved order: %s",
            workflow.name, [s.id for s in order],
        )

        for step in order:
            # Check dependencies
            if not self._dependencies_satisfied(step):
                logger.warning(
                    "Step '%s' skipped: dependencies not satisfied %s",
                    step.id, step.depends_on,
                )
                self._results[step.id] = ProcessResult(
                    scan_id=self.base_scan_id,
                    skill=step.skill,
                    target=",".join(step.targets),
                    sub_process=step.sub_process,
                    status=ProcessStatus.CANCELLED,
                    error_context={"reason": "dependency_not_satisfied"},
                )
                continue

            # Check condition
            if step.condition and not self._evaluate_condition(step.condition):
                logger.info("Step '%s' skipped: condition '%s' not met", step.id, step.condition)
                continue

            # Execute step for each target
            step_results = []
            for target in step.targets:
                scan_id = f"{self.base_scan_id}/{step.id}"

                # Write state before execution
                self._update_step_state(scan_id, step.id, "running")

                result = await self.manager.run_sub_process(
                    scan_id=scan_id,
                    skill=step.skill,
                    target=target,
                    sub_process_path=step.sub_process,
                    parameters=step.parameters,
                )
                step_results.append(result)

                # Write state after execution
                self._update_step_state(
                    scan_id, step.id, result.status.value,
                    {"return_code": result.return_code},
                )

            # Store aggregate result (last target wins for status)
            if step_results:
                self._results[step.id] = step_results[-1]
            else:
                self._results[step.id] = ProcessResult(
                    scan_id=self.base_scan_id,
                    skill=step.skill,
                    target="",
                    sub_process=step.sub_process,
                    status=ProcessStatus.CANCELLED,
                    error_context={"reason": "no_targets"},
                )

        # Write final workflow status
        self._write_workflow_complete(workflow)
        return dict(self._results)

    def _resolve_dag(self, workflow: Workflow) -> list[WorkflowStep]:
        """Topological sort of workflow steps by depends_on.

        Uses Kahn's algorithm. Raises WorkflowValidationError on cycles.
        """
        step_map = {s.id: s for s in workflow.steps}
        in_degree: dict[str, int] = {s.id: 0 for s in workflow.steps}
        adjacency: dict[str, list[str]] = {s.id: [] for s in workflow.steps}

        for step in workflow.steps:
            for dep in step.depends_on:
                if dep not in step_map:
                    raise WorkflowValidationError(
                        f"Step '{step.id}' depends on unknown step '{dep}'"
                    )
                adjacency[dep].append(step.id)
                in_degree[step.id] = in_degree.get(step.id, 0) + 1

        queue = [s_id for s_id, deg in in_degree.items() if deg == 0]
        sorted_steps = []

        while queue:
            # Process all steps at the same level in parallel
            level = queue[:]
            queue = []
            for s_id in level:
                sorted_steps.append(step_map[s_id])
                for neighbour in adjacency[s_id]:
                    in_degree[neighbour] -= 1
                    if in_degree[neighbour] == 0:
                        queue.append(neighbour)

        if len(sorted_steps) != len(workflow.steps):
            cycle = set(workflow.steps) - set(sorted_steps)
            raise WorkflowValidationError(
                f"Cycle detected in workflow '{workflow.name}': "
                f"steps {[s.id for s in cycle]}"
            )

        return sorted_steps

    def _dependencies_satisfied(self, step: WorkflowStep) -> bool:
        """Check if all dependencies have completed successfully."""
        for dep_id in step.depends_on:
            result = self._results.get(dep_id)
            if result is None:
                return False
            if result.status != ProcessStatus.DONE:
                return False
        return True

    def _evaluate_condition(self, condition: str) -> bool:
        """Evaluate a simple step condition expression.

        Supports: ``prev.success``, ``prev.failed``, always ``true``.
        """
        condition = condition.strip()
        if condition == "true":
            return True
        if condition == "prev.success":
            return True  # Would check previous step result in full impl
        if condition == "prev.failed":
            return False
        logger.debug("Unknown condition '%s', defaulting to True", condition)
        return True

    def _update_step_state(
        self,
        scan_id: str,
        step_id: str,
        status: str,
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        """Write step execution state to ``state/{skill}/{scan_id}/steps/{step_id}.json``."""
        state_dir = (
            Path(os.environ.get("STATE_DIR", "state"))
            / self.skill_name
            / scan_id
            / "steps"
        )
        state_dir.mkdir(parents=True, exist_ok=True)

        state = {
            "step_id": step_id,
            "scan_id": scan_id,
            "status": status,
            **(extra or {}),
        }
        try:
            with open(state_dir / f"{step_id}.json", "w") as f:
                json.dump(state, f, indent=2)
        except OSError as exc:
            logger.warning("Failed to write step state: %s", exc)

    def _write_workflow_complete(self, workflow: Workflow) -> None:
        """Write the final workflow-level status file."""
        all_statuses = {s.id: self._results.get(s.id) for s in workflow.steps}
        overall = "done"
        failed = [
            sid for sid, r in all_statuses.items()
            if r and r.status != ProcessStatus.DONE
        ]
        if failed:
            overall = "degraded" if len(failed) < len(workflow.steps) else "failed"

        write_state(
            scan_id=self.base_scan_id,
            data={
                "workflow": workflow.name,
                "overall_status": overall,
                "steps": {
                    sid: {
                        "status": r.status.value if r else "unknown",
                        "return_code": r.return_code if r else None,
                    }
                    for sid, r in all_statuses.items()
                },
                "failed_steps": failed,
            },
            skill=self.skill_name,
        )
        logger.info(
            "Workflow '%s' completed: overall=%s, failed=%s",
            workflow.name, overall, failed,
        )


def load_workflow(
    name: str,
    workflows_dir: Optional[Path] = None,
) -> Workflow:
    """Load a workflow YAML by name (with or without .yaml extension).

    Args:
        name: Workflow name (e.g. "recon-inicial" or "recon-inicial.yaml").
        workflows_dir: Override workflows directory.

    Returns:
        Loaded Workflow instance.

    Raises:
        FileNotFoundError: If no matching workflow file exists.
        WorkflowValidationError: If the YAML is invalid or missing required fields.
    """
    base_dir = workflows_dir or _WORKFLOWS_DIR
    if not base_dir.exists():
        raise FileNotFoundError(f"Workflows directory not found: {base_dir}")

    # Try exact, with .yaml, with .yml
    candidates = [
        base_dir / name,
        base_dir / f"{name}.yaml",
        base_dir / f"{name}.yml",
        base_dir / name.replace(".yaml", "").replace(".yml", ""),
        base_dir / f"{name.replace('.yaml', '').replace('.yml', '')}.yaml",
    ]

    # Deduplicate
    seen = set()
    unique_candidates = []
    for c in candidates:
        s = str(c)
        if s not in seen:
            seen.add(s)
            unique_candidates.append(c)

    for candidate in unique_candidates:
        if candidate.exists() and candidate.is_file():
            return _parse_workflow(candidate)

    raise FileNotFoundError(
        f"Workflow '{name}' not found in {base_dir}. "
        f"Searched: {[str(c) for c in unique_candidates]}"
    )


def _parse_workflow(path: Path) -> Workflow:
    """Parse and validate a workflow YAML file."""
    try:
        with open(path) as f:
            data: dict[str, Any] = yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:
        raise WorkflowValidationError(
            f"YAML parse error in {path}: {exc}"
        ) from exc

    if "steps" not in data or not isinstance(data["steps"], list):
        raise WorkflowValidationError(
            f"Workflow '{path}' must have a 'steps' list"
        )

    for i, step in enumerate(data["steps"]):
        if "id" not in step:
            raise WorkflowValidationError(
                f"Step {i} in '{path}' is missing required 'id' field"
            )

    return Workflow(data, path)
