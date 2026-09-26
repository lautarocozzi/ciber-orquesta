"""
workflow.py — Workflow DAG resolver and step dispatcher.

Reads workflow YAML definitions from workflows/, resolves the dependency DAG
using topological sort, and dispatches each step through the MainManager.
"""

import asyncio
import hashlib
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


def _targets_key(targets: list[str]) -> str:
    """Deterministic hash key for a target set (first 8 hex chars of SHA-1).

    Sorts case-insensitively so identical target sets in any order produce
    the same key — dedup and collision-free step ids rely on this.
    """
    joined = "|".join(sorted(targets, key=lambda t: (t.lower(), t)))
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:8]


def _target_slug(target: str) -> str:
    """Filesystem-safe slug for the ``{base}--{step}--{slug}`` scan id.

    Single source of truth for that convention: state lookup, step
    execution and the dry-run preview MUST agree on it, or the preview
    resolves a different path than the runtime does.
    """
    return (
        target.replace("..", "-")
        .replace(".", "-")
        .replace(":", "-")
        .replace("/", "-")
    )


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
        self.rollback: dict[str, Any] = data.get("rollback", {})
        self.on_failure: str = self.rollback.get("on_failure", "fail")
        self.expansion: dict[str, Any] = data.get("expansion", {
            "anchor_steps": [],
            "max_expansions": 10,
            "on_conflict": "prefer_workflow",
            "require_skill": True,
        })

    def get_step(self, step_id: str) -> Optional[WorkflowStep]:
        """Look up a step by its ID."""
        for step in self.steps:
            if step.id == step_id:
                return step
        return None


def _anchor_steps_for(workflow: Workflow) -> list[WorkflowStep]:
    """Select the expansion anchors of *workflow*.

    Anchors are the steps flagged ``metadata.expansion_anchor: true``. When
    no step carries the flag, the first DAG level (every step with no
    dependencies) acts as the anchor set. An anchor that never wrote
    ``next_vectors.json`` is harmless — its lookup finds nothing.
    """
    anchors = [
        s for s in workflow.steps
        if s.metadata.get("expansion_anchor", False)
    ]
    if anchors:
        return anchors
    return [s for s in workflow.steps if not s.depends_on]


def _anchor_next_vectors(
    anchor: WorkflowStep,
    base_scan_id: Optional[str],
    state_dir: Path,
) -> list[list[dict[str, Any]]]:
    """Read the ``next_vectors`` lists stored on disk for *anchor*.

    Sub-skills write them to ``state/{anchor.skill}/{scan_id}/
    next_vectors.json`` with ``scan_id = {base}--{anchor.id}--{slug}``.

    *base_scan_id* selects the lookup mode: given (runtime) reads that exact
    path; ``None`` (dry run) takes the newest scan dir matching the anchor and
    target, because a dry run mints a fresh scan id that never executed a
    skill and only a PREVIOUS run can supply vectors.

    Returns one list per anchor target that has state; empty when none does.
    """
    collected: list[list[dict[str, Any]]] = []

    for target in anchor.targets:
        slug = _target_slug(target)
        if base_scan_id:
            scan_dirs = [
                state_dir / anchor.skill / f"{base_scan_id}--{anchor.id}--{slug}"
            ]
        else:
            skill_dir = state_dir / anchor.skill
            if not skill_dir.is_dir():
                continue
            # Newest first: the preview reports the latest real state, not the
            # union of every past run of the same anchor.
            scan_dirs = sorted(
                (d for d in skill_dir.glob(f"*--{anchor.id}--{slug}") if d.is_dir()),
                key=lambda d: d.stat().st_mtime,
                reverse=True,
            )[:1]

        for scan_dir in scan_dirs:
            nv_path = scan_dir / "next_vectors.json"
            if not nv_path.exists():
                continue
            try:
                with open(nv_path) as f:
                    nv_data: dict[str, Any] = json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to read %s: %s", nv_path, exc)
                continue
            vectors = nv_data.get("next_vectors", [])
            if isinstance(vectors, list):
                collected.append(vectors)

    return collected


def _build_expanded_step(
    vector: dict[str, Any],
    anchor: WorkflowStep,
    workflow: Workflow,
    skill_loader: SkillLoader,
    seen_ids: set[str],
) -> Optional[WorkflowStep]:
    """Build the expanded step a single ``next_vectors`` entry would create.

    Shared by :meth:`WorkflowEngine._expand_from_anchor` (runtime) and
    :func:`preview_expansion` (dry run) so a preview predicts exactly what a
    real run injects — a preview that computed its own plan could drift from
    runtime and lie about the workflow.

    *seen_ids* carries the ids already planned or injected (seeded with the
    workflow's own ids) and gains the built id on success, so a repeated
    vector dedups exactly like the runtime loop does.

    Returns ``None`` when the vector must be skipped: no skill name,
    unregistered skill, duplicate step, or — for a target-less vector — a
    skill already present in the workflow.
    """
    skill_name = vector.get("skill", "")
    if not skill_name:
        return None

    # Per-vector targets (A): a vector may propose NEW targets (e.g.
    # discovered subdomains). Validate (list of non-empty strings), order
    # deterministically, and cap by max_targets_per_vector. Fall back to
    # the anchor's targets when absent or empty — preserving pre-change
    # behavior.
    max_per_vec = int(workflow.expansion.get("max_targets_per_vector", 10))
    proposed = vector.get("targets")
    valid = [
        t for t in (proposed or [])
        if isinstance(t, str) and t.strip()
    ]
    if valid:
        new_targets = sorted(
            valid, key=lambda t: (t.lower(), t)
        )[:max_per_vec]
        carries_targets = True
    else:
        new_targets = list(anchor.targets)
        carries_targets = False

    # Dedup (B): vectors WITHOUT targets keep the original
    # skip-if-skill-already-in-workflow rule for backward compatibility.
    # Vectors WITH targets deliberately BYPASS that check — the same skill
    # may expand again when it proposes a different target set — and
    # instead dedup on the (skill, targets-key) pair via the hashed id
    # below (identical pairs re-propose the same id and are skipped).
    if not carries_targets:
        # Skip if skill is already used in workflow
        existing_skills = {s.skill for s in workflow.steps}
        if skill_name in existing_skills:
            return None

    # Verify skill exists via SkillLoader
    skill_def = skill_loader.get_skill(skill_name)
    if not skill_def:
        logger.debug("Expansion skip: skill '%s' not registered", skill_name)
        return None

    # Collision-free id (C): hash the sorted target set so distinct target
    # sets get distinct ids (exp-{skill}-{anchor.id}-{targets_key}) and
    # re-proposing an identical set hits the already-added skip below.
    new_step_id = f"exp-{skill_name}-{anchor.id}-{_targets_key(new_targets)}"
    if new_step_id in seen_ids:
        return None  # already added

    # Timeout (D): env-configurable, replaces the hardcoded 480. Scans
    # self-cap internally; no time restriction below 2h per target per skill
    # unless explicitly overridden by STEP_TIMEOUT_SECONDS.
    try:
        exp_timeout = int(os.environ.get("STEP_TIMEOUT_SECONDS", "7200"))
    except ValueError:
        exp_timeout = 7200

    seen_ids.add(new_step_id)
    return WorkflowStep({
        "id": new_step_id,
        "skill": skill_name,
        "sub_process": skill_def.main_script,
        "targets": new_targets,  # vector targets or anchor fallback
        "parameters": {},
        "depends_on": [anchor.id],
        "condition": "prev.success",
        "timeout": exp_timeout,
        "metadata": {
            "description": vector.get("reason", f"Auto-expanded {skill_name}"),
            "phase": "automated-expansion",
            "expanded": True,
        },
    })


def preview_expansion(
    workflow: Workflow,
    skill_loader: SkillLoader,
) -> list[WorkflowStep]:
    """Plan the steps a real run would inject — without running anything.

    Mirrors :meth:`WorkflowEngine._expand_from_anchor` (same anchor selection,
    same vector resolution, same step builder) but reads the anchor's
    ``next_vectors`` from the newest matching state dir on disk: a dry run
    mints a fresh scan id that never executed a skill, so only a PREVIOUS
    run can supply vectors. A cold dry run therefore legitimately previews
    nothing — it cannot invent subdomains.

    Read-only: no subprocess is spawned and nothing is written. *workflow* is
    not mutated, so the caller can still print the static plan.

    Returns the steps that would be injected, in injection order; empty when
    no anchor state exists yet.
    """
    state_dir = Path(os.environ.get("STATE_DIR", "state"))
    max_exp = int(workflow.expansion.get("max_expansions", 10))
    seen_ids = {s.id for s in workflow.steps}
    planned: list[WorkflowStep] = []

    for anchor in _anchor_steps_for(workflow):
        for vectors in _anchor_next_vectors(anchor, None, state_dir):
            for vector in vectors[:max_exp]:
                step = _build_expanded_step(
                    vector, anchor, workflow, skill_loader, seen_ids,
                )
                if step is not None:
                    planned.append(step)

    return planned


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

    async def execute(
        self,
        workflow: Workflow,
        expand_next_vectors: bool = False,
    ) -> dict[str, ProcessResult]:
        """Execute all steps in a workflow respecting DAG dependencies.

        Steps within the same DAG level (no interdependencies) run in parallel.

        Args:
            workflow: A loaded Workflow instance.
            expand_next_vectors: If True, read next_vectors.json from anchor
                steps after they complete and inject new steps for unknown skills.

        Returns:
            Dict of {step_id: ProcessResult} with all outcomes.
        """
        # Resolve DAG into parallel-ready levels
        levels = self._resolve_dag_levels(workflow)
        logger.info(
            "Workflow '%s': DAG resolved into %d levels: %s",
            workflow.name, len(levels),
            [[s.id for s in level] for level in levels],
        )

        executed_levels = 0
        executed_step_ids: set[str] = set()

        while executed_levels < len(levels):
            # Dispatch all steps in this level in parallel,
            # skipping any already-executed steps (from re-resolved DAGs)
            level = [
                s for s in levels[executed_levels]
                if s.id not in executed_step_ids
            ]
            if level:
                tasks = [self._execute_step(step, workflow) for step in level]
                await asyncio.gather(*tasks)
                executed_step_ids.update(s.id for s in level)

            executed_levels += 1

            # Multi-wave expansion: after every completed level, check
            # whether any anchor step produced next_vectors and inject
            # new steps for unknown skills. Dedup prevents re-expanding
            # the same anchor twice.
            if expand_next_vectors and executed_levels >= 1:
                expanded = await self._expand_from_anchor(workflow)
                if expanded:
                    logger.info(
                        "Expanded %d next-vector step(s) into workflow "
                        "(wave after level %d)", expanded, executed_levels - 1,
                    )
                    # Re-resolve DAG with new steps for remaining levels
                    levels = self._resolve_dag_levels(workflow)
                    logger.info(
                        "Workflow '%s': DAG re-resolved into %d levels",
                        workflow.name, len(levels),
                    )

        # Write final workflow status
        await self._write_workflow_complete(workflow)
        return dict(self._results)

    async def _expand_from_anchor(
        self,
        workflow: Workflow,
    ) -> int:
        """Read next_vectors.json from completed anchor steps and inject new steps.

        Vectors may propose NEW targets (e.g. discovered subdomains); those
        use the vector's targets (capped), bypass the static skill-name skip,
        and dedup on (skill, sorted-targets). Vectors without targets fall
        back to the anchor's targets and keep the original skip rules. Each
        expanded step depends on the anchor step.

        Step construction is shared with :func:`preview_expansion`, so a
        dry-run preview predicts exactly what a real run injects.

        Returns:
            Number of new steps injected.
        """
        anchor_steps = _anchor_steps_for(workflow)
        state_dir = Path(os.environ.get("STATE_DIR", "state"))
        max_exp = int(workflow.expansion.get("max_expansions", 10))
        seen_ids = {s.id for s in workflow.steps}
        injected = 0

        for anchor in anchor_steps:
            anchor_result = self._results.get(anchor.id)
            if not anchor_result or anchor_result.status != ProcessStatus.DONE:
                logger.debug("Anchor '%s' not done — skipping expansion", anchor.id)
                continue

            for vectors in _anchor_next_vectors(
                anchor, self.base_scan_id, state_dir
            ):
                for vector in vectors[:max_exp]:
                    step = _build_expanded_step(
                        vector, anchor, workflow, self.skill_loader, seen_ids,
                    )
                    if step is None:
                        continue
                    workflow.steps.append(step)
                    injected += 1
                    logger.info(
                        "Expanded step '%s' (skill=%s) from next_vector",
                        step.id, step.skill,
                    )

        return injected

    async def _execute_step(self, step: WorkflowStep, workflow: Workflow) -> None:
        """Execute a single workflow step (may be called concurrently within a level)."""
        # Check dependencies
        if not self._dependencies_satisfied(step, workflow):
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
            return

        # Check condition
        if step.condition and not self._evaluate_condition(step.condition, step=step):
            logger.info("Step '%s' skipped: condition '%s' not met", step.id, step.condition)
            return

        # Execute step for each target
        step_results = []
        for target in step.targets:
            # Include target in scan_id to avoid collisions in multi-target steps
            target_slug = _target_slug(target)
            scan_id = f"{self.base_scan_id}--{step.id}--{target_slug}"

            # Write state before execution
            self._update_step_state(scan_id, step.id, "running")

            # Configure WORKFLOW_SHARED_DIR so sub-skills can exchange data
            # via write_to_shared_dir / read_predecessor_output
            shared_dir = os.path.join(
                os.environ.get("STATE_DIR", "state"),
                "_shared",
                self.base_scan_id,
            )
            os.makedirs(shared_dir, exist_ok=True)

            result = await self.manager.run_sub_process(
                scan_id=scan_id,
                skill=step.skill,
                target=target,
                sub_process_path=step.sub_process,
                parameters=step.parameters,
                timeout=step.timeout,
                env_overrides={"WORKFLOW_SHARED_DIR": os.path.abspath(shared_dir)},
            )
            step_results.append(result)

            # Write state after execution
            self._update_step_state(
                scan_id, step.id, result.status.value,
                {"return_code": result.return_code},
            )

        # Aggregate multi-target results: worst status wins
        if step_results:
            # Sort by status severity: FAILED > CANCELLED > DONE
            status_rank = {ProcessStatus.FAILED: 0, ProcessStatus.CANCELLED: 1, ProcessStatus.DONE: 2}
            worst = min(step_results, key=lambda r: status_rank.get(r.status, 99))
            self._results[step.id] = worst
            # Preserve all individual results in error context for audit
            if len(step_results) > 1:
                worst.error_context["multi_target"] = {
                    r.target: {"status": r.status.value, "return_code": r.return_code}
                    for r in step_results
                }
        else:
            self._results[step.id] = ProcessResult(
                scan_id=self.base_scan_id,
                skill=step.skill,
                target="",
                sub_process=step.sub_process,
                status=ProcessStatus.CANCELLED,
                error_context={"reason": "no_targets"},
            )

    def _resolve_dag_levels(self, workflow: Workflow) -> list[list[WorkflowStep]]:
        """Topological sort returning levels for parallel execution.

        Each inner list contains steps with no interdependencies that can
        run in parallel. Uses Kahn's algorithm.
        Raises WorkflowValidationError on cycles.
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

        levels: list[list[WorkflowStep]] = []
        queue = [s_id for s_id, deg in in_degree.items() if deg == 0]

        while queue:
            # Each queue batch forms one parallel-execution level
            level_steps = [step_map[s_id] for s_id in queue]
            levels.append(level_steps)
            next_queue = []
            for s_id in queue:
                for neighbour in adjacency[s_id]:
                    in_degree[neighbour] -= 1
                    if in_degree[neighbour] == 0:
                        next_queue.append(neighbour)
            queue = next_queue

        resolved_count = sum(len(lvl) for lvl in levels)
        if resolved_count != len(workflow.steps):
            unresolved = set(workflow.steps) - {s for lvl in levels for s in lvl}
            raise WorkflowValidationError(
                f"Cycle detected in workflow '{workflow.name}': "
                f"steps {[s.id for s in unresolved]}"
            )

        return levels

    def _dependencies_satisfied(self, step: WorkflowStep, workflow: Workflow) -> bool:
        """Check if all dependencies have completed successfully.

        When ``workflow.on_failure == "continue"``, FAILED dependencies
        are allowed — subsequent steps still run. CANCELLED or missing
        dependencies always block.
        """
        for dep_id in step.depends_on:
            result = self._results.get(dep_id)
            if result is None:
                return False
            if result.status == ProcessStatus.CANCELLED:
                return False
            if result.status == ProcessStatus.FAILED:
                if workflow.on_failure == "continue":
                    continue  # allow step to run despite failed dep
                return False
            if result.status != ProcessStatus.DONE:
                return False
        return True

    def _evaluate_condition(self, condition: str, step: Optional[WorkflowStep] = None) -> bool:
        """Evaluate a simple step condition expression.

        Supports: ``prev.success``, ``prev.failed``, always ``true``.
        Checks against ``self._results`` for actual previous step outcomes.
        When *step* is provided, uses its ``depends_on`` list instead of
        insertion order to determine which step result to check.
        """
        condition = condition.strip()
        if condition == "true":
            return True
        if condition == "prev.success" or condition.startswith("prev.success"):
            if not self._results:
                return False
            if step and step.depends_on:
                # Check ALL dependencies explicitly — avoids insertion-order
                # pitfalls with parallel DAG levels.
                return all(
                    self._results.get(dep_id)
                    and self._results[dep_id].status == ProcessStatus.DONE
                    for dep_id in step.depends_on
                )
            # Fallback for steps without explicit depends_on:
            # ALL prior steps must have succeeded (deterministic, no dict-order dependency)
            return all(
                r.status == ProcessStatus.DONE
                for r in self._results.values()
            )
        if condition == "prev.failed" or condition.startswith("prev.failed"):
            if not self._results:
                return False
            if step and step.depends_on:
                return any(
                    self._results.get(dep_id)
                    and self._results[dep_id].status == ProcessStatus.FAILED
                    for dep_id in step.depends_on
                )
            # Fallback without explicit depends_on:
            # ANY prior step failed (deterministic)
            return any(
                r.status == ProcessStatus.FAILED
                for r in self._results.values()
            )
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

    async def _write_workflow_complete(self, workflow: Workflow) -> None:
        """Write the final workflow-level status file."""
        all_statuses = {s.id: self._results.get(s.id) for s in workflow.steps}
        overall = "done"
        failed = [
            sid for sid, r in all_statuses.items()
            if r and r.status != ProcessStatus.DONE
        ]
        if failed:
            overall = "degraded" if len(failed) < len(workflow.steps) else "failed"

        await write_state(
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

    # Sanitize: reject path traversal in user-supplied workflow name
    cleaned = name.replace(".yaml", "").replace(".yml", "")
    if ".." in cleaned.split("/") or cleaned.startswith("/") or cleaned.startswith("~"):
        raise ValueError(f"Workflow name contains path traversal: {name!r}")

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
