"""
skill_loader.py — Load, validate, and cache skill definitions from skills/*/skill.yaml.

Scans the skills/ directory for skill.yaml files, validates required schema fields,
verifies tool dependencies via command -v, and caches loaded skills in memory.
"""

import logging
import os
import shutil
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

_SKILLS_DIR = Path(os.environ.get("SKILLS_DIR", "skills"))

# Required fields in skill.yaml schema
_REQUIRED_FIELDS = {"name", "version", "main_script", "dependencies", "inputs", "outputs"}

# Fields that should be lists
_LIST_FIELDS = {"dependencies", "sub_processes"}


class SkillValidationError(Exception):
    """Raised when a skill.yaml fails schema validation."""


class SkillDependencyError(Exception):
    """Raised when a required tool dependency is not found."""


class Skill:
    """Represents a loaded and validated skill definition."""

    def __init__(self, data: dict[str, Any], source: Path):
        self.name: str = data["name"]
        self.version: str = data.get("version", "0.0.0")
        self.description: str = data.get("description", "")
        self.main_script: str = data["main_script"]
        self.dependencies: list[str] = data.get("dependencies", [])
        self.inputs: dict[str, Any] = data.get("inputs", {})
        self.outputs: dict[str, Any] = data.get("outputs", {})
        self.sub_processes: list[str] = data.get("sub_processes", [])
        self.next_vectors: list[dict[str, Any]] = data.get("next_vectors", [])
        self.source: Path = source
        self._validated = False

    def __repr__(self) -> str:
        return f"Skill(name='{self.name}', version='{self.version}')"


class SkillLoader:
    """Scans skills/, validates, and caches Skill instances."""

    def __init__(self, skills_dir: Optional[Path] = None):
        self.skills_dir: Path = skills_dir or _SKILLS_DIR
        self._cache: dict[str, Skill] = {}
        self._load_errors: list[str] = []

    @property
    def loaded_skills(self) -> dict[str, Skill]:
        """Return the current cached skills dict, loading if needed."""
        if not self._cache:
            self.load_all()
        return dict(self._cache)

    def load_all(self) -> dict[str, Skill]:
        """Scan skills/ directory and load all valid skill.yaml files.

        Returns:
            Dict of {skill_name: Skill} for successfully loaded skills.

        Side effects:
            Populates self._load_errors with any validation/dependency failures.
        """
        self._cache = {}
        self._load_errors = []

        if not self.skills_dir.exists():
            logger.warning("Skills directory not found: %s", self.skills_dir)
            return {}

        for yaml_path in self.skills_dir.rglob("skill.yaml"):
            try:
                skill = self._load_single(yaml_path)
                if skill is not None:
                    self._cache[skill.name] = skill
                    logger.info("Loaded skill: %s", skill.name)
            except (SkillValidationError, SkillDependencyError) as exc:
                self._load_errors.append(str(exc))
                logger.warning("Skipped skill: %s", exc)

        return dict(self._cache)

    def get_skill(self, name: str) -> Optional[Skill]:
        """Get a cached skill by name. Loads all skills if not yet cached."""
        if not self._cache:
            self.load_all()
        return self._cache.get(name)

    def _load_single(self, yaml_path: Path) -> Optional[Skill]:
        """Validate and load a single skill.yaml file.

        Args:
            yaml_path: Path to skill.yaml.

        Returns:
            Skill instance if valid, None if should be skipped.
        """
        try:
            with open(yaml_path) as f:
                data: dict[str, Any] = yaml.safe_load(f) or {}
        except yaml.YAMLError as exc:
            raise SkillValidationError(
                f"YAML parse error in {yaml_path}: {exc}"
            ) from exc

        self._validate_schema(data, yaml_path)
        self._validate_dependencies(data, yaml_path)
        self._validate_main_script(data, yaml_path)

        skill = Skill(data, yaml_path)
        skill._validated = True
        return skill

    @staticmethod
    def _validate_schema(data: dict[str, Any], yaml_path: Path) -> None:
        """Check that all required fields exist and are of correct type."""
        missing = _REQUIRED_FIELDS - set(data.keys())
        if missing:
            skill_name = data.get("name", yaml_path.stem)
            raise SkillValidationError(
                f"Skill {skill_name} skipped: missing required fields {missing}"
            )

        for field in _LIST_FIELDS:
            if field in data and not isinstance(data[field], list):
                raise SkillValidationError(
                    f"Skill {data.get('name', '?')}: field '{field}' must be a list"
                )

        if "inputs" in data and not isinstance(data["inputs"], dict):
            raise SkillValidationError(
                f"Skill {data.get('name', '?')}: 'inputs' must be a dict"
            )

        if "outputs" in data and not isinstance(data["outputs"], dict):
            raise SkillValidationError(
                f"Skill {data.get('name', '?')}: 'outputs' must be a dict"
            )

    @staticmethod
    def _validate_dependencies(data: dict[str, Any], yaml_path: Path) -> None:
        """Check that each dependency is available via command -v.

        Some dep names map to different binaries (e.g. testssl.sh → testssl,
        gvm-tools → gvm-cli).
        """
        dep_binary_map = {
            "testssl.sh": "testssl",
            "gvm-tools": "gvm-cli",
        }
        missing_deps = []
        for dep in data.get("dependencies", []):
            binary = dep_binary_map.get(dep, dep)
            if not shutil.which(binary):
                missing_deps.append(dep)

        if missing_deps:
            skill_name = data.get("name", yaml_path.stem)
            raise SkillDependencyError(
                f"Skill {skill_name} skipped: missing dependency/dependencies "
                f"{' and '.join(missing_deps)}"
            )

    @staticmethod
    def _validate_main_script(data: dict[str, Any], yaml_path: Path) -> None:
        """Check that the main_script path exists relative to the project root."""
        main_script = data.get("main_script", "")
        if main_script:
            candidate = Path(main_script)
            if candidate.exists():
                return
            # Also check relative to the skill directory
            candidate_rel = yaml_path.parent / main_script
            if candidate_rel.exists():
                return

        logger.debug(
            "main_script '%s' for skill '%s' not found at startup "
            "(will be checked at execution time)",
            main_script,
            data.get("name", yaml_path.stem),
        )

    def validate_at_runtime(self, skill: Skill) -> bool:
        """Validate a skill's main_script exists at execution time.

        Args:
            skill: A loaded Skill instance.

        Returns:
            True if the main script exists, False otherwise.
        """
        path = Path(skill.main_script)
        if path.exists():
            return True
        rel_path = skill.source.parent / skill.main_script
        return rel_path.exists()
