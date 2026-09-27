# sub-target-routing Specification

> **Provenance** — canonical spec, synced at archive from change `dns-discovery`
> (`openspec/changes/archive/2026-09-27-dns-discovery/`), merged to `main` @ `99c763f`.
> Verification: `VERIFIED` — Engram `sdd/dns-discovery/verify-report` (obs #110).
> Every requirement below is implemented and evidence-backed. No later change has
> modified this capability.

## Purpose

Engine change to `WorkflowEngine._expand_from_anchor` (`engine/workflow.py`): allow `next_vectors` entries to propose NEW targets (discovered subdomains), deduplicate expansions by target set, hash expanded step ids, and lift the expansion timeout floor. Fully backward compatible when `targets` is absent.

## Requirements

### Requirement: Per-Vector Targets with Anchor Fallback

A `next_vectors` entry MAY carry `targets: [string]`. When present and non-empty, the expanded step MUST use those targets, capped at `max_targets_per_vector` (`workflow.expansion`, default `10`, first-N after ordering). When absent or empty, the expanded step MUST fall back to `list(anchor.targets)` — preserving current behavior. `skills/_shared/envelope.sh` MUST remain untouched (`write_next_vectors` passes vectors verbatim via `--argjson`).

#### Scenario: Vector carries targets

- GIVEN anchor `dnsenum-analyzer` emits `{skill: "httpx", targets: ["a.x.com","b.x.com"]}`
- WHEN expansion runs
- THEN the expanded step's `targets` are `["a.x.com","b.x.com"]`, not the anchor's target

#### Scenario: Target cap applied

- GIVEN a vector carries 15 targets and `max_targets_per_vector: 10`
- WHEN expansion runs
- THEN the expanded step receives exactly 10 targets

#### Scenario: Vector without targets (backward compat)

- GIVEN an existing analyzer emits `{skill: "X", weight: 80}` with no `targets`
- WHEN expansion runs
- THEN the expanded step's targets equal the anchor's targets (pre-change behavior)

### Requirement: Dedup by (skill, sorted-targets)

Expansion dedup MUST key on the pair `(skill, tuple(sorted(targets)))` instead of skill name alone. The same skill MUST be allowed to expand multiple times when the target sets differ.

#### Scenario: Same skill, different target sets

- GIVEN two vectors propose `httpx` with disjoint `targets` sets
- WHEN expansion runs
- THEN two expanded steps are created

#### Scenario: Same skill, identical target sets

- GIVEN two vectors propose `httpx` with the same targets in different order
- WHEN expansion runs
- THEN only ONE step is created (sorted comparison)

#### Scenario: Skill already a workflow step, vector carries targets

- GIVEN `httpx` already exists as a static workflow step
- WHEN a vector proposes `httpx` WITH a `targets` array
- THEN expansion occurs: `exp-httpx-{anchor.id}-{targets_key}` is created for the new target set (the static-skill name check is bypassed when the vector carries its own targets; dedup keys on `(skill, sorted-targets)`)

#### Scenario: Skill already a workflow step, vector carries no targets

- GIVEN `httpx` already exists as a static workflow step
- WHEN a vector proposes `httpx` with NO `targets`
- THEN no expansion occurs (existing skip rule preserved for backward compatibility)

### Requirement: Collision-Free Expanded Step Ids

The expanded step id MUST be `exp-{skill}-{anchor.id}-{targets_key}`, where `targets_key` is the first 8 hex chars of the SHA-1 of the sorted targets joined deterministically. Distinct target sets MUST NOT collide; re-proposing an identical set MUST hit the existing "already added" skip.

#### Scenario: Distinct sets get distinct ids

- GIVEN vectors expand `nuclei` from anchor `dnsenum-analyzer` with target sets A and B
- WHEN expansion runs
- THEN ids match `exp-nuclei-dnsenum-analyzer-{8-hex}` and differ from each other

#### Scenario: Identical set re-proposed

- GIVEN an expanded step for (skill, targets) already exists
- WHEN the same pair is proposed again
- THEN no duplicate step is injected

### Requirement: Expanded-Step Timeout via STEP_TIMEOUT_SECONDS

Expanded-step `timeout` MUST default to `int(os.environ.get("STEP_TIMEOUT_SECONDS", "7200"))`, replacing the hardcoded `480`. No expansion timeout MAY be set below 2h per target per skill unless explicitly overridden by env.

#### Scenario: Default timeout

- GIVEN `STEP_TIMEOUT_SECONDS` is unset
- WHEN an expanded step is created
- THEN `step.timeout == 7200`

#### Scenario: Env override

- GIVEN `STEP_TIMEOUT_SECONDS=1800`
- WHEN an expanded step is created
- THEN `step.timeout == 1800`

### Requirement: One Expanded Step Per Skill, Multi-Target

For each `(skill, target-set)` pair the engine MUST create exactly ONE expanded step whose `targets` contains ALL subdomains, reusing the existing multi-target execution loop (`_execute_step` per-target iteration). The engine MUST NOT create one step per subdomain.

#### Scenario: Eight subdomains, one httpx step

- GIVEN `dnsenum-analyzer` emits one `httpx` vector with 8 targets
- WHEN expansion runs
- THEN exactly one `exp-httpx-*` step exists with 8 targets
- AND execution loops over the 8 targets inside that single step

### Requirement: Dry-Run and Regression Verification

Verification MUST be execution-based: `python3 engine/main.py --help` and a workflow dry-run (`--target <domain> --workflow recon-completo --expand-next-vectors --dry-run`) MUST succeed after the change. When no vector carries `targets`, expansion results (step ids' semantics aside, targets, count, skip rules) MUST match pre-change behavior.

A dry run expands NOTHING on its own — it never executes a skill, so it cannot discover subdomains. To make the plan complete, `--dry-run --expand-next-vectors` MUST additionally replay expansion from the newest matching anchor state already on disk, using the SAME anchor selection, vector resolution and step construction as runtime expansion, so the preview cannot drift from what a real run injects. The replay MUST be read-only: no skill subprocess spawned, no state written, and the static plan left unmodified. `--dry-run` WITHOUT `--expand-next-vectors` MUST keep showing static steps only.

#### Scenario: Dry-run shows subdomain targets

- GIVEN a completed `dnsenum-analyzer` run already exists under `state/` (scan dir `*--dns-analyzer--<target-slug>/next_vectors.json` with target-carrying vectors) for the target being previewed
- WHEN `python3 engine/main.py --target <domain> --workflow recon-completo --expand-next-vectors --dry-run` runs
- THEN the plan lists `exp-httpx` / `exp-nuclei` / `exp-whatweb` steps carrying subdomain targets
- AND each expanded step depends on the anchor step that produced its vectors
- AND exit code is 0

#### Scenario: Dry-run without anchor state

- GIVEN no anchor step has `next_vectors.json` on disk for the target
- WHEN `python3 engine/main.py --target <domain> --workflow recon-completo --expand-next-vectors --dry-run` runs
- THEN the plan prints the static steps plus an explicit "no anchor state" note naming the missing prerequisite
- AND no `exp-*` step is listed
- AND exit code is 0

#### Scenario: Dry-run spawns no skill

- GIVEN `--dry-run --expand-next-vectors` with anchor state present
- WHEN the dry run completes
- THEN no skill subprocess was spawned and no state file was written by the expansion replay
- AND the static step count and step list are identical to the same dry run without `--expand-next-vectors`

#### Scenario: Regression when targets absent

- GIVEN anchors whose vectors have no `targets` field
- WHEN expansion runs
- THEN expanded steps carry anchor targets and the same step count as before the change
