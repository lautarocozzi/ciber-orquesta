# engine-core Specification

## Purpose

Core orchestration engine that loads skill definitions, implements the filesystem event-bus pattern, manages sub-process lifecycle with 3-tier rollback, and executes workflow DAGs.

## Requirements

### Requirement: Skill Loading

The engine MUST scan `skills/` for `skill.yaml` files on startup. Each loaded skill MUST be validated against a required schema: `name`, `version`, `main_script`, `dependencies` (list), `inputs` (map), `outputs` (map). The engine MUST verify tool dependencies via `command -v` before marking a skill as loaded. Loaded skills MUST be cached in memory for the session duration. The engine SHOULD log warnings for missing optional fields. The engine MAY reload skills on SIGHUP.

#### Scenario: Load valid skill
- GIVEN a valid `skills/nmap/skill.yaml` exists with all required fields and all tool deps are installed
- WHEN the engine starts
- THEN the nmap skill is loaded and cached
- AND the engine logs "Loaded skill: nmap"

#### Scenario: Skip skill with missing dependency
- GIVEN `skills/nmap/skill.yaml` requires "nuclei" but nuclei is not in PATH
- WHEN the engine validates dependencies
- THEN the nmap skill is NOT loaded
- AND the engine logs "Skill nmap skipped: missing dependency nuclei"

### Requirement: Filesystem Event Bus

The engine MUST write scan events as JSON files to `events/{skill}/{scan_id}.json`. Each event file MUST contain: `skill`, `target`, `scan_id`, `parameters`, and `timestamp`. The engine MUST detect event completion by monitoring `state/{skill}/{scan_id}/status.json`. The engine MUST support both inotify-based and polling fallback detection. The engine MUST clean up event files older than a configurable TTL (default 24h).

#### Scenario: Event dispatched and completed
- GIVEN the engine writes `events/nmap/scan-001.json`
- WHEN the nmap MAIN process writes `state/nmap/scan-001/status.json` with status "done"
- THEN the engine detects completion via inotify
- AND the engine marks scan-001 as complete in its DAG state

#### Scenario: Polling fallback activated
- GIVEN inotify is unavailable or the watcher limit is exceeded
- WHEN the engine writes an event file
- THEN the engine polls `state/{skill}/{scan_id}/status.json` every 5 seconds
- AND the engine detects completion within one polling interval

### Requirement: 3-Tier Rollback

On sub-process failure, the engine MUST execute 3-tier rollback: Tier 1 — retry once with identical parameters; Tier 2 — retry once with relaxed parameters (longer timeout, fewer ports); Tier 3 — mark execution as "degraded" and proceed with partial results. Critical sub-processes (port-discovery) MUST cascade-stop downstream on failure after exhausting Tier 1 + Tier 2. Non-critical sub-processes (analyzer) SHOULD allow continued execution with degraded status.

#### Scenario: Non-critical sub-process recovers
- GIVEN the analyzer sub-process fails with exit code 1
- WHEN Tier 1 retry succeeds
- THEN the scan status remains "done"
- AND the log records "analyzer: retry 1 succeeded"

#### Scenario: Critical failure cascades stop
- GIVEN port-discovery fails after Tier 1 and Tier 2 retries
- WHEN both retries fail
- THEN the scan status is set to "failed"
- AND all downstream sub-processes are cancelled
- AND the engine logs "Critical failure in port-discovery: scan aborted"

### Requirement: Workflow DAG Execution

The engine MUST read workflow YAML from `workflows/`. It MUST resolve skill dependencies and execute skills in topological order. It MUST skip dependent skills when a prerequisite skill fails. Independent skills MAY execute in parallel.

#### Scenario: Linear workflow execution
- GIVEN `workflows/recon-inicial.yaml` defines a single nmap step
- WHEN the engine starts the workflow
- THEN it writes the nmap event file
- AND waits for nmap to complete
- AND triggers sysreport generation after nmap completes

### Requirement: Concurrent State Protection

The engine MUST use POSIX `flock` for exclusive file locking on state file writes. It MUST use atomic rename (`write tmp → rename`) to prevent partial reads. It SHOULD retry locked writes up to 3 times with 100ms backoff.

#### Scenario: Write contention resolved
- GIVEN two MAIN processes attempt to write `status.json` simultaneously
- WHEN the first process acquires the flock
- THEN the second process waits for the lock
- AND the second retries up to 3 times before failing with a lock error
