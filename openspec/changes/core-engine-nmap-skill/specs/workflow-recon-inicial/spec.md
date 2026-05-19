# workflow-recon-inicial Specification

## Purpose

First workflow definition establishing the YAML format for all future workflows. Runs a single-target nmap reconnaissance scan and triggers sysreport generation as its output artifact.

## Requirements

### Requirement: Workflow YAML Format

The workflow MUST be defined in `workflows/recon-inicial.yaml`. It MUST contain: `name` (string), `description` (string), `version` (string), `skills` (list of skill step definitions), and `rollback` (map). Each skill step MUST contain: `id` (string — unique within workflow), `skill` (string — matching a loaded skill name), `inputs` (map of parameter values), and `depends_on` (list of step IDs that must complete first). The rollback map MUST contain: `max_retries` (integer), `relax_on_retry` (boolean — whether to use Tier 2 relaxation), and `on_failure` (enum: stop, skip, continue).

#### Scenario: Valid workflow loaded
- GIVEN `workflows/recon-inicial.yaml` has a single nmap step with no dependencies
- WHEN the engine reads the workflow
- THEN it parses successfully
- AND the engine resolves the nmap step as ready for execution (no blockers)

#### Scenario: Missing required field
- GIVEN `workflows/recon-inicial.yaml` omits the "skills" list
- WHEN the engine validates the workflow
- THEN the engine rejects the workflow
- AND logs "Workflow recon-inicial rejected: missing required field 'skills'"

### Requirement: Single-Target Nmap Recon

The recon-inicial workflow MUST execute one nmap scan step with input `target` taken from the active target definition. The step MUST use `ports: "top-1000"` and `scan_mode: "syn"` as defaults. After nmap completes, the workflow MUST trigger sysreport generation on the scan results. The workflow SHALL be extensible — adding more steps MUST NOT require changing the existing nmap step definition.

#### Scenario: Happy path — scan and report
- GIVEN active target is "10.0.0.1"
- WHEN the engine executes recon-inicial
- THEN nmap scans target 10.0.0.1 with top-1000 SYN scan
- AND upon completion, a sysreport is generated at `reports/10.0.0.1/nmap/{scan_id}/sysreport.yaml`
- AND the workflow status is "done"

#### Scenario: Nmap step fails
- GIVEN target "10.0.0.1" is unreachable
- WHEN nmap returns host_status "down"
- THEN the step status is "done" (nmap itself succeeded — reporting the host is down is valid)
- AND the sysreport reflects host_status "down" with no open ports
- AND next_vectors is empty (no services to follow up on)

#### Scenario: Engine crash mid-workflow
- GIVEN the engine crashes after nmap completes but before sysreport generation
- WHEN the engine restarts
- THEN it MUST detect incomplete workflow state from disk
- AND it MUST resume sysreport generation from the persisted nmap results
