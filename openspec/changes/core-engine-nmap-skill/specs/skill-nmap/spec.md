# skill-nmap Specification

## Purpose

Nmap skill definition establishing the pattern all future skills follow: structured `skill.yaml` metadata, a MAIN shell wrapper that orchestrates sub-processes, and a `SKILL.md` file with human/AI-readable instructions.

## Requirements

### Requirement: skill.yaml Structure

The `skills/nmap/skill.yaml` file MUST include: `name`, `version`, `description`, `main_script` (path to the MAIN wrapper), `dependencies` (list of `command -v`-checkable tools), `inputs` (map of parameter name to type/default/description), `outputs` (map of result name to type/description), and `sub_processes` (ordered list of phase names). The schema MUST be parseable by Python `yaml.safe_load()`.

Inputs MUST include: `target` (string, required), `ports` (string, default "top-1000"), `scan_mode` (enum: syn, connect, udp, default "syn"), `timing` (integer 0-5, default 4), `skip_discovery` (boolean, default false), `iot_scripts` (boolean, default false).

Outputs MUST include: `host_status` (string: up/down), `open_ports` (list of {port, protocol, state}), `os_detection` (map or null), `nse_findings` (list), `fingerprints` (list), `raw_xml` (string — file path to XML output).

#### Scenario: Valid skill.yaml loaded
- GIVEN `skills/nmap/skill.yaml` exists with all required fields
- WHEN the engine loads it
- THEN the engine parses all inputs and outputs successfully
- AND the engine confirms main_script path `skills/nmap/main.sh` exists

#### Scenario: Missing required input
- GIVEN `skills/nmap/skill.yaml` omits the "target" input definition
- WHEN the engine validates the schema
- THEN the engine rejects the skill
- AND logs a validation error specifying the missing field

### Requirement: Sub-Process Pipeline

The MAIN wrapper MUST execute sub-processes in order: port-discovery, service-detection, iot-scripts (conditional), analyzer, sysreport. Port-discovery MAY be skipped if ports input is empty (full scan). The iot-scripts sub-process MUST only run if `iot_scripts` input is true. The MAIN wrapper MUST write phase status to `state/nmap/{scan_id}/status.json` after each sub-process. If a sub-process fails irrecoverably, MAIN MUST write the failure reason to status.json and stop execution.

#### Scenario: Full pipeline runs
- GIVEN a scan with `ports="top-1000"` and `iot_scripts=false`
- WHEN MAIN executes
- THEN port-discovery runs first
- AND service-detection runs second
- AND iot-scripts is skipped
- AND analyzer runs third
- AND sysreport runs last
- AND status.json transitions through each phase

#### Scenario: Critical sub-process failure
- GIVEN port-discovery fails with exit code non-zero
- WHEN Tier 1 and Tier 2 retries exhaust
- THEN MAIN sets status to "failed"
- AND downstream sub-processes are NOT executed
- AND the failure reason is recorded in status.json

### Requirement: next_vectors Table

The skill.yaml MUST define a `next_vectors` section mapping conditions to suggested follow-up skills. Each entry MUST have: `condition` (string — describing when this applies), `skill` (string), `weight` (integer 0-100), and `reason` (string). Conditions MUST reference open ports or detected services (e.g., "port 443 open" → testssl, "port 80 open" → httpx).

#### Scenario: next_vectors generated from findings
- GIVEN nmap scan finds ports 80, 443, and 22 open
- WHEN the analyzer sub-process runs
- THEN next_vectors includes "testssl" (weight ≥ 70, port 443)
- AND next_vectors includes "httpx" (weight ≥ 70, port 80)
- AND next_vectors includes "nuclei" (weight ≥ 50, multiple services detected)

### Requirement: SKILL.md Documentation

The `skills/nmap/SKILL.md` MUST document: purpose, required inputs with examples, expected outputs, sub-process flow, dependency tools, usage examples, and a troubleshooting section. It MUST be valid Markdown and MUST be AI-readable (structured sections, code blocks for commands, tables for inputs/outputs).

#### Scenario: SKILL.md consumed by AI
- GIVEN an AI agent reads `skills/nmap/SKILL.md`
- WHEN it searches for input parameters
- THEN it finds a clearly formatted table of inputs with types and defaults
- AND it can construct a valid scan event from the documentation alone
