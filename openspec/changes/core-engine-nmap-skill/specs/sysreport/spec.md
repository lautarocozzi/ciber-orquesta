# sysreport Specification

## Purpose

Per-vector machine-readable report format that captures the full result of a single skill execution. Primary consumer is automated analysis (AI or script); secondary is human review. Source of truth for all downstream reports (vector reports, global reports).

## Requirements

### Requirement: Report Format

The sysreport MUST be valid YAML (`.yaml` extension). The report SHOULD also be emitted as valid JSON (`.json` extension) for tooling that prefers JSON. Both formats MUST carry identical data — neither is authoritative over the other.

#### Scenario: YAML output generated
- GIVEN a skill execution completes with status "done"
- WHEN the sysreport sub-process runs
- THEN a file `reports/{target}/{skill}/{scan_id}/sysreport.yaml` is created
- AND the file contains valid YAML

#### Scenario: JSON fallback emitted
- GIVEN the sysreport sub-process runs
- WHEN it writes the YAML report
- THEN an equivalent `sysreport.json` is also written
- AND both files parse to the same semantic data

### Requirement: Required Fields

Each sysreport MUST contain: `skill` (string), `target` (string — IP or domain), `scan_id` (string — UUID or timestamp-based), `status` (enum: done, degraded, failed, cancelled), `start_time` (ISO 8601), `end_time` (ISO 8601), `duration_seconds` (integer), `findings` (list), and `next_vectors` (list).

Each finding MUST contain: `type` (enum: port, service, os, vuln, fingerprint, info), `severity` (enum: critical, high, medium, low, info), `description` (string), `evidence` (string — raw output excerpt or reference), and optionally `cve` (string — CVE-ID format).

Each next_vector MUST contain: `skill` (string — skill name), `weight` (integer 0-100 — priority score), and optionally `reason` (string).

#### Scenario: Complete report with findings
- GIVEN nmap scan completes on target 10.0.0.1 with open port 443
- WHEN the sysreport is generated
- THEN the findings list contains an entry with type "port", port 443, status "open"
- AND next_vectors includes "testssl" with weight >= 50

#### Scenario: Degraded scan report
- GIVEN the analyzer sub-process failed and scan status is "degraded"
- WHEN the sysreport is generated
- THEN the status field is "degraded"
- AND the findings list is non-empty (partial results are preserved)
- AND the report includes a warning field noting which sub-process failed

### Requirement: Schema Validation

The sysreport generator MUST validate the report against its schema before writing. If validation fails, the generator MUST write an error report with status "failed" and a validation_errors field instead of silently producing malformed output.

#### Scenario: Invalid data rejected
- GIVEN required field "target" is empty
- WHEN the sysreport generator attempts to write
- THEN it writes a report with status "failed"
- AND the report contains a `validation_errors` field listing the schema violations
