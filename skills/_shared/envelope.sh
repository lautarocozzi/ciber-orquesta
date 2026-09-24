#!/usr/bin/env bash
# ============================================================================
# skills/_shared/envelope.sh — Universal Envelope Functions
#
# Shared Bash functions for the universal envelope contract. Every sub-skill
# sources this file to write status.json, next_vectors.json, sub-process
# results, and to handle WORKFLOW_SHARED_DIR data handoff.
#
# Required env vars (set by sourcing script before calling):
#   SKILL       — skill name (e.g. "nmap-port-discovery")
#   SCAN_ID     — current scan identifier
#   TARGET      — target IP or hostname
#   STATE_DIR   — defaults to "${PROJECT_ROOT}/state"
#
# Optional env vars:
#   PARTIAL     — "true" if partial results, "false" otherwise
#   STARTED_AT  — ISO8601 timestamp, set by sourcing script if not provided
#
# Usage:
#   source "${PROJECT_ROOT}/skills/_shared/envelope.sh"
#   write_status "port-discovery" "running" 0
#   write_next_vectors "${SCAN_ID}" "${TARGET}" "up" '[{"skill":"...","weight":100}]'
#   write_sub_process_result "port-discovery" 0 "/tmp/stdout" "/tmp/stderr" 12500 "/path/to/output.xml"
#   write_to_shared_dir "nmap-port-discovery" "/path/to/consolidated.json"
#   port_file="$(read_predecessor_output "nmap-port-discovery" "consolidated.json")"
# ============================================================================

# ---- Log helpers (injected by envelope) -----------------------------------
log_info()  { echo "[${SKILL}] [INFO]  $*"; }
log_warn()  { echo "[${SKILL}] [WARN]  $*" >&2; }
log_error() { echo "[${SKILL}] [ERROR] $*" >&2; }

# Guard against multiple sourcing
if [ -n "${_ENVELOPE_SH_SOURCED:-}" ]; then
  return 0
fi
_ENVELOPE_SH_SOURCED=1

# ---------------------------------------------------------------------------
# write_status(phase, status, progress [, scan_id] [, target])
#
# Writes state/{SKILL}/{scan_id}/status.json
#
# Parameters:
#   phase    — sub-process phase name (e.g. "port-discovery")
#   status   — running | done | failed | skipped | degraded
#   progress — integer 0-100
#   scan_id  — (optional) overrides ${SCAN_ID}
#   target   — (optional) overrides ${TARGET}
#
# Env vars used: SKILL, SCAN_ID, TARGET, STATE_DIR, PARTIAL, STARTED_AT
# ---------------------------------------------------------------------------
write_status() {
  local phase="$1" status="$2" progress="$3"
  local scan_id="${4:-${SCAN_ID:-}}"
  local target="${5:-${TARGET:-}}"
  local skill="${SKILL:-unknown}"
  local state_dir="${STATE_DIR:-state}"
  local state_file="${state_dir}/${skill}/${scan_id}/status.json"

  mkdir -p "$(dirname "$state_file")"

  local started
  started="${STARTED_AT:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

  jq -n \
    --arg phase "$phase" \
    --arg status "$status" \
    --argjson progress "${progress}" \
    --argjson pid "$$" \
    --arg started "${started}" \
    --arg scan_id "${scan_id}" \
    --arg target "${target}" \
    --argjson partial "${PARTIAL:-false}" \
    '{phase: $phase, status: $status, progress: $progress, pid: $pid, started_at: $started, scan_id: $scan_id, target: $target, partial: $partial}' > "$state_file"
}

# ---------------------------------------------------------------------------
# write_next_vectors(scan_id, target, host_status, next_vectors_json)
#
# Writes state/{SKILL}/{scan_id}/next_vectors.json
#
# Parameters:
#   scan_id           — scan identifier
#   target            — target IP or hostname
#   host_status       — up | down | filtered
#   next_vectors_json — JSON array string, e.g. '[{"skill":"...","weight":100,"reason":"..."}]'
# ---------------------------------------------------------------------------
write_next_vectors() {
  local scan_id="$1" target="$2" host_status="$3" next_vectors_json="$4"
  local skill="${SKILL:-unknown}"
  local state_dir="${STATE_DIR:-state}"
  local state_file="${state_dir}/${skill}/${scan_id}/next_vectors.json"

  mkdir -p "$(dirname "$state_file")"

  jq -n \
    --arg scan_id "${scan_id}" \
    --arg target "${target}" \
    --arg host_status "${host_status}" \
    --argjson next_vectors "${next_vectors_json}" \
    '{scan_id: $scan_id, target: $target, host_status: $host_status, next_vectors: $next_vectors}' > "$state_file"
}

# ---------------------------------------------------------------------------
# write_sub_process_result(name, exit_code, stdout_file, stderr_file,
#                          duration_ms, output_file)
#
# Writes state/{SKILL}/{scan_id}/sub-processes/{name}.json
#
# Parameters:
#   name        — sub-process name (e.g. "port-discovery")
#   exit_code   — numeric exit code
#   stdout_file — path to captured stdout (contents are JSON-escaped)
#   stderr_file — path to captured stderr (contents are JSON-escaped)
#   duration_ms — run duration in milliseconds
#   output_file — path to primary output file (XML, JSON, etc.)
# ---------------------------------------------------------------------------
write_sub_process_result() {
  local name="$1" exit_code="$2" stdout_file="$3" stderr_file="$4" duration_ms="$5" output_file="$6"
  local skill="${SKILL:-unknown}"
  local scan_id="${SCAN_ID:-unknown}"
  local state_dir="${STATE_DIR:-state}"
  local result_file="${state_dir}/${skill}/${scan_id}/sub-processes/${name}.json"

  mkdir -p "$(dirname "$result_file")"

  local stdout_content stderr_content
  stdout_content="$(cat "$stdout_file" 2>/dev/null | jq -Rs '.' || echo '""')"
  stderr_content="$(cat "$stderr_file" 2>/dev/null | jq -Rs '.' || echo '""')"

  jq -n \
    --arg sub_process "${name}" \
    --arg scan_id "${scan_id}" \
    --argjson exit_code "${exit_code}" \
    --argjson duration_ms "${duration_ms}" \
    --argjson stdout "${stdout_content}" \
    --argjson stderr "${stderr_content}" \
    --arg output_file "${output_file}" \
    '{sub_process: $sub_process, scan_id: $scan_id, exit_code: $exit_code, duration_ms: $duration_ms, stdout: $stdout, stderr: $stderr, output_file: $output_file}' > "$result_file"
}

# ---------------------------------------------------------------------------
# write_to_shared_dir(sub_skill_name, data_file)
#
# Copies data_file to $WORKFLOW_SHARED_DIR/{sub_skill_name}/ if the env var
# is set. No-op when WORKFLOW_SHARED_DIR is unset or empty.
#
# Parameters:
#   sub_skill_name — subdirectory name under WORKFLOW_SHARED_DIR
#   data_file      — path to file to copy
# ---------------------------------------------------------------------------
write_to_shared_dir() {
  local sub_skill_name="$1" data_file="$2"

  if [ -n "${WORKFLOW_SHARED_DIR:-}" ]; then
    local dest_dir="${WORKFLOW_SHARED_DIR}/${sub_skill_name}"
    mkdir -p "${dest_dir}"
    cp "${data_file}" "${dest_dir}/"
  fi
}

# ---------------------------------------------------------------------------
# read_predecessor_output(predecessor_name, file_name)
#
# Returns the path to a predecessor's output file. Tries the following in
# order and returns the first match:
#   1. $WORKFLOW_SHARED_DIR/{predecessor_name}/{file_name}
#   2. $STATE_DIR/{predecessor_name}/{scan_id}/{file_name}
#
# Parameters:
#   predecessor_name — skill name of the predecessor (e.g. "nmap-port-discovery")
#   file_name        — file to look for (e.g. "consolidated.json")
#
# Returns:
#   Prints the resolved file path to stdout and returns 0 if found.
#   Returns 1 and prints nothing if not found.
# ---------------------------------------------------------------------------
read_predecessor_output() {
  local predecessor_name="$1" file_name="$2"
  local scan_id="${SCAN_ID:-}"
  local state_dir="${STATE_DIR:-state}"

  # Try WORKFLOW_SHARED_DIR first (engine-managed handoff)
  if [ -n "${WORKFLOW_SHARED_DIR:-}" ]; then
    local shared_file="${WORKFLOW_SHARED_DIR}/${predecessor_name}/${file_name}"
    if [ -f "${shared_file}" ]; then
      echo "${shared_file}"
      return 0
    fi
  fi

  # Fall back to state directory (standalone or backward compat)
  if [ -n "${scan_id}" ]; then
    local state_file="${state_dir}/${predecessor_name}/${scan_id}/${file_name}"
    if [ -f "${state_file}" ]; then
      echo "${state_file}"
      return 0
    fi
  fi

  return 1
}

# ---------------------------------------------------------------------------
# report_timestamp()
#
# Returns an ISO 8601-ish timestamp suitable for use in directory/file names:
#   YYYY-MM-DD/HH-MM-SS
#
# This is the canonical timestamp used by all sysreports for organizing
# output by date instead of by opaque scan_id.
#
# Usage:
#   ts="$(report_timestamp)"
#   mkdir -p "reports/${TARGET}/${SKILL}/${ts}"
#
# Output: "2026-07-01/21-37-22" (two levels: date/time)
# ---------------------------------------------------------------------------
report_timestamp() {
  date -u +"%Y-%m-%d/%H-%M-%S" 2>/dev/null || echo "unknown-timestamp"
}
