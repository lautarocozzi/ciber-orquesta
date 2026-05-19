#!/usr/bin/env bash
# ============================================================================
# skills/nmap/main.sh — Nmap Skill MAIN wrapper
#
# Reads an event JSON file (or env vars) and orchestrates the nmap sub-process
# pipeline: port-discovery → service-detection → [iot-scripts] → analyzer →
# sysreport.
#
# Invocation (design contract):
#   bash skills/nmap/main.sh events/nmap/{scan_id}.json
#
# Invocation (engine contract — env vars):
#   SCAN_ID=abc TARGET=10.0.0.1 PARAM_PORTS=... bash skills/nmap/main.sh
#
# State written (all relative to STATE_DIR, default "state"):
#   state/nmap/{scan_id}/status.json
#   state/nmap/{scan_id}/sub-processes/{name}.json
#   state/nmap/{scan_id}/consolidated.json
#   state/nmap/{scan_id}/next_vectors.json
#
# Reports written (relative to REPORTS_DIR, default "reports"):
#   reports/{target}/nmap/{scan_id}/sysreport.yaml
#   reports/{target}/nmap/{scan_id}/sysreport.json
# ============================================================================

set -euo pipefail

# ---- Directories ---------------------------------------------------------
SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SKILL_DIR}/../.." && pwd)"
STATE_DIR="${STATE_DIR:-${PROJECT_ROOT}/state}"
REPORTS_DIR="${REPORTS_DIR:-${PROJECT_ROOT}/reports}"
EVENTS_DIR="${EVENTS_DIR:-${PROJECT_ROOT}/events}"

SKILL="nmap"

# ---- Helpers -------------------------------------------------------------

log_info()  { echo "[main.sh] [INFO]  $*"; }
log_warn()  { echo "[main.sh] [WARN]  $*" >&2; }
log_error() { echo "[main.sh] [ERROR] $*" >&2; }

write_status() {
  local phase="$1" status="$2" progress="$3"
  local state_file="${STATE_DIR}/${SKILL}/${SCAN_ID}/status.json"
  mkdir -p "$(dirname "$state_file")"
  cat > "$state_file" <<-STATUSEOF
{
  "phase": "${phase}",
  "status": "${status}",
  "progress": ${progress},
  "pid": $$,
  "started_at": "${STARTED_AT}",
  "scan_id": "${SCAN_ID}",
  "target": "${TARGET}"
}
STATUSEOF
}

write_subprocess_result() {
  local name="$1" exit_code="$2" stdout_file="$3" stderr_file="$4" duration_ms="$5" output_file="$6"
  local result_file="${STATE_DIR}/${SKILL}/${SCAN_ID}/sub-processes/${name}.json"
  mkdir -p "$(dirname "$result_file")"

  # Read stdout/stderr content, escaping for JSON
  local stdout_content stderr_content
  stdout_content="$(cat "$stdout_file" 2>/dev/null | jq -Rs '.' || echo '""')"
  stderr_content="$(cat "$stderr_file" 2>/dev/null | jq -Rs '.' || echo '""')"

  cat > "$result_file" <<-SUBEOF
{
  "sub_process": "${name}",
  "scan_id": "${SCAN_ID}",
  "exit_code": ${exit_code},
  "duration_ms": ${duration_ms},
  "stdout": ${stdout_content},
  "stderr": ${stderr_content},
  "output_file": "${output_file}"
}
SUBEOF
}

run_sub_process() {
  local name="$1" script_path="$2" max_retries="${3:-3}"
  local script_file="${SKILL_DIR}/${script_path}"

  if [ ! -f "$script_file" ]; then
    log_error "Sub-process script not found: ${script_file}"
    write_subprocess_result "$name" 127 "/dev/null" "/dev/null" 0 ""
    return 1
  fi

  local temp_dir
  temp_dir="$(mktemp -d "/tmp/nmap-sub-${name}-XXXXXX")"
  local stdout_file="${temp_dir}/stdout"
  local stderr_file="${temp_dir}/stderr"
  local exit_code=0
  local duration_ms=0

  # Tier 1: Direct retry
  local attempt=1
  while [ "${attempt}" -le "${max_retries}" ]; do
    log_info "Sub-process '${name}' — Tier 1 attempt ${attempt}/${max_retries}"

    local start_ms end_ms
    start_ms="$(date +%s%3N)"

    set +e
    bash "$script_file" >"$stdout_file" 2>"$stderr_file"
    exit_code=$?
    set -e

    end_ms="$(date +%s%3N)"
    duration_ms=$(( end_ms - start_ms ))

    if [ "${exit_code}" -eq 0 ]; then
      break
    fi

    log_warn "Sub-process '${name}' attempt ${attempt} failed (exit ${exit_code})"
    if [ "${attempt}" -lt "${max_retries}" ]; then
      sleep "${attempt}"  # Backoff: 1s, 2s, 3s
    fi
    attempt=$(( attempt + 1 ))
  done

  # Tier 2: Relaxed retry if Tier 1 exhausted
  if [ "${exit_code}" -ne 0 ]; then
    log_warn "Sub-process '${name}' — Tier 1 exhausted, trying Tier 2 (relaxed)"

    local tier2_start tier2_end
    tier2_start="$(date +%s%3N)"

    set +e
    PARAM_SKIP_DISCOVERY=true PARAM_TIMING=3 bash "$script_file" >"$stdout_file" 2>"$stderr_file"
    exit_code=$?
    set -e

    tier2_end="$(date +%s%3N)"
    duration_ms=$(( duration_ms + tier2_end - tier2_start ))

    if [ "${exit_code}" -eq 0 ]; then
      log_info "Sub-process '${name}' — Tier 2 (relaxed) succeeded"
    else
      log_error "Sub-process '${name}' — Tier 2 (relaxed) also failed (exit ${exit_code})"
    fi
  fi

  # Determine output file (check for common nmap output patterns)
  local output_file=""
  local state_subdir="${STATE_DIR}/${SKILL}/${SCAN_ID}"
  for ext in xml nmap gnmap; do
    local candidate="${state_subdir}/${name}.${ext}"
    if [ -f "$candidate" ]; then
      output_file="${candidate}"
    fi
  done

  write_subprocess_result "$name" "$exit_code" "$stdout_file" "$stderr_file" "$duration_ms" "$output_file"

  # Cleanup temp
  rm -rf "$temp_dir"

  return "${exit_code}"
}

run_sub_process_optional() {
  local name="$1" script_path="$2"
  if [ "${PARAM_IOT_SCRIPTS:-false}" = "true" ]; then
    log_info "Running optional sub-process '${name}' (iot_scripts enabled)"
    run_sub_process "$name" "$script_path" || true
    return 0
  else
    log_info "Sub-process '${name}' skipped (iot_scripts=false)"
    local result_file="${STATE_DIR}/${SKILL}/${SCAN_ID}/sub-processes/${name}.json"
    mkdir -p "$(dirname "$result_file")"
    cat > "$result_file" <<-SKIPEOF
{
  "sub_process": "${name}",
  "scan_id": "${SCAN_ID}",
  "exit_code": 0,
  "duration_ms": 0,
  "stdout": "",
  "stderr": "",
  "output_file": "",
  "skipped": true,
  "skip_reason": "iot_scripts is false"
}
SKIPEOF
    return 0
  fi
}

# ---- Parse Input ---------------------------------------------------------

if [ $# -ge 1 ] && [ -f "$1" ]; then
  # Design contract: event file path as argument
  EVENT_FILE="$1"
  log_info "Reading event from: ${EVENT_FILE}"
  SCAN_ID="$(jq -r '.scan_id // empty' "$EVENT_FILE")"
  TARGET="$(jq -r '.target // empty' "$EVENT_FILE")"
  PARAM_PORTS="$(jq -r '.parameters.ports // "top-1000"' "$EVENT_FILE")"
  PARAM_SCAN_MODE="$(jq -r '.parameters.scan_mode // "syn"' "$EVENT_FILE")"
  PARAM_TIMING="$(jq -r '.parameters.timing // 4' "$EVENT_FILE")"
  PARAM_SKIP_DISCOVERY="$(jq -r '.parameters.skip_discovery // false' "$EVENT_FILE")"
  PARAM_IOT_SCRIPTS="$(jq -r '.parameters.iot_scripts // false' "$EVENT_FILE")"
  PARAM_EXTRA_NSE="$(jq -r '.parameters.extra_nse // ""' "$EVENT_FILE")"
else
  # Engine contract: env vars
  SCAN_ID="${SCAN_ID:-}"
  TARGET="${TARGET:-}"
  PARAM_PORTS="${PARAM_PORTS:-top-1000}"
  PARAM_SCAN_MODE="${PARAM_SCAN_MODE:-syn}"
  PARAM_TIMING="${PARAM_TIMING:-4}"
  PARAM_SKIP_DISCOVERY="${PARAM_SKIP_DISCOVERY:-false}"
  PARAM_IOT_SCRIPTS="${PARAM_IOT_SCRIPTS:-false}"
  PARAM_EXTRA_NSE="${PARAM_EXTRA_NSE:-}"
fi

# Validate required inputs
if [ -z "${SCAN_ID}" ] || [ -z "${TARGET}" ]; then
  log_error "Missing required inputs: SCAN_ID and TARGET must be set"
  exit 1
fi

export SCAN_ID TARGET
export PARAM_PORTS PARAM_SCAN_MODE PARAM_TIMING PARAM_SKIP_DISCOVERY PARAM_IOT_SCRIPTS PARAM_EXTRA_NSE
export STATE_DIR REPORTS_DIR EVENTS_DIR SKILL

STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# ---- Create state directory ---------------------------------------------
mkdir -p "${STATE_DIR}/${SKILL}/${SCAN_ID}/sub-processes"
mkdir -p "${REPORTS_DIR}/${TARGET}/${SKILL}/${SCAN_ID}"

log_info "Starting nmap scan | scan_id=${SCAN_ID} target=${TARGET} ports=${PARAM_PORTS} mode=${PARAM_SCAN_MODE}"

# ---- Pipeline -----------------------------------------------------------

OVERALL_STATUS="done"

# Phase 1: Port Discovery
write_status "port-discovery" "running" 10
if run_sub_process "port-discovery" "sub-processes/port-discovery.sh"; then
  write_status "port-discovery" "done" 25
  log_info "Port discovery completed"
else
  write_status "port-discovery" "failed" 25
  log_error "Port discovery failed irrecoverably"
  OVERALL_STATUS="degraded"
fi

# Check if we should continue
if [ "${OVERALL_STATUS}" = "degraded" ]; then
  write_status "pipeline" "${OVERALL_STATUS}" 100
  exit 1
fi

# Phase 2: Service Detection
write_status "service-detection" "running" 35
if run_sub_process "service-detection" "sub-processes/service-detection.sh"; then
  write_status "service-detection" "done" 55
  log_info "Service detection completed"
else
  write_status "service-detection" "failed" 55
  log_error "Service detection failed irrecoverably"
  OVERALL_STATUS="degraded"
fi

# Phase 3: IoT Scripts (optional)
write_status "iot-scripts" "running" 60
run_sub_process_optional "iot-scripts" "sub-processes/iot-scripts.sh"
write_status "iot-scripts" "done" 70

# Phase 4: Analyzer
write_status "analyzer" "running" 75
if run_sub_process "analyzer" "sub-processes/analyzer.sh"; then
  write_status "analyzer" "done" 90
  log_info "Analysis completed"
else
  write_status "analyzer" "failed" 90
  log_error "Analyzer failed"
  OVERALL_STATUS="degraded"
fi

# Phase 5: Sysreport
write_status "sysreport" "running" 92
run_sub_process "sysreport" "sub-processes/sysreport.sh" || true
write_status "sysreport" "done" 100

# ---- Final Status -------------------------------------------------------
write_status "pipeline" "${OVERALL_STATUS}" 100
log_info "Pipeline finished: overall_status=${OVERALL_STATUS}"

exit 0
