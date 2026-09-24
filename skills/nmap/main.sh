#!/usr/bin/env bash
# ============================================================================
# skills/nmap/main.sh — Nmap Skill DELEGATOR
#
# Thin delegator that orchestrates the nmap sub-skill pipeline:
#   nmap-port-discovery → nmap-service-detection → [nmap-iot-scripts] →
#   nmap-analyzer → nmap-sysreport
#
# Each sub-skill is called as an independent bash script with env vars.
# Results are aggregated back to state/nmap/{scan_id}/ and
# reports/{target}/nmap/{scan_id}/ for backward compatibility.
#
# Invocation (design contract):
#   bash skills/nmap/main.sh events/nmap/{scan_id}.json
#
# Invocation (engine contract — env vars):
#   SCAN_ID=abc TARGET=10.0.0.1 PARAM_PORTS=... bash skills/nmap/main.sh
#
# State written:
#   state/nmap/{scan_id}/status.json
#   state/nmap/{scan_id}/consolidated.json
#   state/nmap/{scan_id}/next_vectors.json
#
# Reports written:
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

# ---- Source envelope -----------------------------------------------------
SHARED_DIR="${PROJECT_ROOT}/skills/_shared"
source "${SHARED_DIR}/envelope.sh"

# ---- Helpers -------------------------------------------------------------

write_status() {
  local phase="$1" status="$2" progress="$3"
  local state_file="${STATE_DIR}/${SKILL}/${SCAN_ID}/status.json"
  mkdir -p "$(dirname "$state_file")"
  jq -n \
    --arg phase "$phase" \
    --arg status "$status" \
    --argjson progress "$progress" \
    --argjson pid "$$" \
    --arg started_at "${STARTED_AT}" \
    --arg scan_id "${SCAN_ID}" \
    --arg target "${TARGET}" \
    --argjson partial "${PARTIAL:-false}" \
    '{phase: $phase, status: $status, progress: $progress, pid: $pid, started_at: $started_at, scan_id: $scan_id, target: $target, partial: $partial}' > "$state_file"
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
if [ -z "${TARGET}" ]; then
  log_error "Missing required input: TARGET must be set"
  exit 1
fi

# Auto-generate scan_id if not provided
if [ -z "${SCAN_ID}" ]; then
  SCAN_ID="nmap-$(date +%s)-${RANDOM}-$$"
  log_info "Generated scan_id: ${SCAN_ID}"
fi

export SCAN_ID TARGET
export PARAM_PORTS PARAM_SCAN_MODE PARAM_TIMING PARAM_SKIP_DISCOVERY PARAM_IOT_SCRIPTS PARAM_EXTRA_NSE
export STATE_DIR REPORTS_DIR EVENTS_DIR

PARTIAL=false
export PARTIAL

# Sanitize TARGET for filesystem paths (strip protocol prefix)
REPORT_TARGET="${TARGET#https://}"
REPORT_TARGET="${REPORT_TARGET#http://}"
export REPORT_TARGET

STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# ---- Create state directory ---------------------------------------------
mkdir -p "${STATE_DIR}/${SKILL}/${SCAN_ID}"

log_info "Starting nmap delegator | scan_id=${SCAN_ID} target=${TARGET} ports=${PARAM_PORTS} mode=${PARAM_SCAN_MODE}"

# ---- Set up WORKFLOW_SHARED_DIR for sub-skill data handoff --------------
WORKFLOW_SHARED_DIR="${STATE_DIR}/workflows/${SCAN_ID}"
export WORKFLOW_SHARED_DIR
mkdir -p "${WORKFLOW_SHARED_DIR}"

# ---- Pipeline -----------------------------------------------------------

OVERALL_STATUS="done"

# ---- Phase 1: Port Discovery --------------------------------------------
write_status "port-discovery" "running" 5
log_info "Phase 1: Port discovery"
set +e
bash "${SKILL_DIR}/../nmap-port-discovery/main.sh"
PD_EXIT=$?
set -e
if [ "${PD_EXIT}" -eq 0 ]; then
  write_status "port-discovery" "done" 20
  log_info "Port discovery completed"
else
  write_status "port-discovery" "failed" 20
  log_error "Port discovery failed irrecoverably (exit=${PD_EXIT})"
  OVERALL_STATUS="failed"
fi

# Stop on port-discovery failure (same behavior as old pipeline)
if [ "${OVERALL_STATUS}" != "done" ]; then
  write_status "pipeline" "${OVERALL_STATUS}" 100
  log_error "Pipeline aborted: port-discovery failed"
  exit 1
fi

# ---- Phase 2: Service Detection -----------------------------------------
write_status "service-detection" "running" 25
log_info "Phase 2: Service detection"
set +e
bash "${SKILL_DIR}/../nmap-service-detection/main.sh"
SD_EXIT=$?
set -e
if [ "${SD_EXIT}" -eq 0 ]; then
  write_status "service-detection" "done" 45
  log_info "Service detection completed"
else
  write_status "service-detection" "degraded" 45
  log_warn "Service detection degraded (exit=${SD_EXIT}) — continuing"
  OVERALL_STATUS="degraded"
  PARTIAL=true
  export PARTIAL
fi

# ---- Phase 3: IoT Scripts (optional) ------------------------------------
write_status "iot-scripts" "running" 50
if [ "${PARAM_IOT_SCRIPTS:-false}" = "true" ]; then
  log_info "Phase 3: IoT scripts"
  set +e
  bash "${SKILL_DIR}/../nmap-iot-scripts/main.sh"
  IOT_EXIT=$?
  set -e
  if [ "${IOT_EXIT}" -eq 0 ]; then
    write_status "iot-scripts" "done" 60
    log_info "IoT scripts completed"
  else
    write_status "iot-scripts" "degraded" 60
    log_warn "IoT scripts degraded (exit=${IOT_EXIT}) — non-critical, continuing"
    PARTIAL=true
    export PARTIAL
  fi
else
  log_info "Phase 3: IoT scripts skipped (iot_scripts=false)"
  write_status "iot-scripts" "skipped" 60
fi

# ---- Phase 4: Analyzer --------------------------------------------------
write_status "analyzer" "running" 65
log_info "Phase 4: Analyzer"
set +e
bash "${SKILL_DIR}/../nmap-analyzer/main.sh"
ANALYZER_EXIT=$?
set -e
if [ "${ANALYZER_EXIT}" -eq 0 ]; then
  write_status "analyzer" "done" 80
  log_info "Analysis completed"
else
  write_status "analyzer" "failed" 80
  log_error "Analyzer failed (exit=${ANALYZER_EXIT})"
  OVERALL_STATUS="failed"
fi

# If analyzer failed, abort pipeline — consolidated.json won't be available
if [ $ANALYZER_EXIT -ne 0 ]; then
  log_error "Analyzer failed (exit $ANALYZER_EXIT) — aborting pipeline"
  write_status "pipeline" "failed" 100
  exit 1
fi

# ---- Phase 5: Sysreport --------------------------------------------------
write_status "sysreport" "running" 85
log_info "Phase 5: Sysreport"
set +e
bash "${SKILL_DIR}/../nmap-sysreport/main.sh"
SYSREPORT_EXIT=$?
set -e
if [ "${SYSREPORT_EXIT}" -eq 0 ]; then
  write_status "sysreport" "done" 100
  log_info "Sysreport completed"
else
  write_status "sysreport" "degraded" 100
  log_warn "Sysreport finished with issues (exit=${SYSREPORT_EXIT}) — non-critical"
  PARTIAL=true
  export PARTIAL
fi

# ---- Aggregate results to nmap state dir for backward compat ------------
log_info "Aggregating results to state/nmap/..."

# Copy consolidated.json from analyzer (if it exists)
ANALYZER_CONSOLIDATED="${STATE_DIR}/nmap-analyzer/${SCAN_ID}/consolidated.json"
NMAP_CONSOLIDATED="${STATE_DIR}/${SKILL}/${SCAN_ID}/consolidated.json"
if [ -f "$ANALYZER_CONSOLIDATED" ]; then
  mkdir -p "$(dirname "$NMAP_CONSOLIDATED")"
  cp "$ANALYZER_CONSOLIDATED" "$NMAP_CONSOLIDATED"
  log_info "  consolidated.json ← nmap-analyzer"
else
  log_warn "  consolidated.json not found from nmap-analyzer"
fi

# Copy next_vectors.json from analyzer (if it exists)
ANALYZER_NV="${STATE_DIR}/nmap-analyzer/${SCAN_ID}/next_vectors.json"
NMAP_NV="${STATE_DIR}/${SKILL}/${SCAN_ID}/next_vectors.json"
if [ -f "$ANALYZER_NV" ]; then
  cp "$ANALYZER_NV" "$NMAP_NV"
  log_info "  next_vectors.json ← nmap-analyzer"
fi

# Copy sub-process result files from each sub-skill for backward compat
NMAP_SUB_DIR="${STATE_DIR}/${SKILL}/${SCAN_ID}/sub-processes"
mkdir -p "${NMAP_SUB_DIR}"
for sub_skill in nmap-port-discovery nmap-service-detection nmap-iot-scripts nmap-analyzer nmap-sysreport; do
  sub_result="${STATE_DIR}/${sub_skill}/${SCAN_ID}/sub-processes/${sub_skill#nmap-}.json"
  if [ -f "$sub_result" ]; then
    cp "$sub_result" "${NMAP_SUB_DIR}/${sub_skill#nmap-}.json"
    log_info "  sub-processes/${sub_skill#nmap-}.json ← ${sub_skill}"
  fi
done

# Copy raw nmap output files (*.xml, *.nmap, *.gnmap) from each sub-skill
for skill in port-discovery service-detection iot-scripts; do
  skill_state_dir="${STATE_DIR}/nmap-${skill}/${SCAN_ID}"
  if [ -d "$skill_state_dir" ]; then
    cp "$skill_state_dir"/*.xml "${STATE_DIR}/${SKILL}/${SCAN_ID}/" 2>/dev/null || true
    cp "$skill_state_dir"/*.nmap "${STATE_DIR}/${SKILL}/${SCAN_ID}/" 2>/dev/null || true
    cp "$skill_state_dir"/*.gnmap "${STATE_DIR}/${SKILL}/${SCAN_ID}/" 2>/dev/null || true
  fi
done

# Copy reports from sysreport (written to reports/{target}/nmap/{scan_id}/)
# The nmap-sysreport sub-skill already writes directly to reports/{target}/nmap/{scan_id}/
# for backward compat. No additional copy needed.
log_info "  Reports already present at ${REPORTS_DIR}/${REPORT_TARGET}/nmap/${SCAN_ID}/"

# ---- Final Status -------------------------------------------------------
write_status "pipeline" "${OVERALL_STATUS}" 100
log_info "Pipeline finished: overall_status=${OVERALL_STATUS}"

if [ "${OVERALL_STATUS}" != "done" ]; then
  exit 1
fi
exit 0
