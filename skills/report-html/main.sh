#!/usr/bin/env bash
# ============================================================================
# skills/report-html/main.sh — HTML Infographic Report Skill
#
# Orchestrates the generation of a self-contained HTML infographic report
# from all 4 analyzer consolidated.json sources (nmap-analyzer, nuclei-analyzer,
# whatweb, testssl).
#
# This is a terminal skill — no next_vectors are produced.
# The actual data aggregation and template injection happens in the
# generate-report.sh sub-process. This main.sh is thin orchestration.
#
# Invocation (design contract — event file):
#   bash skills/report-html/main.sh events/{scan_id}.json
#
# Invocation (engine contract — env vars):
#   SCAN_ID=abc TARGET=https://example.com \
#     bash skills/report-html/main.sh
#
# State written:
#   state/report-html/{scan_id}/status.json
#   state/report-html/{scan_id}/sub-processes/generate-report.json
#
# Reports written:
#   reports/{target}/report-html/{scan_id}/report.html
#
# Shared data (when WORKFLOW_SHARED_DIR is set):
#   $WORKFLOW_SHARED_DIR/report-html/report.html
# ============================================================================

set -euo pipefail

# ---- Directories ---------------------------------------------------------
SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SKILL_DIR}/../.." && pwd)"
STATE_DIR="${STATE_DIR:-${PROJECT_ROOT}/state}"
REPORTS_DIR="${REPORTS_DIR:-${PROJECT_ROOT}/reports}"

SKILL="report-html"

# ---- Source envelope -----------------------------------------------------
source "${PROJECT_ROOT}/skills/_shared/envelope.sh"

# ---- Parse Input ---------------------------------------------------------

if [ $# -ge 1 ] && [ -f "$1" ]; then
  EVENT_FILE="$1"
  log_info "Reading event from: ${EVENT_FILE}"
  SCAN_ID="$(jq -r '.scan_id // empty' "$EVENT_FILE")"
  TARGET="$(jq -r '.target // empty' "$EVENT_FILE")"
else
  SCAN_ID="${SCAN_ID:-}"
  TARGET="${TARGET:-}"
fi

# Validate required inputs
if [ -z "${SCAN_ID}" ] || [ -z "${TARGET}" ]; then
  log_error "Missing required inputs: SCAN_ID and TARGET must be set"
  exit 1
fi

export SCAN_ID TARGET
STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
export STARTED_AT
PARTIAL="${PARTIAL:-false}"
export PARTIAL
START_TIME_MS="$(date +%s%3N 2>/dev/null || echo 0)"

# Sanitize TARGET for filesystem paths (strip protocol prefix)
REPORT_TARGET="${TARGET#https://}"
REPORT_TARGET="${REPORT_TARGET#http://}"
export REPORT_TARGET

# ---- State & Report directories -----------------------------------------
OUTPUT_DIR="${STATE_DIR}/${SKILL}/${SCAN_ID}"
mkdir -p "${OUTPUT_DIR}/sub-processes"

# ---- Start ---------------------------------------------------------------
log_info "Starting report-html | scan_id=${SCAN_ID} target=${TARGET}"
write_status "generate-report" "running" 0 "${SCAN_ID}" "${TARGET}"

# ---- Verify sub-process exists -------------------------------------------
SUB_PROCESS="${SKILL_DIR}/sub-processes/generate-report.sh"
if [ ! -f "${SUB_PROCESS}" ]; then
  log_error "Sub-process not found at ${SUB_PROCESS}"
  write_status "generate-report" "failed" 100 "${SCAN_ID}" "${TARGET}"
  exit 2
fi

REPORT_TS="$(report_timestamp)"
export REPORT_TS

# ---- Setup temp files for stdout/stderr capture --------------------------
TEMP_DIR="$(mktemp -d "/tmp/${SKILL}-${SCAN_ID}-XXXXXX")"
STDOUT_FILE="${TEMP_DIR}/stdout"
STDERR_FILE="${TEMP_DIR}/stderr"

START_MS="$(date +%s%3N 2>/dev/null || echo 0)"

# ---- Execute sub-process -------------------------------------------------
set +e
"${SUB_PROCESS}" >"$STDOUT_FILE" 2>"$STDERR_FILE"
EXIT_CODE=$?
set -e

END_MS="$(date +%s%3N 2>/dev/null || echo 0)"
DURATION_MS=$(( END_MS - START_MS ))

# ---- Determine output file path (contract with sub-process) --------------
REPORT_DIR="${REPORTS_DIR}/${REPORT_TARGET}/report-html/${REPORT_TS}"
OUTPUT_FILE="${REPORT_DIR}/report.html"

# ---- Handle result -------------------------------------------------------
if [ "${EXIT_CODE}" -eq 0 ]; then
  log_info "Report generated successfully: ${OUTPUT_FILE}"
  write_sub_process_result "generate-report" 0 "${STDOUT_FILE}" "${STDERR_FILE}" "${DURATION_MS:-0}" "${OUTPUT_FILE}"
  write_to_shared_dir "${SKILL}" "${OUTPUT_FILE}"
  write_status "generate-report" "done" 100 "${SCAN_ID}" "${TARGET}"
  rm -rf "$TEMP_DIR"
  log_info "Report-html finished: status=done"
  exit 0
else
  log_error "Report generation failed (exit ${EXIT_CODE})"
  write_sub_process_result "generate-report" "${EXIT_CODE}" "${STDOUT_FILE}" "${STDERR_FILE}" "${DURATION_MS:-0}" ""
  write_status "generate-report" "failed" 100 "${SCAN_ID}" "${TARGET}"
  rm -rf "$TEMP_DIR"
  exit "${EXIT_CODE}"
fi
