#!/usr/bin/env bash
# ============================================================================
# skills/dnsenum/main.sh — DNS Enumeration Meta-Skill Chain Orchestrator
#
# Runs the DNS pipeline:
#   dnsenum-scan (run + inline parse) → dnsenum-analyzer → dnsenum-sysreport
#
# The wildcard guard runs inside the scan step, so no wildcard name can reach
# the analyzer's next_vectors.
#
# Invocation:
#   SCAN_ID=abc TARGET=example.com WORDLIST=/path/list THREADS=10 \
#     bash skills/dnsenum/main.sh
#
# Or via event file:
#   bash skills/dnsenum/main.sh events/{scan_id}.json
# ============================================================================

set -euo pipefail

SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SKILL_DIR}/../.." && pwd)"
CHAIN_DIR="${SKILL_DIR}/.."

log_info()  { printf '[dnsenum] [INFO]  %s\n' "$*" >&2; }
log_warn()  { printf '[dnsenum] [WARN]  %s\n' "$*" >&2; }
log_error() { printf '[dnsenum] [ERROR] %s\n' "$*" >&2; }

# ---- Parse Input ---------------------------------------------------------
if [ $# -ge 1 ] && [ -f "$1" ]; then
  EVENT_FILE="$1"
  log_info "Reading event from: ${EVENT_FILE}"
  SCAN_ID="$(jq -r '.scan_id // empty' "$EVENT_FILE")"
  TARGET="$(jq -r '.target // empty' "$EVENT_FILE")"
  WORDLIST="$(jq -r '.parameters.wordlist // empty' "$EVENT_FILE")"
  THREADS="$(jq -r '.parameters.threads // empty' "$EVENT_FILE")"
  STEP_TIMEOUT_SECONDS="$(jq -r '.parameters.step_timeout // empty' "$EVENT_FILE")"
  WORKFLOW_SHARED_DIR="$(jq -r '.workflow_shared_dir // empty' "$EVENT_FILE")"
else
  SCAN_ID="${SCAN_ID:-}"
  TARGET="${TARGET:-}"
  WORDLIST="${WORDLIST:-}"
  THREADS="${THREADS:-}"
  STEP_TIMEOUT_SECONDS="${STEP_TIMEOUT_SECONDS:-}"
  WORKFLOW_SHARED_DIR="${WORKFLOW_SHARED_DIR:-}"
fi

if [ -z "${SCAN_ID}" ] || [ -z "${TARGET}" ]; then
  log_error "Missing required inputs: SCAN_ID and TARGET"
  exit 1
fi

export SCAN_ID TARGET WORDLIST THREADS STEP_TIMEOUT_SECONDS WORKFLOW_SHARED_DIR

# ---- Chain runner --------------------------------------------------------
run_step() {
  local step_skill="$1"
  log_info "Running chain step: ${step_skill}"
  SCAN_ID="${SCAN_ID}" TARGET="${TARGET}" \
    WORDLIST="${WORDLIST:-}" THREADS="${THREADS:-}" \
    STEP_TIMEOUT_SECONDS="${STEP_TIMEOUT_SECONDS:-}" \
    WORKFLOW_SHARED_DIR="${WORKFLOW_SHARED_DIR:-}" \
    bash "${CHAIN_DIR}/${step_skill}/main.sh" || {
    log_error "Chain step ${step_skill} failed"
    return 1
  }
}

# ---- Pipeline ------------------------------------------------------------
log_info "Starting DNS pipeline | scan_id=${SCAN_ID} target=${TARGET}"

# Scan failure is not fatal: the scan sub-skill always writes a fallback
# parsed-results.json, and the analyzer degrades to an empty contract.
run_step "dnsenum-scan" || log_warn "dnsenum-scan failed — continuing with degraded results"
run_step "dnsenum-analyzer"
run_step "dnsenum-sysreport"

log_info "DNS pipeline complete | scan_id=${SCAN_ID}"
