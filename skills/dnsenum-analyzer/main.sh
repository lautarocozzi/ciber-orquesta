#!/usr/bin/env bash
# ============================================================================
# skills/dnsenum-analyzer/main.sh — DNS Analysis Sub-Skill
#
# Reads dnsenum-scan parsed-results.json (shared dir, else state dir),
# consolidates it into the DNS analyzer contract, computes severity and emits
# next_vectors that carry the discovered subdomains as `targets`.
#
# The analyzer re-applies the wildcard guard: a name resolving to a wildcard
# IP is dropped here too, so nothing filtered by the scanner can reach a
# vector's targets through a partially written predecessor file.
#
# Contract written to state/dnsenum-analyzer/{scan_id}/consolidated.json:
#   {scan_id, target, started_at, domain, subdomains[{name, ip, source}],
#    subdomain_count, ns[], mx[], zone_transfer{attempted, success, records[]},
#    severity, next_vectors, partial}
#
# Invocation (engine contract — env vars):
#   SCAN_ID=abc TARGET=example.com bash skills/dnsenum-analyzer/main.sh
#
# State written:
#   state/dnsenum-analyzer/{scan_id}/status.json
#   state/dnsenum-analyzer/{scan_id}/consolidated.json
#   state/dnsenum-analyzer/{scan_id}/next_vectors.json
#   state/dnsenum-analyzer/{scan_id}/sub-processes/analyze.json
#
# Shared data (when WORKFLOW_SHARED_DIR is set):
#   $WORKFLOW_SHARED_DIR/dnsenum-analyzer/consolidated.json
# ============================================================================

set -euo pipefail

# ---- Directories ---------------------------------------------------------
SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SKILL_DIR}/../.." && pwd)"
STATE_DIR="${STATE_DIR:-${PROJECT_ROOT}/state}"

# The engine reads next_vectors.json from state/{step.skill}/{scan_id}/, so
# this sub-skill MUST keep its own name as the state directory.
SKILL="dnsenum-analyzer"
STEP_ID="${STEP_ID:-dnsenum-analyzer}"

# Cap per vector; the engine re-caps with workflow.expansion.max_targets_per_vector.
MAX_TARGETS_PER_VECTOR="${MAX_TARGETS_PER_VECTOR:-10}"

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

if [ -z "${SCAN_ID}" ] || [ -z "${TARGET}" ]; then
  log_error "Missing required inputs: SCAN_ID and TARGET"
  exit 1
fi

export SCAN_ID TARGET
PARTIAL=false; export PARTIAL
STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"; export STARTED_AT

OUTPUT_DIR="${STATE_DIR}/${SKILL}/${SCAN_ID}"
mkdir -p "${OUTPUT_DIR}/sub-processes"

log_info "Starting DNS analyzer | scan_id=${SCAN_ID} target=${TARGET}"
write_status "dnsenum-analyze" "running" 0 "${SCAN_ID}" "${TARGET}"

# ---- Read predecessor output --------------------------------------------
PARSED="$(read_predecessor_output "dnsenum-scan" "parsed-results.json" || true)"
if [ -z "${PARSED}" ] || [ ! -f "${PARSED}" ]; then
  CANDIDATE="${STATE_DIR}/dnsenum-scan/${SCAN_ID}/parsed-results.json"
  [ -f "${CANDIDATE}" ] && PARSED="${CANDIDATE}"
fi

HAVE_PARSED=false
if [ -n "${PARSED}" ] && [ -f "${PARSED}" ] && jq -e . "${PARSED}" >/dev/null 2>&1; then
  HAVE_PARSED=true
fi

if [ "${HAVE_PARSED}" != true ]; then
  log_warn "no dnsenum-scan parsed-results.json available — writing empty contract"
  PARTIAL=true; export PARTIAL
  EMPTY_PARSED="$(mktemp /tmp/dnsenum-parsed-XXXXXX.json)"
  echo '{}' > "${EMPTY_PARSED}"
  PARSED="${EMPTY_PARSED}"
fi

START_MS="$(date +%s%3N 2>/dev/null || echo 0)"

# ---- Consolidate ---------------------------------------------------------
# One jq pass: wildcard guard, contract shape, severity, next_vectors.
CONSOLIDATED="${OUTPUT_DIR}/consolidated.json"

jq -n \
  --arg scan_id "${SCAN_ID}" \
  --arg target "${TARGET}" \
  --arg started_at "${STARTED_AT}" \
  --argjson cap "${MAX_TARGETS_PER_VECTOR}" \
  --slurpfile parsed "${PARSED}" \
  '
  ($parsed[0] // {}) as $p
  | (($p.wildcard.wildcard_ips // []) | map(ascii_downcase)) as $wildcard_ips
  | (($p.wildcard.probe_name // "") | ascii_downcase) as $probe
  | ($p.domain // $target) as $domain
  # Drop probe name and any name still resolving to a wildcard IP.
  | (($p.subdomains // [])
      | map(select(((.ip // "") | ascii_downcase) as $ip
          | (($wildcard_ips | length) == 0)
            or (($wildcard_ips | index($ip)) == null)))
      | map(select(((.name // "") | ascii_downcase) != $probe))
      | map({name: (.name // ""), ip: (.ip // ""), source: (.source // "unknown")})
      # Keep the scan inside the target scope: dnsenum also reports CNAME
      # targets (e.g. vendor page hosts) that are not subdomains of the target.
      | map(select(.name as $n | ($n == $domain) or ($n | endswith("." + $domain))))
      | sort_by(.name)) as $subs
  | (($subs | length) as $n
     | if $n > 0 then
         [
           {condition: "subdomains discovered", skill: "httpx", weight: 90,
            reason: "\($n) subdomains discovered — probe live HTTP on each one",
            targets: ($subs | map(.name) | .[0:$cap])},
           {condition: "subdomains discovered", skill: "nuclei", weight: 80,
            reason: "\($n) subdomains discovered — vulnerability scanning the new attack surface",
            targets: ($subs | map(.name) | .[0:$cap])},
           {condition: "subdomains discovered", skill: "whatweb", weight: 70,
            reason: "\($n) subdomains discovered — fingerprint the technology stack",
            targets: ($subs | map(.name) | .[0:$cap])}
         ]
       else [] end) as $vectors
  | {
      scan_id: $scan_id,
      target: $target,
      started_at: $started_at,
      domain: $domain,
      subdomains: $subs,
      subdomain_count: ($subs | length),
      ns: ($p.ns // []),
      mx: ($p.mx // []),
      zone_transfer: {
        attempted: (if ($p.zone_transfer.attempted // null) == null then true
                    else $p.zone_transfer.attempted end),
        success: ($p.zone_transfer.success // false),
        records: ($p.zone_transfer.records // [])
      },
      severity: (if ($p.zone_transfer.success // false) then "medium"
                 elif ($subs | length) > 0 then "low"
                 else "info" end),
      next_vectors: $vectors,
      # `false // true` would yield true in jq: only an explicit false clears it.
      partial: (if ($p.partial == false) then false else true end)
    }
  ' > "${CONSOLIDATED}" 2>"${OUTPUT_DIR}/sub-processes/consolidate-errors.log" || {
    log_error "jq consolidation failed — writing empty contract"
    PARTIAL=true; export PARTIAL
    jq -n \
      --arg scan_id "${SCAN_ID}" \
      --arg target "${TARGET}" \
      --arg started_at "${STARTED_AT}" \
      --arg domain "$(jq -r '.domain // empty' "${PARSED}" 2>/dev/null || echo "${TARGET}")" \
      '{scan_id: $scan_id, target: $target, started_at: $started_at, domain: $domain,
        subdomains: [], subdomain_count: 0, ns: [], mx: [],
        zone_transfer: {attempted: true, success: false, records: []},
        severity: "info", next_vectors: [], partial: true}' > "${CONSOLIDATED}"
  }

END_MS="$(date +%s%3N 2>/dev/null || echo 0)"
DURATION_MS=$(( END_MS - START_MS ))

SUBDOMAIN_COUNT="$(jq -r '.subdomain_count // 0' "${CONSOLIDATED}" 2>/dev/null || echo 0)"
SEVERITY="$(jq -r '.severity // "info"' "${CONSOLIDATED}" 2>/dev/null || echo info)"
ZT_SUCCESS="$(jq -r '.zone_transfer.success // false' "${CONSOLIDATED}" 2>/dev/null || echo false)"
VECTOR_COUNT="$(jq -r '.next_vectors | length' "${CONSOLIDATED}" 2>/dev/null || echo 0)"
NEXT_VECTORS_JSON="$(jq -c '.next_vectors // []' "${CONSOLIDATED}" 2>/dev/null || echo '[]')"

log_info "DNS analyzer: ${SUBDOMAIN_COUNT} subdomain(s), severity=${SEVERITY}, zone_transfer=${ZT_SUCCESS}, vectors=${VECTOR_COUNT}"

# ---- Envelope ------------------------------------------------------------
write_to_shared_dir "${SKILL}" "${CONSOLIDATED}"
write_next_vectors "${SCAN_ID}" "${TARGET}" "${SEVERITY}" "${NEXT_VECTORS_JSON}"
write_sub_process_result "analyze" 0 "/dev/null" \
  "${OUTPUT_DIR}/sub-processes/consolidate-errors.log" "${DURATION_MS:-0}" "${CONSOLIDATED}"

if [ "${PARTIAL}" = "true" ] \
  || [ "$(jq -r '.partial // false' "${CONSOLIDATED}" 2>/dev/null || echo false)" = "true" ]; then
  write_status "dnsenum-analyze" "degraded" 100 "${SCAN_ID}" "${TARGET}"
  log_warn "dnsenum-analyzer finished (degraded) | scan_id=${SCAN_ID}"
  exit 0
fi

write_status "dnsenum-analyze" "done" 100 "${SCAN_ID}" "${TARGET}"
log_info "dnsenum-analyzer finished | scan_id=${SCAN_ID} subdomains=${SUBDOMAIN_COUNT} vectors=${VECTOR_COUNT}"
