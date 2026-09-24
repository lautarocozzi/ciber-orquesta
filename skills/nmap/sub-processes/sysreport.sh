#!/usr/bin/env bash
# ============================================================================
# skills/nmap/sub-processes/sysreport.sh
#
# Phase 5: Generate human-readable YAML and structured JSON reports from
# the consolidated scan results.
#
# Reads: consolidated.json from the analyzer phase.
# Writes: reports/{target}/nmap/{scan_id}/sysreport.yaml
#         reports/{target}/nmap/{scan_id}/sysreport.json
# ============================================================================

set -euo pipefail

log_info()  { echo "[sysreport] [INFO]  $*"; }
log_warn()  { echo "[sysreport] [WARN]  $*" >&2; }
log_error() { echo "[sysreport] [ERROR] $*" >&2; }

TARGET="${TARGET:-}"
SCAN_ID="${SCAN_ID:-}"
STATE_DIR="${STATE_DIR:-state}"
REPORTS_DIR="${REPORTS_DIR:-reports}"
SKILL="${SKILL:-nmap}"

if [ -z "$TARGET" ] || [ -z "$SCAN_ID" ]; then
  log_error "TARGET and SCAN_ID must be set"
  exit 1
fi

OUTPUT_DIR="${STATE_DIR}/${SKILL}/${SCAN_ID}"
REPORT_DIR="${REPORTS_DIR}/${REPORT_TARGET:-$TARGET}/${SKILL}/${SCAN_ID}"
mkdir -p "$REPORT_DIR"

CONSOLIDATED="${OUTPUT_DIR}/consolidated.json"

# ---- Validate consolidated.json exists ----------------------------------
if [ ! -f "$CONSOLIDATED" ]; then
  log_error "consolidated.json not found at ${CONSOLIDATED}"
  log_info "Writing placeholder report indicating missing data"

  # Using printf to avoid shell injection via unquoted heredoc
  printf '# sysreport.yaml — Nmap Scan Report\n# WARNING: consolidated.json was not available at report generation time.\n\nscan_id: %s\ntarget: %s\nstatus: incomplete\nerror: "consolidated.json not found — analysis phase may have failed"\ngenerated_at: %s\n' \
    "${SCAN_ID}" "${TARGET}" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" > "${REPORT_DIR}/sysreport.yaml"

  printf '{\n  "scan_id": "%s",\n  "target": "%s",\n  "status": "incomplete",\n  "error": "consolidated.json not found",\n  "generated_at": "%s"\n}\n' \
    "${SCAN_ID}" "${TARGET}" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" > "${REPORT_DIR}/sysreport.json"

  exit 1
fi

# ---- Parse consolidated.json with jq ------------------------------------
log_info "Reading consolidated.json from ${CONSOLIDATED}"

# Validate JSON
if ! jq '.' "$CONSOLIDATED" > /dev/null 2>&1; then
  log_error "consolidated.json is invalid JSON"
  exit 1
fi

# Extract key fields
HOST_STATUS="$(jq -r '.host_status // "unknown"' "$CONSOLIDATED")"
PORT_COUNT="$(jq -r '.port_count // 0' "$CONSOLIDATED")"
OS_INFO="$(jq -r '.os_detection.os // "not detected"' "$CONSOLIDATED")"
OS_ACCURACY="$(jq -r '.os_detection.accuracy // "N/A"' "$CONSOLIDATED")"
RAW_XML="$(jq -r '.raw_xml // ""' "$CONSOLIDATED")"

# ---- Build port table for YAML ------------------------------------------
PORTS_YAML=""
if [ "$PORT_COUNT" -gt 0 ]; then
  PORTS_YAML="$(jq -r '.open_ports[] | [.port, .protocol, .service, .version] | @tsv' "$CONSOLIDATED" 2>/dev/null | \
    while IFS=$'\t' read -r port protocol service version; do
      echo "    - port: ${port}"
      echo "      protocol: ${protocol}"
      echo "      service: \"${service:-unknown}\""
      echo "      version: \"${version:-}\""
    done || true)"
fi

# ---- Build NSE findings for YAML ----------------------------------------
NSE_YAML=""
NSE_COUNT="$(jq '.nse_findings | length' "$CONSOLIDATED" 2>/dev/null || echo 0)"
if [ "$NSE_COUNT" -gt 0 ]; then
  NSE_YAML="$(jq -c '.nse_findings[] | {script, output}' "$CONSOLIDATED" 2>/dev/null | \
    while IFS= read -r entry; do
      [ -z "$entry" ] && continue
      script="$(jq -r '.script // ""' <<< "$entry" 2>/dev/null)" || script=""
      output="$(jq -r '.output // ""' <<< "$entry" 2>/dev/null)" || output=""
      # Escape newlines for safe YAML single-line output
      output="${output//$'\n'/\\n}"
      echo "  - script: \"${script}\""
      echo "    output: \"${output}\""
    done || true)"
fi

# ---- Build next_vectors for YAML ----------------------------------------
NEXT_YAML=""
NV_COUNT="$(jq '.next_vectors | length' "$CONSOLIDATED" 2>/dev/null || echo 0)"
if [ "$NV_COUNT" -gt 0 ]; then
  NEXT_YAML="$(jq -r '.next_vectors[] | [.skill, .weight, .reason] | @tsv' "$CONSOLIDATED" 2>/dev/null | \
    while IFS=$'\t' read -r skill weight reason; do
      echo "  - skill: \"${skill}\""
      echo "    weight: ${weight}"
      echo "    reason: \"${reason}\""
    done || true)"
fi

# ---- Build fingerprints for YAML ----------------------------------------
FP_YAML=""
FP_COUNT="$(jq '.fingerprints | length' "$CONSOLIDATED" 2>/dev/null || echo 0)"
if [ "$FP_COUNT" -gt 0 ]; then
  FP_YAML="$(jq -r '.fingerprints[] | [.port, .fingerprint] | @tsv' "$CONSOLIDATED" 2>/dev/null | \
    while IFS=$'\t' read -r port fp; do
      echo "  - port: ${port}"
      echo "    fingerprint: \"${fp}\""
    done || true)"
fi

# ---- Generate YAML report -----------------------------------------------
YAML_FILE="${REPORT_DIR}/sysreport.yaml"
# Using printf to avoid shell injection via unquoted heredoc
{
  printf '# sysreport.yaml — Nmap Scan Report\n'
  printf '# Generated by skills/nmap/sub-processes/sysreport.sh\n'
  printf '\n'
  printf 'scan_id: %s\n' "${SCAN_ID}"
  printf 'target: %s\n' "${TARGET}"
  printf 'generated_at: %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf 'status: complete\n'
  printf '\n'
  printf '## Summary\n'
  printf '\n'
  printf 'host_status: %s\n' "${HOST_STATUS}"
  printf 'open_port_count: %s\n' "${PORT_COUNT}"
  printf 'os_detection: %s\n' "${OS_INFO}"
  printf 'os_accuracy: %s\n' "${OS_ACCURACY}"
  printf 'raw_xml: %s\n' "${RAW_XML}"
  printf '\n'
  printf '## Open Ports\n'
  printf '\n'
  printf '%s\n' "${PORTS_YAML:-  (none discovered)}"
  printf '\n'
  printf '## NSE Findings\n'
  printf '\n'
  printf '%s\n' "${NSE_YAML:-  (none)}"
  printf '\n'
  printf '## Service Fingerprints\n'
  printf '\n'
  printf '%s\n' "${FP_YAML:-  (none)}"
  printf '\n'
  printf '## Next Vectors\n'
  printf '\n'
  printf '%s\n' "${NEXT_YAML:-  (none — target is down or no services detected)}"
  printf '\n'
  printf '## Raw Data\n'
  printf '\n'
  printf 'raw_xml: %s\n' "${RAW_XML}"
  printf 'consolidated_json: %s\n' "${CONSOLIDATED}"
} > "$YAML_FILE"

log_info "Wrote YAML report to ${YAML_FILE}"

# ---- Generate JSON report -----------------------------------------------
JSON_FILE="${REPORT_DIR}/sysreport.json"
# Copy consolidated and add report metadata
jq --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
   '. + {"report_generated_at": $ts, "report_type": "nmap-sysreport"}' \
   "$CONSOLIDATED" > "$JSON_FILE" 2>/dev/null || {
  log_warn "jq merge failed, writing direct copy"
  cat "$CONSOLIDATED" > "$JSON_FILE"
}

log_info "Wrote JSON report to ${JSON_FILE}"
log_info "Report generation complete — ${PORT_COUNT} ports documented"
exit 0
