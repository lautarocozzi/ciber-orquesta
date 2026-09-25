#!/usr/bin/env bash
# ============================================================================
# skills/report-html/sub-processes/generate-report.sh
#
# Reads 4 consolidated.json sources (nmap-analyzer, nuclei-analyzer, whatweb,
# testssl), merges them with jq, computes overall severity, truncates nuclei
# findings to top-50, and injects the merged data into the report.html
# template.
#
# This is a sub-process called by main.sh — does NOT source envelope.sh.
# Communicates results via stdout (outputs the report file path on success).
# Logging goes to stderr, errors exit non-zero.
#
# Expected env vars:
#   SCAN_ID             (required) — scan identifier
#   TARGET              (required) — target host/URL
#   STATE_DIR           (optional, default: state)
#   REPORTS_DIR         (optional, default: reports)
#   WORKFLOW_SHARED_DIR (optional) — shared data directory
# ============================================================================

set -euo pipefail

# ---- Configuration ----------------------------------------------------------
SCAN_ID="${SCAN_ID:-}"
TARGET="${TARGET:-}"
STATE_DIR="${STATE_DIR:-state}"
REPORTS_DIR="${REPORTS_DIR:-reports}"
WORKFLOW_SHARED_DIR="${WORKFLOW_SHARED_DIR:-}"

REPORT_TS="${REPORT_TS:-$(date -u +"%Y-%m-%d/%H-%M-%S")}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---- Validation -------------------------------------------------------------
if [ -z "${SCAN_ID}" ] || [ -z "${TARGET}" ]; then
  echo "[generate-report] ERROR: SCAN_ID and TARGET are required" >&2
  exit 2
fi

# Sanitize TARGET for filesystem paths (strip protocol prefix)
REPORT_TARGET="${TARGET#https://}"
REPORT_TARGET="${REPORT_TARGET#http://}"

# ---- Helper functions -------------------------------------------------------

# Resolve a source file: WORKFLOW_SHARED_DIR first, then STATE_DIR.
# Usage: resolve_source <skill_name> [scan_id]
# Looks for <skill_name>/consolidated.json in shared or state dirs.
# Resolution order:
#   1. Shared dir (if WORKFLOW_SHARED_DIR is set)
#   2. Exact scan_id match in state dir
#   3. Prefix glob: state/<skill>/<scan_id>--*/consolidated.json
#   4. When scan_id is "auto": prefix glob from SCAN_ID base (<SCAN_ID%%--*>--*)
resolve_source() {
  local skill_name="$1"
  local scan_id="${2:-${SCAN_ID}}"

  # 1. Shared dir (engine's WORKFLOW_SHARED_DIR)
  if [ -n "${WORKFLOW_SHARED_DIR:-}" ]; then
    local shared="${WORKFLOW_SHARED_DIR}/${skill_name}/consolidated.json"
    if [ -f "${shared}" ]; then
      echo "${shared}"
      return 0
    fi
  fi

  # 2. Exact scan_id match
  local exact="${STATE_DIR}/${skill_name}/${scan_id}/consolidated.json"
  if [ -f "${exact}" ]; then
    echo "${exact}"
    return 0
  fi

  # 3. Prefix glob: state/<skill>/<scan_id>--*/consolidated.json
  # Handles engine-style scan IDs like "uuid--skill--target"
  local match
  match="$(ls -d "${STATE_DIR}/${skill_name}/${scan_id}--"*/consolidated.json 2>/dev/null | head -1)"
  if [ -n "${match}" ] && [ -f "${match}" ]; then
    echo "${match}"
    return 0
  fi

  # 4. Auto-detect: scan by base prefix from SCAN_ID (handles different step SCAN_IDs)
  if [ "${scan_id}" = "auto" ]; then
    local base="${SCAN_ID%%--*}"
    match="$(ls -d "${STATE_DIR}/${skill_name}/${base}--"*/consolidated.json 2>/dev/null | head -1)"
    if [ -n "${match}" ] && [ -f "${match}" ]; then
      echo "${match}"
      return 0
    fi
  fi

  return 1
}

# Build a JSON source entry: {<name>: {present: true/false, ...fields_from_file}}
# Reads the file through jq directly, which validates JSON and merges in present.
# Usage: build_source_json <source_name> <file_path>
build_source_json() {
  local name="$1" path="$2"
  if [ -n "${path}" ] && [ -f "${path}" ]; then
    # Pipe file through jq: validate JSON, merge with present:true
    jq -c --arg name "${name}" \
      '{($name): (. + {present: true})}' \
      "${path}" 2>/dev/null \
    || jq -n --arg name "${name}" \
      '{($name): {present: false}}'
  else
    jq -n --arg name "${name}" \
      '{($name): {present: false}}'
  fi
}

# Numeric severity rank (higher = more severe)
# Usage: sev_rank <severity_string>
sev_rank() {
  case "$1" in
    critical) echo 6 ;;
    high)     echo 5 ;;
    medium)   echo 4 ;;
    low)      echo 3 ;;
    info)     echo 2 ;;
    *)        echo 1 ;;  # none or unknown
  esac
}

# Compute a source's worst severity based on its content.
# For nuclei, this uses severity_counts. For others, returns "none".
# Reads JSON from stdin (pipe-friendly).
# Usage: echo '{"severity_counts":{"critical":1}}' | source_severity
source_severity() {
  local src_json
  src_json="$(cat - 2>/dev/null || echo '{}')"
  echo "${src_json}" | jq -r '
    if .severity and (.severity | type == "string") then .severity
    elif .severity_counts then
      if (.severity_counts.critical // 0) > 0 then "critical"
      elif (.severity_counts.high // 0) > 0 then "high"
      elif (.severity_counts.medium // 0) > 0 then "medium"
      elif (.severity_counts.low // 0) > 0 then "low"
      else "info" end
    else "none" end
  ' 2>/dev/null || echo "none"
}

# ---- Resolve source files ---------------------------------------------------
echo "[generate-report] Resolving sources for scan=${SCAN_ID} target=${TARGET}" >&2

NMAP_FILE="$(resolve_source "nmap-analyzer" || true)"
NUCLEI_FILE="$(resolve_source "nuclei-analyzer" || true)"
WHATWEB_FILE="$(resolve_source "whatweb-analyzer" "auto" || true)"
TESTSSL_FILE="$(resolve_source "testssl-analyzer" "auto" || true)"
HTTPX_FILE="$(resolve_source "httpx-analyzer" || true)"
NIKTO_FILE="$(resolve_source "nikto-analyzer" || true)"

echo "[generate-report] Sources:" >&2
echo "  nmap:    ${NMAP_FILE:-NOT_FOUND}" >&2
echo "  nuclei:  ${NUCLEI_FILE:-NOT_FOUND}" >&2
echo "  whatweb: ${WHATWEB_FILE:-NOT_FOUND}" >&2
echo "  testssl: ${TESTSSL_FILE:-NOT_FOUND}" >&2
echo "  httpx:   ${HTTPX_FILE:-NOT_FOUND}" >&2
echo "  nikto:   ${NIKTO_FILE:-NOT_FOUND}" >&2

# ---- Process nuclei separately (truncation support) -------------------------
# Nuclei findings can be very large. We truncate to top-50 sorted by severity
# and add a truncated_count field for the JS banner.
NUCLEI_SRC='{"nuclei":{"present":false}}'
if [ -n "${NUCLEI_FILE}" ] && [ -f "${NUCLEI_FILE}" ]; then
  FINDING_COUNT="$(jq '(.findings | length) // 0' "${NUCLEI_FILE}" 2>/dev/null || echo 0)"

  if [ "${FINDING_COUNT}" -gt 50 ]; then
    TRUNCATED_COUNT=$(( FINDING_COUNT - 50 ))
    echo "[generate-report] Truncating nuclei: ${FINDING_COUNT} findings → top 50 (+${TRUNCATED_COUNT} additional)" >&2

    # Sort by severity (critical first), take top 50, add truncated_count
    NUCLEI_SRC="$(jq -c \
      --argjson truncated_count "${TRUNCATED_COUNT}" \
      '
        .findings |= (
          sort_by(
            if .severity == "critical" then 0
            elif .severity == "high" then 1
            elif .severity == "medium" then 2
            elif .severity == "low" then 3
            elif .severity == "info" then 4
            else 5 end
          )[:50]
        )
        | . + {truncated_count: $truncated_count}
        | . + {present: true}
      ' \
      "${NUCLEI_FILE}" 2>/dev/null \
    )"
    # Wrap in nuclei key
    NUCLEI_SRC="$(echo "${NUCLEI_SRC}" | jq -c '{nuclei: .}' 2>/dev/null || echo '{"nuclei":{"present":false}}')"
  else
    # No truncation needed — read as-is
    NUCLEI_SRC="$(build_source_json "nuclei" "${NUCLEI_FILE}")"
  fi
fi

# ---- Process nikto separately (truncation support) ----------------------------
# Nikto findings can also be very large. Truncate to top-50 sorted by severity.
NIKTO_SRC='{"nikto":{"present":false}}'
if [ -n "${NIKTO_FILE}" ] && [ -f "${NIKTO_FILE}" ]; then
  FINDING_COUNT="$(jq '(.findings | length) // 0' "${NIKTO_FILE}" 2>/dev/null || echo 0)"

  if [ "${FINDING_COUNT}" -gt 50 ]; then
    TRUNCATED_COUNT=$(( FINDING_COUNT - 50 ))
    echo "[generate-report] Truncating nikto: ${FINDING_COUNT} findings → top 50 (+${TRUNCATED_COUNT} additional)" >&2

    NIKTO_SRC="$(jq -c \
      --argjson truncated_count "${TRUNCATED_COUNT}" \
      '
        .findings |= (
          sort_by(
            if .severity == "critical" then 0
            elif .severity == "high" then 1
            elif .severity == "medium" then 2
            elif .severity == "low" then 3
            elif .severity == "info" then 4
            else 5 end
          )[:50]
        )
        | . + {truncated_count: $truncated_count}
        | . + {present: true}
      ' \
      "${NIKTO_FILE}" 2>/dev/null \
    )"
    NIKTO_SRC="$(echo "${NIKTO_SRC}" | jq -c '{nikto: .}' 2>/dev/null || echo '{"nikto":{"present":false}}')"
  else
    NIKTO_SRC="$(build_source_json "nikto" "${NIKTO_FILE}")"
  fi
fi

# ---- Build source JSONs for remaining sources -------------------------------
NMAP_SRC="$(build_source_json "nmap" "${NMAP_FILE}")"
WHATWEB_SRC="$(build_source_json "whatweb" "${WHATWEB_FILE}")"
TESTSSL_SRC="$(build_source_json "testssl" "${TESTSSL_FILE}")"
HTTPX_SRC="$(build_source_json "httpx" "${HTTPX_FILE}")"

# ---- Compute overall severity (highest across all present sources) ----------
OVERALL_SEVERITY="none"

for src_key in nmap nuclei whatweb testssl httpx nikto; do
  # Select the correct source variable
  case "${src_key}" in
    nmap)    SRC_OBJ="${NMAP_SRC}"    ;;
    nuclei)  SRC_OBJ="${NUCLEI_SRC}"  ;;
    whatweb) SRC_OBJ="${WHATWEB_SRC}" ;;
    testssl) SRC_OBJ="${TESTSSL_SRC}" ;;
    httpx)   SRC_OBJ="${HTTPX_SRC}"   ;;
    nikto)   SRC_OBJ="${NIKTO_SRC}"   ;;
  esac

  PRESENT="$(echo "${SRC_OBJ}" | jq -r ".[\"${src_key}\"].present // false" 2>/dev/null || echo "false")"
  [ "${PRESENT}" != "true" ] && continue

  SEV="$(echo "${SRC_OBJ}" | jq -c ".[\"${src_key}\"]" 2>/dev/null | source_severity || echo "none")"
  if [ "$(sev_rank "${SEV}")" -gt "$(sev_rank "${OVERALL_SEVERITY}")" ]; then
    OVERALL_SEVERITY="${SEV}"
  fi
done

echo "[generate-report] Overall severity: ${OVERALL_SEVERITY}" >&2

# ---- Merge all sources into a single REPORT_DATA object ---------------------
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# Extract each source object (with {"present":false} fallback)
NMAP_OBJ="$(echo "${NMAP_SRC}"    | jq -c '.nmap    // {"present":false}' 2>/dev/null || echo '{"present":false}')"
NUCLEI_OBJ="$(echo "${NUCLEI_SRC}"  | jq -c '.nuclei  // {"present":false}' 2>/dev/null || echo '{"present":false}')"
WHATWEB_OBJ="$(echo "${WHATWEB_SRC}" | jq -c '.whatweb // {"present":false}' 2>/dev/null || echo '{"present":false}')"
TESTSSL_OBJ="$(echo "${TESTSSL_SRC}" | jq -c '.testssl // {"present":false}' 2>/dev/null || echo '{"present":false}')"
HTTPX_OBJ="$(echo "${HTTPX_SRC}"   | jq -c '.httpx   // {"present":false}' 2>/dev/null || echo '{"present":false}')"
NIKTO_OBJ="$(echo "${NIKTO_SRC}"   | jq -c '.nikto   // {"present":false}' 2>/dev/null || echo '{"present":false}')"

REPORT_DATA="$(jq -n \
  --arg scan_id "${SCAN_ID}" \
  --arg target "${TARGET}" \
  --arg generated_at "${GENERATED_AT}" \
  --arg overall_severity "${OVERALL_SEVERITY}" \
  --argjson nmap "${NMAP_OBJ}" \
  --argjson nuclei "${NUCLEI_OBJ}" \
  --argjson whatweb "${WHATWEB_OBJ}" \
  --argjson testssl "${TESTSSL_OBJ}" \
  --argjson httpx "${HTTPX_OBJ}" \
  --argjson nikto "${NIKTO_OBJ}" \
  '{
    scan_id: $scan_id,
    target: $target,
    generated_at: $generated_at,
    overall_severity: $overall_severity,
    sources: {
      nmap: $nmap,
      nuclei: $nuclei,
      whatweb: $whatweb,
      testssl: $testssl,
      httpx: $httpx,
      nikto: $nikto
    }
  }'
)"

# ---- Inject into template ---------------------------------------------------
TEMPLATE_FILE="${SKILL_DIR}/templates/report.html"
OUTPUT_DIR="${REPORTS_DIR}/${REPORT_TARGET}/report-html/${REPORT_TS}"
mkdir -p "${OUTPUT_DIR}"
OUTPUT_FILE="${OUTPUT_DIR}/report.html"

if [ ! -f "${TEMPLATE_FILE}" ]; then
  echo "[generate-report] ERROR: Template not found at ${TEMPLATE_FILE}" >&2
  exit 2
fi

echo "[generate-report] Injecting merged data into template" >&2

INJECTED=false

# Method 1 (preferred): python3 with temp file — clean, no shell quoting issues
if command -v python3 &>/dev/null; then
  REPORT_DATA_FILE="$(mktemp /tmp/report-html-data-XXXXXX.json)"
  echo "${REPORT_DATA}" > "${REPORT_DATA_FILE}"

  python3 - "${TEMPLATE_FILE}" "${REPORT_DATA_FILE}" "${TARGET}" "${SCAN_ID}" "${OUTPUT_FILE}" << 'PYEOF'
import sys, json

tpl_file = sys.argv[1]
data_file = sys.argv[2]
target = sys.argv[3]
scan_id = sys.argv[4]
out_file = sys.argv[5]

with open(tpl_file) as f:
    template = f.read()
with open(data_file) as f:
    report_data = json.load(f)

html = template.replace('{{REPORT_DATA}}', json.dumps(report_data))
html = html.replace('{{TARGET}}', target)
html = html.replace('{{SCAN_ID}}', scan_id)

with open(out_file, 'w') as f:
    f.write(html)
PYEOF

  rm -f "${REPORT_DATA_FILE}"
  INJECTED=true
  echo "[generate-report] Template injection: python3" >&2
fi

# Method 2 (fallback): jq -c to produce single-line JSON + sed with safe delimiter
if ! ${INJECTED} && command -v jq &>/dev/null; then
  REPORT_DATA_SINGLE="$(echo "${REPORT_DATA}" | jq -c . 2>/dev/null || echo "${REPORT_DATA}")"
  # Escape / & " and newlines for sed
  REPORT_DATA_SAFE="$(echo "${REPORT_DATA_SINGLE}" | sed 's/[\/&]/\\&/g; s/"/\\"/g')"
  sed "s/{{REPORT_DATA}}/${REPORT_DATA_SAFE}/g; s/{{TARGET}}/${TARGET}/g; s/{{SCAN_ID}}/${SCAN_ID}/g" \
    "${TEMPLATE_FILE}" > "${OUTPUT_FILE}" && INJECTED=true
  echo "[generate-report] Template injection: jq+sed" >&2
fi

# Method 3 (last resort): basic sed with flattened JSON
if ! ${INJECTED}; then
  REPORT_DATA_FLAT="$(echo "${REPORT_DATA}" | tr -d '\n' | sed 's/[\/&]/\\&/g; s/"/\\"/g')"
  sed "s/{{REPORT_DATA}}/${REPORT_DATA_FLAT}/g; s/{{TARGET}}/${TARGET}/g; s/{{SCAN_ID}}/${SCAN_ID}/g" \
    "${TEMPLATE_FILE}" > "${OUTPUT_FILE}" && INJECTED=true
  echo "[generate-report] Template injection: sed (fallback)" >&2
fi

if ! ${INJECTED}; then
  echo "[generate-report] ERROR: Failed to inject data into template (no suitable method)" >&2
  exit 1
fi

# Verify output was written
if [ ! -f "${OUTPUT_FILE}" ]; then
  echo "[generate-report] ERROR: Output file was not created at ${OUTPUT_FILE}" >&2
  exit 1
fi

echo "[generate-report] Report written: ${OUTPUT_FILE}" >&2

# ---- Copy to WORKFLOW_SHARED_DIR if set -------------------------------------
if [ -n "${WORKFLOW_SHARED_DIR:-}" ]; then
  SHARED_DIR="${WORKFLOW_SHARED_DIR}/report-html"
  mkdir -p "${SHARED_DIR}"
  cp "${OUTPUT_FILE}" "${SHARED_DIR}/"
  echo "[generate-report] Copied to shared dir: ${SHARED_DIR}/" >&2
fi

# ---- Output the report file path (consumed by main.sh via stdout capture) ----
echo "${OUTPUT_FILE}"
