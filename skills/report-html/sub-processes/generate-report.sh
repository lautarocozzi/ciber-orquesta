#!/usr/bin/env bash
# ============================================================================
# skills/report-html/sub-processes/generate-report.sh
#
# Reads the analyzer consolidated.json sources (nmap-analyzer, nuclei-analyzer,
# whatweb, testssl, httpx, nikto, dnsenum-analyzer), merges them with jq,
# computes overall severity, truncates nuclei findings to top-50, and injects
# the merged data into the report.html template.
#
# The parent report is ROOT-TARGET SCOPED: every per-stage section resolves its
# own root-anchored state file via resolve_root_source, never the shared dir,
# so per-subdomain expanded runs (which share WORKFLOW_SHARED_DIR and are
# last-writer-wins) can never taint the parent.
#
# When the DNS source lists subdomains, one child report per subdomain is
# rendered next to the parent (subdomains/<subdomain>/report.html) and a
# SUBDOMAINS section with one card per subdomain is added to the parent.
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

# How many subdomains get a card + a child report. Must stay in sync with
# expansion.max_targets_per_vector — the engine only expands the first N
# subdomains, so cards beyond the cap would have nothing behind them.
SUBDOMAIN_REPORT_CAP="${SUBDOMAIN_REPORT_CAP:-10}"

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

# Slugify a target the SAME way engine/workflow.py builds per-target scan ids,
# so a state path can be reconstructed from a target string.
# Usage: slugify <target>
slugify() {
  local t="$1"
  t="${t//\.\./-}"   # escaped dots: an unescaped ".." is a glob, not a literal
  t="${t//./-}"
  t="${t//:/-}"
  t="${t//\//-}"
  printf '%s' "${t}"
}

# Resolve a ROOT-TARGET source file — the parent report guard.
#
# resolve_source prefers WORKFLOW_SHARED_DIR, which every expanded
# per-subdomain run also writes to (last-writer-wins on
# <skill>/consolidated.json). A parent section that used it could render one
# subdomain's data under the root target's heading. This resolver therefore
# stays inside state/<skill>/ and only accepts non-expanded scan ids.
#
# There is NO fallback to the shared dir on purpose. Every analyzer writes its
# own state dir alongside the shared copy, so a missing root state file means
# the root run produced nothing — in that case the section must read "Not run"
# rather than borrow a file whose origin cannot be verified. (The fallback
# exists in the design as a convenience for standalone runs, but the
# standalone case is already covered by step 2: a standalone SCAN_ID is just
# another {prefix}--* dir with no --exp- in its name.)
#
# Usage: resolve_root_source <skill_name> <root_step_id>
#   1. Exact root-anchored scan: state/<skill>/{base}--<step_id>--<root_slug>/
#   2. Any non-expanded sibling of the same base scan id
resolve_root_source() {
  local skill_name="$1" step_id="$2"
  local base="${SCAN_ID%%--*}"
  local root_slug
  root_slug="$(slugify "${TARGET}")"

  local exact="${STATE_DIR}/${skill_name}/${base}--${step_id}--${root_slug}/consolidated.json"
  if [ -f "${exact}" ]; then
    echo "${exact}"
    return 0
  fi

  local match
  match="$(ls -d "${STATE_DIR}/${skill_name}/${base}--"*/consolidated.json 2>/dev/null \
    | grep -v -- '--exp-' | head -1 || true)"
  if [ -n "${match}" ] && [ -f "${match}" ]; then
    echo "${match}"
    return 0
  fi

  return 1
}

# Resolve the consolidated.json of an EXPANDED per-subdomain run of <skill>.
# The engine expands one step per skill carrying every subdomain, and each
# target gets its own scan id: {base}--exp-{skill}-{anchor}-{hash}--{sub_slug}.
# Usage: resolve_expanded_source <skill_name> <subdomain_slug>
resolve_expanded_source() {
  local skill_name="$1" sub_slug="$2"
  local base="${SCAN_ID%%--*}"
  local match
  # The quotes must close around the "*" or bash treats it as a literal and
  # ls receives a path that does not exist.
  match="$(ls -d "${STATE_DIR}/${skill_name}-analyzer/${base}--exp-${skill_name}-"*--"${sub_slug}"/consolidated.json 2>/dev/null \
    | head -1 || true)"
  if [ -n "${match}" ] && [ -f "${match}" ]; then
    echo "${match}"
    return 0
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

# Extract a single source object from a build_source_json envelope.
# Usage: source_obj <source_name> <file_path>
source_obj() {
  build_source_json "$1" "$2" \
    | jq -c --arg n "$1" '.[$n] // {present: false}' 2>/dev/null \
    || echo '{"present":false}'
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

# Every parent source is ROOT-SCOPED: the second argument is the workflow step
# id whose scan dir holds the root run (they differ per skill — nmap's analyzer
# step is just "analyzer", httpx's chain starts at "httpx-scan").
NMAP_FILE="$(resolve_root_source "nmap-analyzer" "analyzer" || true)"
NUCLEI_FILE="$(resolve_root_source "nuclei-analyzer" "nuclei-analyzer" || true)"
WHATWEB_FILE="$(resolve_root_source "whatweb-analyzer" "whatweb-analyzer" || true)"
TESTSSL_FILE="$(resolve_root_source "testssl-analyzer" "testssl-analyzer" || true)"
HTTPX_FILE="$(resolve_root_source "httpx-analyzer" "httpx-scan" || true)"
NIKTO_FILE="$(resolve_root_source "nikto-analyzer" "nikto-analyzer" || true)"

echo "[generate-report] Sources:" >&2
echo "  nmap:    ${NMAP_FILE:-NOT_FOUND}" >&2
echo "  nuclei:  ${NUCLEI_FILE:-NOT_FOUND}" >&2
echo "  whatweb: ${WHATWEB_FILE:-NOT_FOUND}" >&2
echo "  testssl: ${TESTSSL_FILE:-NOT_FOUND}" >&2
echo "  httpx:   ${HTTPX_FILE:-NOT_FOUND}" >&2
echo "  nikto:   ${NIKTO_FILE:-NOT_FOUND}" >&2
# The dnsenum analyzer writes state under its SKILL name (dnsenum-analyzer)
# even though the workflow step is called dns-analyzer; the state dir is keyed
# by skill, so the resolver must be given the skill name.
DNS_FILE="$(resolve_root_source "dnsenum-analyzer" "dns-analyzer" || true)"
echo "  dns:     ${DNS_FILE:-NOT_FOUND}" >&2

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
DNS_SRC="$(build_source_json "dns" "${DNS_FILE}")"

# ---- Compute overall severity (highest across all present sources) ----------
OVERALL_SEVERITY="none"

for src_key in nmap nuclei whatweb testssl httpx nikto dns; do
  # Select the correct source variable
  case "${src_key}" in
    nmap)    SRC_OBJ="${NMAP_SRC}"    ;;
    nuclei)  SRC_OBJ="${NUCLEI_SRC}"  ;;
    whatweb) SRC_OBJ="${WHATWEB_SRC}" ;;
    testssl) SRC_OBJ="${TESTSSL_SRC}" ;;
    httpx)   SRC_OBJ="${HTTPX_SRC}"   ;;
    nikto)   SRC_OBJ="${NIKTO_SRC}"   ;;
    dns)     SRC_OBJ="${DNS_SRC}"     ;;
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
DNS_OBJ="$(echo "${DNS_SRC}"     | jq -c '.dns     // {"present":false}' 2>/dev/null || echo '{"present":false}')"

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
  --argjson dns "${DNS_OBJ}" \
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
      nikto: $nikto,
      dns: $dns
    }
  }'
)"

# ---- Render one report from the template ------------------------------------
# Injects a REPORT_DATA object into the template and writes it to out_file.
# Shared by the parent report and every per-subdomain child report so all of
# them come from the same template and the same three fallback tiers.
# Usage: render_report <report_data_file> <out_file> <target> <scan_id>
render_report() {
  local data_file="$1" out_file="$2" target="$3" scan_id="$4"
  local data_single
  data_single="$(cat "${data_file}")"

  local injected=false

  # Method 1 (preferred): python3 with temp file — clean, no shell quoting issues
  if command -v python3 &>/dev/null; then
    python3 - "${TEMPLATE_FILE}" "${data_file}" "${target}" "${scan_id}" "${out_file}" << 'PYEOF'
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
    injected=true
    echo "[generate-report] Template injection: python3" >&2
  fi

  # Method 2 (fallback): jq -c to produce single-line JSON + sed with safe delimiter
  if ! ${injected} && command -v jq &>/dev/null; then
    data_single="$(echo "${data_single}" | jq -c . 2>/dev/null || echo "${data_single}")"
    # Escape / & " and newlines for sed
    local data_safe
    data_safe="$(echo "${data_single}" | sed 's/[\/&]/\\&/g; s/"/\\"/g')"
    sed "s/{{REPORT_DATA}}/${data_safe}/g; s/{{TARGET}}/${target}/g; s/{{SCAN_ID}}/${scan_id}/g" \
      "${TEMPLATE_FILE}" > "${out_file}" && injected=true
    echo "[generate-report] Template injection: jq+sed" >&2
  fi

  # Method 3 (last resort): basic sed with flattened JSON
  if ! ${injected}; then
    local data_flat
    data_flat="$(echo "${data_single}" | tr -d '\n' | sed 's/[\/&]/\\&/g; s/"/\\"/g')"
    sed "s/{{REPORT_DATA}}/${data_flat}/g; s/{{TARGET}}/${target}/g; s/{{SCAN_ID}}/${scan_id}/g" \
      "${TEMPLATE_FILE}" > "${out_file}" && injected=true
    echo "[generate-report] Template injection: sed (fallback)" >&2
  fi

  if ! ${injected}; then
    echo "[generate-report] ERROR: Failed to inject data into template (no suitable method)" >&2
    return 1
  fi

  if [ ! -f "${out_file}" ]; then
    echo "[generate-report] ERROR: Output file was not created at ${out_file}" >&2
    return 1
  fi
  return 0
}

# ---- Output paths -----------------------------------------------------------
TEMPLATE_FILE="${SKILL_DIR}/templates/report.html"
OUTPUT_DIR="${REPORTS_DIR}/${REPORT_TARGET}/report-html/${REPORT_TS}"
mkdir -p "${OUTPUT_DIR}"
OUTPUT_FILE="${OUTPUT_DIR}/report.html"

if [ ! -f "${TEMPLATE_FILE}" ]; then
  echo "[generate-report] ERROR: Template not found at ${TEMPLATE_FILE}" >&2
  exit 2
fi

# ---- Per-subdomain child reports + parent cards -----------------------------
# The dns source is the index of discovered subdomains. For each of them (up to
# the expansion cap) a child report aggregates ONLY that subdomain's expanded
# analyzer state, and a card is collected for the parent's SUBDOMAINS section.
SUBDOMAINS_JSON='[]'
DNS_PRESENT="$(echo "${DNS_OBJ}" | jq -r '.present // false' 2>/dev/null || echo false)"
DNS_SUBDOMAIN_TOTAL=0
SUBDOMAIN_ADDITIONAL=0
CHILD_REPORT_COUNT=0

if [ "${DNS_PRESENT}" = "true" ]; then
  DNS_SUBDOMAIN_TOTAL="$(echo "${DNS_OBJ}" | jq -r '.subdomain_count // ((.subdomains // []) | length)' 2>/dev/null || echo 0)"

  while IFS=$'\t' read -r sub_name sub_ip sub_source; do
    [ -z "${sub_name}" ] && continue

    # A subdomain name becomes a directory name. DNS labels cannot contain
    # slashes or dots-only sequences, but a hand-edited state file can, so
    # reject anything that could escape the report folder.
    if ! [[ "${sub_name}" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]]; then
      echo "[generate-report] WARN: skipping subdomain with unsafe name: ${sub_name}" >&2
      continue
    fi

    sub_slug="$(slugify "${sub_name}")"
    c_httpx_obj="$(source_obj "httpx" "$(resolve_expanded_source "httpx" "${sub_slug}" || true)")"
    c_nuclei_obj="$(source_obj "nuclei" "$(resolve_expanded_source "nuclei" "${sub_slug}" || true)")"
    c_whatweb_obj="$(source_obj "whatweb" "$(resolve_expanded_source "whatweb" "${sub_slug}" || true)")"
    c_nikto_obj="$(source_obj "nikto" "$(resolve_expanded_source "nikto" "${sub_slug}" || true)")"

    # Child severity: worst of the child's own sources only.
    c_overall="none"
    for c_key in nuclei whatweb httpx nikto; do
      case "${c_key}" in
        nuclei)  c_obj="${c_nuclei_obj}"  ;;
        whatweb) c_obj="${c_whatweb_obj}" ;;
        httpx)   c_obj="${c_httpx_obj}"   ;;
        nikto)   c_obj="${c_nikto_obj}"   ;;
      esac
      c_present="$(echo "${c_obj}" | jq -r '.present // false' 2>/dev/null || echo false)"
      [ "${c_present}" != "true" ] && continue
      c_sev="$(echo "${c_obj}" | jq -c . 2>/dev/null | source_severity || echo none)"
      if [ "$(sev_rank "${c_sev}")" -gt "$(sev_rank "${c_overall}")" ]; then
        c_overall="${c_sev}"
      fi
    done

    # A child report is a full report scoped to one host: sources it never ran
    # (nmap, testssl, dns) stay absent and render as "Not run".
    child_file="$(mktemp /tmp/report-html-child-XXXXXX.json)"
    jq -n \
      --arg scan_id "${SCAN_ID}" \
      --arg target "${sub_name}" \
      --arg generated_at "${GENERATED_AT}" \
      --arg overall_severity "${c_overall}" \
      --arg name "${sub_name}" \
      --arg ip "${sub_ip}" \
      --arg source "${sub_source}" \
      --argjson nuclei "${c_nuclei_obj}" \
      --argjson whatweb "${c_whatweb_obj}" \
      --argjson httpx "${c_httpx_obj}" \
      --argjson nikto "${c_nikto_obj}" \
      '{
        scan_id: $scan_id,
        target: $target,
        generated_at: $generated_at,
        overall_severity: $overall_severity,
        parent_report: "../../report.html",
        subdomain: {name: $name, ip: $ip, source: $source},
        sources: {
          nmap: {present: false},
          nuclei: $nuclei,
          whatweb: $whatweb,
          testssl: {present: false},
          httpx: $httpx,
          nikto: $nikto,
          dns: {present: false}
        }
      }' > "${child_file}"

    sub_dir="${OUTPUT_DIR}/subdomains/${sub_name}"
    mkdir -p "${sub_dir}"
    if render_report "${child_file}" "${sub_dir}/report.html" "${sub_name}" "${SCAN_ID}"; then
      CHILD_REPORT_COUNT=$(( CHILD_REPORT_COUNT + 1 ))
    else
      echo "[generate-report] WARN: child report failed for ${sub_name}" >&2
    fi
    rm -f "${child_file}"

    # Card fields for the parent: identity from DNS, findings from the child.
    card="$(jq -n \
      --arg name "${sub_name}" \
      --arg ip "${sub_ip}" \
      --arg source "${sub_source}" \
      --arg report "subdomains/${sub_name}/report.html" \
      --argjson nuclei "${c_nuclei_obj}" \
      --argjson whatweb "${c_whatweb_obj}" \
      --argjson httpx "${c_httpx_obj}" \
      --argjson nikto "${c_nikto_obj}" \
      '{
        name: $name,
        ip: $ip,
        source: $source,
        report: $report,
        http_status: (if $httpx.present
                       then ((($httpx.endpoints // [])[0].status_code // 0) as $s | if $s > 0 then $s else null end)
                       else null end),
        live_web_server: (if $httpx.present then ($httpx.live_web_server // null) else null end),
        # httpx reports bare names ("Nginx"), whatweb reports name + version
        # ("Nginx 1.24.0"). Group by name so a card shows one chip per
        # technology, keeping whichever version we have.
        tech: (([($httpx.tech_stack // [])[] | {name: ., version: ""}]
                + [(($whatweb.technologies // [])[]
                    | if type == "object"
                      then {name: (.name // ""), version: (.version // "")}
                      else {name: ., version: ""} end)])
               | map(select(.name != null and .name != ""))
               | group_by(.name | ascii_downcase)
               | map(([.[] | select(.version != "") | .version][0] // "") as $v
                     | if $v == "" then .[0].name else (.[0].name + " " + $v) end)
               | unique),
        vuln_total: (if $nuclei.present
                       then (($nuclei.total_matched // (($nuclei.findings // []) | length)) // 0)
                       else 0 end),
        vuln_severity_counts: (if $nuclei.present then ($nuclei.severity_counts // {}) else {} end),
        top_vulns: (if $nuclei.present
                      then ([($nuclei.findings // [])[]
                             | {severity: (.severity // "info"),
                                name: (.name // .template_id // "unknown"),
                                template_id: (.template_id // "")}][0:3])
                      else [] end),
        nikto_findings: (if $nikto.present then ((($nikto.findings // []) | length) // 0) else 0 end),
        has_data: ($httpx.present or $whatweb.present or $nuclei.present or $nikto.present)
      }')"
    SUBDOMAINS_JSON="$(echo "${SUBDOMAINS_JSON}" | jq -c --argjson card "${card}" '. + [$card]')"
  done < <(echo "${DNS_OBJ}" \
    | jq -r --argjson cap "${SUBDOMAIN_REPORT_CAP}" \
        '((.subdomains // []) | .[0:$cap][] | [(.name // ""), (.ip // ""), (.source // "")] | @tsv)' \
    2>/dev/null || true)

  SUBDOMAIN_ADDITIONAL=$(( DNS_SUBDOMAIN_TOTAL - CHILD_REPORT_COUNT ))
  [ "${SUBDOMAIN_ADDITIONAL}" -lt 0 ] && SUBDOMAIN_ADDITIONAL=0
  echo "[generate-report] Subdomains: ${CHILD_REPORT_COUNT} child report(s) for ${DNS_SUBDOMAIN_TOTAL} discovered, cap ${SUBDOMAIN_REPORT_CAP}, ${SUBDOMAIN_ADDITIONAL} not reported" >&2
fi

# The SUBDOMAINS section renders only when the dns source ran: an empty
# subdomain list is a real "none found" state, while a missing dns source
# means the section has nothing to say at all.
if [ "${DNS_PRESENT}" = "true" ]; then
  REPORT_DATA="$(echo "${REPORT_DATA}" | jq -c \
    --argjson subdomains "${SUBDOMAINS_JSON}" \
    --argjson total "${DNS_SUBDOMAIN_TOTAL}" \
    --argjson additional "${SUBDOMAIN_ADDITIONAL}" \
    '. + {
      subdomains: $subdomains,
      subdomain_total: $total,
      subdomains_additional: $additional
    }')"
fi

echo "[generate-report] Injecting merged data into template" >&2

PARENT_DATA_FILE="$(mktemp /tmp/report-html-data-XXXXXX.json)"
echo "${REPORT_DATA}" > "${PARENT_DATA_FILE}"
render_report "${PARENT_DATA_FILE}" "${OUTPUT_FILE}" "${TARGET}" "${SCAN_ID}" || exit 1
rm -f "${PARENT_DATA_FILE}"

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
