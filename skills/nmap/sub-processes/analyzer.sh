#!/usr/bin/env bash
# ============================================================================
# skills/nmap/sub-processes/analyzer.sh
#
# Phase 4: Parse nmap output files and build consolidated results.
#
# Reads nmap XML output from port-discovery, service-detection, and
# iot-scripts sub-processes. Produces:
#   - consolidated.json  — all findings structured
#   - next_vectors.json  — suggested follow-up skills
#
# Uses grep/awk/sed for XML parsing (no xmlstarlet dependency).
# ============================================================================

set -euo pipefail

log_info()  { echo "[analyzer] [INFO]  $*"; }
log_warn()  { echo "[analyzer] [WARN]  $*" >&2; }
log_error() { echo "[analyzer] [ERROR] $*" >&2; }

TARGET="${TARGET:-}"
SCAN_ID="${SCAN_ID:-}"
STATE_DIR="${STATE_DIR:-state}"
SKILL="${SKILL:-nmap}"
PARTIAL="${PARTIAL:-false}"

if [ -z "$TARGET" ] || [ -z "$SCAN_ID" ]; then
  log_error "TARGET and SCAN_ID must be set"
  exit 1
fi

OUTPUT_DIR="${STATE_DIR}/${SKILL}/${SCAN_ID}"

# ---- Parse host status --------------------------------------------------
HOST_STATUS="down"
XML_FILES=(
  "${OUTPUT_DIR}/port-discovery.xml"
  "${OUTPUT_DIR}/service-detection.xml"
)

for xml in "${XML_FILES[@]}"; do
  if [ -f "$xml" ]; then
    STATUS="$(grep -oP '<status state="\K[^"]+' "$xml" 2>/dev/null | head -1)" || true
    if [ -n "$STATUS" ]; then
      HOST_STATUS="$STATUS"
      break
    fi
  fi
done

log_info "Host status: ${HOST_STATUS}"

# ---- Parse open ports ---------------------------------------------------
declare -a OPEN_PORTS=()

# Try to read ports from service-detection first (richer data), then fall back
PARSE_SOURCES=(
  "${OUTPUT_DIR}/service-detection.xml"
  "${OUTPUT_DIR}/service-detection.nmap"
  "${OUTPUT_DIR}/service-detection.gnmap"
  "${OUTPUT_DIR}/port-discovery.xml"
  "${OUTPUT_DIR}/port-discovery.nmap"
  "${OUTPUT_DIR}/port-discovery.gnmap"
)

for src in "${PARSE_SOURCES[@]}"; do
  if [ ! -f "$src" ]; then
    continue
  fi

  case "$src" in
    *.xml)
      # Parse XML: extract portid, protocol, state, service name, product, version
      while IFS=$'\x1f' read -r portid protocol state service product version; do
        if [ -n "$portid" ]; then
          # Sanitize service/version for JSON (nmap banners can contain ", \, control chars)
          # Order: backslash first, then quote, then control chars
          # (control chars after backslash so \\t doesn't become \\\\t)
          service="${service//\\/\\\\}"
          service="${service//\"/\\\"}"
          service="${service//$'\t'/\\t}"
          service="${service//$'\n'/\\n}"
          service="${service//$'\r'/\\r}"
          service="${service//$'\b'/\\b}"
          service="${service//$'\f'/\\f}"
          product="${product//\\/\\\\}"
          product="${product//\"/\\\"}"
          product="${product//$'\t'/\\t}"
          product="${product//$'\n'/\\n}"
          product="${product//$'\r'/\\r}"
          product="${product//$'\b'/\\b}"
          product="${product//$'\f'/\\f}"
          version="${version//\\/\\\\}"
          version="${version//\"/\\\"}"
          version="${version//$'\t'/\\t}"
          version="${version//$'\n'/\\n}"
          version="${version//$'\r'/\\r}"
          version="${version//$'\b'/\\b}"
          version="${version//$'\f'/\\f}"
          OPEN_PORTS+=("{\"port\":${portid},\"protocol\":\"${protocol}\",\"state\":\"${state}\",\"service\":\"${service}\",\"version\":\"${version}\"}")
        fi
      done < <(
        awk '
        /<port / {
          portid=""; protocol=""; state=""; service=""; product=""; version=""
          match($0, /portid="([^"]+)"/, a); portid=a[1]
          match($0, /protocol="([^"]+)"/, a); protocol=a[1]
          in_port = 1
          next
        }
        in_port && /<state / {
          match($0, /state="([^"]+)"/, a); state=a[1]
        }
        in_port && /<service / {
          match($0, /name="([^"]+)"/, a); service=a[1]
          match($0, /product="([^"]+)"/, a); product=a[1]
          match($0, /version="([^"]+)"/, a); version=a[1]
        }
        in_port && /<\/port>/ {
          if (portid != "" && state == "open") {
            gsub(/"/, "", portid)
            gsub(/"/, "", protocol)
            printf "%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n", portid, protocol, state, service, product, version
          }
          in_port = 0
        }
        ' "$src" 2>/dev/null || true
      )
      ;;
    *.nmap)
      # Parse normal nmap output: "80/tcp   open  http  Apache httpd 2.4.41"
      while IFS=$'\x1f' read -r portid protocol state service version; do
        if [ -n "$portid" ]; then
          # Sanitize version for JSON (nmap banners can contain ", \, control chars)
          service="${service//\\/\\\\}"
          service="${service//\"/\\\"}"
          service="${service//$'\t'/\\t}"
          service="${service//$'\n'/\\n}"
          service="${service//$'\r'/\\r}"
          service="${service//$'\b'/\\b}"
          service="${service//$'\f'/\\f}"
          version="${version//\\/\\\\}"
          version="${version//\"/\\\"}"
          version="${version//$'\t'/\\t}"
          version="${version//$'\n'/\\n}"
          version="${version//$'\r'/\\r}"
          version="${version//$'\b'/\\b}"
          version="${version//$'\f'/\\f}"
          OPEN_PORTS+=("{\"port\":${portid},\"protocol\":\"${protocol}\",\"state\":\"${state}\",\"service\":\"${service}\",\"version\":\"${version}\"}")
        fi
      done < <(
        grep -E '^[0-9]' "$src" 2>/dev/null | \
        grep 'open' | \
        awk '{
          split($1, a, "/");
          portid = a[1];
          protocol = a[2];
          state = $2;
          service = "";
          version = "";
          for(i=3; i<=NF; i++) {
            if (i == 3) service = $i;
            else if (i == 4) version = $i;
            else if (i > 4) version = version " " $i;
          }
          printf "%s\x1f%s\x1f%s\x1f%s\x1f%s\n", portid, protocol, state, service, version;
        }' 2>/dev/null || true
      )
      ;;
    *.gnmap)
      # Parse gnmap: "Ports: 22/open/tcp//ssh//.../"
      PORTS_LINE="$(grep 'Ports:' "$src" 2>/dev/null | head -1)" || true
      if [ -n "$PORTS_LINE" ]; then
        # Extract each port entry
        entries="$(echo "$PORTS_LINE" | grep -oP '\d+/open/[a-z]+[^/]*/[^/]*/[^/]*/' 2>/dev/null)" || true
        while read -r entry; do
          [ -z "$entry" ] && continue
          PORTID="$(echo "$entry" | cut -d/ -f1)"
          PROTO="$(echo "$entry" | cut -d/ -f3)"
          SERVICE="$(echo "$entry" | cut -d/ -f5)"
          # Sanitize service for JSON
          SERVICE="${SERVICE//\\/\\\\}"
          SERVICE="${SERVICE//\"/\\\"}"
          SERVICE="${SERVICE//$'\t'/\\t}"
          SERVICE="${SERVICE//$'\n'/\\n}"
          SERVICE="${SERVICE//$'\r'/\\r}"
          SERVICE="${SERVICE//$'\b'/\\b}"
          SERVICE="${SERVICE//$'\f'/\\f}"
          # Gnmap doesn't have rich version info
          OPEN_PORTS+=("{\"port\":${PORTID},\"protocol\":\"${PROTO}\",\"state\":\"open\",\"service\":\"${SERVICE}\",\"version\":\"\"}")
        done <<< "$entries"
      fi
      ;;
  esac

  # If we found ports, stop looking at more sources
  if [ ${#OPEN_PORTS[@]} -gt 0 ]; then
    break
  fi
done

log_info "Parsed ${#OPEN_PORTS[@]} open ports"

# ---- Parse OS detection -------------------------------------------------
OS_DETECTION="null"
for xml in "${XML_FILES[@]}"; do
  if [ -f "$xml" ]; then
    OS_MATCH="$(grep -oP '<osmatch name="\K[^"]+' "$xml" 2>/dev/null | head -1)" || true
    OS_ACCURACY="$(grep -oP 'accuracy="\K[^"]+' "$xml" 2>/dev/null | head -1)" || true
    OS_VENDOR="$(grep -oP '<osclass vendor="\K[^"]+' "$xml" 2>/dev/null | head -1)" || true
    if [ -n "$OS_MATCH" ]; then
      # Sanitize OS values for JSON
      OS_MATCH="${OS_MATCH//\\/\\\\}"
      OS_MATCH="${OS_MATCH//\"/\\\"}"
      OS_MATCH="${OS_MATCH//$'\t'/\\t}"
      OS_MATCH="${OS_MATCH//$'\n'/\\n}"
      OS_MATCH="${OS_MATCH//$'\r'/\\r}"
      OS_MATCH="${OS_MATCH//$'\b'/\\b}"
      OS_MATCH="${OS_MATCH//$'\f'/\\f}"
      OS_VENDOR="${OS_VENDOR:-}"
      OS_VENDOR="${OS_VENDOR//\\/\\\\}"
      OS_VENDOR="${OS_VENDOR//\"/\\\"}"
      OS_VENDOR="${OS_VENDOR//$'\t'/\\t}"
      OS_VENDOR="${OS_VENDOR//$'\n'/\\n}"
      OS_VENDOR="${OS_VENDOR//$'\r'/\\r}"
      OS_VENDOR="${OS_VENDOR//$'\b'/\\b}"
      OS_VENDOR="${OS_VENDOR//$'\f'/\\f}"
      OS_DETECTION="{\"os\":\"${OS_MATCH}\",\"vendor\":\"${OS_VENDOR}\",\"accuracy\":${OS_ACCURACY:-0}}"
      break
    fi
  fi
done

# ---- Parse NSE findings -------------------------------------------------
declare -a NSE_FINDINGS=()
for src in "${XML_FILES[@]}"; do
  case "$src" in
    *.xml)
      if [ -f "$src" ]; then
        while IFS=$'\x1f' read -r -d '' script_id output; do
          if [ -n "$script_id" ]; then
            # Escape for JSON: \ first, then ", then control chars
            output="${output//\\/\\\\}"
            output="${output//\"/\\\"}"
            output="${output//$'\t'/\\t}"
            output="${output//$'\n'/\\n}"
            output="${output//$'\r'/\\r}"
            output="${output//$'\b'/\\b}"
            output="${output//$'\f'/\\f}"
            NSE_FINDINGS+=("{\"script\":\"${script_id}\",\"output\":\"${output}\"}")
          fi
        done < <(
          python3 -c '
import sys, xml.etree.ElementTree as ET
src = sys.argv[1]
try:
    tree = ET.parse(src)
    for host in tree.getroot().findall(".//host"):
        for script in host.findall(".//script"):
            sid = script.get("id", "")
            out = script.get("output", "")
            if sid:
                sys.stdout.write(sid + "\x1f" + out + "\x00")
except Exception:
    pass
' "$src" 2>/dev/null || true
        )
      fi
      ;;
  esac
done

# Also parse iot-scripts NSE output if it exists
IOT_XML="${OUTPUT_DIR}/iot-scripts.xml"
if [ -f "$IOT_XML" ]; then
  while IFS=$'\x1f' read -r -d '' script_id output; do
    if [ -n "$script_id" ]; then
      output="${output//\\/\\\\}"
      output="${output//\"/\\\"}"
      output="${output//$'\t'/\\t}"
      output="${output//$'\n'/\\n}"
      output="${output//$'\r'/\\r}"
      output="${output//$'\b'/\\b}"
      output="${output//$'\f'/\\f}"
      NSE_FINDINGS+=("{\"script\":\"${script_id}\",\"output\":\"${output}\"}")
    fi
  done < <(
    python3 -c '
import sys, xml.etree.ElementTree as ET
src = sys.argv[1]
try:
    tree = ET.parse(src)
    for host in tree.getroot().findall(".//host"):
        for script in host.findall(".//script"):
            sid = script.get("id", "")
            out = script.get("output", "")
            if sid:
                sys.stdout.write(sid + "\x1f" + out + "\x00")
except Exception:
    pass
' "$IOT_XML" 2>/dev/null || true
  )
fi

# ---- Parse fingerprints (service banners) --------------------------------
declare -a FINGERPRINTS=()
for src in "${XML_FILES[@]}"; do
  case "$src" in
    *.xml)
      if [ -f "$src" ]; then
        while IFS=$'\x1f' read -r portid fingerprint; do
          if [ -n "$portid" ] && [ -n "$fingerprint" ]; then
            fingerprint="${fingerprint//\\/\\\\}"
            fingerprint="${fingerprint//\"/\\\"}"
            fingerprint="${fingerprint//$'\t'/\\t}"
            fingerprint="${fingerprint//$'\n'/\\n}"
            fingerprint="${fingerprint//$'\r'/\\r}"
            fingerprint="${fingerprint//$'\b'/\\b}"
            fingerprint="${fingerprint//$'\f'/\\f}"
            FINGERPRINTS+=("{\"port\":${portid},\"fingerprint\":\"${fingerprint}\"}")
          fi
        done < <(
          awk '
          /<port / {
            portid=""; match($0, /portid="([^"]+)"/, a); portid=a[1]
          }
          /<service / && portid != "" {
            # Extract service fingerprint info
            name=""; product=""; version=""; extrainfo=""
            match($0, /name="([^"]+)"/, a); name=a[1]
            match($0, /product="([^"]+)"/, a); product=a[1]
            match($0, /version="([^"]+)"/, a); version=a[1]
            match($0, /extrainfo="([^"]+)"/, a); extrainfo=a[1]
            fp = name
            if (product != "") fp = fp " " product
            if (version != "") fp = fp " " version
            if (extrainfo != "") fp = fp " (" extrainfo ")"
            printf "%s\x1f%s\n", portid, fp
          }
          ' "$src" 2>/dev/null || true
        )
      fi
      ;;
  esac
done

# ---- Determine raw XML path ---------------------------------------------
RAW_XML=""
for xml in "${XML_FILES[@]}"; do
  if [ -f "$xml" ]; then
    RAW_XML="$xml"
    break
  fi
done

# ---- Build next_vectors -------------------------------------------------
declare -a NEXT_VECTORS=()
declare -a PORTS_SEEN=()
PORT_COUNT=${#OPEN_PORTS[@]}

# Extract port numbers for vector decisions
for entry in "${OPEN_PORTS[@]:-}"; do
  PORT_NUM="$(echo "$entry" | jq -r '.port' 2>/dev/null || echo "")"
  if [ -n "$PORT_NUM" ]; then
    PORTS_SEEN+=("$PORT_NUM")
  fi
done

# Build next_vectors based on discovered ports
if [ "${HOST_STATUS}" = "down" ] || [ "${HOST_STATUS}" = "filtered" ]; then
  NEXT_VECTORS+=("{\"condition\":\"host_status is down\",\"skill\":\"none\",\"weight\":0,\"reason\":\"Target unreachable — no further reconnaissance possible\"}")
else
  # Port-specific vectors
  has_443=false; has_80=false; has_22=false
  has_3306=false; has_5432=false; has_6379=false
  has_8080=false; has_8443=false
  multi_services=false

  for p in "${PORTS_SEEN[@]:-}"; do
    case "$p" in
      443)   has_443=true ;;
      80)    has_80=true ;;
      22)    has_22=true ;;
      3306)  has_3306=true ;;
      5432)  has_5432=true ;;
      6379)  has_6379=true ;;
      8080)  has_8080=true ;;
      8443)  has_8443=true ;;
    esac
  done

  if [ "$PORT_COUNT" -ge 3 ]; then multi_services=true; fi

  # Use `if` statements instead of `${var} &&` to avoid `set -e` issues
  if [ "$has_443" = "true" ]; then
    NEXT_VECTORS+=("{\"condition\":\"port 443 open\",\"skill\":\"testssl\",\"weight\":80,\"reason\":\"TLS certificate and cipher audit recommended\"}")
  fi
  if [ "$has_80" = "true" ]; then
    NEXT_VECTORS+=("{\"condition\":\"port 80 open\",\"skill\":\"httpx\",\"weight\":80,\"reason\":\"HTTP service fingerprinting and technology detection\"}")
  fi
  if [ "$has_22" = "true" ]; then
    NEXT_VECTORS+=("{\"condition\":\"port 22 open\",\"skill\":\"ssh-audit\",\"weight\":50,\"reason\":\"SSH configuration audit and banner analysis\"}")
  fi
  if [ "$has_3306" = "true" ]; then
    NEXT_VECTORS+=("{\"condition\":\"port 3306 open\",\"skill\":\"db-audit\",\"weight\":70,\"reason\":\"MySQL database service discovered — follow up with credential testing\"}")
  fi
  if [ "$has_5432" = "true" ]; then
    NEXT_VECTORS+=("{\"condition\":\"port 5432 open\",\"skill\":\"db-audit\",\"weight\":70,\"reason\":\"PostgreSQL database service discovered — follow up with credential testing\"}")
  fi
  if [ "$has_6379" = "true" ]; then
    NEXT_VECTORS+=("{\"condition\":\"port 6379 open\",\"skill\":\"db-audit\",\"weight\":70,\"reason\":\"Redis service discovered — follow up with credential testing\"}")
  fi
  if [ "$has_8080" = "true" ]; then
    NEXT_VECTORS+=("{\"condition\":\"port 8080 or 8443 open\",\"skill\":\"httpx\",\"weight\":75,\"reason\":\"Alternative web service port discovered — HTTP fingerprinting recommended\"}")
  fi
  if [ "$has_8443" = "true" ]; then
    NEXT_VECTORS+=("{\"condition\":\"port 8080 or 8443 open\",\"skill\":\"httpx\",\"weight\":75,\"reason\":\"Alternative web service port discovered — HTTP fingerprinting recommended\"}")
  fi
  if [ "$multi_services" = "true" ]; then
    NEXT_VECTORS+=("{\"condition\":\"multiple services detected\",\"skill\":\"nuclei\",\"weight\":60,\"reason\":\"Vulnerability scanning across multiple detected services\"}")
  fi
fi

# ---- Build open_ports JSON array ----------------------------------------
OPEN_PORTS_JSON="[]"
if [ ${#OPEN_PORTS[@]} -gt 0 ]; then
  OPEN_PORTS_JSON="["
  first=true
  for entry in "${OPEN_PORTS[@]}"; do
    if [ "$first" = true ]; then first=false; else OPEN_PORTS_JSON+=","; fi
    OPEN_PORTS_JSON+="${entry}"
  done
  OPEN_PORTS_JSON+="]"
fi

# ---- Build NSE findings JSON array --------------------------------------
NSE_FINDINGS_JSON="[]"
if [ ${#NSE_FINDINGS[@]} -gt 0 ]; then
  NSE_FINDINGS_JSON="["
  first=true
  for entry in "${NSE_FINDINGS[@]}"; do
    if [ "$first" = true ]; then first=false; else NSE_FINDINGS_JSON+=","; fi
    NSE_FINDINGS_JSON+="${entry}"
  done
  NSE_FINDINGS_JSON+="]"
fi

# ---- Build fingerprints JSON array --------------------------------------
FINGERPRINTS_JSON="[]"
if [ ${#FINGERPRINTS[@]} -gt 0 ]; then
  FINGERPRINTS_JSON="["
  first=true
  for entry in "${FINGERPRINTS[@]}"; do
    if [ "$first" = true ]; then first=false; else FINGERPRINTS_JSON+=","; fi
    FINGERPRINTS_JSON+="${entry}"
  done
  FINGERPRINTS_JSON+="]"
fi

# ---- Build next_vectors JSON array --------------------------------------
NEXT_VECTORS_JSON="[]"
if [ ${#NEXT_VECTORS[@]} -gt 0 ]; then
  NEXT_VECTORS_JSON="["
  first=true
  for entry in "${NEXT_VECTORS[@]}"; do
    if [ "$first" = true ]; then first=false; else NEXT_VECTORS_JSON+=","; fi
    NEXT_VECTORS_JSON+="${entry}"
  done
  NEXT_VECTORS_JSON+="]"
fi

# ---- Write consolidated.json --------------------------------------------
STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# Escape string variables for safe JSON interpolation in fallback heredocs
_ESC_SCAN_ID="${SCAN_ID:-}"; _ESC_SCAN_ID="${_ESC_SCAN_ID//\\/\\\\}"; _ESC_SCAN_ID="${_ESC_SCAN_ID//\"/\\\"}"; _ESC_SCAN_ID="${_ESC_SCAN_ID//$'\t'/\\t}"; _ESC_SCAN_ID="${_ESC_SCAN_ID//$'\n'/\\n}"; _ESC_SCAN_ID="${_ESC_SCAN_ID//$'\r'/\\r}"; _ESC_SCAN_ID="${_ESC_SCAN_ID//$'\b'/\\b}"; _ESC_SCAN_ID="${_ESC_SCAN_ID//$'\f'/\\f}"
_ESC_TARGET="${TARGET:-}"; _ESC_TARGET="${_ESC_TARGET//\\/\\\\}"; _ESC_TARGET="${_ESC_TARGET//\"/\\\"}"; _ESC_TARGET="${_ESC_TARGET//$'\t'/\\t}"; _ESC_TARGET="${_ESC_TARGET//$'\n'/\\n}"; _ESC_TARGET="${_ESC_TARGET//$'\r'/\\r}"; _ESC_TARGET="${_ESC_TARGET//$'\b'/\\b}"; _ESC_TARGET="${_ESC_TARGET//$'\f'/\\f}"
_ESC_STARTED_AT="${STARTED_AT:-}"; _ESC_STARTED_AT="${_ESC_STARTED_AT//\\/\\\\}"; _ESC_STARTED_AT="${_ESC_STARTED_AT//\"/\\\"}"; _ESC_STARTED_AT="${_ESC_STARTED_AT//$'\t'/\\t}"; _ESC_STARTED_AT="${_ESC_STARTED_AT//$'\n'/\\n}"; _ESC_STARTED_AT="${_ESC_STARTED_AT//$'\r'/\\r}"; _ESC_STARTED_AT="${_ESC_STARTED_AT//$'\b'/\\b}"; _ESC_STARTED_AT="${_ESC_STARTED_AT//$'\f'/\\f}"
_ESC_HOST_STATUS="${HOST_STATUS:-}"; _ESC_HOST_STATUS="${_ESC_HOST_STATUS//\\/\\\\}"; _ESC_HOST_STATUS="${_ESC_HOST_STATUS//\"/\\\"}"; _ESC_HOST_STATUS="${_ESC_HOST_STATUS//$'\t'/\\t}"; _ESC_HOST_STATUS="${_ESC_HOST_STATUS//$'\n'/\\n}"; _ESC_HOST_STATUS="${_ESC_HOST_STATUS//$'\r'/\\r}"; _ESC_HOST_STATUS="${_ESC_HOST_STATUS//$'\b'/\\b}"; _ESC_HOST_STATUS="${_ESC_HOST_STATUS//$'\f'/\\f}"
_ESC_RAW_XML="${RAW_XML:-}"; _ESC_RAW_XML="${_ESC_RAW_XML//\\/\\\\}"; _ESC_RAW_XML="${_ESC_RAW_XML//\"/\\\"}"; _ESC_RAW_XML="${_ESC_RAW_XML//$'\t'/\\t}"; _ESC_RAW_XML="${_ESC_RAW_XML//$'\n'/\\n}"; _ESC_RAW_XML="${_ESC_RAW_XML//$'\r'/\\r}"; _ESC_RAW_XML="${_ESC_RAW_XML//$'\b'/\\b}"; _ESC_RAW_XML="${_ESC_RAW_XML//$'\f'/\\f}"

CONSOLIDATED="${OUTPUT_DIR}/consolidated.json"
# Build JSON through jq to properly escape all values
if command -v jq &>/dev/null; then
  jq -n \
    --arg scan_id "$SCAN_ID" \
    --arg target "$TARGET" \
    --arg started_at "$STARTED_AT" \
    --arg host_status "$HOST_STATUS" \
    --argjson open_ports "${OPEN_PORTS_JSON:-[]}" \
    --argjson os_detection "${OS_DETECTION:-null}" \
    --argjson nse_findings "${NSE_FINDINGS_JSON:-[]}" \
    --argjson fingerprints "${FINGERPRINTS_JSON:-[]}" \
    --arg raw_xml "${RAW_XML:-}" \
    --argjson next_vectors "${NEXT_VECTORS_JSON:-[]}" \
    --argjson port_count "${PORT_COUNT:-0}" \
    --argjson partial "${PARTIAL:-false}" \
    '{
      "scan_id": $scan_id,
      "target": $target,
      "started_at": $started_at,
      "host_status": $host_status,
      "open_ports": $open_ports,
      "os_detection": $os_detection,
      "nse_findings": $nse_findings,
      "fingerprints": $fingerprints,
      "raw_xml": $raw_xml,
      "next_vectors": $next_vectors,
      "port_count": $port_count,
      "partial": $partial
    }' > "$CONSOLIDATED" 2>/dev/null || {
      log_error "jq failed to build consolidated.json — writing minimal fallback"
      log_warn "jq failed — writing minimal consolidated.json fallback"
      # Using printf to avoid shell injection via unquoted heredoc
      {
        printf '{\n'
        printf '  "scan_id": "%s",\n' "$_ESC_SCAN_ID"
        printf '  "target": "%s",\n' "$_ESC_TARGET"
        printf '  "started_at": "%s",\n' "$_ESC_STARTED_AT"
        printf '  "host_status": "%s",\n' "$_ESC_HOST_STATUS"
        printf '  "open_ports": %s,\n' "${OPEN_PORTS_JSON:-[]}"
        printf '  "os_detection": %s,\n' "${OS_DETECTION:-null}"
        printf '  "nse_findings": %s,\n' "${NSE_FINDINGS_JSON:-[]}"
        printf '  "fingerprints": %s,\n' "${FINGERPRINTS_JSON:-[]}"
        printf '  "raw_xml": "%s",\n' "$_ESC_RAW_XML"
        printf '  "next_vectors": %s,\n' "${NEXT_VECTORS_JSON:-[]}"
        printf '  "port_count": %s,\n' "${PORT_COUNT:-0}"
        printf '  "partial": %s\n' "${PARTIAL:-false}"
        printf '}\n'
      } > "$CONSOLIDATED"
    }
  log_info "consolidated.json written with jq escaping"
else
  # jq not available — fall back to printf (safe from shell injection)
  log_warn "jq not available — consolidated.json may have escaping issues"
  {
    printf '{\n'
    printf '  "scan_id": "%s",\n' "$_ESC_SCAN_ID"
    printf '  "target": "%s",\n' "$_ESC_TARGET"
    printf '  "started_at": "%s",\n' "$_ESC_STARTED_AT"
    printf '  "host_status": "%s",\n' "$_ESC_HOST_STATUS"
    printf '  "open_ports": %s,\n' "${OPEN_PORTS_JSON:-[]}"
    printf '  "os_detection": %s,\n' "${OS_DETECTION:-null}"
    printf '  "nse_findings": %s,\n' "${NSE_FINDINGS_JSON:-[]}"
    printf '  "fingerprints": %s,\n' "${FINGERPRINTS_JSON:-[]}"
    printf '  "raw_xml": "%s",\n' "$_ESC_RAW_XML"
    printf '  "next_vectors": %s,\n' "${NEXT_VECTORS_JSON:-[]}"
    printf '  "port_count": %s,\n' "${PORT_COUNT:-0}"
    printf '  "partial": %s\n' "${PARTIAL:-false}"
    printf '}\n'
  } > "$CONSOLIDATED"
fi

log_info "Wrote consolidated.json (${PORT_COUNT} ports)"

# ---- Write next_vectors.json --------------------------------------------
NEXT_FILE="${OUTPUT_DIR}/next_vectors.json"
if command -v jq &>/dev/null; then
  jq -n \
    --arg scan_id "$SCAN_ID" \
    --arg target "$TARGET" \
    --arg host_status "$HOST_STATUS" \
    --argjson next_vectors "${NEXT_VECTORS_JSON:-[]}" \
    '{
      "scan_id": $scan_id,
      "target": $target,
      "host_status": $host_status,
      "next_vectors": $next_vectors
    }' > "$NEXT_FILE" 2>/dev/null || {
      log_warn "jq failed for next_vectors.json — using printf fallback"
      {
        printf '{\n'
        printf '  "scan_id": "%s",\n' "$_ESC_SCAN_ID"
        printf '  "target": "%s",\n' "$_ESC_TARGET"
        printf '  "host_status": "%s",\n' "$_ESC_HOST_STATUS"
        printf '  "next_vectors": %s\n' "${NEXT_VECTORS_JSON:-[]}"
        printf '}\n'
      } > "$NEXT_FILE"
    }
else
  {
    printf '{\n'
    printf '  "scan_id": "%s",\n' "$_ESC_SCAN_ID"
    printf '  "target": "%s",\n' "$_ESC_TARGET"
    printf '  "host_status": "%s",\n' "$_ESC_HOST_STATUS"
    printf '  "next_vectors": %s\n' "${NEXT_VECTORS_JSON:-[]}"
    printf '}\n'
  } > "$NEXT_FILE"
fi

log_info "Wrote next_vectors.json with ${#NEXT_VECTORS[@]} suggestions"
exit 0
