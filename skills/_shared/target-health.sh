#!/usr/bin/env bash
# ============================================================================
# skills/_shared/target-health.sh — Pre-flight HTTP State Capture
#
# Phase 0: Captures the target's current HTTP state before any scan runs.
# Detects whether the target responds, with what status, and captures headers.
# This lets downstream analysis detect target state changes between scans.
#
# Reads:  TARGET, SCAN_ID, STATE_DIR (env vars)
# Writes: state/{skill}/{SCAN_ID}/target-state.json
#
# Fields in target-state.json:
#   reachable:  true/false  — was any TCP connection established?
#   status:     HTTP status code (0 if not HTTP, e.g. pure IP targets)
#   status_category: 2xx | 3xx | 4xx | 5xx | tcp | dns
#   headers:    map of selected security-relevant headers
#   body_hash:  SHA256 of first 4KB of body (detect content changes)
#   scheme:     https | http | tcp
#   error:      error message if unreachable
# ============================================================================

set -euo pipefail

log_info()  { echo "[target-health] [INFO]  $*"; }
log_warn()  { echo "[target-health] [WARN]  $*" >&2; }
log_error() { echo "[target-health] [ERROR] $*" >&2; }

TARGET="${TARGET:-}"
SCAN_ID="${SCAN_ID:-}"
STATE_DIR="${STATE_DIR:-state}"
SKILL="${SKILL:-}"

if [ -z "$TARGET" ] || [ -z "$SCAN_ID" ]; then
  log_error "TARGET and SCAN_ID must be set"
  exit 1
fi

if [ -z "$SKILL" ]; then
  log_error "SKILL must be set"
  exit 1
fi

OUTPUT_DIR="${STATE_DIR}/${SKILL}/${SCAN_ID}"
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="${OUTPUT_DIR}/target-state.json"

SCHEME="${TARGET%%://*}"
case "$SCHEME" in
  https|http) SCHEME="$SCHEME" ;;
  *) SCHEME="tcp" ;;
esac

# ---- TCP check (for non-HTTP targets like nmap) --------------------------
HOST="${TARGET#*://}"
HOST="${HOST%%/*}"
PORT="${PORT:-443}"

# Default result
RESULT='{"reachable":false,"status":0,"status_category":"unknown","headers":{},"body_hash":"","scheme":"'"$SCHEME"'","error":"check not completed"}'

# ---- HTTP(s) target ------------------------------------------------------
if [ "$SCHEME" = "https" ] || [ "$SCHEME" = "http" ]; then
  # Use curl for a fast HEAD+GET to capture status and headers.
  # Connect timeout 5s, overall max 10s — don't block the pipeline.
  HTTP_STATUS=""
  HEADER_HSTS=""
  HEADER_XFO=""
  HEADER_XCTO=""
  HEADER_SERVER=""
  HEADER_POWERED=""
  BODY_HASH=""
  ERROR_MSG=""

  # First: HEAD request for status + headers (fast)
  set +e
  HTTP_STATUS="$(curl -skI -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "${TARGET}" 2>/dev/null)"
  HEAD_EXIT=$?
  set -e

  if [ "$HEAD_EXIT" -ne 0 ] || [ -z "$HTTP_STATUS" ]; then
    ERROR_MSG="HEAD request failed (exit=$HEAD_EXIT)"
    HTTP_STATUS=0
  fi

  # Second: GET request for body hash + full headers (only if HEAD succeeded)
  if [ "$HTTP_STATUS" -gt 0 ] 2>/dev/null; then
    set +e
    CURL_OUTPUT="$(curl -skS -o /tmp/target-health-body-${SCAN_ID}.tmp -w "%{http_code}" --connect-timeout 5 --max-time 15 "${TARGET}" 2>/dev/null)"
    CURL_EXIT=$?
    set -e

    if [ "$CURL_EXIT" -eq 0 ] && [ -s "/tmp/target-health-body-${SCAN_ID}.tmp" ]; then
      HTTP_STATUS="$CURL_OUTPUT"
      BODY_HASH="$(sha256sum "/tmp/target-health-body-${SCAN_ID}.tmp" 2>/dev/null | cut -d' ' -f1 || echo "")"

      # Extract headers from the downloaded response file
      # curl -sS doesn't save headers by default, so re-fetch with -i for headers
      set +e
      curl -skI -o "/tmp/target-health-headers-${SCAN_ID}.tmp" --connect-timeout 5 --max-time 10 "${TARGET}" 2>/dev/null
      HEADER_EXIT=$?
      set -e

      if [ "$HEADER_EXIT" -eq 0 ] && [ -s "/tmp/target-health-headers-${SCAN_ID}.tmp" ]; then
        HEADER_HSTS="$(grep -i '^Strict-Transport-Security:' "/tmp/target-health-headers-${SCAN_ID}.tmp" 2>/dev/null | sed 's/^[^:]*: *//' | tr -d '\r\n' || true)"
        HEADER_XFO="$(grep -i '^X-Frame-Options:' "/tmp/target-health-headers-${SCAN_ID}.tmp" 2>/dev/null | sed 's/^[^:]*: *//' | tr -d '\r\n' || true)"
        HEADER_XCTO="$(grep -i '^X-Content-Type-Options:' "/tmp/target-health-headers-${SCAN_ID}.tmp" 2>/dev/null | sed 's/^[^:]*: *//' | tr -d '\r\n' || true)"
        HEADER_SERVER="$(grep -i '^Server:' "/tmp/target-health-headers-${SCAN_ID}.tmp" 2>/dev/null | sed 's/^[^:]*: *//' | tr -d '\r\n' || true)"
        HEADER_POWERED="$(grep -i '^X-Powered-By:' "/tmp/target-health-headers-${SCAN_ID}.tmp" 2>/dev/null | sed 's/^[^:]*: *//' | tr -d '\r\n' || true)"
        rm -f "/tmp/target-health-headers-${SCAN_ID}.tmp"
      fi
    else
      ERROR_MSG="GET request failed (exit=$CURL_EXIT)"
    fi

    rm -f "/tmp/target-health-body-${SCAN_ID}.tmp"
  fi

  # Categorize status
  STATUS_CATEGORY="unknown"
  if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
    STATUS_CATEGORY="2xx"
  elif [ "$HTTP_STATUS" -ge 300 ] && [ "$HTTP_STATUS" -lt 400 ]; then
    STATUS_CATEGORY="3xx"
  elif [ "$HTTP_STATUS" -ge 400 ] && [ "$HTTP_STATUS" -lt 500 ]; then
    STATUS_CATEGORY="4xx"
  elif [ "$HTTP_STATUS" -ge 500 ] && [ "$HTTP_STATUS" -lt 600 ]; then
    STATUS_CATEGORY="5xx"
  fi

  # Build JSON
  RESULT="$(jq -n \
    --argjson reachable "$([ "$HTTP_STATUS" -gt 0 ] && echo true || echo false)" \
    --argjson status "${HTTP_STATUS:-0}" \
    --arg status_category "$STATUS_CATEGORY" \
    --arg hsts "$HEADER_HSTS" \
    --arg xfo "$HEADER_XFO" \
    --arg xcto "$HEADER_XCTO" \
    --arg server "$HEADER_SERVER" \
    --arg powered "$HEADER_POWERED" \
    --arg body_hash "$BODY_HASH" \
    --arg scheme "$SCHEME" \
    --arg error "$ERROR_MSG" \
    '{
      reachable: $reachable,
      status: $status,
      status_category: $status_category,
      headers: {
        strict_transport_security: $hsts,
        x_frame_options: $xfo,
        x_content_type_options: $xcto,
        server: $server,
        x_powered_by: $powered
      },
      body_hash: $body_hash,
      scheme: $scheme,
      error: $error
    }' 2>/dev/null || echo '{"reachable":false,"status":0,"status_category":"error","headers":{},"body_hash":"","scheme":"'"$SCHEME"'","error":"jq failed to build result"}')"

# ---- TCP target (e.g. nmap on IP) -----------------------------------------
else
  # Just check basic TCP connectivity
  set +e
  timeout 5 bash -c "echo > /dev/tcp/${HOST}/${PORT}" 2>/dev/null
  TCP_OK=$?
  set -e

  RESULT="$(jq -n \
    --argjson reachable "$([ "$TCP_OK" -eq 0 ] && echo true || echo false)" \
    --argjson status 0 \
    --arg status_category "tcp" \
    --arg scheme "tcp" \
    --arg error "$([ "$TCP_OK" -ne 0 ] && echo 'TCP connection refused or timed out' || echo '')" \
    '{
      reachable: $reachable,
      status: $status,
      status_category: $status_category,
      headers: {},
      body_hash: "",
      scheme: $scheme,
      error: $error
    }' 2>/dev/null || echo '{"reachable":false,"status":0,"status_category":"error","headers":{},"body_hash":"","scheme":"tcp","error":"jq failed"}')"
fi

# ---- Write output ---------------------------------------------------------
echo "$RESULT" > "$OUTPUT_FILE"

# Also write to REPORTS_DIR if available (so global-report can read it)
if [ -n "${REPORTS_DIR:-}" ] && [ -n "${REPORT_TARGET:-}" ]; then
  REPORT_DIR="${REPORTS_DIR}/${REPORT_TARGET}/${SKILL}/${SCAN_ID}"
  mkdir -p "$REPORT_DIR"
  echo "$RESULT" > "${REPORT_DIR}/target-state.json"
fi

log_info "Target state captured: $(echo "$RESULT" | jq -c '{reachable, status, status_category}' 2>/dev/null || echo 'parse error')"

exit 0
