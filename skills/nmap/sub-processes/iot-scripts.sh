#!/usr/bin/env bash
# ============================================================================
# skills/nmap/sub-processes/iot-scripts.sh
#
# Phase 3 (optional): Run IoT-specific NSE scripts on discovered services.
# Only executes when PARAM_IOT_SCRIPTS=true.
#
# Targets common IoT protocols: RTSP (554), MQTT (1883, 8883),
# Modbus (502), BACnet (47808).
#
# Reads: TARGET, STATE_DIR, SKILL, SCAN_ID, PARAM_SCAN_MODE, PARAM_TIMING
# Writes: state/nmap/{SCAN_ID}/iot-scripts.{xml,nmap,gnmap}
# ============================================================================

set -euo pipefail

log_info()  { echo "[iot-scripts] [INFO]  $*"; }
log_warn()  { echo "[iot-scripts] [WARN]  $*" >&2; }
log_error() { echo "[iot-scripts] [ERROR] $*" >&2; }

TARGET="${TARGET:-}"
SCAN_ID="${SCAN_ID:-}"
STATE_DIR="${STATE_DIR:-state}"
SKILL="${SKILL:-nmap}"
PARAM_SCAN_MODE="${PARAM_SCAN_MODE:-syn}"
PARAM_TIMING="${PARAM_TIMING:-4}"
PARAM_IOT_SCRIPTS="${PARAM_IOT_SCRIPTS:-false}"

# Safety check — this script should only run when iot_scripts is true
if [ "${PARAM_IOT_SCRIPTS}" != "true" ]; then
  log_info "IoT scripts disabled, exiting"
  exit 0
fi

if [ -z "$TARGET" ] || [ -z "$SCAN_ID" ]; then
  log_error "TARGET and SCAN_ID must be set"
  exit 1
fi

OUTPUT_DIR="${STATE_DIR}/${SKILL}/${SCAN_ID}"

# ---- Discover IoT ports from service-detection or fall back to common port scan ---
IOT_PORTS=""

# Try to read IoT-relevant ports from service-detection gnmap
GNMAP_FILE="${OUTPUT_DIR}/service-detection.gnmap"
XML_FILE="${OUTPUT_DIR}/service-detection.xml"

if [ -f "$GNMAP_FILE" ]; then
  IOT_PORTS="$(
    grep -oP '\d+/open/tcp' "$GNMAP_FILE" | cut -d/ -f1 | \
    while read -r port; do
      case "$port" in
        502|554|1883|8883|47808) echo "$port" ;;
      esac
    done | tr '\n' ',' | sed 's/,$//'
  )"
elif [ -f "$XML_FILE" ]; then
  IOT_PORTS="$(
    grep '<port ' "$XML_FILE" | grep 'state="open"' | \
    sed -n 's/.*portid="\([^"]*\)".*/\1/p' | \
    while read -r port; do
      case "$port" in
        502|554|1883|8883|47808) echo "$port" ;;
      esac
    done | tr '\n' ',' | sed 's/,$//'
  )"
fi

# If no IoT ports found through parsing, check common IoT ports directly
if [ -z "${IOT_PORTS}" ]; then
  log_info "No IoT ports found in service-detection results, probing common IoT ports"
  IOT_PORTS="502,554,1883,8883,47808"
fi

log_info "IoT ports to scan: ${IOT_PORTS}"

# ---- Build nmap command with IoT NSE scripts ---------------------------
NMAP_CMD=(nmap)

# IoT-focused NSE scripts
# - rtsp-url-brute: brute forces RTSP URLs (port 554)
# - mqtt-subscribe: subscribes to MQTT topics (port 1883, 8883)
# - modbus-discover: discovers Modbus unit IDs (port 502)
# - bacnet-info: BACnet device info (port 47808)
# - stuxnet: Stuxnet-style detection on SCADA ports
IOT_NSE_SCRIPTS="rtsp-url-brute,mqtt-subscribe,modbus-discover,bacnet-info"

OUTPUT_PREFIX="${OUTPUT_DIR}/iot-scripts"

# BACnet (47808) is UDP-only; add UDP scan and protocol prefixes when BACnet port is present
UDP_FLAG=""
if [[ "${IOT_PORTS}" == *"47808"* ]]; then
  UDP_FLAG="-sU"
  # Prepend protocol prefixes so nmap scans each port on the correct protocol:
  # TCP ports (502,554,1883,8883) get T:, UDP port 47808 gets U:
  IOT_PORTS="$(echo "${IOT_PORTS}" | sed -e 's/^/T:/' -e 's/,/,T:/g' -e 's/T:47808/U:47808/')"
  log_info "BACnet (47808) detected — adding UDP scan flag, port list: ${IOT_PORTS}"
fi

NMAP_CMD+=(
  -sV
  ${UDP_FLAG}
  --script "${IOT_NSE_SCRIPTS}"
  -p "${IOT_PORTS}"
  -T"${PARAM_TIMING}"
  -Pn
  --open
  -oA "${OUTPUT_PREFIX}"
  "${TARGET}"
)

log_info "Running IoT NSE scripts: ${NMAP_CMD[*]}"

set +e
"${NMAP_CMD[@]}"
NMAP_EXIT=$?
set -e

if [ "${NMAP_EXIT}" -eq 0 ]; then
  log_info "IoT scripts completed successfully"
  exit 0
fi

# If no IoT-relevant NSE scripts exist (e.g., not compiled into this nmap),
# reduce to version scan on IoT ports as a fallback
if [ "${NMAP_EXIT}" -ne 0 ]; then
  log_warn "IoT NSE scripts failed (exit ${NMAP_EXIT}), retrying with version scan only"

  NMAP_CMD_FALLBACK=(nmap)
  NMAP_CMD_FALLBACK+=(
    -sV
    -p "${IOT_PORTS}"
    -T"${PARAM_TIMING}"
    -Pn
    --open
    -oA "${OUTPUT_PREFIX}"
    "${TARGET}"
  )

  set +e
  "${NMAP_CMD_FALLBACK[@]}"
  NMAP_EXIT=$?
  set -e
fi

if [ "${NMAP_EXIT}" -eq 0 ]; then
  log_info "IoT version scan completed successfully"
  exit 0
fi

log_warn "IoT scripts completed with exit code ${NMAP_EXIT} (non-critical)"
exit "${NMAP_EXIT}"
