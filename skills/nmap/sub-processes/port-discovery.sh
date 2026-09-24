#!/usr/bin/env bash
# ============================================================================
# skills/nmap/sub-processes/port-discovery.sh
#
# Phase 1: Discover open ports on the target.
#
# Reads: TARGET, PARAM_PORTS, PARAM_SCAN_MODE, PARAM_TIMING,
#        PARAM_SKIP_DISCOVERY from environment.
# Writes: nmap XML/Nmap/Gnmap output files to:
#         state/nmap/{SCAN_ID}/port-discovery.{xml,nmap,gnmap}
# ============================================================================

set -euo pipefail

log_info()  { echo "[port-discovery] [INFO]  $*"; }
log_warn()  { echo "[port-discovery] [WARN]  $*" >&2; }
log_error() { echo "[port-discovery] [ERROR] $*" >&2; }

TARGET="${TARGET:-}"
SCAN_ID="${SCAN_ID:-}"
PARAM_PORTS="${PARAM_PORTS:-top-1000}"
PARAM_SCAN_MODE="${PARAM_SCAN_MODE:-syn}"
PARAM_TIMING="${PARAM_TIMING:-4}"
PARAM_SKIP_DISCOVERY="${PARAM_SKIP_DISCOVERY:-false}"
STATE_DIR="${STATE_DIR:-state}"
SKILL="${SKILL:-nmap}"

if [ -z "$TARGET" ] || [ -z "$SCAN_ID" ]; then
  log_error "TARGET and SCAN_ID must be set"
  exit 1
fi

OUTPUT_DIR="${STATE_DIR}/${SKILL}/${SCAN_ID}"
mkdir -p "$OUTPUT_DIR"

# Resolve port specification
case "${PARAM_PORTS}" in
  top-1000)
    PORT_ARG="--top-ports 1000"
    PORT_LABEL="top-1000"
    ;;
  top-100)
    PORT_ARG="--top-ports 100"
    PORT_LABEL="top-100"
    ;;
  top-10)
    PORT_ARG="--top-ports 10"
    PORT_LABEL="top-10"
    ;;
  all)
    PORT_ARG="-p-"
    PORT_LABEL="all"
    ;;
  *)
    PORT_ARG="-p ${PARAM_PORTS}"
    PORT_LABEL="${PARAM_PORTS}"
    ;;
esac

# Determine scan type flags
SCAN_FLAG=""
case "${PARAM_SCAN_MODE}" in
  syn)
    SCAN_FLAG="-sS"
    ;;
  connect)
    SCAN_FLAG="-sT"
    ;;
  udp)
    SCAN_FLAG="-sU"
    ;;
  *)
    log_warn "Unknown scan_mode '${PARAM_SCAN_MODE}', defaulting to SYN"
    SCAN_FLAG="-sS"
    ;;
esac

# Host discovery flag
DISCOVERY_FLAG=""
if [ "${PARAM_SKIP_DISCOVERY}" = "true" ]; then
  DISCOVERY_FLAG="-Pn"
fi

OUTPUT_PREFIX="${OUTPUT_DIR}/port-discovery"

log_info "Scanning ${TARGET} ports=${PORT_LABEL} mode=${PARAM_SCAN_MODE} timing=${PARAM_TIMING}"

# Build nmap command
# NOTE: -sS (SYN) requires root privileges. Without root, nmap will fail.
# If not root and scan_mode=syn, auto-fallback to -sT (connect scan).
# Explicit sudo requires a TTY which may not be available in sub-process mode.
if [ "$PARAM_SCAN_MODE" = "syn" ] && [ "$(id -u)" -ne 0 ]; then
  log_warn "Not running as root — falling back from SYN scan (-sS) to Connect scan (-sT)"
  PARAM_SCAN_MODE="connect"
  SCAN_FLAG="-sT"
fi
NMAP_CMD=(nmap)

NMAP_CMD+=(
  "${SCAN_FLAG}"
  ${PORT_ARG}
  -T"${PARAM_TIMING}"
  ${DISCOVERY_FLAG}
  --open
  -oA "${OUTPUT_PREFIX}"
  "${TARGET}"
)

log_info "Running: ${NMAP_CMD[*]}"

# Execute with retry built-in through MAIN's Tier system
set +e
"${NMAP_CMD[@]}"
NMAP_EXIT=$?
set -e

if [ "${NMAP_EXIT}" -eq 0 ]; then
  log_info "Port discovery completed successfully"
  exit 0
fi
# nmap exit code 1 means ALL ports filtered — common, not an error
# Treat as success with empty result. Only exit code 2+ is a real error.
if [ "${NMAP_EXIT}" -eq 1 ]; then
  log_info "Port discovery completed — all ports filtered (nmap exit 1)"
  exit 0
fi

# If host appears down, retry with -Pn automatically
if [ "${NMAP_EXIT}" -ne 0 ] && [ "${PARAM_SKIP_DISCOVERY}" != "true" ]; then
  log_warn "Scan failed (exit ${NMAP_EXIT}), retrying with -Pn (skip discovery)"

  NMAP_CMD_WITH_PN=(nmap)
  NMAP_CMD_WITH_PN+=(
    "${SCAN_FLAG}"
    ${PORT_ARG}
    -T"${PARAM_TIMING}"
    -Pn
    --open
    -oA "${OUTPUT_PREFIX}"
    "${TARGET}"
  )

  set +e
  "${NMAP_CMD_WITH_PN[@]}"
  NMAP_EXIT=$?
  set -e

  if [ "${NMAP_EXIT}" -eq 0 ]; then
    log_info "Port discovery succeeded with -Pn"
    exit 0
  fi
  # nmap exit code 1 = all ports filtered, still a valid result
  if [ "${NMAP_EXIT}" -eq 1 ]; then
    log_info "Port discovery completed with -Pn — all ports filtered (nmap exit 1)"
    exit 0
  fi
fi

log_error "Port discovery failed (exit ${NMAP_EXIT})"
exit "${NMAP_EXIT}"
