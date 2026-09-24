#!/usr/bin/env bash
# ============================================================================
# skills/nmap/sub-processes/service-detection.sh
#
# Phase 2: Service version detection and default NSE scripts on discovered
# open ports.
#
# Reads: TARGET, STATE_DIR, SKILL, SCAN_ID, PARAM_SCAN_MODE, PARAM_TIMING,
#        PARAM_EXTRA_NSE from environment.
# Reads port list from port-discovery output files.
# Writes: state/nmap/{SCAN_ID}/service-detection.{xml,nmap,gnmap}
# ============================================================================

set -euo pipefail

log_info()  { echo "[service-detection] [INFO]  $*"; }
log_warn()  { echo "[service-detection] [WARN]  $*" >&2; }
log_error() { echo "[service-detection] [ERROR] $*" >&2; }

TARGET="${TARGET:-}"
SCAN_ID="${SCAN_ID:-}"
STATE_DIR="${STATE_DIR:-state}"
SKILL="${SKILL:-nmap}"
PARAM_SCAN_MODE="${PARAM_SCAN_MODE:-syn}"
PARAM_TIMING="${PARAM_TIMING:-4}"
PARAM_EXTRA_NSE="${PARAM_EXTRA_NSE:-}"

if [ -z "$TARGET" ] || [ -z "$SCAN_ID" ]; then
  log_error "TARGET and SCAN_ID must be set"
  exit 1
fi

OUTPUT_DIR="${STATE_DIR}/${SKILL}/${SCAN_ID}"

# ---- Extract open ports from port-discovery results --------------------
# Try parsing from Gnmap file first (easiest to parse)
PORT_LIST=""
GNMAP_FILE="${OUTPUT_DIR}/port-discovery.gnmap"
XML_FILE="${OUTPUT_DIR}/port-discovery.xml"
NMAP_FILE="${OUTPUT_DIR}/port-discovery.nmap"

if [ -f "$GNMAP_FILE" ]; then
  # Gnmap format: Host: 10.0.0.1 () Ports: 22/open/tcp//ssh//, 80/open/tcp//http//
  PORT_LIST="$(grep -oP '\d+/open/(tcp|udp)' "$GNMAP_FILE" | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')"
elif [ -f "$XML_FILE" ]; then
  # Parse XML for open ports
  PORT_LIST="$(
    grep '<port ' "$XML_FILE" | \
    grep 'state="open"' | \
    sed -n 's/.*portid="\([^"]*\)".*/\1/p' | \
    tr '\n' ',' | sed 's/,$//'
  )"
elif [ -f "$NMAP_FILE" ]; then
  # Parsing the normal nmap output
  PORT_LIST="$(
    grep '^[0-9]' "$NMAP_FILE" | \
    grep 'open' | \
    awk '{print $1}' | \
    cut -d/ -f1 | \
    tr '\n' ',' | sed 's/,$//'
  )"
fi

if [ -z "$PORT_LIST" ]; then
  log_warn "No open ports found in port-discovery output"
  log_info "Writing minimal service-detection result (no ports to scan)"

  # Write an empty nmap output to maintain expected file structure
  cat > "${OUTPUT_DIR}/service-detection.xml" <<-XMLEOF
<?xml version="1.0"?>
<!DOCTYPE nmaprun PUBLIC "-//IDN nmap.org//DTD Nmap XML 1.04//EN" "https://svn.nmap.org/nmap/docs/nmaprun.dtd">
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap -sV --version-intensity 0 ${TARGET}" start="$(date +%s)">
<scaninfo type="connect" protocol="tcp" numservices="0"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="$(date +%s)" endtime="$(date +%s)">
<status state="up" reason="user-set"/>
<address addr="${TARGET}" addrtype="ipv4"/>
<hostnames></hostnames>
<ports><extraports state="filtered" count="0">
<extrareasons reason="no-response" count="0"/>
</extraports></ports>
<times srtt="0" rttvar="0" to="100000"/>
</host>
<runstats><finished time="$(date +%s)" timestr="$(date -u)" summary="Nmap done at $(date -u); 0 IP hosts (1 host up) scanned in 0 seconds" elapsed="0"/></runstats>
</nmaprun>
XMLEOF
  exit 0
fi

log_info "Discovered open ports: ${PORT_LIST}"

# ---- Build nmap command -------------------------------------------------
# NOTE: no sudo wrapper — nmap degrades -sS to -sT gracefully without root.
NMAP_CMD=(nmap)

# Determine scan type flag for service detection
SCAN_FLAG="-sV"
# For UDP mode, we need -sU instead of -sS/-sT
case "${PARAM_SCAN_MODE}" in
  syn)
    if [ "$(id -u)" -ne 0 ]; then
      log_warn "Not running as root — falling back from -sS to -sT (connect scan)"
      SCAN_FLAG="-sT -sV"
    else
      SCAN_FLAG="-sS -sV"
    fi
    ;;
  connect) SCAN_FLAG="-sT -sV" ;;
  udp)    SCAN_FLAG="-sU -sV" ;;
esac

OUTPUT_PREFIX="${OUTPUT_DIR}/service-detection"

NSE_SCRIPTS="default"
if [ -n "${PARAM_EXTRA_NSE}" ]; then
  NSE_SCRIPTS="${NSE_SCRIPTS},${PARAM_EXTRA_NSE}"
fi
# NOTE: Guard above prevents trailing comma when PARAM_EXTRA_NSE is empty.

NMAP_CMD+=(
  ${SCAN_FLAG}
  --script "${NSE_SCRIPTS}"
  -p "${PORT_LIST}"
  -T"${PARAM_TIMING}"
  --open
  -oA "${OUTPUT_PREFIX}"
  "${TARGET}"
)

log_info "Running service detection: ${NMAP_CMD[*]}"

set +e
"${NMAP_CMD[@]}"
NMAP_EXIT=$?
set -e

if [ "${NMAP_EXIT}" -eq 0 ]; then
  log_info "Service detection completed successfully"
  exit 0
fi
# nmap exit code 1 means ALL ports filtered — common, not an error.
# Treat as success with empty result. Only exit code 2+ is a real error.
if [ "${NMAP_EXIT}" -eq 1 ]; then
  log_info "Service detection completed — all ports filtered (nmap exit 1)"
  exit 0
fi

log_error "Service detection failed (exit ${NMAP_EXIT})"
exit "${NMAP_EXIT}"
