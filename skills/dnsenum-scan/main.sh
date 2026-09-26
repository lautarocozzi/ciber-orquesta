#!/usr/bin/env bash
# ============================================================================
# skills/dnsenum-scan/main.sh — DNS Early Discovery Sub-Skill
#
# Runs dnsenum in fast discovery mode against the target domain and parses the
# result inline into parsed-results.json (subdomains, NS, MX, zone transfer).
#
# Invocation:
#   dnsenum --noreverse [-f <wordlist>] --threads <n> -t <n> \
#     --subfile <subs.txt> -o <out.xml> <domain>
#
# -s / -p (Google scraping) and -w (whois) are NEVER passed.
# Zone transfer is never disabled: dnsenum >= 1.3.1 attempts AXFR against every
# NS automatically, and zone_transfer.attempted is always recorded as true.
#
# Wildcard guard: a random label is probed with `dig +short A` before the run.
# Names that resolve to the wildcard IP are dropped by the parser, so they can
# never reach subdomains[] or any next_vectors targets[].
#
# Invocation (engine contract — env vars):
#   SCAN_ID=abc TARGET=example.com PARAM_THREADS=20 PARAM_TIMEOUT=3 \
#     bash skills/dnsenum-scan/main.sh
#
# State written:
#   state/dnsenum-scan/{scan_id}/status.json
#   state/dnsenum-scan/{scan_id}/parsed-results.json
#   state/dnsenum-scan/{scan_id}/wildcard.json
#   state/dnsenum-scan/{scan_id}/subs.txt
#   state/dnsenum-scan/{scan_id}/out.xml
#   state/dnsenum-scan/{scan_id}/command.txt
#   state/dnsenum-scan/{scan_id}/sub-processes/dnsenum.json
#
# Shared data (when WORKFLOW_SHARED_DIR is set):
#   $WORKFLOW_SHARED_DIR/dnsenum-scan/parsed-results.json
# ============================================================================

set -euo pipefail

# ---- Directories ---------------------------------------------------------
SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SKILL_DIR}/../.." && pwd)"
STATE_DIR="${STATE_DIR:-${PROJECT_ROOT}/state}"

SKILL="dnsenum-scan"
STEP_ID="${STEP_ID:-dnsenum-scan}"

source "${PROJECT_ROOT}/skills/_shared/envelope.sh"

# ---- Defaults (spec: wordlist /usr/share/dnsenum/dns.txt, threads 20, -t 3) -
DEFAULT_WORDLIST="/usr/share/dnsenum/dns.txt"
DEFAULT_THREADS=20
DEFAULT_REQ_TIMEOUT=3
DEFAULT_STEP_TIMEOUT=7200
MAX_DIG_IP_FALLBACK=25

# ---- Parse Input ---------------------------------------------------------
if [ $# -ge 1 ] && [ -f "$1" ]; then
  EVENT_FILE="$1"
  log_info "Reading event from: ${EVENT_FILE}"
  SCAN_ID="$(jq -r '.scan_id // empty' "$EVENT_FILE")"
  TARGET="$(jq -r '.target // empty' "$EVENT_FILE")"
  WORDLIST="$(jq -r '.parameters.wordlist // empty' "$EVENT_FILE")"
  THREADS="$(jq -r '.parameters.threads // empty' "$EVENT_FILE")"
  REQ_TIMEOUT="$(jq -r '.parameters.timeout // empty' "$EVENT_FILE")"
else
  SCAN_ID="${SCAN_ID:-}"
  TARGET="${TARGET:-}"
  # PARAM_* arrives from the engine (workflow parameters); plain env vars are
  # the standalone-run contract.
  WORDLIST="${WORDLIST:-${PARAM_WORDLIST:-}}"
  THREADS="${THREADS:-${PARAM_THREADS:-}}"
  REQ_TIMEOUT="${REQ_TIMEOUT:-${DNSENUM_REQ_TIMEOUT:-${PARAM_TIMEOUT:-}}}"
fi

if [ -z "${SCAN_ID}" ] || [ -z "${TARGET}" ]; then
  log_error "Missing required inputs: SCAN_ID and TARGET"
  exit 1
fi

WORDLIST="${WORDLIST:-${DEFAULT_WORDLIST}}"
THREADS="${THREADS:-${DEFAULT_THREADS}}"
REQ_TIMEOUT="${REQ_TIMEOUT:-${DEFAULT_REQ_TIMEOUT}}"
STEP_TIMEOUT_SECONDS="${STEP_TIMEOUT_SECONDS:-${DEFAULT_STEP_TIMEOUT}}"

# dnsenum enumerates a domain, not a URL: strip scheme, port and path.
DOMAIN="${TARGET%%\?*}"
DOMAIN="${DOMAIN#*://}"
DOMAIN="${DOMAIN%%/*}"
DOMAIN="${DOMAIN%%:*}"
DOMAIN="${DOMAIN,,}"

if [ -z "${DOMAIN}" ]; then
  log_error "Could not derive a domain from TARGET='${TARGET}'"
  exit 1
fi

export SCAN_ID TARGET
PARTIAL=false; export PARTIAL
STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"; export STARTED_AT

OUTPUT_DIR="${STATE_DIR}/${SKILL}/${SCAN_ID}"
mkdir -p "${OUTPUT_DIR}/sub-processes"

DISPLAY_LOG="${OUTPUT_DIR}/dnsenum-display.log"
STDERR_LOG="${OUTPUT_DIR}/sub-processes/dnsenum-stderr.log"
SUBFILE="${OUTPUT_DIR}/subs.txt"
XML_FILE="${OUTPUT_DIR}/out.xml"
WILDCARD_FILE="${OUTPUT_DIR}/wildcard.json"
PARSED_FILE="${OUTPUT_DIR}/parsed-results.json"
COMMAND_FILE="${OUTPUT_DIR}/command.txt"

log_info "Starting DNS discovery | scan_id=${SCAN_ID} target=${TARGET} domain=${DOMAIN}"
write_status "dnsenum-scan" "running" 0 "${SCAN_ID}" "${TARGET}"

# ---- Tool check ----------------------------------------------------------
if ! command -v dnsenum >/dev/null 2>&1; then
  log_error "dnsenum binary not found (requires dnsenum >= 1.3.1)"
  write_status "dnsenum-scan" "failed" 100 "${SCAN_ID}" "${TARGET}"
  exit 2
fi

# ---- Wildcard probe (before the scan) ------------------------------------
PROBE_LABEL="w-$(date -u +%s)-$$"
PROBE_NAME="${PROBE_LABEL}.${DOMAIN}"
WILDCARD_IPS=()
WILDCARD_METHOD="dig"

if command -v dig >/dev/null 2>&1; then
  while IFS= read -r _ip; do
    [ -n "${_ip}" ] && WILDCARD_IPS+=("${_ip}")
  done < <(
    dig +short A "${PROBE_NAME}" 2>/dev/null \
      | grep -E '^(([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]+)$' || true
  )
else
  WILDCARD_METHOD="unavailable"
  log_warn "dig not available — wildcard probe skipped (wildcard noise may leak)"
fi

WILDCARD_DETECTED=false
[ "${#WILDCARD_IPS[@]}" -gt 0 ] && WILDCARD_DETECTED=true

WILDCARD_IPS_JSON="[]"
if [ "${#WILDCARD_IPS[@]}" -gt 0 ]; then
  WILDCARD_IPS_JSON="$(printf '%s\n' "${WILDCARD_IPS[@]}" | jq -R . | jq -sc 'unique')"
fi

jq -n \
  --arg domain "${DOMAIN}" \
  --arg probe_name "${PROBE_NAME}" \
  --arg probed_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg method "${WILDCARD_METHOD}" \
  --argjson detected "${WILDCARD_DETECTED}" \
  --argjson ips "${WILDCARD_IPS_JSON}" \
  '{domain: $domain, probe_name: $probe_name, probed_at: $probed_at,
    method: $method, detected: $detected, wildcard_ips: $ips}' \
  > "${WILDCARD_FILE}"

if [ "${WILDCARD_DETECTED}" = true ]; then
  log_warn "wildcard DNS detected (${WILDCARD_IPS[*]}) — matching subdomains will be filtered"
else
  log_info "no wildcard DNS for ${PROBE_NAME}"
fi

# ---- Build invocation ----------------------------------------------------
# -f is only passed when the wordlist exists on disk; otherwise dnsenum falls
# back to its built-in default (/usr/share/dnsenum/dns.txt).
DNSENUM_CMD=(dnsenum --noreverse)
if [ -f "${WORDLIST}" ]; then
  DNSENUM_CMD+=(-f "${WORDLIST}")
else
  log_warn "wordlist not found: ${WORDLIST} — using dnsenum built-in default"
  WORDLIST="(dnsenum default)"
fi
DNSENUM_CMD+=(--threads "${THREADS}" -t "${REQ_TIMEOUT}")
DNSENUM_CMD+=(--subfile "${SUBFILE}" -o "${XML_FILE}" "${DOMAIN}")

printf '%s ' "${DNSENUM_CMD[@]}" > "${COMMAND_FILE}"
printf '\n' >> "${COMMAND_FILE}"
log_info "dnsenum command: $(cat "${COMMAND_FILE}")"

START_MS="$(date +%s%3N 2>/dev/null || echo 0)"

# ---- Run -----------------------------------------------------------------
# Bash-level timeout so STEP_TIMEOUT_SECONDS also applies to standalone runs
# (the engine applies its own asyncio timeout on top of this).
set +e
timeout "${STEP_TIMEOUT_SECONDS}" "${DNSENUM_CMD[@]}" \
  >"${DISPLAY_LOG}" 2>"${STDERR_LOG}"
DNSENUM_EXIT=$?
set -e

END_MS="$(date +%s%3N 2>/dev/null || echo 0)"
DURATION_MS=$(( END_MS - START_MS ))

if [ "${DNSENUM_EXIT}" -eq 124 ]; then
  log_warn "dnsenum hit the ${STEP_TIMEOUT_SECONDS}s timeout — parsing partial output"
  PARTIAL=true; export PARTIAL
elif [ "${DNSENUM_EXIT}" -ne 0 ]; then
  log_warn "dnsenum exited ${DNSENUM_EXIT} — parsing available output"
  PARTIAL=true; export PARTIAL
fi

# ---- Parse (inline python3: XML + subfile + display log) ------------------
set +e
python3 - \
  "${DOMAIN}" \
  "${SCAN_ID}" \
  "${TARGET}" \
  "${STARTED_AT}" \
  "${XML_FILE}" \
  "${SUBFILE}" \
  "${DISPLAY_LOG}" \
  "${WILDCARD_FILE}" \
  "${PARSED_FILE}" \
  "${MAX_DIG_IP_FALLBACK}" <<'PYTHON_PARSE'
"""Parse dnsenum output into parsed-results.json.

Sources:
  out.xml       MagicTree XML — hostname -> A record mapping
  subs.txt      dnsenum --subfile — authoritative "valid subdomains" (domain
                suffix stripped; NS/MX names may be mixed in and are excluded)
  dnsenum-display.log — section-scoped records: NS, MX, brute force, AXFR

Set/Clear semantics: names resolving to a wildcard IP are dropped here, before
the analyzer can build next_vectors targets.
"""
import json
import os
import re
import shutil
import subprocess
import sys
from xml.etree import ElementTree as ET

DOMAIN, SCAN_ID, TARGET, STARTED_AT, XML_PATH, SUB_PATH, LOG_PATH, \
    WILDCARD_PATH, OUT_PATH, MAX_DIG_STR = sys.argv[1:11]
MAX_DIG = int(MAX_DIG_STR)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# printrr() format: name ttl IN type data
RECORD_RE = re.compile(r"^(\S+)\s+(\d+)\s+IN\s+([A-Z0-9]+)\s+(.+?)\s*$")
AXFR_SERVER_RE = re.compile(r"^Trying Zone Transfer for (\S+) on (\S+)")
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
VERSION_RE = re.compile(r"dnsenum VERSION:\s*([\d.]+)", re.I)

partial = False
errors = []


def norm(name):
    return (name or "").strip().rstrip(".").lower()


def to_fqdn(name):
    """subfile entries are domain-suffix-stripped labels."""
    n = norm(name)
    if not n:
        return ""
    if n == DOMAIN or n.endswith("." + DOMAIN):
        return n
    if "." not in n:
        return n + "." + DOMAIN
    return n


def read_text(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        errors.append("read_error:%s:%s" % (os.path.basename(path), exc))
        return ""


log_raw = read_text(LOG_PATH)
log_text = ANSI_RE.sub("", log_raw)
dnsenum_version = ""
m = VERSION_RE.search(log_text)
if m:
    dnsenum_version = m.group(1)

# ---- wildcard guard ------------------------------------------------------
wildcard = {"detected": False, "wildcard_ips": [], "probe_name": ""}
try:
    with open(WILDCARD_PATH) as fh:
        wildcard = json.load(fh)
except (OSError, ValueError) as exc:
    errors.append("wildcard_read_error:%s" % exc)
wildcard_ips = set(wildcard.get("wildcard_ips") or [])
probe_name = norm(wildcard.get("probe_name"))

# ---- display log: NS / MX / brute force / AXFR ---------------------------
ns_names, mx_names, brute, axfr_records, axfr_servers = [], [], [], [], []
axfr_attempted = False
axfr_success = False
section = None
axfr_block = None


def close_axfr_block():
    global axfr_block, axfr_success
    if axfr_block and axfr_block["records"]:
        axfr_success = True
        axfr_records.extend(axfr_block["records"])
        axfr_servers.append(axfr_block["ns"])
    axfr_block = None


for raw in log_text.splitlines():
    line = raw.strip()
    if not line or set(line) == {"_"}:
        continue
    low = line.lower()

    m = AXFR_SERVER_RE.match(line)
    if m:
        close_axfr_block()
        axfr_block = {"ns": norm(m.group(2)), "records": []}
        section = "axfr"
        axfr_attempted = True
        continue

    if "axfr record query failed" in low:
        close_axfr_block()
        section = None
        continue

    # Section headers all end with ':' and never match RECORD_RE.
    if line.endswith(":") and not RECORD_RE.match(line):
        close_axfr_block()
        section = None
        if low.startswith("name servers:"):
            section = "ns"
        elif low.startswith("mail (mx) servers:"):
            section = "mx"
        elif low.startswith("host's addresses:"):
            section = "host"
        elif low.startswith("brute forcing with"):
            section = "brute"
        elif low.startswith("trying zone transfers"):
            section = "axfr"
        continue

    m = RECORD_RE.match(line)
    if not m or section is None:
        continue
    rec = {
        "name": norm(m.group(1)),
        "ttl": int(m.group(2)),
        "type": m.group(3),
        "data": m.group(4).strip(),
    }
    if section == "ns":
        ns_names.append(norm(rec["data"].split()[-1]) if rec["type"] == "NS" else rec["name"])
    elif section == "mx":
        mx_names.append(norm(rec["data"].split()[-1]) if rec["type"] == "MX" else rec["name"])
    elif section == "brute":
        brute.append(rec)
    elif section == "axfr" and axfr_block is not None:
        axfr_block["records"].append(rec)

close_axfr_block()

if re.search(r"zone transfer was successful", log_text, re.I):
    axfr_success = True

# dnsenum >= 1.3.1 always attempts AXFR against every NS.
axfr_attempted = True
axfr_names = {rec["name"] for rec in axfr_records if rec["name"]}

# ---- XML: hostname -> first A record -------------------------------------
xml_ips, xml_names = {}, []
if not os.path.exists(XML_PATH):
    errors.append("xml_missing")
    partial = True
else:
    try:
        tree = ET.parse(XML_PATH)
    except ET.ParseError as exc:
        errors.append("xml_parse_error:%s" % exc)
        partial = True
    except OSError as exc:
        errors.append("xml_io_error:%s" % exc)
        partial = True
    else:
        for el in tree.iter():
            tag = el.tag.lower() if isinstance(el.tag, str) else ""
            if tag == "host":
                ip = (el.text or "").strip()
                name = ""
                for child in el:
                    if isinstance(child.tag, str) and child.tag.lower() == "hostname":
                        name = norm(child.text)
                if not name and " " in ip:
                    parts = ip.split()
                    ip, name = parts[0], norm(parts[1])
                if name:
                    xml_names.append(name)
                    if IPV4_RE.match(ip) and name not in xml_ips:
                        xml_ips[name] = ip
            elif tag == "fqdn":
                name = norm(el.text)
                if name:
                    xml_names.append(name)

# ---- subfile: authoritative valid subdomains -----------------------------
subfile_names = []
for line in read_text(SUB_PATH).splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    name = to_fqdn(line)
    if name:
        subfile_names.append(name)

# ---- assemble candidates -------------------------------------------------
excluded = {DOMAIN, probe_name}
excluded.update(n for n in ns_names if n)
excluded.update(n for n in mx_names if n)

sources, ips, found = {}, {}, {}


def add(name, source, ip=""):
    n = norm(name)
    if not n or n in excluded:
        return
    if n not in found:
        found[n] = True
        sources[n] = set()
    # Late sources still contribute provenance and can supply a missing IP
    # (the brute-force log lists names before the XML mapping is consulted).
    sources[n].add(source)
    if ip and not ips.get(n):
        ips[n] = ip


for rec in brute:
    add(rec["name"], "bruteforce", "")
for name in subfile_names:
    add(name, "bruteforce", xml_ips.get(name, ""))
for name in xml_names:
    add(name, "xml", xml_ips.get(name, ""))
for rec in axfr_records:
    add(rec["name"], "zone_transfer", xml_ips.get(rec["name"], ""))
    if rec["type"] == "A" and rec["name"] not in ips:
        ips.setdefault(rec["name"], rec["data"].strip())

# ---- dig fallback for names without an IP --------------------------------
dig_used = 0
if shutil.which("dig"):
    for name in sorted(found):
        if ips.get(name) or dig_used >= MAX_DIG:
            continue
        try:
            res = subprocess.run(
                ["dig", "+short", "A", name],
                capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            break
        dig_used += 1
        for line in res.stdout.splitlines():
            if IPV4_RE.match(line.strip()):
                ips[name] = line.strip()
                break

# ---- wildcard filtering (BEFORE anything downstream sees the names) ------
# Runs after the dig fallback so names whose IP was only learned by dig are
# filtered too.
wildcard_filtered = [n for n, ip in ips.items() if ip in wildcard_ips]
for name in wildcard_filtered:
    found.pop(name, None)
    sources.pop(name, None)
    ips.pop(name, None)

# ---- build subdomains ----------------------------------------------------
subdomains = []
for name in sorted(found):
    prov = sources.get(name, set())
    if name in axfr_names:
        source = "zone_transfer"
    elif "bruteforce" in prov:
        source = "bruteforce"
    else:
        source = "xml"
    subdomains.append({"name": name, "ip": ips.get(name, ""), "source": source})

ns_out, seen = [], set()
for n in ns_names:
    if n and n not in seen:
        seen.add(n)
        ns_out.append(n)
mx_out, seen = [], set()
for n in mx_names:
    if n and n not in seen:
        seen.add(n)
        mx_out.append(n)

# Names kept without an IP: the wildcard guard cannot compare them, so the
# count is surfaced instead of being silently trusted.
unresolved = [s["name"] for s in subdomains if not s["ip"]]

result = {
    "scan_id": SCAN_ID,
    "target": TARGET,
    "domain": DOMAIN,
    "started_at": STARTED_AT,
    "dnsenum_version": dnsenum_version,
    "subdomains": subdomains,
    "subdomain_count": len(subdomains),
    "ns": ns_out,
    "mx": mx_out,
    "zone_transfer": {
        "attempted": axfr_attempted,
        "success": axfr_success,
        "records": axfr_records,
        "servers": axfr_servers,
    },
    "wildcard": {
        "detected": bool(wildcard.get("detected")),
        "wildcard_ips": sorted(wildcard_ips),
        "probe_name": probe_name,
        "filtered_count": len(wildcard_filtered),
        "filtered": sorted(wildcard_filtered),
    },
    "unresolved_count": len(unresolved),
    "unresolved": unresolved,
    "artifacts": {
        "xml": os.path.basename(XML_PATH),
        "subfile": os.path.basename(SUB_PATH),
        "log": os.path.basename(LOG_PATH),
    },
    "partial": partial,
    "errors": errors,
}

with open(OUT_PATH, "w") as fh:
    json.dump(result, fh, indent=2)

print("[dnsenum-scan] parsed %d subdomain(s), %d NS, %d MX, zone_transfer=%s%s" % (
    len(subdomains), len(ns_out), len(mx_out),
    "success" if axfr_success else "not successful",
    ", %d wildcard name(s) filtered" % len(wildcard_filtered) if wildcard_filtered else "",
), file=sys.stderr)
PYTHON_PARSE
PARSE_EXIT=$?
set -e

if [ "${PARSE_EXIT}" -ne 0 ] || [ ! -f "${PARSED_FILE}" ]; then
  log_error "inline parse failed (exit=${PARSE_EXIT}) — writing empty parsed-results"
  PARTIAL=true; export PARTIAL
  jq -n \
    --arg scan_id "${SCAN_ID}" \
    --arg target "${TARGET}" \
    --arg domain "${DOMAIN}" \
    --arg started_at "${STARTED_AT}" \
    '{
      scan_id: $scan_id, target: $target, domain: $domain,
      started_at: $started_at, dnsenum_version: "",
      subdomains: [], subdomain_count: 0, ns: [], mx: [],
      zone_transfer: {attempted: true, success: false, records: [], servers: []},
      wildcard: {detected: false, wildcard_ips: [], probe_name: "", filtered_count: 0, filtered: []},
      artifacts: {}, partial: true, errors: ["parse_failed"]
    }' > "${PARSED_FILE}"
fi

# The parse owns the partial verdict: a truncated XML sets partial=true even
# when dnsenum itself exited cleanly.
if [ "$(jq -r '.partial // false' "${PARSED_FILE}" 2>/dev/null || echo false)" = "true" ]; then
  PARTIAL=true; export PARTIAL
fi

SUBDOMAIN_COUNT="$(jq -r '.subdomain_count // 0' "${PARSED_FILE}" 2>/dev/null || echo 0)"

# ---- Envelope ------------------------------------------------------------
write_sub_process_result "dnsenum-scan" "${DNSENUM_EXIT}" "${DISPLAY_LOG}" \
  "${STDERR_LOG}" "${DURATION_MS:-0}" "${PARSED_FILE}"
write_to_shared_dir "${SKILL}" "${PARSED_FILE}"
write_to_shared_dir "${SKILL}" "${WILDCARD_FILE}"

if [ "${PARTIAL}" = "true" ]; then
  write_status "dnsenum-scan" "degraded" 100 "${SCAN_ID}" "${TARGET}"
  log_warn "dnsenum-scan finished (degraded) | scan_id=${SCAN_ID} subdomains=${SUBDOMAIN_COUNT}"
  exit 0
fi

write_status "dnsenum-scan" "done" 100 "${SCAN_ID}" "${TARGET}"
log_info "dnsenum-scan finished | scan_id=${SCAN_ID} subdomains=${SUBDOMAIN_COUNT}"
