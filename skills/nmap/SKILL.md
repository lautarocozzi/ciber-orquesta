# Nmap Skill

Port scanning, service detection, OS fingerprinting, and IoT reconnaissance.

## Purpose

The nmap skill wraps Nmap into the core engine's skill architecture. It
provides structured sub-processes that can be orchestrated individually or
as a full pipeline: port discovery → service detection → [IoT scripts] →
analysis → sysreport generation.

## Inputs

| Input | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `target` | string | yes | — | Target IP or hostname |
| `ports` | string | no | `top-1000` | Port spec: `top-1000`, `top-100`, `all`, or `22,80,443` |
| `scan_mode` | enum | no | `syn` | `syn` (-sS, needs sudo), `connect` (-sT), `udp` (-sU) |
| `timing` | integer | no | `4` | Timing 0–5 (aggressive=4, insane=5) |
| `skip_discovery` | boolean | no | `false` | Skip host discovery (-Pn) |
| `iot_scripts` | boolean | no | `false` | Enable RTSP/MQTT/Modbus NSE scripts |
| `extra_nse` | string | no | `""` | Extra NSE scripts, comma-separated |

## Outputs

| Output | Type | Description |
|--------|------|-------------|
| `host_status` | string | `up`, `down`, or `filtered` |
| `open_ports` | list | Discovered ports with service and version |
| `os_detection` | map | OS vendor, family, accuracy (or null) |
| `nse_findings` | list | NSE script results |
| `fingerprints` | list | Service banners and fingerprints |
| `raw_xml` | string | Path to raw nmap XML output |

## Sub-Process Flow

```
port-discovery ──► service-detection ──► [iot-scripts?] ──► analyzer ──► sysreport
      │                   │                    │               │             │
      │  nmap -p-         │  nmap -sV -sC      │  NSE scripts   │  parse XML  │  YAML report
      │  -oA state/...   │  on open ports     │  on open ports │  + JSON     │  + JSON
      ▼                   ▼                    ▼               ▼             ▼
   status.json ◄──────── state/nmap/{scan_id}/sub-processes/{name}.json
```

Each sub-process writes its result to:
`state/nmap/{scan_id}/sub-processes/{name}.json`

The analyzer writes:
- `state/nmap/{scan_id}/consolidated.json`
- `state/nmap/{scan_id}/next_vectors.json`

sysreport writes:
- `reports/{target}/nmap/{scan_id}/sysreport.yaml`
- `reports/{target}/nmap/{scan_id}/sysreport.json`

## Usage Examples

### Full scan via engine

```bash
python3 engine/main.py --target 10.0.0.1 --workflow recon-inicial
```

### Direct invocation (for testing)

```bash
# Write event file first
mkdir -p events/nmap
cat > events/nmap/test-001.json <<'EOF'
{
  "skill": "nmap",
  "target": "127.0.0.1",
  "scan_id": "test-001",
  "parameters": {
    "ports": "top-100",
    "scan_mode": "syn",
    "timing": 4,
    "iot_scripts": false
  },
  "timestamp": "2026-05-19T12:00:00Z"
}
EOF

# Run main.sh directly
bash skills/nmap/main.sh events/nmap/test-001.json
```

### Step-by-step sub-process testing

```bash
export SCAN_ID="test-001"
export TARGET="127.0.0.1"
export STATE_DIR="state"
export SKILL="nmap"
export PARAM_PORTS="22,80,443"
export PARAM_SCAN_MODE="syn"
export PARAM_TIMING="4"
export PARAM_SKIP_DISCOVERY="false"
export PARAM_IOT_SCRIPTS="false"

# Run individual sub-processes
bash skills/nmap/sub-processes/port-discovery.sh
bash skills/nmap/sub-processes/service-detection.sh
bash skills/nmap/sub-processes/analyzer.sh
bash skills/nmap/sub-processes/sysreport.sh
```

### IoT scan

```bash
python3 engine/main.py --target 10.0.0.50 --workflow recon-inicial
# Or with iot_scripts enabled by editing the workflow or event:
# {"parameters": {"iot_scripts": true, "ports": "all"}}
```

## Sub-Process Details

### port-discovery

Discovers open ports using fast scanning:
- Mode `syn` (default): `sudo nmap -sS -p <ports> -T<timing> <target> -oA <output>`
- Mode `connect`: `nmap -sT -p <ports> -T<timing> <target> -oA <output>`
- Mode `udp`: `sudo nmap -sU -p <ports> -T<timing> <target> -oA <output>`
- Adds `-Pn` when `skip_discovery` is true
- Retries with `-Pn` if initial scan reports host down

### service-detection

Runs service version detection and default scripts on discovered ports:
- `nmap -sV -sC -p <open_ports> -T<timing> <target> -oA <output>`
- Non-SYN modes add the appropriate `-sT` or `-sU` flag

### iot-scripts

Conditional — only runs when `iot_scripts: true`:
- `rtsp-url-brute`: Attempts to enumerate RTSP URLs
- `mqtt-subscribe`: Subscribes to MQTT topics to discover messages
- `modbus-discover`: Discovers Modbus unit IDs and registers
- `bacnet-info`: Enumerates BACnet device info
- Runs on the same discovered ports

### analyzer

Parses nmap XML output to produce:
- **consolidated.json**: Structured result with open ports, services, OS, NSE findings
- **next_vectors.json**: Suggested follow-up skills based on findings
- Cleans up raw XML from the data (keeps path reference)

### sysreport

Generates a human-readable YAML report and a structured JSON report:
- **sysreport.yaml**: Formatted report with all findings
- **sysreport.json**: Machine-readable JSON version
- Written to `reports/{target}/nmap/{scan_id}/`

## Next Vectors

The analyzer generates follow-up suggestions based on detected services:

| Condition | Suggested Skill | Weight | Rationale |
|-----------|----------------|--------|-----------|
| Port 443 open | testssl | 80 | TLS cipher audit |
| Port 80 open | httpx | 80 | HTTP tech detection |
| Port 22 open | ssh-audit | 50 | SSH config audit |
| Multiple services | nuclei | 60 | Vulnerability scan |
| Database ports (3306, 5432, 6379) | db-audit | 70 | Database credential testing |
| Port 8080/8443 open | httpx | 75 | Alternate web service |
| Host down | none | 0 | Stop further recon |

## Error Handling

Each sub-process implements the 3-tier retry strategy:
1. **Tier 1**: Direct retry with same parameters (up to 3 attempts)
2. **Tier 2**: Relaxed mode — add `-Pn` if host appears down, reduce timing
3. **Tier 3**: Record failure with context, mark sub-process as `failed`

If a mandatory sub-process fails irrecoverably, MAIN writes status
`degraded` and stops the pipeline. Optional sub-processes (iot-scripts)
are skipped without affecting overall status.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|------------|-----|
| "sudo: not found" or "permission denied" | SYN scan requires root | Use `connect` mode or run engine as root |
| "Failed to open output file" | State directory missing | Create `state/nmap/` before running |
| Host always shows "down" | ICMP blocked | Set `skip_discovery: true` |
| Service detection slow | Too many ports | Reduce port range or increase timing |
| NSE scripts not running | iot_scripts flag false | Set `iot_scripts: true` |

## Dependencies

- `nmap` (>= 7.0) — network scanning
- `jq` (>= 1.6) — JSON processing
- Optional: `sudo` — required for SYN scan
