# Design: Core Engine + Nmap Skill

## Technical Approach

Python 3 engine with asyncio + filesystem event bus. Engine writes events as JSON to
`events/{skill}/`, MAIN shell scripts pick them up via inotify/polling, write state to
`state/{skill}/{scan_id}/`. The nmap skill sets the wrapper pattern: `main.sh` runs
sub-processes sequentially (port-discovery → service-detection → [iot-scripts] →
analyzer → sysreport), protected by 3-tier retry (same params → relaxed → degraded).
sysreport generator validates output against schema and writes dual YAML+JSON.

## Architecture Decisions

| Decision | Choice | Alternatives | Rationale |
|----------|--------|-------------|-----------|
| Engine language | Python 3 | Bash, Go | JSON/YAML handling, asyncio for sub-process, jinja2. Tool execution time dominates — Python overhead irrelevant |
| Event mechanism | Filesystem JSON | MQTT (already running) | Zero infra dep, transparent state on disk, upgradable to MQTT later — events/{skill}/ becomes a topic |
| Skill wrapper | Shell scripts | Python wrappers | AI-manageable, zero deps, CLI tools are shell-native. Engine invokes `main.sh` |
| Locking | `flock` + atomic rename | sqlite, redis | POSIX-native, no extra deps. Atomic rename (`write tmp → mv`) prevents partial reads |
| Event detection | inotify + polling fallback | Pure polling | inotify is instant; polling fallback avoids inotify limits and NFS issues |
| Retry architecture | 3-tier in MAIN | Engine-level retry | Decentralized — MAIN knows its tools best. Engine only sees final status |
| State recovery | On-disk replay | In-memory only | Crash-safe: engine reads existing state files on restart, resumes incomplete scans |

## Data Flow

```
Engine                        Filesystem                       MAIN (nmap)
  │                              │                                │
  ├─ writes ───────────► events/nmap/scan-001.json ──────────►  │(inotify)
  │                              │                                │
  │                         (MAIN detects event)                  │
  │                              │                                ├─ port-discovery
  │                              │                                ├─ service-detection
  │                              │                                ├─ [iot-scripts]
  │                              │                                ├─ analyzer
  │                              │                                └─ sysreport
  │                              │  state/nmap/scan-001/              │
  │  ◄── inotify/poll ───       │  ├─ status.json                    │
  │  on status.json ◄─────────  │  ├─ sub-processes/*.json           │
  │                              │  └─ consolidated.json              │
  │                              │                                    │
  ├─ reads ───────────► reports/{target}/nmap/{scan_id}/              │
  │                     ├─ sysreport.yaml                             │
  │                     └─ sysreport.json                             │
```

## File Changes (ALL NEW — greenfield, 18 files)

| File | Description |
|------|-------------|
| `engine/engine.py` | Entry point: args → load skills → run workflow |
| `engine/skill_loader.py` | Scan `skills/*/skill.yaml`, validate schema, `command -v` deps |
| `engine/event_bus.py` | Write event JSON, watch `state/` via inotify + polling |
| `engine/process_manager.py` | Spawn MAIN scripts, manage lifecycle, 3-tier rollback |
| `engine/workflow_engine.py` | Read `workflows/*.yaml`, resolve DAG, dispatch steps |
| `engine/sysreport.py` | Generate validated YAML+JSON reports |
| `engine/requirements.txt` | pyyaml, requests, jinja2, rich, aiohttp, markdown |
| `skills/nmap/skill.yaml` | Metadata, inputs/outputs, sub-process list, next_vectors |
| `skills/nmap/SKILL.md` | AI-readable docs: purpose, args, flow, examples |
| `skills/nmap/main.sh` | MAIN wrapper: read event, orchestrate sub-processes, write state |
| `skills/nmap/sub-processes/port-discovery.sh` | `nmap -p- -oA {target}` |
| `skills/nmap/sub-processes/service-detection.sh` | `nmap -p $PORTS -sV -sC -oA` |
| `skills/nmap/sub-processes/iot-scripts.sh` | Conditional RTSP/MQTT/Modbus NSE |
| `skills/nmap/sub-processes/analyzer.sh` | Parse results, build next_vectors |
| `skills/nmap/sub-processes/sysreport.sh` | Call engine/sysreport.py with scan data |
| `workflows/recon-inicial.yaml` | Single-step DAG: nmap → sysreport |
| `activos/default.yaml` | Example target definition |
| `notifications/.gitkeep` | Stub (deferred) |

## Interfaces / Contracts

### Event JSON (`events/{skill}/{scan_id}.json`)
```json
{"skill":"nmap","target":"10.0.0.1","scan_id":"scan-001",
 "parameters":{"ports":"top-1000","scan_mode":"syn","timing":4,"iot_scripts":false},
 "timestamp":"2026-05-19T12:00:00Z"}
```

### State (`state/{skill}/{scan_id}/`)
- `status.json`: `{phase, status, progress, pid, started_at}`
- `sub-processes/{name}.json`: `{stdout, stderr, exit_code, duration, output_file}`
- `consolidated.json`: `{open_ports[], services[], findings[], next_vectors[]}`

### skill.yaml Schema
```yaml
name: nmap                     # required
version: "1.0.0"               # required
description: "Port scan + service detection"
main_script: "skills/nmap/main.sh"               # required
dependencies: [nmap, jq]        # command -v check
inputs:                         # map of name → {type, required, default, description}
  target: {type: string, required: true}
  ports: {type: string, default: "top-1000"}
  scan_mode: {type: enum, values: [syn,connect,udp], default: syn}
outputs:                        # map of name → {type, description}
  host_status: {type: string}
  open_ports: {type: list}
next_vectors:                   # optional
  - condition: "port 443 open"
    skill: testssl
    weight: 80
sub_processes: [port-discovery, service-detection, iot-scripts, analyzer, sysreport]
```

## Testing Strategy (Execution-Based)

| Layer | What | Approach |
|-------|------|----------|
| Integration | Full scan pipeline | Run engine against `localhost`, verify state files + sysreport path exist with correct JSON/YAML structure |
| Integration | 3-tier rollback | Point nmap at unreachable host; verify status transitions through retries → "failed" or "degraded" |
| Integration | Event dispatch | Engine writes event → MAIN detects via inotify → verify sub-processes produce state files |
| Integration | Workflow DAG | Load `recon-inicial.yaml`, verify no blockers resolved, step executes |
| E2E | Golden file | Full nmap scan on `127.0.0.1`, capture sysreport.yaml, diff structure (not content) against expected schema |
| E2E | Crash recovery | Kill engine mid-scan, restart, verify it resumes from persisted state files |

No unit tests — Python mocking would not validate real tool execution. All verification is
live execution against controlled targets.
