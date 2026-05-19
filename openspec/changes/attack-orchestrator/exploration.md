# Exploration: Attack Vector Orchestration Platform

## Current State: System Audit Results

### Tools Installation Matrix

| Tool | Status | Version | Source |
|------|--------|---------|--------|
| **nmap** | ✅ INSTALLED | 7.98 | apt (613 NSE scripts) |
| **masscan** | ✅ INSTALLED | 1.3.2 | apt |
| **sslscan** | ✅ INSTALLED | 2.1.5 | apt |
| **whatweb** | ✅ INSTALLED | 0.6.3 | apt |
| **nikto** | ✅ INSTALLED | 2.6.0 | apt |
| **gobuster** | ✅ INSTALLED | 3.8.2 | apt |
| **wpscan** | ✅ INSTALLED | 3.8.28 | apt |
| **dirb** | ✅ INSTALLED | — | apt |
| **wfuzz** | ✅ INSTALLED | — | apt |
| **sqlmap** | ✅ INSTALLED | — | apt |
| **hydra** | ✅ INSTALLED | — | apt |
| **john** | ✅ INSTALLED | — | apt |
| **metasploit** | ✅ INSTALLED | framework | apt |
| **exploitdb** | ✅ INSTALLED | — | apt |
| **patator** | ✅ INSTALLED | 1.0 | apt |
| **proxychains4** | ✅ INSTALLED | 4.17 | apt |
| **ZAP** | ✅ INSTALLED | 2.17.0 | apt (zap.sh) |
| **GVM/OpenVAS** | ✅ RUNNING | — | Services active: gvmd, ospd-openvas, notus-scanner |
| **nuclei** | ⚡ APT AVAILABLE | 3.8.0 | `apt install nuclei` |
| **httpx** | ⚡ APT AVAILABLE | 1.9.0 | `apt install httpx-toolkit` |
| **testssl.sh** | ⚡ APT AVAILABLE | 3.2.2 | `apt install testssl.sh` |
| **ffuf** | ⚡ APT AVAILABLE | 2.1.0 | `apt install ffuf` |
| **jq** | ⚡ APT AVAILABLE | 1.8.1 | `apt install jq` |
| **gvm-tools** | ⚡ APT AVAILABLE | 25.4.6 | `apt install gvm-tools` |
| **defectdojo** | ⚡ APT AVAILABLE | 2.37.3 | Full orchestration + reporting platform |
| **katana** | ❌ NOT AVAILABLE | — | Needs Go or manual install |
| **dirsearch** | ❌ NOT AVAILABLE | — | pip install |
| **tor** | ❌ NOT AVAILABLE | — | apt install tor |
| **feroxbuster** | ❌ NOT AVAILABLE | — | Needs Go or cargo |

### Surprising Infrastructure Already Present

- **PostgreSQL 18** running (gvmd backend)
- **Redis** running (OpenVAS cache)
- **Mosquitto MQTT broker** running (!!)
- **GVM/OpenVAS fully operational** — gvmd, ospd-openvas, notus-scanner all active
- **Python 3.14.5** available but with minimal libraries (no yaml, requests, jinja2, rich)
- **Node + npm** available via linuxbrew
- **Go NOT installed** but `golang-go` available via apt
- **42GB free disk**, 79G total

### Python Library Gap (for Engine + Reports)

| Library | Needed For | Status |
|---------|-----------|--------|
| PyYAML | skill.yaml parsing | ❌ |
| requests | API calls, webhooks | ❌ |
| jinja2 | HTML report templates | ❌ |
| rich | CLI output formatting | ❌ |
| aiohttp | Async task execution | ❌ |
| markdown | MD report generation | ❌ |

---

## Affected Areas

Since this is a greenfield project (no existing codebase), the "affected areas" are the new project structure to be created:

- `engine/` — Core orchestration engine (Python or Bash)
- `skills/` — Skill definitions and wrappers per tool
- `activos/` — Target/environment definitions (YAML)
- `workflows/` — Workflow DAG definitions
- `reports/` — Report generation (sysreport, vector, global)
- `notifications/` — Telegram/mail dispatch

---

## Skill Taxonomy (Based on Real Tool Availability)

### Group 1: Reconnaissance (INSTALLED)
- **nmap** — Port discovery, service detection, OS fingerprinting, NSE vuln scripts
- **masscan** — Fast port scanning (wide ranges, internet-scale)
- **httpx** — HTTP service probing, tech detection (install needed)
- **whatweb** — Web tech fingerprinting (INSTALLED)

### Group 2: Web Application Scanning (MIXED)
- **nuclei** — Template-based vulnerability scanner (install needed)
- **ZAP** — Full-featured web app scanner (INSTALLED via zap.sh, daemon mode possible)
- **nikto** — Web server scanner (INSTALLED)
- **gobuster** — Directory/file brute force (INSTALLED)
- **ffuf** — Fast web fuzzer (install needed)
- **wfuzz** — Web fuzzer (INSTALLED)
- **dirb** — Directory brute force (INSTALLED)

### Group 3: SSL/TLS (MIXED)
- **testssl.sh** — TLS/SSL cipher/protocol checking (install needed)
- **sslscan** — SSL/TLS scanner (INSTALLED)

### Group 4: Vulnerability & CMS (INSTALLED)
- **wpscan** — WordPress vuln scanner (INSTALLED)
- **sqlmap** — SQL injection automation (INSTALLED)
- **nikto** — Generic web server vuln scanner (INSTALLED)
- **metasploit** — Exploit framework (INSTALLED)
- **searchsploit/exploitdb** — Exploit lookup (INSTALLED)

### Group 5: Network & Proxy (INSTALLED)
- **proxychains4** — Proxy chain for anonymized scanning (INSTALLED)
- **hydra** — Network login cracker (INSTALLED)

### Group 6: Infrastructure (RUNNING)
- **GVM/OpenVAS** — Full vulnerability management (SERVICES RUNNING)
- **gvm-tools** — Python API for GVM control (install needed)

### Group 7: Intelligence (CUSTOM)
- **Analyzer** — AI-driven fingerprint → next_vectors table
- **Fingerprint Matcher** — Service version → CVE mapping

---

## Approaches: Core Engine Architecture

### Option A: Event-Driven (MQTT Pub/Sub)

**How it works:**
- Core Engine publishes scan targets to MQTT topics (e.g., `orchestrator/nmap/scan`)
- Each MAIN process subscribes to its topic, processes, publishes results back (`responses/nmap/done`)
- Sub-processes communicate via state files on disk (JSON), NOT additional MQTT routing
- MQTT broker already running (Mosquitto service active)
- Engine tracks DAG state via a state machine (Python/asyncio or shell)

**Pros:**
- Mosquitto already installed and running — zero additional infrastructure
- Natural decoupling: MAIN processes can be stopped/restarted independently
- Easy to add new skills: just subscribe to a new topic
- No polling, no busy-waiting
- DAG-level parallelism is trivial (fan-out via MQTT topics)
- Scales to distributed workers (MQTT over network)

**Cons:**
- Adds MQTT client dependency to every skill (Python `paho-mqtt` or `mosquitto_pub`)
- Debugging async flows is harder than linear scripts
- State reconstruction requires replaying MQTT messages or relying on disk state
- Overkill if the system stays single-host with <10 concurrent processes
- Skill MAIN processes need to handle connection drops

**Effort:** Medium (requires MQTT client integration but leverages existing infra)

### Option B: Pipeline (State-File DAG with Direct Execution)

**How it works:**
- Core Engine reads workflow YAML → spawns MAIN processes sequentially/by dependency
- Each MAIN process writes results to a shared JSON state file
- The Engine checks dependency completion via state file presence/age
- Sub-processes are child processes of MAIN, also writing to state files
- Engine uses `inotify` or polling to detect completion
- Everything is shell + Python scripts

**Pros:**
- Zero external dependencies (no MQTT, no Redis)
- Simplest to debug: everything is a linear shell script
- State is always on disk — easy to inspect, replay, recover
- Natural fit for bash-first environment
- Easy rollback: kill PID chain, remove partial state files

**Cons:**
- Coupling: Engine needs to know exactly which MAIN processes exist
- Polling for completion is wasteful (inotify helps but is Linux-specific)
- Parallelism requires manual `&` / `wait` management or Python asyncio
- Adding new skills requires updating the Engine's dispatcher
- State file contention on concurrent writes (need locking)
- Single point of failure (Engine crash = lost workflow state)

**Effort:** Low (direct execution, minimal infra)

### Option C (Hybrid Recommendation): Lightweight Event Bus over State Files

**How it works:**
- Core Engine uses a **simple JSON-based event bus** (files in `events/` directory watched by MAIN processes)
- Engine writes `events/nmap/scan-001.json` → MAIN process picks it up via `inotify` or periodic scan
- MAIN writes results to `state/nmap/scan-001.json` → Engine detects completion
- For parallel fan-out: Engine writes multiple event files, MAIN processes pick them concurrently
- This is "event-driven by filesystem" — no MQTT dependency but same decoupling benefits

**Pros:**
- Zero infra dependencies (no MQTT, no Redis)
- Decoupled like MQTT but transparent like state files
- State is always on disk, always inspectable
- Adding a skill = creating a MAIN watcher for `events/{skill}/` + writing `state/{skill}/`
- Easy recovery: replay by copying event files
- File locking via `flock` for concurrent writes
- Can later replace filesystem with MQTT without changing skill contracts

**Cons:**
- `inotify` doesn't work over NFS (irrelevant for single-host)
- Polling fallback adds latency
- File cleanup needed to avoid disk bloat
- Race conditions if MAIN processes scan event dir faster than Engine writes

**Effort:** Low-Medium (simple pipe system, easy to implement in bash or Python)

---

## Recommendation

**Option C: Lightweight Event Bus over State Files** — with Python as the engine language.

**Why Python for the engine:**
1. Better JSON/YAML handling than bash
2. `asyncio` for concurrent sub-process management
3. `inotify` bindings via `watchfiles` or `pyinotify`
4. Rich templating for reports (jinja2)
5. The bottleneck is tool execution time (seconds/minutes), not Python overhead

**But shell wrappers for tools:**
- Each MAIN process should be a **shell script** that wraps the CLI tool
- The engine invokes these scripts, they don't need to be Python
- This keeps the "CLI tools manageable by AI" requirement satisfied

**Why not full MQTT now:**
- Mosquitto IS available but adds complexity during the MVP phase
- The event-bus-on-filesystem pattern can be upgraded to MQTT later WITHOUT changing skill contracts (skills read/write JSON to a directory, the directory becomes MQTT topics later)

**Why not defectdojo:**
- DefectDojo is a full orchestration platform available in apt, but it's Django-based and opinionated
- Building a custom system gives flexibility for the AI/skill-driven architecture the user wants
- However, DefectDojo could be integrated in v2 for report aggregation

---

## Sub-Process Architecture Pattern

### State Contract
Each MAIN process manages:
```
state/{skill}/{scan_id}/
├── status.json         # {phase: "port-discovery"|"service-detection"|"analyzer"|"sysreport", 
                        #  status: "running"|"done"|"failed", progress: 0-100}
├── sub-processes/      # One file per sub-process
│   ├── port-discovery.json   # {stdout, stderr, exit_code, duration, output_file}
│   ├── service-detection.json
│   ├── iot-scripts.json
│   ├── analyzer.json
│   └── sysreport.json
├── consolidated.json   # MAIN's view: open_ports, services, findings
└── next_vectors.json   # {suggested: ["testssl", "httpx", ...], priority: "high"}
```

### Rollback Strategy
- **3-tier retry**: Sub-process fails → retry 1x with same params → retry 1x with relaxed params → mark as `degraded`
- **Critical sub-process failure** (e.g., port-discovery fails in nmap): MAIN marks scan as `falló`, writes error, stops downstream
- **Non-critical failure** (e.g., analyzer can't fingerprint): MAIN continues, writes `degraded` status, continues with partial results
- **Engine-level rollback**: Engine marks workflow state, skips dependent DAG nodes, notifies admin

### Skill Loading
```
skills/{name}/
├── skill.yaml      # Structured: inputs, outputs, deps, install_cmd, main_script
└── SKILL.md        # Human/AI readable: purpose, args, expected output, examples
```

Engine loads skills by:
1. Scan `skills/` directory for `skill.yaml` files
2. Validate schema (name, version, main_script, dependencies, inputs, outputs)
3. Verify tool dependencies (check `command -v` for required CLI tools)
4. Cache skill state in memory

---

## Report Architecture (3-Tier)

### Tier 1: sysreport — Per-vector YAML/JSON
```
reports/{target}/{skill}/{scan_id}/sysreport.yaml
```
Single source of truth for one scan execution. Machine-readable, structured YAML.
Contains: raw findings, exit codes, durations, warnings, errors.

### Tier 2: Vector Report — AI-friendly Markdown
```
reports/{target}/{skill}/report.md
```
Generated by MAIN process from sysreport. Sections: Summary, Findings, Technical Details, Recommendations.
Consumed by AI Analyzer and human operators.

### Tier 3: Global Report — HTML Info + Professional MD
```
reports/{target}/global/
├── index.html      # Visual: timeline, severity charts, asset map
└── report.md       # Professional markdown for printing/sharing
```
Generated by Core Engine after ALL workflow steps complete.
Timeline shows execution order, duration, results per skill.
HTML can use Chart.js or similar for visualization.

---

## Risks (From Actual System Probing)

| # | Risk | Severity | Mitigation |
|---|------|----------|------------|
| 1 | **No test infrastructure** | HIGH | All verification is execution-based. Must create golden-file tests for report output and mock targets for integration tests |
| 2 | **Python dependency desert** | HIGH | Engine can't parse YAML or send HTTP without installing 5+ pip packages. Bundle a `requirements.txt` or use `apt install python3-yaml python3-requests python3-jinja2` |
| 3 | **Go tools need install** | MEDIUM | nuclei, httpx, ffuf must be installed. They're in apt but need `apt install`. katana needs Go compilation |
| 4 | **testssl.sh needs install** | LOW | `apt install testssl.sh` — one command |
| 5 | **ZAP headless untested** | MEDIUM | ZAP is installed but headless/daemon mode needs verification. `zap.sh -daemon` may need display configuration |
| 6 | **Rate limiting / WAF bypass** | MEDIUM | No built-in delay system. Must add configurable rate limiting and proxy rotation (proxychains config exists but tor not running) |
| 7 | **Report storage growth** | LOW | Full scans (nmap -p- + NSE) generate MBs of output. Need retention policy and auto-cleanup |
| 8 | **Proxychains config exists but no tor** | LOW | tor not installed. proxychains4.conf points to `127.0.0.1:9050` which will fail. Need to install tor OR update config |
| 9 | **No git repo** | LOW | Can't version-track skill definitions or report changes. Suggest `git init` at project start |
| 10 | **jq not installed** | LOW | Needed for JSON parsing in shell scripts. `apt install jq` |

---

## Ready for Proposal
**YES**

### What the Proposal Should Cover
1. Project scaffolding (directory structure, git init)
2. Install all missing tool dependencies (nuclei, httpx, testssl.sh, ffuf, jq, gvm-tools, Python libs)
3. Core Engine prototype with event-bus-on-filesystem pattern
4. First skill: nmap (already modeled with MAIN + sub-processes)
5. Report generation: start with sysreport YAML → build up
6. CI/CD pipeline spec (GitHub Actions or GitLab CI for scheduled scans)
7. Telegram notification integration

### What to Tell the User
- **The tooling landscape is solid.** 15+ security tools already installed, and the missing ones (nuclei, httpx, testssl.sh, ffuf) are one `apt install` away.
- **PostgreSQL, Redis, AND Mosquitto MQTT are already running** on this system — the infrastructure is richer than expected.
- **The event-bus-on-filesystem approach** gives the flexibility of event-driven architecture without adding MQTT complexity during MVP.
- **Python for the engine, shell scripts for skill wrappers** — both the AI and the developer can read and modify everything.
- **GVM/OpenVAS is fully operational** and can be integrated as a "vulnerability-scan" skill using gvm-tools.
