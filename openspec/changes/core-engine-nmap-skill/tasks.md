# Tasks: Core Engine + Nmap Skill

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~700-900 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1: Foundation + Engine Core \| PR 2: Nmap Skill + Integration |
| Delivery strategy | auto-forecast |
| Chain strategy | pending |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR |
|------|------|-----------|
| 1 | Foundation + Engine Core (git init, deps, state.py, event_bus.py, skill_loader.py, main_manager.py, workflow.py, main.py) | PR 1 |
| 2 | Nmap Skill + Integration (skill.yaml, SKILL.md, main.sh, 5 sub-process scripts, recon-inicial.yaml, execution verification) | PR 2 |

## Phase 1: Foundation

- [x] 1.1 `git init` + create dirs: `engine/`, `skills/nmap/sub-processes/`, `activos/`, `workflows/`, `reports/`, `state/`, `events/`, `notifications/` with `.gitkeep`
- [x] 1.2 Install apt deps: nuclei, httpx-toolkit, testssl.sh, ffuf, jq, gvm-tools; verify via `command -v`
- [x] 1.3 Install pip deps: PyYAML, requests, jinja2, rich, aiohttp, markdown; verify `python3 -c "import <pkg>"`
- [x] 1.4 Create `activos/example.yaml` — target definition with ip, hostname, tags, environment

## Phase 2: Engine Core

- [x] 2.1 Create `engine/requirements.txt` + `engine/__init__.py`
- [x] 2.2 Create `engine/state.py` — `read_state()`/`write_state()` with `flock` + atomic rename
- [x] 2.3 Create `engine/event_bus.py` — write `events/{skill}/{scan_id}.json`; inotify + polling watcher on `state/`
- [x] 2.4 Create `engine/skill_loader.py` — scan `skills/*/skill.yaml`, validate schema, `command -v` deps, cache
- [x] 2.5 Create `engine/main_manager.py` — spawn MAIN subprocesses, track PIDs, 3-tier retry logic
- [x] 2.6 Create `engine/workflow.py` — read `workflows/*.yaml`, resolve DAG, dispatch steps
- [x] 2.7 Create `engine/main.py` — argparse (--target, --workflow), load skills, event loop, execute workflow

## Phase 3: Nmap Skill

- [ ] 3.1 Create `skills/nmap/skill.yaml` — name, version, deps, inputs, outputs, next_vectors, sub_processes
- [ ] 3.2 Create `skills/nmap/SKILL.md` — AI/human docs with args table, sub-process flow, examples
- [ ] 3.3 Create `skills/nmap/main.sh` — read event JSON, run sub-process pipeline, write `status.json` per phase
- [ ] 3.4 Create `skills/nmap/sub-processes/port-discovery.sh` — `nmap -p- -oA`
- [ ] 3.5 Create `skills/nmap/sub-processes/service-detection.sh` — `nmap -sV -sC` on discovered ports
- [ ] 3.6 Create `skills/nmap/sub-processes/iot-scripts.sh` — conditional RTSP/MQTT/Modbus NSE scripts
- [ ] 3.7 Create `skills/nmap/sub-processes/analyzer.sh` — parse nmap output, build `consolidated.json` + next_vectors
- [ ] 3.8 Create `skills/nmap/sub-processes/sysreport.sh` — invoke engine sysreport generator with scan data

## Phase 4: Integration

- [ ] 4.1 Create `workflows/recon-inicial.yaml` — single-step nmap DAG, target from activos, top-1000 SYN defaults
- [ ] 4.2 Verify: engine against localhost, confirm `state/status.json` transitions + `reports/sysreport.yaml` valid
- [ ] 4.3 Verify: 3-tier rollback with unreachable target, confirm retries → degraded/failed cascade stop
- [ ] 4.4 Verify: crash recovery — kill engine mid-scan, restart, confirm resume from persisted state files
- [ ] 4.5 `git add . && git commit -m "feat: core engine + nmap skill"`
