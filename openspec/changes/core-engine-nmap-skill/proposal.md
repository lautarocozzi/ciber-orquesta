# Proposal: Core Engine + Nmap Skill

## Intent

Establish foundational architecture for a custom attack-vector orchestration platform. Greenfield project at `/home/kali` — scaffolding, core engine (event-bus-on-filesystem), and the first skill (nmap) to set the pattern all future skills follow.

## Scope

**In:**
1. Directory structure: `engine/`, `skills/`, `activos/`, `workflows/`, `reports/`, `notifications/`
2. `git init` in `/home/kali`
3. Install apt deps: nuclei, httpx-toolkit, testssl.sh, ffuf, jq, gvm-tools
4. Install Python deps: PyYAML, requests, jinja2, rich, aiohttp, markdown
5. nmap skill definition: `skills/nmap/skill.yaml` + `skills/nmap/SKILL.md`
6. Core Engine (Python): skill loader, event bus, MAIN manager, sub-process orchestration, 3-tier rollback
7. sysreport format + YAML generator
8. First workflow: `workflows/recon-inicial.yaml`

**Out:** Web dashboard, MQTT integration, other skills, CI/CD, notifications, auth bypass skills, multi-target parallel scanning — all deferred.

## Capabilities

### New Capabilities
- `engine-core`: Skill loader (scans `skills/` for `skill.yaml`), filesystem event bus (`events/{skill}/`, `state/{skill}/`), sub-process manager with 3-tier rollback, DAG state machine
- `sysreport`: Per-scan machine-readable YAML report format + generator with schema validation
- `skill-nmap`: Nmap skill with MAIN wrapper + 4 sub-processes (port-discovery, service-detection, analyzer, sysreport)
- `workflow-recon-inicial`: First workflow definition — nmap single-target scan with output to sysreport

### Modified Capabilities
None — greenfield project, no existing specs.

## Approach

Python engine + shell skill wrappers. Event-bus-on-filesystem:
- Engine writes `events/{skill}/{scan_id}.json` → MAIN processes pick up via inotify/polling
- Sub-processes write state to `state/{skill}/{scan_id}/` (status, findings, next_vectors)
- nmap sub-process pipeline: port-discovery → service-detection → analyzer → sysreport
- Rollback: 3-tier retry (same params → relaxed params → degraded), critical failures cascade-stop
- Architecture upgradeable to MQTT later without changing skill contracts

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `engine/` | New | Core orchestrator (Python 3) |
| `skills/nmap/` | New | Skill def YAML + shell wrappers |
| `workflows/` | New | Workflow DAG YAML definitions |
| `reports/` | New | sysreport output directory |
| `activos/` | New | Target definition YAML files |
| `notifications/` | New | Stub directory (deferred) |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Python deps fail to install | Low | Prefer `apt python3-*` packages; pip as fallback |
| State file race conditions | Med | `flock` for exclusive writes + atomic rename pattern |
| Engine crash mid-workflow | Med | State on disk = recoverable; replay event files to resume |
| No test infrastructure | High | Execution-based golden tests on sysreport output |

## Rollback Plan

1. `git reset --hard HEAD` to discard all new files
2. `pip uninstall -y pyyaml requests jinja2 rich aiohttp markdown`
3. `apt remove -y nuclei httpx-toolkit testssl.sh ffuf jq gvm-tools`
4. `rm -rf engine/ skills/ workflows/ reports/ activos/ notifications/`
5. Verify: `ls /home/kali` — only dotfiles and pre-existing dirs remain

## Dependencies

- **apt**: nuclei (3.8.0), httpx-toolkit (1.9.0), testssl.sh (3.2.2), ffuf (2.1.0), jq (1.8.1), gvm-tools (25.4.6)
- **pip**: PyYAML, requests, jinja2, rich, aiohttp, markdown
- **Pre-installed**: nmap 7.98 ✅, Python 3.14.5 ✅

## Success Criteria

- [ ] All project directories created with correct structure
- [ ] All deps installed; `command -v` passes for each apt tool; `python3 -c "import <pkg>"` passes for each pip package
- [ ] Engine loads nmap skill from `skills/nmap/skill.yaml` with validated schema
- [ ] Engine writes event file → nmap MAIN picks it up → sub-processes execute → state files written with correct structure
- [ ] sysreport YAML generated for a real nmap scan, schema-valid
- [ ] `workflows/recon-inicial.yaml` loadable by engine
- [ ] `git status` shows clean working tree with all new files tracked
