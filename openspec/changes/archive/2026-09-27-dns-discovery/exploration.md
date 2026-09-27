# Exploration: dns-discovery (DNS early-discovery phase)

## Executive Summary

Add a `dnsenum` skill as an EARLY DISCOVERY phase in `recon-completo`: a fast
A/NS/MX + AXFR + wordlist brute-force enumeration running in parallel with nmap
port-discovery (no port dependency). Its analyzer consolidates subdomains and —
with a minimal engine change — proposes NEW TARGETS (subdomains) through
`next_vectors.json`, which the existing multi-wave expansion would route into
`exp-<skill>-<anchor>` steps against each subdomain. Today the engine copies the
anchor's targets verbatim (`workflow.py:244`) and dedupes expanded steps by skill
name only (`workflow.py:223-225`), so sub-target propagation is feasible with
~5 lines of change. dnsenum v1.3.1 outputs XML only (`-o`) plus a flat
subdomain list (`--subfile`); dnsrecon is installed and offers native JSON +
crt.sh as a later complement.

## Findings

### 1. dnsenum capabilities (v1.3.1 at /usr/bin/dnsenum)

- Brute force: `-f <wordlist>` (default `/usr/share/dnsenum/dns.txt`, 1505
  entries); `-r` recursion on discovered subdomains with NS records.
- Zone transfer: AXFR is attempted automatically (step 4 of the default
  pipeline, threaded against all NS) — no flag needed; `--dnsserver <srv>` only
  overrides A/NS/MX queries, AXFR/PTR still go to the domain's NS.
- Reverse lookup: on by default; `--noreverse` skips it (recommended for speed —
  big netranges are slow). `-e <regexp>` excludes PTR records.
- WhoIs: `-w` (+ `-d <delay>`) — can generate very large netranges, slow;
  exclude from an early-discovery phase.
- Google scraping: `-s <max>` / `-p <pages>` — unreliable (CAPTCHA/blocking,
  needs http_proxy); exclude from v1.
- Output: `-o <file>` XML (MagicTree-compatible), `--subfile <file>` plain-text
  list of valid subdomains (the ideal raw input for target extraction),
  `--private` includes private IPs, `--nocolor`, `-v` verbose.
- Tuning: `-t <timeout>` defaults to 10s → lower to 3-5s; `--threads <n>`;
  `--enum` == `--threads 5 -s 15 -w` (includes whois — avoid).
- Fast phase invocation:
  `dnsenum --noreverse --threads 20 -t 3 --subfile <subs> -o <out.xml> <domain>`
- Runtime estimate: std enumeration ≈ seconds; brute force of the 1505-name
  wordlist threaded (20 threads, 3s timeout) ≈ 2-6 min depending on resolver.

dnsrecon (installed, Python): native `-j json` output, `-a` AXFR, `-k` crt.sh
certificate transparency, `-z` DNSSEC zone walk, `-D` wordlist brute force,
`-t std|brt|axfr|...`, `--iw` keep going on wildcards, `-f` wildcard filtering.
Tradeoff vs dnsenum: native JSON parsing + more enumeration types, but slower
(Python) and mode-selective; dnsenum is the requested tool for v1, dnsrecon's
JSON/crt.sh is a natural future complement.

### 2. Skill envelope pattern (httpx/ and nikto/ as representatives)

Structure every new skill must follow:

- **Meta-skill**: `skills/<tool>/skill.yaml` (schema: name, version, description,
  main_script, dependencies validated via `command -v`, inputs, outputs,
  next_vectors static, sub_processes) + `skills/<tool>/main.sh` chain runner
  (`run_step` passing SCAN_ID/TARGET/WORKFLOW_SHARED_DIR env — httpx/main.sh:47-64
  chains 4 steps; nikto/main.sh:66-70 chains 3 scans + analyzer + sysreport).
- **Sub-skills** each have `main.sh` sourcing `skills/_shared/envelope.sh`
  (httpx-analyzer/main.sh:38). Helpers (envelope.sh):
  - `write_status(phase, status, progress)` → `state/{SKILL}/{scan_id}/status.json`
  - `write_next_vectors(scan_id, target, host_status, json)` →
    `state/{SKILL}/{scan_id}/next_vectors.json` with shape
    `{scan_id, target, host_status, next_vectors: [{condition, skill, weight, reason}]}`
  - `write_sub_process_result(name, exit_code, stdout, stderr, duration_ms,
    output_file)` → `state/{SKILL}/{scan_id}/sub-processes/{name}.json`
  - `write_to_shared_dir(sub_skill_name, file)` →
    `$WORKFLOW_SHARED_DIR/{sub_skill_name}/` (engine sets
    WORKFLOW_SHARED_DIR=`state/_shared/{base_scan_id}`, workflow.py:304-318)
  - `read_predecessor_output(name, file)` → shared dir first, then
    `state/{name}/{scan_id}/{file}`
- **State contract**: `state/{skill}/{scan_id}/` holding status.json,
  next_vectors.json, consolidated.json (written by the analyzer),
  sub-processes/*.json, and raw tool outputs.
- **Chain for dnsenum**: `dnsenum-scan → dnsenum-parse-results →
  dnsenum-analyzer → dnsenum-sysreport`. For expansion anchoring the analyzer
  MUST be its own workflow step (nikto-style decomposed DAG), because the engine
  reads `state/{anchor.skill}/{scan_id}/next_vectors.json` (workflow.py:191-203)
  with `anchor.skill` = the step's skill name. A pure httpx-style meta-step would
  write next_vectors under the sub-skill's name and be invisible to expansion.

### 3. next_vectors + sub-target propagation (engine)

- `WorkflowEngine._expand_from_anchor` (engine/workflow.py:157-267), invoked
  multi-wave after every completed DAG level (workflow.py:135-151), reads
  `state/{anchor.skill}/{base_scan_id}--{anchor.id}--{target_slug}/next_vectors.json`
  for anchors (YAML `expansion_anchor: true` or level-0 fallback).
- Per vector `{skill, weight, reason}`: skips if the skill is ALREADY a step in
  the workflow (workflow.py:223-225 — blocks httpx/nuclei/nikto proposals, which
  are exactly the natural DNS downstream), verifies via SkillLoader (line 228),
  then creates `exp-{skill}-{anchor.id}` with **the anchor's own targets**
  (line 244: `"targets": list(anchor.targets)`) and `depends_on: [anchor.id]`.
- **Conclusion: next_vectors cannot carry new targets today.** The schema has no
  targets field and no existing analyzer emits target hints (grepped all
  `skills/*-analyzer/main.sh` + hardening-judge; sample state
  next_vectors.json files contain only condition/skill/weight/reason objects).
- **Minimal mechanism** (2 edits, both in `_expand_from_anchor`):
  1. Line 244 → `"targets": vector.get("targets") or list(anchor.targets)`
     (per-vector optional targets list).
  2. Lines 223-225 → dedup on `(skill, targets)` instead of skill name only,
     otherwise every subdomain proposal to httpx/nuclei/nikto is dropped.
- No further plumbing needed: `main.py:_resolve_workflow_target` substitutes
  `{{ target }}` only at load (main.py:206); expanded steps carry literal
  targets that flow straight into `_execute_step`'s per-target loop
  (workflow.py:294-319, scan_id = `base--step--targetslug`, multi-target
  aggregation at 329-339). Multi-target step support already exists.
- CLI: `python3 engine/main.py --target X --workflow recon-completo
  --expand-next-vectors` (main.py:89, 412).

### 4. Workflow insertion point (workflows/recon-completo.yaml, 517 lines)

Current DAG: Level 0a `port-discovery` (anchor) → 0b `service-detection` →
0c `iot-scripts` + `analyzer` (anchor) → 0d `sysreport` → Level 1 whatweb
4-step, testssl 4-step, nuclei 5-step, httpx meta-step, nikto 5-step DAGs →
`hardening-judge` (anchor) → `report-html` (depends on nmap/whatweb/testssl/
nuclei sysreports only).

`expansion.anchor_steps` (lines 59-69): port-discovery, analyzer,
whatweb-analyzer, testssl-analyzer, nuclei-analyzer, hardening-judge.

Insertion (minimal DAG disruption):
- `dnsenum-scan` — `depends_on: []`, runs parallel to port-discovery (DNS does
  not need open ports; it needs the domain, which is the target).
- `dnsenum-analyzer` — `depends_on: [dnsenum-scan]`, `expansion_anchor: true`.
- Optional `dnsenum-sysreport` and/or a `dnsenum-parse` step (scan can parse
  inline, as nmap-port-discovery does).
- Do NOT add dnsenum to report-html's `depends_on` for v1 (generate-report.sh
  tolerates missing sources via prefix resolution; a missing source renders
  "Not run" in the timeline).

### 5. report-html (skills/report-html/sub-processes/generate-report.sh + templates/report.html)

6 sources are wired today: nmap, nuclei, whatweb, testssl, httpx, nikto.

- `resolve_source()` (lines 55-95): shared dir → exact scan_id → prefix glob
  `state/<skill>/<scan_id>--*/consolidated.json` → auto base-prefix.
- Source resolution calls: lines 150-155 (nikto/httpx already there).
- nuclei + nikto special top-50 truncation: lines 168-235;
  `build_source_json()` for the rest: lines 238-241.
- Overall severity loop over the 6 keys: lines 246-264; `source_severity`
  handles a string `severity` or `severity_counts` (lines 132-145).
- `REPORT_DATA` merge with `sources: {nmap, nuclei, whatweb, testssl, httpx,
  nikto}`: lines 279-304.
- Template: per-source `<section id="section-X" style="display:none">`
  (e.g. section-httpx line 745, section-nikto line 769); JS dispatch calls
  `renderX(data.sources.x || {present:false})` (lines 1482-1490); timeline
  `sourceMeta = [{key,label},...]` array (lines 1443-1450).

Adding a 7th `dns` source requires: `resolve_source "dns-analyzer"` (≈line 155),
`DNS_SRC=$(build_source_json "dns" "${DNS_FILE}")` (≈line 241), severity-loop
key `dns`, `--argjson dns "${DNS_OBJ}"` + `dns: $dns` in REPORT_DATA (lines
288/301), a `<section id="section-dns">` + `renderDns()`, one dispatch line, and
one `sourceMeta` entry `{key: 'dns', label: 'DNS Enumeration (dnsenum)'}`.

### 6. Consolidated output shape (report-html contract)

Real examples under state/:
- `state/nuclei-analyzer/d7a3c964--nuclei-analyzer--geosuite-erictelm2m-com/consolidated.json`:
  `{scan_id, target, started_at, severity_counts{critical,high,medium,low,info,unknown},
  total_matched, findings[], templates_loaded, raw_jsonl, partial, next_vectors}`
  (18 findings).
- `state/nmap-analyzer/3291720d--analyzer--geosuite-erictelm2m-com/consolidated.json`:
  `{scan_id, target, host_status, open_ports[], port_count, fingerprints,
  os_detection, nse_findings, raw_xml, next_vectors, partial, started_at}`.

Report generator only *requires*: `present` (injected), a severity signal
(string `severity` or `severity_counts`), and `started_at`; everything else is
rendered by template JS per source. Suggested `dns-analyzer` contract:
`{scan_id, target, started_at, domain, subdomains[{name, ip, source}],
subdomain_count, ns[], mx[], zone_transfer{attempted, success, records[]},
severity, next_vectors, partial}`.

## Recommended Scope (v1)

1. **dnsenum skill pipeline** (scan → parse → analyzer → sysreport) following
   the envelope pattern, decomposed in the workflow (analyzer as its own
   `expansion_anchor` step):
   - `dnsenum-scan`: `dnsenum --noreverse --threads 20 -t 3 --subfile ... -o ... <domain>`.
   - `dnsenum-parse-results`: XML → JSON (subdomains list + NS/MX + AXFR records).
   - `dnsenum-analyzer`: severity + consolidated.json + next_vectors proposing
     httpx/nuclei against discovered subdomains.
   - `dnsenum-sysreport`: YAML/JSON under reports/.
2. **Minimal engine change** for sub-target routing (2 edits in
   `_expand_from_anchor`: per-vector `targets` + (skill,targets) dedup) +
   optional `targets` passthrough in `write_next_vectors`. This IS the point of
   the change ("subdomains become new targets"), it is ~5 lines, and is testable
   with a dry-run + a real small-target run.
3. **Workflow insertion**: dnsenum-scan at level 0 (depends_on []) +
   dnsenum-analyzer (anchor) + sysreport; anchors list updated.
4. **report-html**: dns source as 7th source (label "DNS Enumeration (dnsenum)").

Deferred to later changes: dnsrecon crt.sh/DNSSEC integration, reverse-lookup
phases, per-subdomain deep-chaining beyond one expansion wave, wildcard
dedup hardening.

## Risks

- Brute-force runtime: 1505-name wordlist × resolvers ≈ minutes; add resolver
  rate-limit/timeout params and make the wordlist a parameter.
- Google scraping excluded from v1 (unreliable/blockable).
- Wildcard-DNS noise: dnsenum has no wildcard filter (dnsrecon has `--iw`/`-f`);
  guard in parse or analyzer.
- Expansion explosion: N subdomains × (httpx+nuclei+…) can exceed
  `max_expansions: 10`; cap per-vector targets and rely on existing caps.
- report-html shared-dir race: expanded per-subdomain analyzers overwrite the
  same `WORKFLOW_SHARED_DIR/<skill>/consolidated.json` (last writer wins);
  v1 report resolution stays root-target-scoped, so impact is limited to
  shared-dir consumers — document it.
- Relaxing the skill-name dedup changes existing expansion behavior; verify with
  a dry-run + regression run before enabling.

## Ready for Proposal

Yes, for the scope described (full dnsenum pipeline + minimal engine change +
workflow insertion + report-html dns source). Orchestrator should tell the user:
v1 includes a small engine change to route subdomains as targets; without it the
DNS analyzer can only report subdomains, not drive them into downstream scans.