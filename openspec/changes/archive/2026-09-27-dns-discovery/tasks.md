# Tasks: DNS early discovery — sub-target re-use loop (dns-discovery)

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~600–650 (engine ≈40, skills ≈450, workflow ≈35, report-html ≈130) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1: engine → PR 2: dnsenum skills + workflow → PR 3: report-html |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Engine sub-target routing (`_expand_from_anchor` A–D) | PR 1 | Standalone; verify dry-run + no-targets regression |
| 2 | dnsenum skill family + recon-completo insertion | PR 2 | Base = PR 1 branch; verify bash -n + standalone chain run |
| 3 | report-html dual-result (dns source, SUBDOMAINS, children) | PR 3 | Base = PR 2 branch; verify fixture runs + "Not run" tolerance |
| 4 | Dry-run expansion preview hook (gap closure, tasks 1.7–1.8) | PR 6 | Base = PR 3 branch; engine-only; verify preview==runtime parity |

Tool prerequisites: dnsenum >= 1.3.1 (`/usr/bin/dnsenum`), jq >= 1.8, python3, `/usr/share/dnsenum/dns.txt`.

## Phase 1: Engine sub-target routing (engine/workflow.py)

- [x] 1.1 Add `import hashlib` + `_targets_key(targets)`: sha1 of `"|".join(sorted(targets, key=lambda t: (t.lower(), t)))`, first 8 hex chars.
- [x] 1.2 Change A (~L244): `proposed = vector.get("targets")`; keep only `isinstance(t, str) and t.strip()`; `new_targets = list(anchor.targets)` when none valid, else `sorted(valid, key=lower)[:max_per_vec]`; cap `int(workflow.expansion.get("max_targets_per_vector", 10))`.
- [x] 1.3 Change B (~L223): no-targets path keeps existing skill-name skip verbatim; target-carrying path dedups on `(skill_name, _targets_key(new_targets))` vs existing steps and BYPASSES the static-skill name check. Confirm: `targets` bypass of static check already user-approved.
- [x] 1.4 Change C (~L236): `new_step_id = f"exp-{skill_name}-{anchor.id}-{_targets_key(new_targets)}"`; keep `workflow.get_step(new_step_id)` already-added skip.
- [x] 1.5 Change D (~L252): `try: exp_timeout = int(os.environ.get("STEP_TIMEOUT_SECONDS", "7200")) except ValueError: exp_timeout = 7200`; replace hardcoded 480.
- [x] 1.6 Verify: `python3 -m py_compile engine/workflow.py`; `python3 engine/main.py --help`; dry-run `--target <domain> --workflow recon-completo --expand-next-vectors --dry-run` shows exp steps with subdomain targets; no-targets fixture → step count/targets/skip rules identical to pre-change.
- [x] 1.7 (PR 6, gap closure) Extract the shared expansion logic out of `WorkflowEngine._expand_from_anchor` into module-level helpers in `engine/workflow.py` — `_target_slug`, `_anchor_steps_for`, `_anchor_next_vectors`, `_build_expanded_step` — and add `preview_expansion(workflow, skill_loader) -> List[WorkflowStep]`. Runtime and dry-run MUST use the same anchor selection, vector resolution and step construction; a preview that computed its own plan could drift from runtime and lie about the workflow. Hook lives strictly inside the `if dry_run:` block of `run_scan()` and only runs when `expand_next_vectors` is set: prints the static plan, then `Expanded steps (would run after execution):` with the `exp-*` steps and their targets, or an explicit no-anchor-state note. Read-only — no skill subprocess spawned, no state written, workflow not mutated. `_expand_from_anchor` lost its now-unused `levels` parameter (its single call site updated).
- [x] 1.8 Verify 1.7: `python3 -m py_compile engine/main.py engine/workflow.py`; cold dry-run (isolated empty `STATE_DIR`) → static steps + no-anchor-state note, exit 0; warm dry-run (real 12-key consolidated + envelope `next_vectors.json` fixture) → `exp-nuclei`/`exp-whatweb` (and `exp-httpx` when the skill registers) with the subdomain targets, exit 0; dry-run WITHOUT `--expand-next-vectors` → static steps only, byte-identical; `preview_expansion` output == runtime `_expand_from_anchor` injection across 21 harness checks (parity, no-targets fallback, cap, dedup, hashed ids, timeout floor, cold, no-op anchor, level-0 fallback); real run `--target 127.0.0.1 --workflow recon-inicial --expand-next-vectors` → 5/5 steps done, exit 0.

> Note (apply): CLI dry-run used to return before `engine.execute()` (main.py L208), so expanded steps could never appear in a CLI dry-run — expansion ran only mid-execution. A–D semantics were therefore verified execution-based via a direct `_expand_from_anchor` harness (27 checks: targets/cap/fallback, dedup/bypass, hashed ids, timeout floor, no-targets regression parity) + a real run `--target 127.0.0.1 --workflow recon-inicial --expand-next-vectors` (exit 0, no crash). The gap was closed in the final code slice (PR 6, `feature/dry-run-expansion`): `engine.workflow.preview_expansion()` replays expansion from anchor state on disk inside the `if dry_run:` block, sharing `_build_expanded_step` with runtime so preview and runtime cannot diverge. See 1.7 and apply-progress.

## Phase 2: dnsenum skill pipeline (new dirs, nikto decomposition)

- [x] 2.1 `skills/dnsenum-scan/skill.yaml`: name `dnsenum-scan`, main_script, deps (dnsenum>=1.3.1, jq, python3), inputs wordlist/threads/timeout.
- [x] 2.2 `skills/dnsenum-scan/main.sh`: env/event parse; wildcard probe `dig +short A w-<ts>.<domain>` → wildcard.json; run `timeout ${STEP_TIMEOUT_SECONDS:-7200} dnsenum --noreverse [-f $WORDLIST] --threads $THREADS -t $TIMEOUT --subfile <subs.txt> -o <out.xml> <domain>`; NEVER emit `-s`/`-p`/`-w`; AXFR untouched; write status.json + sub-processes.
- [x] 2.3 Inline python3 XML+subfile parse in `dnsenum-scan/main.sh` → parsed-results.json `{subdomains[{name,ip,source}], ns[], mx[], zone_transfer{attempted:true,success,records[]}}`; drop names resolving to wildcard IP; `dig +short A` fallback when XML lacks IP; malformed XML → `partial: true`; write_to_shared_dir.
- [x] 2.4 `skills/dnsenum-analyzer/` (skill.yaml + main.sh): read parsed-results (shared-dir → state fallback); write consolidated.json per contract (`subdomain_count == (.subdomains|length)`); severity axfr→medium, subs>0→low, else info; write_next_vectors with 3 vectors httpx(90)/nuclei(80)/whatweb(70), each `targets` = first 10 subdomains sorted by name; `SKILL=dnsenum-analyzer`.
- [x] 2.5 `skills/dnsenum/` meta (skill.yaml + main.sh chaining scan → analyzer → sysreport, nikto/main.sh pattern) + `skills/dnsenum-sysreport/` writing `reports/<target>/dnsenum/{ts}/dnsenum.{json,yaml}`.
- [x] 2.6 Verify: `bash -n` all scripts; standalone `SCAN_ID=dnsenum-test TARGET=<domain> bash skills/dnsenum/main.sh`; jq-check contract keys + subdomain_count; no targets[] entry equals wildcard IP.

## Phase 3: Workflow insertion (workflows/recon-completo.yaml)

- [x] 3.1 Add step `dnsenum-scan` (skill `dnsenum-scan`, depends_on [], timeout 7200, params wordlist/threads/timeout, phase reconnaissance) + `dnsenum-analyzer` (depends_on [dnsenum-scan], condition prev.success, timeout 60, metadata.expansion_anchor: true); add `expansion.max_targets_per_vector: 10`; add `dnsenum-analyzer` to `expansion.anchor_steps` (rest UNCHANGED; report-html depends_on untouched).
- [x] 3.2 Verify: `python3 -c "import yaml; yaml.safe_load(open('workflows/recon-completo.yaml'))"`; dry-run shows dnsenum-scan level 0a parallel to port-discovery; with fixture state `--expand-next-vectors --dry-run` lists exp-httpx/exp-nuclei/exp-whatweb with subdomain targets — **now CLI-verifiable**: the dry-run hook (task 1.7) replays the `dns-analyzer` anchor's vectors off disk, so this scenario is exercised by the CLI itself rather than by a direct `_expand_from_anchor` harness. Anchor selection is `step.metadata.expansion_anchor`, so the vectors land on `dns-analyzer` (the sub-skill that writes `next_vectors.json`), not on `dns-discovery`.

## Phase 4: report-html dual-result (skills/report-html/)

- [x] 4.1 `sub-processes/generate-report.sh`: `DNS_FILE="$(resolve_source "dnsenum-analyzer" || true)"` — predecessor name is `dnsenum-analyzer` (resolve_source globs `state/<skill_name>/`); `DNS_SRC="$(build_source_json "dns" "${DNS_FILE}")"`; add `dns` to severity loop; `--argjson dns "$DNS_OBJ"` + `sources.dns` in REPORT_DATA.
- [x] 4.2 Add `resolve_root_source <skill> <prefix>` (exact `state/<skill>/{base}--<prefix>--<slug>/consolidated.json` → non-exp glob `grep -v -- '--exp-'` → resolve_source fallback); use for analyzer, whatweb-analyzer, testssl-analyzer, nuclei-analyzer, httpx-scan, nikto-analyzer so per-subdomain shared-dir writes never taint root sections.
- [x] 4.3 `templates/report.html`: add `<section id="section-dns">` (NS/MX/AXFR) + `<section id="section-subdomains">` (cards: subdomain/ip/status/tech/top-vulns + link `subdomains/<sub>/report.html`, empty state when subdomain_count==0); add `renderDns()` + `renderSubdomains()` + 2 dispatch lines (~L1482–1490); sourceMeta entry `{key: 'dns', label: 'DNS Enumeration (dnsenum)'}` (L1443–1450).
- [x] 4.4 Child reports: refactor template injection L321–351 into `render_report(data, out_path)`; per subdomain (cap 10) glob `state/{skill}-analyzer/{base}--exp-{skill}-*--{sub_slug}/consolidated.json` (skill ∈ httpx, whatweb, nuclei, nikto; sub_slug = dots→dashes); child REPORT_DATA = that subdomain's sources only; write `OUTPUT_DIR/subdomains/<subdomain>/report.html` under the SAME REPORT_TS as parent.
- [x] 4.5 Document v1 limitation (shared-dir last-writer-wins among per-subdomain analyzers; parent stays root-scoped) in report-html skill.yaml/docs.
- [x] 4.6 Verify: `bash -n` generate-report.sh; fixture run with sample dns consolidated + subdomain data → parent section + child files exist; run WITHOUT dns fixture → exit 0, timeline shows "Not run".

## Phase 5: Regression + integration

- [x] 5.1 Dry-run `recon-completo --expand-next-vectors --dry-run` on small domain with real dnsenum state → exp-httpx/exp-nuclei/exp-whatweb steps carry subdomain `targets`. **Evidence (PR 6)**: satisfied through the CLI itself — cold run prints the no-anchor-state note (exit 0), warm run against a real 12-key consolidated + envelope `next_vectors.json` fixture lists `exp-nuclei`/`exp-whatweb` with the 3 subdomain targets depending on `dns-analyzer` (exit 0). `exp-httpx` is emitted only when the skill registers; on this box `SkillLoader` drops it because the declared dependency `httpx-pd` is absent, which is the registration gate working, not a preview defect (proven with only the dependency gate stubbed).
- [x] 5.2 No-targets regression: anchors without `targets` → expanded step count, targets, skip rules identical to pre-change baseline. **Evidence (PR 6)**: the fallback now lives in the shared `_build_expanded_step`, and preview-vs-runtime parity is asserted on the no-targets vector set (static skill skipped, unregistered skill skipped, target-less new skill falls back to anchor targets) plus the real 5/5-step `recon-inicial` run.
- [x] 5.3 Report integration: generate with and without dns source; assert SUBDOMAINS cards render and child links resolve via `file:///`; missing dns tolerated ("Not run").
