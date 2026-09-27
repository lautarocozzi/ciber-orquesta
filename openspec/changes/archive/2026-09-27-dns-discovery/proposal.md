# Proposal: DNS early discovery — sub-target re-use loop

## Intent

recon-completo has no DNS phase: discovered subdomains stay invisible to downstream
tools, so coverage stops at the root target. Add fast dnsenum enumeration at level 0
(parallel to nmap port-discovery) and — via a minimal engine change — route discovered
subdomains as NEW TARGETS into one expanded step per downstream skill (httpx, nuclei,
whatweb). Extends the active attack-orchestrator plan; stays a separate change (no
folder merge).

## Scope

### In Scope

- **dnsenum skill** (nikto-style decomposition): `skills/dnsenum/` meta-skill
  (skill.yaml + main.sh chaining scan → analyzer → sysreport) + sub-skills
  `dnsenum-scan` (scan + inline XML parse) and `dnsenum-analyzer` (own workflow
  step, `expansion_anchor: true`).
- **Invocation**: `dnsenum --noreverse --threads 20 -t 3 --subfile <subs> -o <out.xml> <domain>`;
  params: wordlist (default `/usr/share/dnsenum/dns.txt`, 1505 names), threads,
  timeout. Google (-s/-p) + whois (-w) EXCLUDED. AXFR automatic (dnsenum ≥ 1.3.1).
- **Parser**: XML → subdomains + NS/MX + zone-transfer records; wildcard-DNS filter
  BEFORE emitting targets (guard in parse/analyzer).
- **Analyzer contract**: `{scan_id, target, started_at, domain,
  subdomains[{name, ip, source}], subdomain_count, ns[], mx[],
  zone_transfer{attempted, success, records[]}, severity, next_vectors, partial}`;
  next_vectors emit a `targets` array per vector (httpx/nuclei/whatweb), capped at 10.
- **Engine** (`_expand_from_anchor`, ~15 lines):
  - A (~L244): `new_targets = vector.get("targets") or list(anchor.targets)`;
    validate list; cap `max_targets_per_vector` (default 10) from `workflow.expansion`;
    use new_targets in the created step.
  - B (~L223): dedup by `(skill, tuple(sorted(targets)))` instead of skill name alone
    — same skill may expand multiple times with different target sets.
  - C (~L236): step id `exp-{skill}-{anchor.id}-{targets_key}` (sha1 of sorted
    targets, 8 chars) so distinct target-sets don't collide.
  - D (~L252): expanded-step timeout
    `int(os.environ.get("STEP_TIMEOUT_SECONDS", "7200"))` — policy: no restriction
    below 2h per target per skill (replaces hardcoded 480).
  - `envelope.sh` UNTOUCHED — `write_next_vectors` passes vectors verbatim via
    `--argjson`, so a `targets` field flows through with no change.
- **Workflow insertion** (recon-completo.yaml): `dnsenum-scan` (depends_on [],
  level 0a, parallel to port-discovery) + `dnsenum-analyzer` (depends_on
  [dnsenum-scan], level 0b, `expansion_anchor: true`); add
  `expansion.max_targets_per_vector: 10`. Re-use loop: ONE expanded step per skill
  with ALL subdomains in `targets` (multi-target loop already exists @workflow.py:294)
  — NOT one step per subdomain.
- **v1 re-use toolset**: httpx + nuclei + whatweb. Heavy tools (nikto, testssl,
  nmap) per-subdomain DEFERRED (cost/benefit).
- **report-html dual-result**: dns as 7th source; parent report gets a SUBDOMAINS
  section (card per subdomain: ip, status, tech, top vulns + link to full report);
  child `reports/<target>/report-html/YYYY-MM-DD/HH-MM-SS/subdomains/<subdomain>/report.html`.
  report-html must (a) detect subdomains from shared dir/consolidated dns data,
  (b) generate child report.html per subdomain, (c) embed mini-summaries in parent.
  `depends_on` UNTOUCHED — missing sources render "Not run".

### Out of Scope

- dnsrecon (crt.sh/DNSSEC zone walk) — later complement.
- Per-subdomain heavy tooling (nikto, testssl, nmap) — deferred.
- dnsenum Google scraping (-s/-p) and whois (-w) — excluded from v1.
- envelope.sh edits; report-html `depends_on` changes.

## Capabilities

### New Capabilities

- `dns-enumeration`: dnsenum skill pipeline, analyzer contract, wildcard guard,
  target-emitting next_vectors.
- `sub-target-routing`: engine target arrays, (skill, targets) dedup, hashed step
  ids, env-configurable expansion timeout.
- `subdomain-reporting`: report-html dns source, per-subdomain child reports,
  parent SUBDOMAINS section.

### Modified Capabilities

- **None** — `openspec/specs/` is empty; workflow recon-completo behavior changes
  are captured under the new capabilities above.

## Approach

1. Build `skills/dnsenum-scan/` (invocation + inline XML parse → JSON, wildcard
   filter, write parsed output to WORKFLOW_SHARED_DIR).
2. Build `skills/dnsenum-analyzer/` (consolidated.json per contract + severity +
   next_vectors with `targets`).
3. Build `skills/dnsenum/` meta-skill (standalone chain: scan → analyze → sysreport).
4. Apply engine edits A–D in `_expand_from_anchor`; verify with dry-run.
5. Insert 2 workflow steps + `expansion.max_targets_per_vector` in recon-completo.yaml.
6. Extend report-html (dns source + dual-result); verify missing-source tolerance.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `engine/workflow.py` | Modified | `_expand_from_anchor` L223–252: changes A–D (~15 lines) |
| `skills/dnsenum/` | New | meta-skill (skill.yaml + main.sh) |
| `skills/dnsenum-scan/` | New | scan + inline parse sub-skill |
| `skills/dnsenum-analyzer/` | New | analyzer sub-skill, `expansion_anchor: true` |
| `workflows/recon-completo.yaml` | Modified | +2 steps, +`max_targets_per_vector: 10` |
| `skills/report-html/` | Modified | generate-report.sh + templates/report.html (dns source, SUBDOMAINS, child reports) |
| `skills/_shared/envelope.sh` | None | untouched |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Wildcard DNS → phantom subdomain targets | Med | wildcard-IP filter in parse/analyzer before emit |
| Expansion explosion (N subdomains × skills) | Med | caps: `max_targets_per_vector` 10 + `max_expansions` 10 |
| Dedup change alters existing expansion behavior | Med | dry-run + regression run before enabling |
| Slow brute force / resolver rate limits | Med | wordlist/threads/timeout parametrizable |
| Shared-dir last-writer-wins among per-subdomain analyzers | Low | parent report stays root-target-scoped; documented v1 limitation; child reports generated separately |

## Rollback Plan

All changes are additive: delete the 3 new skill dirs; remove the 2 workflow steps;
revert engine edits (isolated in `_expand_from_anchor`, active only behind the
existing `--expand-next-vectors` flag — disabled by default); revert report-html
dns block (missing sources already render "Not run"). Single `git revert`; state/
paths unchanged.

## Dependencies

- dnsenum ≥ 1.3.1 (installed: `/usr/bin/dnsenum` VERSION 1.3.1) — AXFR automatic.
- jq ≥ 1.8 (installed: jq-1.8.1) — required for parsing/consolidation.
- `/usr/share/dnsenum/dns.txt` (1505 entries) — default wordlist.
- Existing httpx / nuclei / whatweb skills — reused as expansion targets.

## Success Criteria

- [ ] `bash -n` clean on all new scripts; engine modules unchanged behavior apart
      from A–D (syntax/dry-run).
- [ ] Standalone: `SCAN_ID=dnsenum-test TARGET=<domain> bash skills/dnsenum/main.sh`
      produces consolidated.json matching the analyzer contract.
- [ ] Engine dry-run: `python3 engine/main.py --target <domain> --workflow
      recon-completo --expand-next-vectors --dry-run` shows exp-httpx /
      exp-nuclei / exp-whatweb steps carrying subdomain targets.
- [ ] Real small-target run: expanded steps execute against discovered subdomains;
      per-skill results aggregated (one step per skill, multi-target).
- [ ] report.html: dns section rendered, SUBDOMAINS cards present with working
      links; child reports exist under `subdomains/<subdomain>/`.
- [ ] No emitted target shares the wildcard IP (guard verified).