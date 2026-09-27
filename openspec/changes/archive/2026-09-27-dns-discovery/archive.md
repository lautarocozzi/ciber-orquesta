# Archive: dns-discovery

**Change**: dns-discovery — DNS early discovery / sub-target re-use loop
**Archived**: 2026-09-27
**State**: CLOSED (ARCHIVED-WITH-GAPS)
**Verification**: VERIFIED (obs #110), with 2 traceability gaps and 3 known limits
**Merged to**: `main` @ `99c763f` (PR #2 tracker, cascade #3 → #6)

---

## Executive Summary

Added DNS early discovery to `recon-completo` and turned discovered subdomains into
real downstream targets. Three new capabilities shipped as a 4-slice Feature Branch
Chain (5 PRs):

1. **`dns-enumeration`** — a decomposed `dnsenum` skill family (`dnsenum-scan` →
   `dnsenum-analyzer` → `dnsenum-sysreport`, plus the `dnsenum` meta-skill) inserted at
   workflow level 0, parallel to `port-discovery`. Wildcard-DNS noise is filtered before
   any target is emitted; the analyzer writes a 12-key contract whose `next_vectors`
   carry `targets` arrays.
2. **`sub-target-routing`** — `WorkflowEngine._expand_from_anchor` now routes per-vector
   target arrays, dedups on `(skill, sorted-targets)`, hashes expanded step ids, and
   takes the expanded-step timeout from `STEP_TIMEOUT_SECONDS` (7200 default, replacing
   the hardcoded 480). A read-only `preview_expansion()` replays the exact same
   construction inside `--dry-run`, so a dry run can no longer lie about the plan.
3. **`subdomain-reporting`** — `report-html` gained a 7th `dns` source, a parent
   `SUBDOMAINS` section with one card per subdomain, and standalone child reports per
   subdomain under the same timestamp directory.

All 25 tasks are `[x]`. All 18 requirements are implemented. `skills/_shared/envelope.sh`
was never touched — `write_next_vectors` passes vectors verbatim, so a `targets` field
flows through with no change. A stored XSS found during verification (unescaped `</script>`
breakout in the embedded `REPORT_DATA`) was fixed in `57c9c8d` before merge.

**Verified by fixture and harness, not by a live DNS scan** — see [Gaps](#gaps).

---

## SDD Artifacts

| Artifact | File (in this archive) | Engram topic | Obs ID |
|----------|----------------------|--------------|--------|
| Exploration | `exploration.md` | `sdd/dns-discovery/explore` | #91 |
| Proposal | `proposal.md` | `sdd/dns-discovery/proposal` | #92 |
| Spec (3 domains) | `specs/*/spec.md` | `sdd/dns-discovery/spec` | #93 |
| Design | — (Engram only) | `sdd/dns-discovery/design` | #95 |
| Tasks | `tasks.md` | `sdd/dns-discovery/tasks` | #96 |
| Apply progress | — (Engram only) | `sdd/dns-discovery/apply-progress` | #98 (merged state), #101 (slice 4 detail) |
| Verify report | — (Engram only) | `sdd/dns-discovery/verify-report` | #110 |
| Archive report | `archive.md` + Engram | `sdd/dns-discovery/archive-report` | this archive |

Related observations: #100 (expansion machinery foundation commit), #102
(anchor-must-write-next_vectors contract), #106 (report-html root-source guard fixed two
taint paths), #108 (the XSS finding, superseded by the fix).

`design.md` and `verify-report.md` were never written to disk for this change — the
pipeline ran them through Engram only. This archive folder therefore holds 6 files, not 8.

---

## Canonical Specs Synced

`openspec/specs/` did not exist before this archive (the proposal recorded
"Modified Capabilities: None — `openspec/specs/` is empty"). All three delta specs were
**new capabilities written as full specs**, not deltas, so per the OpenSpec convention
they were copied verbatim into the canonical structure and stamped with provenance.

| Canonical spec | Requirements | Scenarios | Merge action |
|----------------|--------------|-----------|--------------|
| `openspec/specs/dns-enumeration/spec.md` | 6 | 13 | Created (verbatim) |
| `openspec/specs/sub-target-routing/spec.md` | 6 | 16 | Created (verbatim) |
| `openspec/specs/subdomain-reporting/spec.md` | 6 | 10 | Created (verbatim) |

Each carries a provenance block naming the change, the merge commit `99c763f`, the
verdict, and the obs ID of the verify report. Content is byte-identical to the archived
delta apart from that header — verified by diff at archive time.

Nothing was removed or weakened: no requirement was `MODIFIED` or `REMOVED`, so the merge
was non-destructive and no pre-confirmation was required.

---

## Requirement → Task → Evidence Matrix

Tasks: 25/25 `[x]`. Evidence codes: **V** = verify-report #110, **A** = apply-progress
#101 (slice 4 / PR #6), **R** = re-verified by the archiver against merged `main`.

### dns-enumeration (6/6)

| # | Requirement | Tasks | Evidence |
|---|-------------|-------|----------|
| 1 | Discovery-Level Placement | 3.1, 3.2, 5.1 | **V** "level-0 depends_on []" + **R** `recon-completo.yaml` L76-88: `dns-discovery` `depends_on: []` |
| 2 | Fast Invocation with Overridable Parameters | 2.1, 2.2, 2.6 | **V** exact argv `--noreverse --threads 20 -t 3 --subfile -o`, no `-s`/`-p`/`-w` (dns harness 71/71). **R** workflow overrides `threads: 10` — sanctioned, spec requires overridability |
| 3 | Automatic Zone Transfer | 2.3, 2.4 | **V** 12-key contract incl. `zone_transfer{attempted,success,records[]}` |
| 4 | Analyzer Contract | 2.4, 2.6 | **V** contract + `subdomain_count == (.subdomains\|length)`, out-of-scope CNAME dropped, meta-skill + sysreport present |
| 5 | Wildcard-DNS Filtering | 2.3 | **V** wildcard guard proven end-to-end and re-asserted in the analyzer |
| 6 | Timeout Policy | 1.5, 3.1 | **V** timeout 7200 default / 1800 env; **R** `recon-completo.yaml` L84, L102 both `7200` |

### sub-target-routing (6/6)

| # | Requirement | Tasks | Evidence |
|---|-------------|-------|----------|
| 1 | Per-Vector Targets with Anchor Fallback | 1.2 | **V** targets / cap / fallback proven; **A** 21-check harness, no-targets fallback cases |
| 2 | Dedup by (skill, sorted-targets) | 1.3 | **V** dedup; **A** 3 identical-order-variant vectors → 1 step, 2 distinct sets → 2 steps |
| 3 | Collision-Free Expanded Step Ids | 1.4 | **V** hashed ids; **A** ids match `exp-{skill}-{anchor}-{8hex}` |
| 4 | Expanded-Step Timeout via STEP_TIMEOUT_SECONDS | 1.5 | **V** timeout floor; **A** 7200 default / 1800 env / 7200 on malformed env |
| 5 | One Expanded Step Per Skill, Multi-Target | 1.2, 1.4 | **V** one-step-per-(skill,target-set); **A** 3 subdomain targets inside ONE `exp-*` step |
| 6 | Dry-Run and Regression Verification | 1.6, 1.7, 1.8, 5.1, 5.2 | **A only** — see [G1](#g1--dry-run-scenarios-evidenced-in-apply-not-in-a-formal-re-verify). **R** re-confirmed: `expansion.anchor_steps` still lists `dns-analyzer`/`dns-discovery` (dead config) |

### subdomain-reporting (6/6)

| # | Requirement | Tasks | Evidence |
|---|-------------|-------|----------|
| 1 | Per-Skill Reports Unchanged | 4.1–4.4 | **V** per-skill state written; no path/shape change |
| 2 | 7th Report Source "dns" | 4.1, 4.3 | **V** 7th `dns` source, `section-dns`, timeline entry `DNS Enumeration (dnsenum)` |
| 3 | Parent Report Layout | 4.3 | **V** parent cards + links (report renderer 57/57) |
| 4 | Child Report Path | 4.4 | **V** child reports under the same `REPORT_TS` |
| 5 | Missing Sources Render "Not run" | 4.6 | **V** all Not-run / degradation paths |
| 6 | Documented v1 Shared-Dir Limitation | 4.2, 4.5 | **V** root-scoped resolution, 0 TAINTED bytes from a poisoned shared dir (#106: two taint paths, not one). **R** limitation is documented in `skills/report-html/skill.yaml` L4-15 and `generate-report.sh` L13, L126 |

**Totals**: 18/18 requirements implemented and task-marked. 17/18 backed by the formal
verify report; 18/18 backed by some evidence; **0/18 backed by a live DNS end-to-end run**
(see [G2](#g2--no-live-dns-end-to-end-run-ever-executed)).

---

## Gaps

Recorded, not papered over.

### G1 — Dry-run scenarios evidenced in apply, not in a formal re-verify

`sub-target-routing` requirement 6 ("Dry-run shows subdomain targets" plus the two
scenarios added later) was flagged **CRITICAL** by verify-report #110: `engine/main.py`
returned on `--dry-run` before `engine.execute()`, so the scenario could never pass
through the CLI. The gap was then closed by PR #6 (`4b030e3`, `preview_expansion()`).

The closure is well evidenced in apply-progress #101 (21-check preview/runtime parity
harness, cold dry-run note, warm dry-run listing `exp-nuclei`/`exp-whatweb`, regression
with the flag off, real 5/5-step `recon-inicial` run). But **no formal verify pass was
re-run after the closure** — #110 predates `4b030e3` and still records the finding as
open. Severity: documentation/traceability, not code. Fix: fold #101's slice-4 evidence
into a refreshed verify-report when the next change touches the engine.

### G2 — No live DNS end-to-end run ever executed

Re-verified at archive time on merged `main`:

- no `reports/*/report-html/*/*/subdomains/` directory exists (child reports were only
  produced by a fixture),
- no `reports/*/dnsenum/*/` exists (the sysreport output path was never exercised),
- the only `state/dnsenum-analyzer/` scan dirs are `cap-test*` fixtures.

Consequence: the full wiring dnsenum → `next_vectors` → expanded httpx/nuclei/whatweb
steps has **never executed together with real DNS data**. The proposal's success
criteria "Real small-target run" and "SUBDOMAINS cards with working links" were satisfied
by fixtures, not by a live scan. Everything below is harness-verified, and one real
nmap-based `recon-inicial` run confirmed the engine's expansion path end to end — but
that is not the DNS chain.

### G3 — `httpx` never runs on this box

`httpx-pd` is not on PATH (re-confirmed at archive: `which httpx-pd` → not found), so
`SkillLoader` drops the skill and `exp-httpx` is never emitted. This is the registration
gate working as designed, not a defect — proven at apply time by stubbing only the
dependency gate. It does mean the `exp-httpx` branch of requirements 1–5 is untested on
this host.

### G4 — Known doc drift, deliberately preserved

`tasks.md` L54 still describes `dnsenum-analyzer` with `timeout 60`; the shipped YAML
(L102) is `7200`. The **spec** (`7200`) is what shipped, so this is a stale task
description, not a behavior violation. Left unmodified on purpose — this folder is an
audit trail.

### G5 — Carried debt

- `expansion.anchor_steps` in `workflows/recon-completo.yaml` (L60-68) is **dead config**:
  the engine selects anchors via `step.metadata.expansion_anchor`.
- The `dns-discovery` step still carries `expansion_anchor: true` (L88) while
  `dnsenum-scan` never writes `next_vectors.json` — a no-op anchor that is harmless
  (the lookup finds nothing) but misleading.

---

## Merge State

Cascade, all merged, all PRs closed:

| PR | Branch | Content |
|----|--------|---------|
| #6 | `feature/dry-run-expansion` | `preview_expansion()` dry-run hook (A–D extracted to module helpers) |
| #5 | `feature/dns-discovery-reporting` | `dns` source, `section-dns`, SUBDOMAINS cards, child reports, root-source fix, XSS fix |
| #4 | `feature/dns-discovery-skills` | dnsenum scan/analyzer/sysreport/meta + `recon-completo` wiring |
| #3 | `feature/dns-discovery` | engine sub-target routing (A–D) |
| #2 | `tracker/dns-discovery` | tracker branch → `main` |

`main` @ `99c763f` carries 10 dns-discovery commits. Issue #1 closed. Branch heads were
intentionally left in place (no `--delete-branch`) so review history stays browsable.

---

## Verification Evidence (reproducible)

- dns offline harness (stubbed dnsenum + dig): **71/71**
- engine harness (`_expand_from_anchor`): **30/30**
- report renderer (`report_verify.py`): **56/57 → 57/57** after the XSS fix
- preview/runtime parity harness (PR #6): **21/21**
- `bash -n` on 6 scripts, `py_compile` on 2 modules, YAML parses, 27-step dry run,
  cap 10 honored, dry-run exit 0

Harnesses live in `/tmp/opencode/dns-verify-fixture/` and are **ephemeral — not
committed**. They are the evidence behind every claim in this report and will be lost on
a reboot. Re-creating them is follow-up work if the team wants a durable regression net.

---

## Rollback Viability

All changes are additive. Revert the chain in reverse: `git revert -m 1 99c763f`, or
revert the 10 individual commits. `state/` and `reports/` paths are unchanged.
`skills/_shared/envelope.sh` was never modified, so no other skill's behavior depends on
this change. `report-html` `depends_on` was untouched, so a missing dns source still
renders "Not run" and cannot break an existing workflow.

---

## Follow-ups (not blocking)

1. Remove the no-op `expansion_anchor: true` from the `dns-discovery` step (G5).
2. Delete `expansion.anchor_steps` or make the engine honor it (G5) — one of the two.
3. Install `httpx-pd` on this box (G3).
4. Run one live DNS end-to-end scan on a domain you own (G2) — the only way to close the
   real coverage gap.
5. Refresh the verify-report with PR #6 evidence (G1).
6. Delete the 5 merged feature/tracker branches.
