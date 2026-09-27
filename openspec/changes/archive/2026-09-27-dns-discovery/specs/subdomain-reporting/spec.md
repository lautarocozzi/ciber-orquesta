# subdomain-reporting Specification

## Purpose

Dual-result reporting: per-skill state reports stay as today, while `report-html` gains a 7th `dns` source, a parent SUBDOMAINS section with one card per subdomain, and standalone child reports per subdomain.

## Requirements

### Requirement: Per-Skill Reports Unchanged

Every skill (including expanded per-subdomain runs) MUST keep writing `state/{skill}/{scan_id}/consolidated.json` with the existing layout; scan_id remains `{base}--{step}--{target_slug}`. No reporting change MAY alter these paths or shapes.

#### Scenario: dnsenum analyzer state written

- GIVEN `dnsenum-analyzer` completes for the root domain
- WHEN state is inspected
- THEN `state/dnsenum-analyzer/{scan_id}/consolidated.json` exists per the dns-enumeration contract

#### Scenario: Expanded skills keep per-skill state

- GIVEN an expanded `httpx` step runs against `sub.example.com`
- WHEN it completes
- THEN its results live under `state/httpx/{base}--exp-httpx-*--sub-example-com/consolidated.json`

### Requirement: 7th Report Source "dns"

`generate-report.sh` MUST resolve a `dns` source (predecessor `dnsenum-analyzer`, same `resolve_source` shared-dir → exact → prefix-glob chain) and include it in the severity loop and `REPORT_DATA.sources`. The template MUST render a `section-dns`, a `renderDns()` dispatch line, and a timeline `sourceMeta` entry `{key: 'dns', label: 'DNS Enumeration (dnsenum)'}`.

#### Scenario: dns source present

- GIVEN `state/dnsenum-analyzer/.../consolidated.json` exists
- WHEN report-html runs
- THEN `REPORT_DATA.sources.dns.present` is `true`
- AND the timeline shows "DNS Enumeration (dnsenum)" with its `started_at`

#### Scenario: dns source missing

- GIVEN no dnsenum-analyzer consolidated file exists
- WHEN report-html runs
- THEN `sources.dns = {present: false}` and generation still exits 0

### Requirement: Parent Report Layout

The parent `report.html` MUST keep all existing per-stage sections scoped to the ROOT target and MUST add a SUBDOMAINS section: one card per discovered subdomain showing `ip`, `status`, `tech`, and top vulns, plus a relative link to that subdomain's child report.

#### Scenario: Cards rendered

- GIVEN the dns source lists 3 subdomains and expanded runs produced child data
- WHEN the parent report opens via `file:///`
- THEN 3 subdomain cards render with ip, status, tech, top-vulns fields
- AND each card's link opens the corresponding child report

#### Scenario: No subdomains discovered

- GIVEN `subdomain_count == 0`
- WHEN the parent report opens
- THEN the SUBDOMAINS section shows an empty state and no broken links

### Requirement: Child Report Path

For each subdomain, report-html MUST generate a child report at:

```
reports/<target>/report-html/YYYY-MM-DD/HH-MM-SS/subdomains/<subdomain>/report.html
```

using the SAME timestamp directory (`REPORT_TS`) as the parent report.

#### Scenario: Child files written

- GIVEN parent report generates at `reports/example.com/report-html/2026-09-22/16-11-54/report.html` with 2 subdomains
- WHEN generation completes
- THEN `.../2026-09-22/16-11-54/subdomains/<name1>/report.html` and `.../<name2>/report.html` exist

#### Scenario: Relative links resolve

- GIVEN parent and child reports share the timestamp directory
- WHEN a card link is followed from `file:///`
- THEN the child report opens without path errors

### Requirement: Missing Sources Render "Not run"

`report-html` `depends_on` in recon-completo.yaml MUST remain UNTOUCHED (no dnsenum dependency). Any missing source — including `dns` — MUST render as "Not run" in the timeline; report generation MUST NOT fail because a source is absent.

#### Scenario: dns never ran

- GIVEN dnsenum-analyzer did not execute (e.g. expansion disabled)
- WHEN report-html runs with all other sources present
- THEN the dns timeline entry shows "Not run" and all other sections render

### Requirement: Documented v1 Shared-Dir Limitation

Expanded per-subdomain analyzers share `WORKFLOW_SHARED_DIR` (last-writer-wins on `{skill}/consolidated.json`). This MUST be documented as a v1 limitation, and the parent report MUST remain root-target-scoped (it MUST NOT consume per-subdomain shared-dir overwrites for its per-stage sections).

#### Scenario: Concurrent subdomain analyzers

- GIVEN expanded analyzers for two subdomains write the same shared-dir path
- WHEN both complete
- THEN the parent report still renders root-target per-stage data unaffected
- AND documentation records the last-writer-wins limitation
