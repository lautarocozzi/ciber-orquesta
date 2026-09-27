# dns-enumeration Specification

> **Provenance** — canonical spec, synced at archive from change `dns-discovery`
> (`openspec/changes/archive/2026-09-27-dns-discovery/`), merged to `main` @ `99c763f`.
> Verification: `VERIFIED` — Engram `sdd/dns-discovery/verify-report` (obs #110).
> Every requirement below is implemented and evidence-backed. No later change has
> modified this capability.

## Purpose

Early DNS discovery for recon-completo: a dnsenum skill pipeline at level 0 (parallel to port-discovery) that enumerates subdomains, NS/MX, and zone transfers for the root domain, filters wildcard-DNS noise, and emits an analyzer contract whose `next_vectors` propose downstream skills against discovered subdomains.

## Requirements

### Requirement: Discovery-Level Placement

The `dnsenum-scan` step MUST be inserted in `workflows/recon-completo.yaml` at level 0 with `depends_on: []`, parallel to `port-discovery`. It MUST require only the domain (the step target) — no ports, no nmap output. `dnsenum-analyzer` MUST depend on `dnsenum-scan` and set `expansion_anchor: true`.

#### Scenario: Parallel with port-discovery

- GIVEN recon-completo is loaded
- WHEN the DAG resolves levels
- THEN `dnsenum-scan` and `port-discovery` are scheduled in the same level
- AND `dnsenum-scan` starts without waiting for any port result

#### Scenario: Port-discovery failure does not block DNS

- GIVEN `port-discovery` fails
- WHEN level 0 dispatches
- THEN `dnsenum-scan` still executes (empty `depends_on`)

### Requirement: Fast Invocation with Overridable Parameters

`dnsenum-scan` MUST invoke dnsenum (v1.3.1) as:

```bash
dnsenum --noreverse --threads 20 -t 3 --subfile <subs.txt> -o <out.xml> <domain>
```

Effective defaults: wordlist `/usr/share/dnsenum/dns.txt` (1505 names), threads `20`, timeout `3`. Parameters `wordlist`, `threads`, and `timeout` MUST be overridable via skill inputs / workflow parameters. Google scraping (`-s`/`-p`) and whois (`-w`) MUST NOT be used.

#### Scenario: Default fast run

- GIVEN no parameter overrides
- WHEN `dnsenum-scan` executes
- THEN the command contains `--noreverse --threads 20 -t 3`
- AND the wordlist resolves to `/usr/share/dnsenum/dns.txt`

#### Scenario: Parameters overridden

- GIVEN parameters `wordlist=/tmp/small.txt`, `threads=5`, `timeout=5`
- WHEN `dnsenum-scan` executes
- THEN the command contains `-f /tmp/small.txt --threads 5 -t 5`

#### Scenario: Excluded flags never appear

- GIVEN any run completes
- WHEN the sub-process stdout/command record is inspected
- THEN no `-s`, `-p`, or `-w` flag was passed

### Requirement: Automatic Zone Transfer

The skill MUST NOT disable zone transfer: dnsenum ≥ 1.3.1 attempts AXFR automatically against all NS. The parser MUST record `zone_transfer.attempted=true` on every run, with `success` and `records[]` reflecting the outcome.

#### Scenario: AXFR refused

- GIVEN the domain's nameservers refuse AXFR
- WHEN dnsenum completes
- THEN `zone_transfer = {attempted: true, success: false, records: []}`

#### Scenario: AXFR succeeded

- GIVEN a nameserver permits transfer
- WHEN dnsenum completes
- THEN `zone_transfer.success` is `true` and `records[]` lists transferred entries

### Requirement: Analyzer Contract

`dnsenum-analyzer` MUST write `state/dnsenum-analyzer/{scan_id}/consolidated.json` containing exactly: `{scan_id, target, started_at, domain, subdomains[{name, ip, source}], subdomain_count, ns[], mx[], zone_transfer{attempted, success, records[]}, severity, next_vectors, partial}`. `subdomain_count` MUST equal `length(subdomains)`. Each `next_vectors` entry MAY carry a `targets` array (see sub-target-routing).

#### Scenario: Standalone run produces contract

- GIVEN `SCAN_ID=dnsenum-test TARGET=<domain> bash skills/dnsenum/main.sh`
- WHEN the chain completes
- THEN `consolidated.json` parses under `jq` and contains every contract key
- AND `subdomain_count == (.subdomains | length)`

#### Scenario: Malformed XML degrades gracefully

- GIVEN dnsenum output XML is truncated
- WHEN the parser runs
- THEN `partial` is `true`, `severity` is set, and available fields are still emitted

### Requirement: Wildcard-DNS Filtering

The parser/analyzer MUST identify the wildcard record and MUST exclude every subdomain resolving to the wildcard IP BEFORE writing `next_vectors`. Filtered names MUST NOT appear in `subdomains[]` nor in any vector `targets[]`.

#### Scenario: Wildcard noise filtered

- GIVEN `*.example.com` resolves all names to `203.0.113.5`
- WHEN brute force returns `random1.example.com`, `random2.example.com` (both → 203.0.113.5) plus `www.example.com` → `198.51.100.9`
- THEN `subdomains[]` contains only `www.example.com`
- AND no emitted `targets[]` entry resolves to `203.0.113.5`

#### Scenario: Non-wildcard domain preserved

- GIVEN no wildcard record exists
- WHEN parsing completes
- THEN all valid subdomains are retained and emitted

### Requirement: Timeout Policy

Per-target per-skill execution MUST NOT be restricted below 2 hours. The dnsenum pipeline timeout MUST default to `STEP_TIMEOUT_SECONDS` (default `7200` seconds) and MUST be env-overridable.

#### Scenario: Default 2h budget

- GIVEN `STEP_TIMEOUT_SECONDS` is unset
- WHEN the step runs
- THEN its timeout is `7200`

#### Scenario: Env override applied

- GIVEN `STEP_TIMEOUT_SECONDS=3600`
- WHEN the step runs
- THEN its timeout is `3600`
