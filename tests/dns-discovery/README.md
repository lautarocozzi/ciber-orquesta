# dns-discovery — offline verification harnesses

Verification suite for the `dns-discovery` change (DNS enumeration → sub-target
routing → report-html dual result → dry-run expansion preview).

These harnesses started as throwaway scripts in `/tmp` during the change. They
were every claim's only evidence, and `/tmp` dies on reboot. They now live here
so the evidence outlives the session.

## Run

```bash
bash tests/dns-discovery/run_all.sh            # everything
bash tests/dns-discovery/run_all.sh dns_verify # one harness
```

Exit code is non-zero if any check fails. Totals are parsed from each harness's
own `=== RESULT: <n> passed, <n> failed` line.

## What each harness covers

| Harness | Checks | Covers |
| --- | --- | --- |
| `dns_verify.py` | 71 | The DNS chain end to end with **stubbed** `dnsenum`/`dig`: fast-flag argv, wildcard-DNS probe and guard, XML/subfile/log parsing, the 12-key analyzer contract, domain-scope filtering (out-of-scope CNAMEs must not reach `next_vectors`), subdomain discovery, and every degradation rung (truncated XML, missing binary, corrupt input). |
| `engine_expansion.py` | 34 | `WorkflowEngine._expand_from_anchor`: per-vector `targets`, the `max_targets_per_vector` cap, `(skill, sorted-targets)` dedup, hashed step ids, `STEP_TIMEOUT_SECONDS` resolution, the static-skill bypass, no-targets regression parity with the pre-change algorithm, `expansion_anchor` selection, and the degradation rungs (anchor not done, `next_vectors.json` missing/corrupt, non-string targets). |
| `report_verify.py` | 57 | `report-html` dual result: the 7th `dns` source, parent DNS + SUBDOMAINS sections, per-subdomain child reports, root-scoped source resolution (a deliberately poisoned shared dir must not taint the parent), unsafe-name handling, and a stored-`</script>`-breakout injection probe. |

`_harness.py` is a shared helper, not a runnable harness.

Total: **162 checks**.

## These are offline checks — read this before trusting a green run

Everything here runs against **stubbed binaries and synthetic state** in a temp
sandbox. `STATE_DIR` / `REPORTS_DIR` are redirected per run; `run_all.sh` also
snapshots the repo's real `state/`, `reports/`, `events/`, and
`notifications/` and fails if a run touched them.

A green run proves the code does what the specs say. It does **not** prove a
live scan works. Specifically, `dnsenum → next_vectors → exp-*` has never been
executed against real DNS data from a real target — that gap is tracked as G2
in the change's archive report.

Two further environment caveats:

- The `httpx` skill cannot load on this box: `skills/httpx/skill.yaml`
  declares dependency `httpx-pd`, which is not a Kali package name. Kali ships
  projectdiscovery's tool as `httpx-toolkit`. Until the dependency name is
  aligned and the tool installed, `exp-httpx` is never emitted here.
- `report_verify.py`'s XSS probe (X1–X5) is the regression guard for the
  `</script>` breakout fixed in `57c9c8d`. If you see it fail, do not "fix" the
  assertion — the escaping in `generate-report.sh` regressed.

## Adding a harness

Drop a `<name>.py` next to this README, print a final
`=== RESULT: <n> passed, <n> failed` line, exit non-zero on failure, route all
filesystem writes through `STATE_DIR`/`REPORTS_DIR`, and add the name to `ALL`
in `run_all.sh`.
