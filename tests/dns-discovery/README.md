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
| `preview_parity.py` | 70 | The dry-run expansion preview (PR #6): `preview_expansion()` vs. the real `WorkflowEngine._expand_from_anchor()` step-for-step parity over the same anchor state, the CLI dry-run contract cold (exit 0, "no anchor state" note, zero `exp-*`) and warm (exit 0, `exp-<skill>-dns-analyzer-<8hex>` with the discovered subdomains), proof that neither path spawns a tool or writes, and the path guard for a traversal-shaped target. |

`_harness.py` is a shared helper, not a runnable harness.

Total: **232 checks**.

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
  `preview_parity.py` derives its expected `exp-*` set from what the host
  actually registers, so it stays green either way — the fixture still carries
  the `httpx` vector, and both paths skip it identically.
- `report_verify.py`'s XSS probe (X1–X5) is the regression guard for the
  `</script>` breakout fixed in `57c9c8d`. If you see it fail, do not "fix" the
  assertion — the escaping in `generate-report.sh` regressed.

## Findings these harnesses turned up

- ~~**A `--dry-run` is not read-only on disk.**~~ **FIXED.** `main.py:196`
  called `write_event()` *before* the `dry_run` branch, and `EVENTS_DIR` defaults
  to the relative `events/` (`engine/event_bus.py:22`), which `STATE_DIR` does
  not cover — so a plain `--dry-run` dropped `events/engine/<id>.json` into the
  checkout. `main.py` now emits the opening event and running state only when
  `not dry_run`. P3e and P4f were inverted to assert **zero** writes (they used
  to pin the buggy shape, so they got stronger, not weaker). A real run still
  writes its full event trail.
- **The wildcard guard lives only in the analyzer, not the engine.**
  `preview_expansion()` re-applies no name filter beyond
  `isinstance(t, str) and t.strip()`, so a hostile `targets` entry in a vector
  reaches `step.targets` verbatim (P5e). The traversal *path* is safe —
  `_target_slug` neutralizes it and the CLI rejects a traversal `--target`
  outright — but the engine trusts the analyzer to have filtered names.
- **`dns-discovery` is a permanent no-op anchor.** It carries
  `expansion_anchor: true`, yet its skill (`dnsenum-scan`) never writes
  `next_vectors.json`. Relatedly, `workflow.expansion.anchor_steps` lists 8
  steps while 9 carry the flag, and that list is dead config —
  `_anchor_steps_for()` reads the `metadata` flag only.

## Adding a harness

Drop a `<name>.py` next to this README, print a final
`=== RESULT: <n> passed, <n> failed` line, exit non-zero on failure, route all
filesystem writes through `STATE_DIR`/`REPORTS_DIR`, and add the name to `ALL`
in `run_all.sh`.
