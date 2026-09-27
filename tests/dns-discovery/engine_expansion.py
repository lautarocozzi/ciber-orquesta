#!/usr/bin/env python3
"""Adversarial harness for dns-discovery sub-target routing (engine A-D).

Drives the REAL WorkflowEngine._expand_from_anchor against the REAL
recon-completo workflow and the REAL SkillLoader, with a synthetic state dir.

Section V folds in the assertions that used to live only in the retired
dns_pr1_harness.py (expanded-step wiring + no-targets backward-compat parity),
so that ground is covered here without shipping a second, redundant harness.

Nothing is scanned and no subprocess is spawned: STATE_DIR points at a temp
sandbox and the engine only ever reads next_vectors.json out of it.

NOT a live scan. See README.md.
"""
import asyncio
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _harness import (  # noqa: E402
    PROJECT, Reporter, activate_engine_env, finish, new_workspace,
)

R = Reporter("engine _expand_from_anchor (sub-target routing)")
WS = new_workspace("engine-expansion")

# MUST happen before importing engine.*: engine/workflow.py snapshots
# $WORKFLOWS_DIR into a module-level constant at import time.
activate_engine_env(WS.state)
sys.path.insert(0, str(PROJECT))

from engine.main_manager import ProcessResult, ProcessStatus  # noqa: E402
from engine.skill_loader import SkillLoader  # noqa: E402
from engine.workflow import (  # noqa: E402
    Workflow, WorkflowEngine, _targets_key, load_workflow,
)

STATE = WS.state
BASE = "verifybase0001"
TARGET = "example.com"
ANCHOR = "dns-analyzer"

ck = R.ck
section = R.section
info = R.info

# Probe skills are chosen from what THIS host actually registers, so the harness
# is green whether or not an optional dependency (e.g. httpx-pd) is installed.
# The engine skips a vector whose skill is unregistered -- that is correct
# behaviour, not a failure, so it must not be asserted as either.
_CANDIDATES = ("nuclei", "whatweb", "nikto", "httpx")


def fresh_state():
    shutil.rmtree(STATE, ignore_errors=True)
    STATE.mkdir(parents=True)


def write_vectors(step_id, vectors, skill="dnsenum-analyzer", base=BASE, target=TARGET):
    slug = target.replace("..", "-").replace(".", "-").replace(":", "-").replace("/", "-")
    d = STATE / skill / f"{base}--{step_id}--{slug}"
    d.mkdir(parents=True, exist_ok=True)
    body = vectors if isinstance(vectors, str) else json.dumps({"next_vectors": vectors})
    (d / "next_vectors.json").write_text(body)


def build_engine(wf=None):
    """Real loader, real workflow, bare engine (bypasses __init__/subprocesses)."""
    loader = SkillLoader(PROJECT / "skills")
    loader.load_all()
    if wf is None:
        wf = load_workflow("recon-completo", workflows_dir=PROJECT / "workflows")
        for s in wf.steps:                      # mirror main.py::_resolve_workflow_target
            s.targets = [t.replace("{{ target }}", TARGET) for t in s.targets]
    eng = WorkflowEngine.__new__(WorkflowEngine)
    eng.base_scan_id = BASE
    eng.skill_name = "recon-completo"
    eng._results = {}
    eng.skill_loader = loader
    return eng, wf, loader


def mark_done(eng, *step_ids):
    for sid in step_ids:
        eng._results[sid] = ProcessResult(
            scan_id=BASE, skill="x", target=TARGET, sub_process="x",
            status=ProcessStatus.DONE,
        )


def expanded(wf):
    return [s for s in wf.steps if s.metadata.get("expanded")]


def ctx():
    """Fresh engine + fresh workflow: no expanded-step leakage between sections."""
    eng, wf, loader = build_engine()
    return eng, wf, loader


async def _run():
    section("Skill registration on this host (informs the probe set)")
    eng, wf, loader = ctx()
    available = [s for s in _CANDIDATES if loader.get_skill(s) is not None]
    unavailable = [s for s in _CANDIDATES if loader.get_skill(s) is None]
    info(f"registered probe skills: {available}")
    if unavailable:
        info(f"unregistered (engine will skip vectors for these): {unavailable}")
    ck("PROBE at least 3 probe skills are registered on this host", len(available) >= 3,
       f"have {available}")
    PRIMARY, SECOND, THIRD = available[:3]

    section("A: per-vector targets + cap (15 subdomains, cap 10)")
    fresh_state()
    subs = [f"s{i:02d}.{TARGET}" for i in range(15)]
    write_vectors(ANCHOR, [
        {"skill": PRIMARY, "weight": 90, "targets": subs},
        {"skill": SECOND, "weight": 70, "targets": subs},
        {"skill": THIRD, "weight": 60, "targets": subs},
    ])
    mark_done(eng, ANCHOR)
    n = await eng._expand_from_anchor(wf)
    ex = expanded(wf)
    ck("A1 one expanded step per (skill,target-set)", n == 3 and len(ex) == 3, f"injected={n}")
    prim = [s for s in ex if s.skill == PRIMARY]
    ck("A2 ONE exp step, NOT one per subdomain (15 subdomains)", len(prim) == 1, f"count={len(prim)}")
    ck("A3 cap applied: 10 of 15 proposed targets", len(prim[0].targets) == 10, f"got={len(prim[0].targets)}")
    ck("A4 targets come from the vector, not the anchor",
       all(t != TARGET for t in prim[0].targets) and all(t.endswith(TARGET) for t in prim[0].targets))
    ck("A5 deterministic order (sorted)", prim[0].targets == sorted(prim[0].targets))
    ck("A6 cap key read from workflow.expansion",
       wf.expansion.get("max_targets_per_vector") == 10, str(wf.expansion.get("max_targets_per_vector")))
    # Wiring: an expanded step is a real DAG edge, not a detached node.
    ck("A7 expanded step depends_on the anchor step", prim[0].depends_on == [ANCHOR],
       str(prim[0].depends_on))
    ck("A8 expanded step condition is prev.success", prim[0].condition == "prev.success",
       str(prim[0].condition))

    section("C: collision-free hashed ids")
    ck("C1 id shape exp-{skill}-dns-analyzer-<8hex>",
       prim[0].id.startswith(f"exp-{PRIMARY}-{ANCHOR}-")
       and len(prim[0].id.rsplit("-", 1)[1]) == 8, prim[0].id)
    want = hashlib.sha1("|".join(sorted(subs[:10])).encode()).hexdigest()[:8]
    ck("C2 targets_key == sha1(sorted(capped targets))[:8]", prim[0].id.endswith(want), want)
    ids = [s.id for s in ex]
    ck("C3 all expanded ids distinct", len(set(ids)) == len(ids))
    ck("C4 different skills -> different ids", len({s.id for s in ex}) == 3)

    section("D: timeout policy")
    os.environ.pop("STEP_TIMEOUT_SECONDS", None)
    fresh_state()
    write_vectors(ANCHOR, [{"skill": PRIMARY, "targets": ["a." + TARGET, "b." + TARGET]}])
    mark_done(eng, ANCHOR)
    await eng._expand_from_anchor(wf)
    d1 = [s for s in expanded(wf) if s.id not in ids]
    ck("D1 default timeout 7200 when env unset", len(d1) == 1 and d1[0].timeout == 7200,
       f"t={d1[0].timeout if d1 else 'n/a'}")
    os.environ["STEP_TIMEOUT_SECONDS"] = "1800"
    fresh_state()
    write_vectors(ANCHOR, [{"skill": SECOND, "targets": ["c." + TARGET]}])
    await eng._expand_from_anchor(wf)
    d2 = [s for s in expanded(wf) if s.id not in ids and s.skill == SECOND]
    ck("D2 env override STEP_TIMEOUT_SECONDS=1800", len(d2) == 1 and d2[0].timeout == 1800,
       f"t={d2[0].timeout if d2 else 'n/a'}")
    os.environ["STEP_TIMEOUT_SECONDS"] = "not-a-number"
    fresh_state()
    write_vectors(ANCHOR, [{"skill": THIRD, "targets": ["d." + TARGET]}])
    await eng._expand_from_anchor(wf)
    d3 = [s for s in expanded(wf) if s.skill == THIRD and s.targets == ["d." + TARGET]]
    ck("D3 non-numeric env falls back to 7200", len(d3) == 1 and d3[0].timeout == 7200,
       f"t={d3[0].timeout if d3 else 'n/a'}")
    os.environ.pop("STEP_TIMEOUT_SECONDS", None)
    static = [s for s in wf.steps if s.id in ("dns-discovery", ANCHOR)]
    info("static step timeouts: " + ", ".join(f"{s.id}={s.timeout}" for s in static))

    section("B: dedup on (skill, sorted-targets) + static-skill bypass")
    eng, wf, _ = ctx()
    fresh_state()
    t1 = [f"d{i}.{TARGET}" for i in range(3)]
    write_vectors(ANCHOR, [{"skill": PRIMARY, "targets": t1}])
    mark_done(eng, ANCHOR)
    b1 = await eng._expand_from_anchor(wf)
    ck("B1 vector with targets BYPASSES the static-skill name check",
       b1 == 1, f"injected={b1} (skill is also a static workflow step)")

    write_vectors(ANCHOR, [{"skill": PRIMARY, "targets": list(reversed(t1))}])
    b2 = await eng._expand_from_anchor(wf)
    ck("B2 identical set, different order -> NO duplicate", b2 == 0, f"injected={b2}")

    write_vectors(ANCHOR, [{"skill": PRIMARY, "targets": [f"other{i}.{TARGET}" for i in range(3)]}])
    b3 = await eng._expand_from_anchor(wf)
    prim_ids = sorted(s.id for s in expanded(wf) if s.skill == PRIMARY)
    ck("B3 disjoint set, same skill -> SECOND step allowed", b3 == 1 and len(prim_ids) == 2, f"{prim_ids}")

    fresh_state()
    write_vectors(ANCHOR, [{"skill": PRIMARY, "weight": 90}])       # no targets
    mark_done(eng, ANCHOR)
    b4 = await eng._expand_from_anchor(wf)
    ck("B4 no-targets + skill already a static step -> NO expansion (backward compat)",
       b4 == 0, f"injected={b4}")

    section("Backward-compat: no-targets vector falls back to anchor targets")
    eng, wf, _ = ctx()
    fresh_state()
    # 'dnsenum' is registered but NOT a static workflow step, so the no-targets
    # path must expand and fall back to the anchor's own targets.
    write_vectors(ANCHOR, [{"skill": "dnsenum", "weight": 50}])
    mark_done(eng, ANCHOR)
    b5 = await eng._expand_from_anchor(wf)
    fb = [s for s in expanded(wf) if s.skill == "dnsenum"]
    ck("B5 no-targets vector -> expanded step carries anchor targets",
       b5 == 1 and fb and fb[0].targets == [TARGET], f"t={fb[0].targets if fb else 'n/a'}")
    ck("B6 no-targets step id also carries the hash suffix",
       bool(fb) and fb[0].id.startswith(f"exp-dnsenum-{ANCHOR}-"), fb[0].id if fb else "n/a")

    section("Degradation: anchor NOT done / vectors missing / corrupt")
    eng, wf, _ = ctx()
    fresh_state()
    write_vectors(ANCHOR, [{"skill": PRIMARY, "targets": ["x." + TARGET]}])
    b6 = await eng._expand_from_anchor(wf)
    ck("DGD1 anchor result missing -> 0 injected, no crash", b6 == 0, f"injected={b6}")
    mark_done(eng, ANCHOR)
    shutil.rmtree(STATE / "dnsenum-analyzer")
    b7 = await eng._expand_from_anchor(wf)
    ck("DGD2 next_vectors.json missing -> 0 injected, no crash", b7 == 0, f"injected={b7}")
    write_vectors(ANCHOR, "{ this is not json ]")
    b8 = await eng._expand_from_anchor(wf)
    ck("DGD3 corrupt next_vectors.json -> 0 injected, no crash", b8 == 0, f"injected={b8}")
    write_vectors(ANCHOR, [{"skill": PRIMARY, "targets": [123, "  ", None, f"ok.{TARGET}"]}])
    b9 = await eng._expand_from_anchor(wf)
    val = [s for s in expanded(wf) if s.skill == PRIMARY]
    ck("DGD4 non-string/blank targets filtered out", b9 == 1 and val[0].targets == [f"ok.{TARGET}"],
       f"t={val[0].targets if val else 'n/a'}")

    section("Anchor selection (recon-completo)")
    anchors = [s.id for s in wf.steps if s.metadata.get("expansion_anchor", False)]
    info("expansion_anchor steps: " + ", ".join(anchors))
    ck("ANC1 dns-analyzer (the vector source) is an anchor", ANCHOR in anchors)
    ck("ANC2 dns-discovery (scan, writes NO next_vectors) is ALSO an anchor -> latent no-op",
       "dns-discovery" in anchors)
    ck("ANC3 report-html depends_on has no dnsenum dependency",
       not any("dns" in dep for dep in
               [s for s in wf.steps if s.id == "report-html"][0].depends_on))

    # -----------------------------------------------------------------------
    # Section V: retired dns_pr1_harness.py ground, folded in.
    # A synthetic workflow keeps the pre-change skip rules observable without
    # the real workflow's unrelated static steps getting in the way.
    # -----------------------------------------------------------------------
    section("V: vector-list validation + no-targets parity with pre-change semantics")

    def synthetic(steps_extra, expansion=None):
        data = {
            "name": "harness-wf",
            "steps": [
                {"id": ANCHOR, "skill": "dnsenum-analyzer", "targets": [TARGET],
                 "depends_on": [], "metadata": {"expansion_anchor": True}},
                *steps_extra,
            ],
        }
        if expansion:
            data["expansion"] = expansion
        return Workflow(data, source=Path("workflows/harness-wf.yaml"))

    # Static steps: two skills the engine must skip on the no-targets path.
    static_steps = [
        {"id": "httpx-scan", "skill": "httpx", "targets": [TARGET]},
        {"id": "nikto-scan", "skill": "nikto", "targets": [TARGET]},
    ]
    vectors_no_targets = [
        {"skill": "httpx"},               # static skill      -> legacy skip
        {"skill": "nuclei", "reason": "r"},
        {"skill": ""},                     # no skill name     -> dropped
        {"skill": "unknown-skill"},        # not registered    -> dropped
        {"skill": "httpx"},                # static + dup     -> skipped
        {"skill": "whatweb"},
        {"skill": "whatweb", "reason": "d"},  # duplicate skill -> collapses
    ]

    eng, wfv, _ = build_engine(wf=synthetic(static_steps))
    fresh_state()
    write_vectors(ANCHOR, vectors_no_targets)
    mark_done(eng, ANCHOR)
    await eng._expand_from_anchor(wfv)
    new_steps = [(s.id, s.skill, tuple(s.targets)) for s in expanded(wfv)]

    def pre_change_semantics(vectors, static_skills, anchor_targets, registered):
        """The OLD (pre-targets) _expand_from_anchor, for regression parity."""
        steps, seen = [], set()
        for v in vectors:
            skill = v.get("skill", "")
            if not skill or skill in static_skills or skill not in registered:
                continue
            sid = f"exp-{skill}-{ANCHOR}"
            if sid in seen:
                continue
            seen.add(sid)
            steps.append((sid, skill, tuple(anchor_targets)))
        return steps

    registered = {s for s in ("httpx", "nuclei", "whatweb", "nikto")
                  if loader.get_skill(s) is not None}
    pre_steps = pre_change_semantics(vectors_no_targets, {"httpx", "nikto"}, [TARGET], registered)

    ck("V1 same step COUNT as pre-change semantics", len(new_steps) == len(pre_steps),
       f"new={len(new_steps)} pre={len(pre_steps)}")
    ck("V2 same skills + targets as pre-change semantics",
       [(a[1], a[2]) for a in new_steps] == [(b[1], b[2]) for b in pre_steps],
       f"new={[(a[1], a[2]) for a in new_steps]} pre={[(b[1], b[2]) for b in pre_steps]}")
    ck("V3 legacy skip preserved (static skipped, empty name dropped, dups collapsed)",
       [(a[1], a[2]) for a in new_steps] == [("nuclei", (TARGET,)), ("whatweb", (TARGET,))],
       str([(a[1], a[2]) for a in new_steps]))
    ck("V4 ids are now hashed (the one documented semantic change)",
       all(sid == f"exp-{skill}-{ANCHOR}-" + _targets_key(list(tgt))
           for sid, skill, tgt in new_steps),
       str([a[0] for a in new_steps]))
    ck("V5 unregistered skill in a vector list is dropped, not injected",
       "unknown-skill" not in {a[1] for a in new_steps})


if __name__ == "__main__":
    try:
        asyncio.run(_run())
    except Exception:  # noqa: BLE001 - a crashing harness is a failing harness
        import traceback
        traceback.print_exc()
        ck("harness completed without an unhandled exception", False, "see traceback above")
    finish(R)
