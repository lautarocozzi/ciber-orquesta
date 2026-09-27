#!/usr/bin/env python3
"""Parity harness for the dry-run expansion preview (PR #6, 4b030e3).

``engine.workflow.preview_expansion()`` lets
``main.py --dry-run --expand-next-vectors`` print the ``exp-*`` steps a real run
would inject, without executing a single skill. Its whole value rests on ONE
claim: the preview predicts the runtime exactly. This harness is the durable
evidence for that claim -- the original 21-check parity script lived only in
/tmp and is gone, so the function shipped with ZERO coverage.

Three things are pinned here:

* PARITY      -- for the same anchor state, ``preview_expansion()`` and the
                 real ``WorkflowEngine._expand_from_anchor()`` produce the same
                 steps, field for field. Both call the same
                 ``_build_expanded_step()``, so a drift here means that sharing
                 broke.
* CONTRACT    -- the CLI dry run behaves as specified: exit 0 cold with a clear
                 "no anchor state" note and zero ``exp-*`` lines; exit 0 warm
                 with the ``exp-*`` lines carrying the discovered subdomains.
                 Neither run may execute a skill.
* SANDBOXING  -- a traversal-shaped name cannot steer the state lookup out of
                 STATE_DIR, and no run writes outside the work dir.

The fixture mirrors what ``skills/dnsenum-analyzer/main.sh`` really emits: the
12-key ``consolidated.json`` contract and the 4-key ``next_vectors.json``
envelope written by ``skills/_shared/envelope.sh::write_next_vectors``, with
the three real sub-target vectors (httpx / nuclei / whatweb).

Everything runs offline against synthetic state in a temp sandbox. NOT a live
scan. See README.md.
"""
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _harness import (  # noqa: E402
    PROJECT, Reporter, activate_engine_env, finish, new_workspace, write_executable,
)

R = Reporter("preview_expansion parity + dry-run contract")
WS = new_workspace("preview-parity")

# MUST happen before importing anything under engine.*: engine/workflow.py and
# engine/skill_loader.py both snapshot their dir env into module constants at
# import time.
activate_engine_env(WS.state)
sys.path.insert(0, str(PROJECT))

from engine.main_manager import ProcessResult, ProcessStatus  # noqa: E402
from engine.skill_loader import SkillLoader  # noqa: E402
from engine.workflow import (  # noqa: E402
    Workflow, WorkflowEngine, _anchor_steps_for, _target_slug, _targets_key,
    load_workflow, preview_expansion,
)

STATE = WS.state
BASE = "prevbase001"
TARGET = "example.com"
ANCHOR = "dns-analyzer"
ANCHOR_SKILL = "dnsenum-analyzer"

# Tools a real skill run would exec. Stubbed onto PATH so "no skill subprocess
# was spawned" is a measured fact, not an assumption: if any of them runs, it
# drops a marker file and the check fails.
TOOLS = ("dnsenum", "dig", "nmap", "nuclei", "whatweb", "httpx", "nikto", "curl", "gau")
MARKERS = WS.path("tool-markers")

ck = R.ck
section = R.section
info = R.info


# ---------------------------------------------------------------------------
# Fixture: byte-compatible with what dnsenum-analyzer/main.sh writes
# ---------------------------------------------------------------------------
def analyzer_vectors(subs, cap=10):
    """The exact three sub-target vectors main.sh's jq emits.

    Kept as a function of the subdomain list so the harness stays honest about
    the two caps that exist: the analyzer's own MAX_TARGETS_PER_VECTOR and the
    engine's workflow.expansion.max_targets_per_vector. They are both 10.
    """
    n = len(subs)
    picked = subs[:cap]
    return [
        {"condition": "subdomains discovered", "skill": "httpx", "weight": 90,
         "reason": f"{n} subdomains discovered — probe live HTTP on each one",
         "targets": list(picked)},
        {"condition": "subdomains discovered", "skill": "nuclei", "weight": 80,
         "reason": f"{n} subdomains discovered — vulnerability scanning the new attack surface",
         "targets": list(picked)},
        {"condition": "subdomains discovered", "skill": "whatweb", "weight": 70,
         "reason": f"{n} subdomains discovered — fingerprint the technology stack",
         "targets": list(picked)},
    ]


def write_anchor_state(step_id, skill, vectors, subdomains, *,
                       base=BASE, target=TARGET, severity="low", write_contract=True):
    """Write a genuine dnsenum-analyzer state dir. Returns its path.

    Layout mirrors a real run exactly:
      state/{skill}/{base}--{step}--{slug}/next_vectors.json   (engine reads this)
      state/{skill}/{base}--{step}--{slug}/consolidated.json   (12-key contract)
    """
    scan_dir = f"{base}--{step_id}--{_target_slug(target)}"
    d = STATE / skill / scan_dir
    d.mkdir(parents=True, exist_ok=True)
    (d / "next_vectors.json").write_text(json.dumps({
        "scan_id": scan_dir,
        "target": target,
        "host_status": severity,
        "next_vectors": vectors,
    }, indent=2))
    if write_contract:
        (d / "consolidated.json").write_text(json.dumps({
            "scan_id": scan_dir,
            "target": target,
            "started_at": "2026-09-26T12:00:00Z",
            "domain": target,
            "subdomains": [{"name": s, "ip": "93.184.216.34", "source": "dnsenum"}
                           for s in subdomains],
            "subdomain_count": len(subdomains),
            "ns": [{"host": "a.iana-servers.net", "ip": "199.43.135.53"}],
            "mx": [{"host": "mail.example.com", "ip": "93.184.216.35", "pref": 10}],
            "zone_transfer": {"attempted": True, "success": False, "records": []},
            "severity": severity,
            "next_vectors": vectors,
            "partial": False,
        }, indent=2))
    return d


def fresh_state():
    shutil.rmtree(STATE, ignore_errors=True)
    STATE.mkdir(parents=True)


def build_workflow(target=TARGET):
    """Real workflow, real target substitution (mirrors main.py::_resolve_workflow_target)."""
    wf = load_workflow("recon-completo", workflows_dir=PROJECT / "workflows")
    for s in wf.steps:
        s.targets = [t.replace("{{ target }}", target) for t in s.targets]
    return wf


def build_engine(base=BASE):
    """Real loader, bare engine: __init__ is bypassed so no subprocess exists."""
    loader = SkillLoader(PROJECT / "skills")
    loader.load_all()
    eng = WorkflowEngine.__new__(WorkflowEngine)
    eng.base_scan_id = base
    eng.skill_name = "recon-completo"
    eng._results = {}
    eng.skill_loader = loader
    return eng, loader


def mark_all_anchors_done(eng, wf):
    """Runtime only considers an anchor whose result is DONE.

    Every anchor is marked so the runtime and the preview walk the SAME anchor
    set -- that is what makes the two comparable.
    """
    for s in _anchor_steps_for(wf):
        eng._results[s.id] = ProcessResult(
            scan_id=BASE, skill=s.skill, target=TARGET, sub_process=s.sub_process,
            status=ProcessStatus.DONE,
        )


def signature(step):
    """Full step identity. Order-sensitive on targets/depends_on on purpose."""
    return (
        step.id,
        step.skill,
        step.sub_process,
        tuple(step.targets),
        tuple(step.depends_on),
        step.condition,
        step.timeout,
        json.dumps(step.metadata, sort_keys=True),
    )


def tree_fingerprint(root: Path) -> dict:
    out = {}
    for p in sorted(Path(root).rglob("*")):
        try:
            st = p.stat()
        except OSError:
            continue
        out[str(p.relative_to(root))] = ("d" if p.is_dir() else "f", st.st_size,
                                         int(st.st_mtime_ns))
    return out


# ---------------------------------------------------------------------------
# CLI driver
# ---------------------------------------------------------------------------
def cli_env(state_dir: Path, *, stub_tools=False):
    env = dict(os.environ)
    env["WORKFLOWS_DIR"] = str(PROJECT / "workflows")
    env["SKILLS_DIR"] = str(PROJECT / "skills")
    env["STATE_DIR"] = str(state_dir)
    env["REPORTS_DIR"] = str(state_dir.parent / (state_dir.name + "-reports"))
    # engine/event_bus.py snapshots EVENTS_DIR at import and defaults it to the
    # RELATIVE path "events". main.py no longer writes an opening event on a dry
    # run, but the redirect stays: it keeps P3e a real guard — it proves the
    # assertion fails when a write DOES land, rather than passing because the
    # dir was never created at the default location.
    env["EVENTS_DIR"] = str(state_dir.parent / (state_dir.name + "-events"))
    env["STEP_TIMEOUT_SECONDS"] = "7200"
    if stub_tools:
        env["PATH"] = str(WS.bin) + os.pathsep + env["PATH"]
    return env


def run_cli(target, state_dir, *, stub_tools=False):
    return subprocess.run(
        [sys.executable, "engine/main.py", "--target", target,
         "--workflow", "recon-completo", "--expand-next-vectors", "--dry-run"],
        cwd=str(PROJECT), env=cli_env(state_dir, stub_tools=stub_tools),
        capture_output=True, text=True, timeout=180,
    )


def install_tool_stubs():
    """Every scanner/network tool becomes a marker-dropper. A hit == a real run."""
    MARKERS.mkdir(parents=True, exist_ok=True)
    for tool in TOOLS:
        write_executable(WS.bin / tool, (
            "#!/usr/bin/env bash\n"
            f'printf "spawned %s %s\\n" "{tool}" "$*" >> "{MARKERS}/{tool}"\n'
            "exit 0\n"
        ))


def expanded_lines(stdout):
    """The dry-run's exp-* lines, in printed order."""
    return [ln.strip() for ln in stdout.splitlines() if ln.strip().startswith("exp-")]


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------
def run():
    install_tool_stubs()
    _, loader = build_engine()

    section("P0: probe skills on this host (fixture covers 3 vectors, host may register fewer)")
    probes = ("httpx", "nuclei", "whatweb", "nikto")
    registered = [p for p in probes if loader.get_skill(p) is not None]
    unregistered = [p for p in probes if loader.get_skill(p) is None]
    info(f"registered: {registered} | unregistered (engine skips their vectors): {unregistered}")
    ck("P0a at least 2 probe skills registered, so a preview can be non-empty", len(registered) >= 2,
       f"have {registered}")
    ck("P0b every unregistered probe is a real host fact, not a harness bug",
       all(loader.get_skill(p) is None for p in unregistered) and len(registered) + len(unregistered) == len(probes),
       f"reg={registered} unreg={unregistered}")

    # -----------------------------------------------------------------------
    # P1 — the fixture must look like a genuine run
    # -----------------------------------------------------------------------
    section("P1: fixture mirrors the real dnsenum-analyzer contract")
    subs = sorted(["www.example.com", "api.example.com", "dev.example.com"])
    vectors = analyzer_vectors(subs)
    fresh_state()
    d = write_anchor_state(ANCHOR, ANCHOR_SKILL, vectors, subs)

    env = json.loads((d / "next_vectors.json").read_text())
    ck("P1a next_vectors.json is the 4-key envelope.sh writes",
       sorted(env) == ["host_status", "next_vectors", "scan_id", "target"], str(sorted(env)))
    ck("P1b each vector carries the 5 keys main.sh's jq emits",
       all(sorted(v) == ["condition", "reason", "skill", "targets", "weight"] for v in vectors),
       str(sorted(vectors[0])))
    contract = json.loads((d / "consolidated.json").read_text())
    ck("P1c consolidated.json is the full 12-key analyzer contract", len(contract) == 12,
       f"{len(contract)} keys")
    ck("P1d the engine's reader key is present and is a list",
       isinstance(env.get("next_vectors"), list) and len(env["next_vectors"]) == 3)
    ck("P1e dir name follows {base}--{step}--{slug}, the convention both sides resolve",
       d.name == f"{BASE}--{ANCHOR}--{_target_slug(TARGET)}" and env["scan_id"] == d.name,
       d.name)
    expected_vec_skills = [v["skill"] for v in vectors if loader.get_skill(v["skill"])]

    # -----------------------------------------------------------------------
    # P2 — PARITY: preview vs. the real runtime path
    # -----------------------------------------------------------------------
    section("P2: preview_expansion() == WorkflowEngine._expand_from_anchor()")

    async def parity(label, write_fixture, *, want=None, wf_target=TARGET):
        """Run both paths over the same on-disk state and diff the signatures."""
        fresh_state()
        write_fixture()
        before = tree_fingerprint(WS.root)

        wf_prev = build_workflow(wf_target)
        n_steps_before = len(wf_prev.steps)
        eng, ld = build_engine()
        mark_all_anchors_done(eng, wf_prev)
        prev = preview_expansion(wf_prev, ld)
        wf_after_preview = len(wf_prev.steps)

        wf_run = build_workflow(wf_target)
        eng2, _ = build_engine()
        mark_all_anchors_done(eng2, wf_run)
        injected = await eng2._expand_from_anchor(wf_run)
        runtime = [s for s in wf_run.steps if s.metadata.get("expanded")]

        after = tree_fingerprint(WS.root)
        sig_prev = [signature(s) for s in prev]
        sig_run = [signature(s) for s in runtime]

        ck(f"P2[{label}] runtime actually injected steps (harness exercises both paths)",
           injected == len(runtime) and (want is None or len(runtime) == want),
           f"injected={injected} steps={len(runtime)}")
        ck(f"P2[{label}] full step signatures identical (id/skill/sub_process/targets/"
           f"depends_on/condition/timeout/metadata)", sig_prev == sig_run,
           f"preview={sig_prev[:1]} runtime={sig_run[:1]}")
        ck(f"P2[{label}] neither path wrote anything to disk",
           before == after,
           f"new={sorted(set(after) - set(before))}")
        ck(f"P2[{label}] preview did not mutate the workflow", wf_after_preview == n_steps_before)
        return prev, runtime, eng

    # -- the headline case: the real three sub-target vectors ---------------
    previewed, injected_steps, _ = asyncio.run(parity(
        "3 vectors",
        lambda: write_anchor_state(ANCHOR, ANCHOR_SKILL, vectors, subs),
        want=len(expected_vec_skills),
    ))
    ck("P2a both paths emitted the same number of steps",
       len(previewed) == len(injected_steps), f"{len(previewed)}/{len(injected_steps)}")
    ck("P2b one step per REGISTERED vector skill (unregistered ones are skipped by both sides)",
       [s.skill for s in previewed] == expected_vec_skills,
       f"got={[s.skill for s in previewed]} want={expected_vec_skills}")
    want_key = _targets_key(subs)
    ck("P2c ids are exp-{skill}-dns-analyzer-<8hex> and share the target-set hash",
       all(s.id == f"exp-{s.skill}-{ANCHOR}-{want_key}" for s in previewed), want_key)
    ck("P2d sub_process comes from the real skill definition, not a guess",
       all(s.sub_process == loader.get_skill(s.skill).main_script for s in previewed),
       str([(s.skill, s.sub_process) for s in previewed]))
    ck("P2e targets are the discovered subdomains, sorted, and NOT the anchor's own target",
       all(s.targets == subs and TARGET not in s.targets for s in previewed),
       str([s.targets for s in previewed]))
    ck("P2f wiring: depends_on the anchor, condition prev.success",
       all(s.depends_on == [ANCHOR] and s.condition == "prev.success" for s in previewed))
    reason_by_skill = {v["skill"]: v["reason"] for v in vectors}
    ck("P2g metadata carries each vector's own reason + phase/expanded markers",
       all(s.metadata.get("expanded") is True
           and s.metadata.get("phase") == "automated-expansion"
           and s.metadata.get("description") == reason_by_skill[s.skill]
           for s in previewed),
       str([(s.skill, s.metadata.get("description")) for s in previewed]))

    # -- cap case: 15 subdomains, analyzer + engine both cap at 10 ----------
    many = sorted(f"s{i:02d}.{TARGET}" for i in range(15))
    capped, _, _ = asyncio.run(parity(
        "cap",
        lambda: write_anchor_state(ANCHOR, ANCHOR_SKILL, analyzer_vectors(many), many),
        want=len(expected_vec_skills),
    ))
    ck("P2h cap case: 15 proposed -> 10 kept, identically on both paths",
       all(s.targets == many[:10] for s in capped) and capped
       and all(s.id.endswith(_targets_key(many[:10])) for s in capped),
       str(capped[0].targets if capped else "n/a"))

    # -- backward-compat: no-targets vectors, static-skill skip, dups ------
    legacy = [
        {"skill": "dnsenum", "weight": 50},                       # no targets -> anchor fallback
        {"skill": "dnsenum-analyzer", "weight": 40},              # static skill -> legacy skip
        {"skill": "", "weight": 10},                              # no skill name  -> dropped
        {"skill": "not-a-real-skill", "weight": 5},               # unregistered   -> dropped
        {"skill": "nuclei", "targets": [f"z{i}.{TARGET}" for i in range(3)]},
        {"skill": "nuclei", "targets": [f"{TARGET.replace('example.com','y')}{i}.com" for i in range(3)]},
        {"skill": "nuclei", "targets": list(reversed([f"z{i}.{TARGET}" for i in range(3)]))},
        {"skill": "nuclei", "targets": [123, "  ", None, f"ok.{TARGET}"]},
    ]
    legacy_steps, _, _ = asyncio.run(parity(
        "legacy vectors",
        lambda: write_anchor_state(ANCHOR, ANCHOR_SKILL, legacy, subs),
    ))
    got_ids = sorted(s.id for s in legacy_steps)
    want_ids = sorted(
        {f"exp-dnsenum-{ANCHOR}-{_targets_key([TARGET])}"}                       # anchor fallback
        | {f"exp-nuclei-{ANCHOR}-{_targets_key(sorted([f'z{i}.{TARGET}' for i in range(3)]))}"}  # bypass + dedup
        | {f"exp-nuclei-{ANCHOR}-{_targets_key(sorted([f'ok.{TARGET}']))}"}      # invalid targets filtered
        | {f"exp-nuclei-{ANCHOR}-{_targets_key(sorted([f'y{i}.com' for i in range(3)]))}"}
    )
    ck("P2i legacy vector set: exactly the fallback + bypass/dedup steps on both paths "
       "(static skill skipped, empty name dropped, unregistered dropped)",
       got_ids == want_ids, f"got={got_ids} want={want_ids}")
    ck("P2i2 the reordered duplicate vector produced no extra step",
       sum(1 for s in legacy_steps if s.targets == sorted(f"z{i}.{TARGET}" for i in range(3))) == 1)

    # -- degradation: no state / corrupt / different anchor ----------------
    empty, empty_run, _ = asyncio.run(parity("no state", lambda: None, want=0))
    ck("P2k COLD parity: no anchor state -> both paths plan nothing", not empty and not empty_run)

    def _corrupt():
        write_anchor_state(ANCHOR, ANCHOR_SKILL, vectors, subs, write_contract=False)
        (STATE / ANCHOR_SKILL / f"{BASE}--{ANCHOR}--{_target_slug(TARGET)}"
         / "next_vectors.json").write_text("{ not json ]")
    corrupt, corrupt_run, _ = asyncio.run(parity("corrupt json", _corrupt, want=0))
    ck("P2l corrupt next_vectors.json -> both paths plan nothing, no crash",
       not corrupt and not corrupt_run)

    other, other_run, _ = asyncio.run(parity(
        "dns-discovery anchor",
        lambda: write_anchor_state("dns-discovery", "dnsenum-scan", vectors, subs),
        want=len(expected_vec_skills),
    ))
    ck("P2m parity also holds for the dns-discovery anchor's own state dir "
       "(a latent no-op: dnsenum-scan never writes next_vectors)",
       [signature(s) for s in other] == [signature(s) for s in other_run],
       f"n={len(other)}")

    # -----------------------------------------------------------------------
    # P3 — the preview is read-only and spawns nothing
    # -----------------------------------------------------------------------
    section("P3: preview is read-only, the dry run spawns no scanner")
    info(f"tool stubs on PATH: {' '.join(TOOLS)} (each drops a marker if executed)")

    stub_state = WS.path("cli-stub-state")
    shutil.rmtree(stub_state, ignore_errors=True)
    stub_state.mkdir(parents=True)
    write_anchor_state(ANCHOR, ANCHOR_SKILL, vectors, subs)  # in-process state, unrelated
    (stub_state / ANCHOR_SKILL / f"{BASE}--{ANCHOR}--{_target_slug(TARGET)}").mkdir(
        parents=True, exist_ok=True)
    (stub_state / ANCHOR_SKILL / f"{BASE}--{ANCHOR}--{_target_slug(TARGET)}"
     / "next_vectors.json").write_text(json.dumps({
        "scan_id": f"{BASE}--{ANCHOR}--{_target_slug(TARGET)}", "target": TARGET,
        "host_status": "low", "next_vectors": vectors}))
    fixture_fp = tree_fingerprint(stub_state / ANCHOR_SKILL)
    fixture_paths = {f"{ANCHOR_SKILL}/{rel}" for rel in fixture_fp}
    warm_stub = run_cli(TARGET, stub_state, stub_tools=True)
    fired = sorted(p.name for p in MARKERS.glob("*")) if MARKERS.is_dir() else []
    ck("P3a WARM dry run with every scanner on PATH: NO tool was executed", not fired, str(fired))
    ck("P3b WARM dry run exited 0 with the stubbed PATH", warm_stub.returncode == 0,
       f"rc={warm_stub.returncode}")
    written = sorted(
        str(p.relative_to(stub_state)) for p in stub_state.rglob("*")
        if p.is_file() and str(p.relative_to(stub_state)) not in fixture_paths
    )
    ck("P3c no skill wrote state during the dry run — nothing at all was written "
       "into STATE_DIR (the engine writes none either; P3e/P4f cover that)",
       written == [], str(written))
    ck("P3d the anchor state dir was read, never written",
       tree_fingerprint(stub_state / ANCHOR_SKILL) == fixture_fp)
    ev_dir = stub_state.parent / (stub_state.name + "-events")
    ev_files = sorted(str(p.relative_to(ev_dir)) for p in ev_dir.rglob("*") if p.is_file())
    ck("P3e the dry run is read-only on disk: ZERO events written, even with a "
       "writable EVENTS_DIR", ev_files == [], str(ev_files))
    info("FIXED (was a finding): write_event()/write_state() used to run BEFORE the "
         "dry_run branch and EVENTS_DIR defaults to the relative 'events/', which "
         "STATE_DIR does not cover — so a plain `--dry-run` dropped "
         "events/engine/<id>.json into the checkout. main.py now emits the opening "
         "event only when not dry_run. P3e was inverted from 'exactly ONE opening "
         "event' to 'zero events': the assertion got stronger, not weaker.")

    # -----------------------------------------------------------------------
    # P4 — the dry-run contract, COLD and WARM
    # -----------------------------------------------------------------------
    section("P4: dry-run contract -- COLD (no anchor state)")

    cold_state = WS.path("cli-cold-state")
    shutil.rmtree(cold_state, ignore_errors=True)
    cold_state.mkdir(parents=True)
    ck("P4a the COLD run really is cold (no anchor state exists)",
       not (cold_state / ANCHOR_SKILL).exists())
    cold = run_cli(TARGET, cold_state)
    cold_out = cold.stdout
    ck("P4b COLD exit 0", cold.returncode == 0, f"rc={cold.returncode}")
    ck("P4c COLD prints the 'no anchor state' note telling the operator to run the workflow first",
       "no anchor state" in cold_out and "run the workflow once" in cold_out)
    ck("P4d COLD lists the static plan (27 steps) but ZERO exp-* lines",
       "Steps (27):" in cold_out and not expanded_lines(cold_out), str(expanded_lines(cold_out)))
    ck("P4e COLD previews no subdomain target",
       not any(s in cold_out for s in subs), "a subdomain leaked into a cold preview")
    ck("P4f COLD created NOTHING in STATE_DIR — a dry run is read-only end to end",
       sorted(p.name for p in cold_state.iterdir()) == [],
       str(sorted(p.name for p in cold_state.iterdir())))

    section("P4: dry-run contract -- WARM (anchor state on disk)")
    warm_state = WS.path("cli-warm-state")
    shutil.rmtree(warm_state, ignore_errors=True)
    warm_state.mkdir(parents=True)
    wdir = warm_state / ANCHOR_SKILL / f"{BASE}--{ANCHOR}--{_target_slug(TARGET)}"
    wdir.mkdir(parents=True)
    (wdir / "next_vectors.json").write_text(json.dumps({
        "scan_id": wdir.name, "target": TARGET, "host_status": "low",
        "next_vectors": vectors}))
    warm_before = tree_fingerprint(warm_state / ANCHOR_SKILL)
    warm = run_cli(TARGET, warm_state)
    warm_out = warm.stdout

    want_lines = [
        f"exp-{sk}-{ANCHOR}-{want_key}: {sk}/{loader.get_skill(sk).main_script} "
        f"-> {subs} (after: {ANCHOR})"
        for sk in expected_vec_skills
    ]
    got_lines = expanded_lines(warm_out)
    ck("P4g WARM exit 0", warm.returncode == 0, f"rc={warm.returncode}")
    ck("P4h WARM prints the expansion section", "Expanded steps (would run after execution):" in warm_out)
    ck("P4i WARM lists exactly the expected exp-<skill>-dns-analyzer-<8hex> lines, in vector order",
       got_lines == want_lines, f"got={got_lines} want={want_lines}")
    ck("P4j no 'no anchor state' note when state exists", "no anchor state" not in warm_out)
    ck("P4k WARM exp-* lines carry the discovered subdomains as targets",
       all(f"-> {subs}" in ln for ln in got_lines) and got_lines, str(got_lines))
    ck("P4l the preview read the state read-only (anchor state dir byte-identical)",
       tree_fingerprint(warm_state / ANCHOR_SKILL) == warm_before)
    ck("P4m the WARM CLI preview matches the in-process preview, step for step",
       got_lines == [f"{s.id}: {s.skill}/{s.sub_process} -> {s.targets} (after: {', '.join(s.depends_on)})"
                     for s in previewed],
       "CLI output and preview_expansion() disagree")
    ck("P4n unregistered vector skills are absent from the WARM preview",
       all(f"exp-{sk}-" not in warm_out for sk in unregistered), str(unregistered))

    # -----------------------------------------------------------------------
    # P5 — the wildcard / path guard
    # -----------------------------------------------------------------------
    section("P5: path guard -- a traversal-shaped name cannot escape STATE_DIR")
    hostile = f"../../../../ESCAPE-CANARY-{WS.name}"
    canary = WS.root / f"ESCAPE-CANARY-{WS.name}"
    ck("P5a _target_slug neutralizes '..' and every path separator",
       "/" not in _target_slug(hostile) and ".." not in _target_slug(hostile),
       _target_slug(hostile))

    fresh_state()
    # A decoy where a NAIVE (unsanitized) implementation would land: outside
    # STATE_DIR but inside the work dir.
    canary.mkdir(parents=True, exist_ok=True)
    (canary / "next_vectors.json").write_text(json.dumps({
        "scan_id": "decoy", "target": hostile, "host_status": "low",
        "next_vectors": [{"skill": "nuclei", "targets": ["decoy.example.com"]}],
    }))
    canary_before = tree_fingerprint(canary)
    # The real fixture lives at the SANITIZED path the guard redirects to.
    write_anchor_state(ANCHOR, ANCHOR_SKILL,
                       [{"skill": "nuclei", "targets": ["safe.example.com"]}],
                       ["safe.example.com"], target=hostile)

    def _hostile_wf():
        data = {
            "name": "hostile-wf",
            "steps": [{"id": ANCHOR, "skill": ANCHOR_SKILL, "targets": [hostile],
                       "sub_process": "skills/dnsenum-analyzer/main.sh",
                       "depends_on": [], "timeout": 7200,
                       "metadata": {"expansion_anchor": True}}],
            "expansion": {"max_expansions": 10, "max_targets_per_vector": 10},
        }
        return Workflow(data, source=Path("workflows/hostile-wf.yaml"))

    _, ld = build_engine()
    wf_h = _hostile_wf()
    hostile_steps = preview_expansion(wf_h, ld)
    ck("P5b the preview follows the SANITIZED path, never the traversal path",
       [s.targets for s in hostile_steps] == [["safe.example.com"]]
       and not any("decoy" in t for s in hostile_steps for t in s.targets),
       str([s.targets for s in hostile_steps]))
    ck("P5c the traversal landing zone was never written to or read as state",
       tree_fingerprint(canary) == canary_before and
       not any("decoy" in str(p) for p in STATE.rglob("*")),
       "engine touched the traversal path")
    ck("P5d the CLI refuses a traversal target outright (exit 2, explicit reason)",
       run_cli(hostile, WS.path("cli-reject-state")).returncode == 2
       and "path traversal" in run_cli(hostile, WS.path("cli-reject-state")).stderr,
       "target validation did not reject the traversal")

    # A traversal name carried in a VECTOR is a different question: the engine
    # does not sanitize step targets, it only filters non-strings/blanks. Assert
    # what the product actually does, and prove it still writes nothing.
    fresh_state()
    wild = ["../../escape-me.example.com", "ok.example.com"]
    write_anchor_state(ANCHOR, ANCHOR_SKILL, [{"skill": "nuclei", "targets": wild}],
                       ["ok.example.com"])
    wf_w = build_workflow()
    wild_before = tree_fingerprint(WS.root)
    wild_steps = preview_expansion(wf_w, ld)
    wild_after = tree_fingerprint(WS.root)
    ck("P5e a traversal name in vector targets is carried verbatim (engine does NOT "
       "sanitize step targets; the analyzer is the wildcard guard) but writes nothing",
       [s.targets for s in wild_steps] == [sorted(wild)], str([s.targets for s in wild_steps]))
    ck("P5f the whole work dir is byte-identical after the hostile preview "
       "(no write, no stray path, anywhere in the sandbox)",
       wild_before == wild_after, f"new={sorted(set(wild_after) - set(wild_before))}")
    ck("P5g no traversal-derived path exists anywhere in the work dir",
       not any("escape-me" in str(p) for p in WS.root.rglob("*")))
    info("GAP: the wildcard/wildcard-IP guard lives in skills/dnsenum-analyzer/main.sh, "
         "not in the engine. preview_expansion re-applies NO name filter beyond "
         "isinstance(str) and .strip() -- see P5e.")

    shutil.rmtree(canary, ignore_errors=True)
    info("known finding carried over from engine_expansion ANC2: dns-discovery is "
         "flagged expansion_anchor but its skill (dnsenum-scan) never writes "
         "next_vectors.json, so it is a permanent no-op anchor; and "
         "workflow.expansion.anchor_steps lists 8 steps while 9 carry the flag "
         "(that list is never read -- _anchor_steps_for uses metadata only).")


if __name__ == "__main__":
    from _harness import main
    main(run, R)
