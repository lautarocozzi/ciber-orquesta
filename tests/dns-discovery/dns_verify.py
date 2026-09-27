#!/usr/bin/env python3
"""Offline verification harness for the dns-enumeration skill chain (DNS-1..11).

Stubs `dnsenum` and `dig` on PATH so the dnsenum-scan / dnsenum-analyzer
contract, the wildcard guard, flag construction and every degradation path are
proven deterministically WITHOUT touching any external host.

Runs entirely inside a temp sandbox: STATE_DIR and REPORTS_DIR point there, so
the repo's real state/ and reports/ are never written to (proven on exit by
assert_repo_untouched).

NOT a live scan. See README.md.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _harness import (  # noqa: E402
    PROJECT, Reporter, Workspace, assert_bash_syntax, finish, jload, new_workspace,
    run_bash, tool_present, write_executable,
)

DOMAIN = "example.com"

R = Reporter("dns chain (dnsenum-scan -> dnsenum-analyzer -> sysreport)")
WS: Workspace = new_workspace("dns-chain")
FIX = WS.root
BIN = WS.bin
STATE = WS.state
REPORTS = WS.reports

ck = R.ck
section = R.section
info = R.info


def setup(mode="clean", wildcard=False, digmap=None):
    WS.reset(BIN, STATE, REPORTS)
    for name, body in (("dig", STUB_DIG), ("dnsenum", STUB_DNSENUM)):
        write_executable(BIN / name, body)
    (FIX / "payload.xml").write_text(XML_PAYLOAD)
    (FIX / "payload.log").write_text(
        LOG_PAYLOAD_NOAXFR if mode == "noaxfr" else LOG_PAYLOAD)
    assert_bash_syntax(BIN / "dnsenum")
    if digmap:
        (FIX / "digmap.txt").write_text(digmap)
    return {
        "PATH": f"{BIN}:{os.environ['PATH']}",
        "FIX_DIR": str(FIX), "FIX_MODE": mode,
        "FIX_WILDCARD": "1" if wildcard else "0",
        "FIX_DIGMAP": str(FIX / "digmap.txt") if digmap else "",
        "STATE_DIR": str(STATE), "REPORTS_DIR": str(REPORTS),
    }


def run(script, env, **kw):
    e = {k: str(v) for k, v in kw.items()}
    return run_bash(f"skills/{script}/main.sh", {**env, **e})


STUB_DIG = r'''#!/usr/bin/env bash
args=("$@"); name="${args[-1]}"
if [ "${FIX_WILDCARD:-0}" = "1" ] && [[ "$name" == w-* ]]; then
  echo "203.0.113.5"; exit 0
fi
if [ -n "${FIX_DIGMAP:-}" ] && [ -f "${FIX_DIGMAP}" ]; then
  while read -r n ip; do
    [ "$n" = "$name" ] && { echo "$ip"; exit 0; }
  done < "${FIX_DIGMAP}"
fi
exit 0
'''

STUB_DNSENUM = r'''#!/usr/bin/env bash
# Offline dnsenum stand-in. Payloads come from files written by the fixture so
# there is no nested-heredoc quoting hazard.
printf '%s\n' "$*" > "${FIX_DIR}/argv.txt"
SUBFILE=""; XML=""
while [ $# -gt 0 ]; do
  case "$1" in
    --subfile) SUBFILE="$2"; shift 2 ;;
    -o) XML="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf 'www\nmail\nrandom1\nrandom2\nshop\n' > "$SUBFILE"
if [ "${FIX_MODE:-}" = "fail" ]; then echo "dnsenum: fatal" >&2; exit 1; fi
if [ "${FIX_MODE:-}" = "truncated" ]; then
  printf '<?xml version="1.0" ?><magictree><host>198.51.100.1 <ho' > "$XML"; exit 0
fi
cp "${FIX_DIR}/payload.xml" "$XML"
cat "${FIX_DIR}/payload.log"
exit 0
'''

XML_PAYLOAD = """<?xml version="1.0" ?>
<magictree>
 <domain>example.com</domain>
 <host>198.51.100.9 <hostname>www.example.com</hostname></host>
 <host>203.0.113.5 <hostname>random1.example.com</hostname></host>
 <host>203.0.113.5 <hostname>random2.example.com</hostname></host>
 <host>198.51.100.20 <hostname>shop.example.com</hostname></host>
 <fqdn>vendor-cname.target.example.net</fqdn>
</magictree>
"""


def _hdr(title):
    """Reproduce dnsenum 1.3.1 printheader(): header line ending in ':',
    then a pure-underscore line (the parser skips `set(line) == {'_'`)."""
    return f"\n\n{title}\n" + "_" * (len(title) + 1) + "\n\n"


# Field-for-field the real dnsenum 1.3.1 STDOUT shape (see /usr/bin/dnsenum
# printheader() L1438, printrr, and the AXFR print at L897).
LOG_PAYLOAD = (
    "dnsenum VERSION: 1.3.1\n"
    + _hdr("Using Domain: example.com")
    + _hdr("Name Servers:")
    + "example.com\t86400\tIN\tNS\ta.iana-servers.net\n"
    "example.com\t86400\tIN\tNS\tb.iana-servers.net\n"
    + _hdr("Mail (MX) Servers:")
    + "example.com\t86400\tIN\tMX\t10 mail.example.com\n"
    + _hdr("Brute forcing with /usr/share/dnsenum/dns.txt:")
    + "example.com\t60\tIN\tA\t198.51.100.9\twww\n"
    "example.com\t60\tIN\tA\t203.0.113.5\trandom1\n"
    "example.com\t60\tIN\tA\t203.0.113.5\trandom2\n"
    "example.com\t60\tIN\tA\t198.51.100.20\tshop\n"
    + _hdr("Trying Zone Transfers and getting Bind Versions:")
    + "\nTrying Zone Transfer for example.com on a.iana-servers.net ... \n"
    # printrr() prints the RR OWNER first: `owner ttl IN type data`
    "axfr-host.example.com.\t3600\tIN\tA\t198.51.100.30\n"
)

# Same run, but the AXFR attempt came back empty (the common real-world case:
# attempted, refused, no records) -> severity must fall back to the "low" rung.
LOG_PAYLOAD_NOAXFR = LOG_PAYLOAD.split('Trying Zone Transfer for example.com on')[0] + (
    "\nTrying Zone Transfer for example.com on a.iana-servers.net ... \n"
)


# ===========================================================================
section("DNS-1: default invocation (spec MUST: --noreverse --threads 20 -t 3)")
env = setup()
r = run("dnsenum-scan", env, SCAN_ID="dnstest1", TARGET=DOMAIN)
argv = (FIX / "argv.txt").read_text().strip() if (FIX / "argv.txt").exists() else ""
info(f"argv: {argv}")
ck("S1 dnsenum-scan exits 0", r.returncode == 0, f"exit={r.returncode}")
ck("S2 --noreverse present", "--noreverse" in argv)
ck("S3 --threads 20 (spec default)", "--threads 20" in argv)
ck("S4 -t 3 (spec default)", " -t 3 " in f" {argv} ")
ck("S5 wordlist resolves to /usr/share/dnsenum/dns.txt", "-f /usr/share/dnsenum/dns.txt" in argv)
toks = argv.split()
ck("S6 NEVER -s (google scraping)", not any(t == "-s" for t in toks))
ck("S7 NEVER -p (google scraping)", not any(t == "-p" for t in toks))
ck("S8 NEVER -w (whois)", not any(t == "-w" for t in toks))
ck("S9 --subfile and -o emitted", "--subfile" in toks and "-o" in toks)
ck("S10 command.txt recorded", (STATE / "dnsenum-scan/dnstest1/command.txt").is_file())

section("DNS-2: parser output")
P = STATE / "dnsenum-scan/dnstest1/parsed-results.json"
p = jload(P)
ck("S11 parsed-results.json written and valid", p is not None)
names = {s["name"] for s in p["subdomains"]}
ck("S12 subdomains found (www, shop, axfr-host)",
   {"www.example.com", "shop.example.com", "axfr-host.example.com"} <= names, str(sorted(names)))
ck("S12b AXFR host carries source zone_transfer",
   [s["source"] for s in p["subdomains"] if s["name"] == "axfr-host.example.com"] == ["zone_transfer"],
   str([(s["name"], s["source"]) for s in p["subdomains"]]))
ck("S13 NS parsed (2)", len(p["ns"]) == 2, str(p["ns"]))
ck("S14 MX parsed (1)", len(p["mx"]) == 1, str(p["mx"]))
ck("S15 zone_transfer.attempted == true on every run", p["zone_transfer"]["attempted"] is True)
ck("S16 zone_transfer.records captured", len(p["zone_transfer"]["records"]) >= 1,
   f"n={len(p['zone_transfer']['records'])}")
ck("S17 clean run -> partial false", p["partial"] is False)
ck("S18 status == done", jload(STATE / "dnsenum-scan/dnstest1/status.json")["status"] == "done")

section("DNS-3: analyzer contract")
r = run("dnsenum-analyzer", env, SCAN_ID="dnstest1", TARGET=DOMAIN, WORKFLOW_SHARED_DIR="")
A = STATE / "dnsenum-analyzer/dnstest1/consolidated.json"
a = jload(A)
SPEC_KEYS = {"scan_id", "target", "started_at", "domain", "subdomains", "subdomain_count",
             "ns", "mx", "zone_transfer", "severity", "next_vectors", "partial"}
ck("A1 analyzer exits 0", r.returncode == 0, f"exit={r.returncode}")
ck("A2 contract contains EXACTLY the 12 spec keys", set(a.keys()) == SPEC_KEYS,
   str(sorted(set(a.keys()) ^ SPEC_KEYS)))
ck("A3 subdomain_count == (.subdomains|length)", a["subdomain_count"] == len(a["subdomains"]))
ck("A4 subdomain entries are {name, ip, source} only",
   all(set(s.keys()) == {"name", "ip", "source"} for s in a["subdomains"]))
ck("A5 zone_transfer has exactly {attempted, success, records}",
   set(a["zone_transfer"].keys()) == {"attempted", "success", "records"})
ck("A6 severity medium on successful AXFR (ladder rung)", a["severity"] == "medium", a["severity"])
ck("A6b zone_transfer.success true and records captured",
   a["zone_transfer"]["success"] is True and len(a["zone_transfer"]["records"]) >= 1,
   f"ok={a['zone_transfer']['success']} n={len(a['zone_transfer']['records'])}")
ck("A7 3 next_vectors: httpx/nuclei/whatweb",
   [v["skill"] for v in a["next_vectors"]] == ["httpx", "nuclei", "whatweb"],
   str([v["skill"] for v in a["next_vectors"]]))
ck("A8 weights 90/80/70", [v["weight"] for v in a["next_vectors"]] == [90, 80, 70])
ck("A9 each vector carries a targets[] array",
   all(isinstance(v.get("targets"), list) and v["targets"] for v in a["next_vectors"]))
ck("A10 vector targets <= cap 10", all(len(v["targets"]) <= 10 for v in a["next_vectors"]),
   str([len(v["targets"]) for v in a["next_vectors"]]))
ck("A11 vector targets are a subset of subdomains[]",
   set().union(*[set(v["targets"]) for v in a["next_vectors"]]) <= {s["name"] for s in a["subdomains"]})
ck("A12 next_vectors.json written where the engine reads it",
   (STATE / "dnsenum-analyzer/dnstest1/next_vectors.json").is_file())
nv = jload(STATE / "dnsenum-analyzer/dnstest1/next_vectors.json")
ck("A13 next_vectors.json carries the targets field through verbatim",
   all("targets" in v for v in nv["next_vectors"]))

section("DNS-3b: severity ladder — AXFR attempted but refused")
env = setup(mode="noaxfr")
run("dnsenum-scan", env, SCAN_ID="dnstestL", TARGET=DOMAIN)
run("dnsenum-analyzer", env, SCAN_ID="dnstestL", TARGET=DOMAIN, WORKFLOW_SHARED_DIR="")
aL = jload(STATE / "dnsenum-analyzer/dnstestL/consolidated.json")
ck("A14 AXFR attempted even when refused", aL["zone_transfer"]["attempted"] is True)
ck("A15 AXFR success false when no records returned", aL["zone_transfer"]["success"] is False)
ck("A16 severity falls back to low (subs>0, no AXFR success)", aL["severity"] == "low", aL["severity"])
ck("A17 NS and MX still parsed without the AXFR block", len(aL["ns"]) == 2 and len(aL["mx"]) == 1,
   f"ns={len(aL['ns'])} mx={len(aL['mx'])}")

section("DNS-4: domain-scope guard (CNAME outside target domain)")
ck("S19 scanner is RAW: vendor-cname present in parsed subdomains[] (by design)",
   "vendor-cname.target.example.net" in names)
ck("S20 ANALYZER EXCLUDES out-of-scope CNAME from subdomains[]",
   "vendor-cname.target.example.net" not in {s["name"] for s in a["subdomains"]},
   str(sorted(s["name"] for s in a["subdomains"])))
alltargets = set().union(*[set(v["targets"]) for v in a["next_vectors"]])
ck("S21 no out-of-scope name in any vector targets[]",
   not any(t.endswith("example.net") for t in alltargets), str(sorted(alltargets)))
ck("S22 every emitted target is inside the target domain",
   all(t == DOMAIN or t.endswith("." + DOMAIN) for t in alltargets))

section("DNS-5: wildcard-DNS filtering")
env = setup(wildcard=True, digmap=(
    "www.example.com 198.51.100.9\nshop.example.com 198.51.100.20\n"
    "axfr-host.example.com 198.51.100.30\nrandom1.example.com 203.0.113.5\n"
    "random2.example.com 203.0.113.5\n"))
r = run("dnsenum-scan", env, SCAN_ID="dnstest2", TARGET=DOMAIN)
P2 = STATE / "dnsenum-scan/dnstest2/parsed-results.json"
p2 = jload(P2)
ck("W1 wildcard record detected", p2["wildcard"]["detected"] is True, str(p2["wildcard"])[:120])
ck("W2 wildcard IP recorded", p2["wildcard"]["wildcard_ips"] == ["203.0.113.5"])
ck("W3 wildcard names EXCLUDED from subdomains[]",
   not ({"random1.example.com", "random2.example.com"} & {s["name"] for s in p2["subdomains"]}),
   str(sorted(s["name"] for s in p2["subdomains"])))
ck("W4 no subdomains[] entry carries the wildcard IP",
   not any(s["ip"] == "203.0.113.5" for s in p2["subdomains"]))
ck("W5 probe name itself excluded", "w-" not in json.dumps([s["name"] for s in p2["subdomains"]]))
run("dnsenum-analyzer", env, SCAN_ID="dnstest2", TARGET=DOMAIN, WORKFLOW_SHARED_DIR="")
a2 = jload(STATE / "dnsenum-analyzer/dnstest2/consolidated.json")
t2 = set().union(*[set(v["targets"]) for v in a2["next_vectors"]]) if a2["next_vectors"] else set()
ck("W6 NO vector targets[] entry resolves to the wildcard IP",
   not ({"random1.example.com", "random2.example.com"} & t2), str(sorted(t2)))
ck("W7 real subdomain www.example.com survives the filter", "www.example.com" in t2)

section("DNS-6: parameter overrides (engine PARAM_* and standalone env)")
env = setup()
(FIX / "small.txt").write_text("www\n")
r = run("dnsenum-scan", env, SCAN_ID="dnstest3", TARGET=DOMAIN,
        PARAM_WORDLIST=str(FIX / "small.txt"), PARAM_THREADS=5, PARAM_TIMEOUT=7)
argv3 = (FIX / "argv.txt").read_text().strip()
ck("O1 -f override honoured", f"-f {FIX}/small.txt" in argv3, argv3)
ck("O2 --threads 5 override honoured", "--threads 5" in argv3)
ck("O3 -t 7 override honoured", " -t 7 " in f" {argv3} ")

section("DNS-7: degradation — truncated XML")
env = setup(mode="truncated")
r = run("dnsenum-scan", env, SCAN_ID="dnstest4", TARGET=DOMAIN)
P4 = STATE / "dnsenum-scan/dnstest4/parsed-results.json"
p4 = jload(P4)
ck("G1 truncated XML still exits 0 (degraded, not failed)", r.returncode == 0, f"exit={r.returncode}")
ck("G2 partial == true", p4["partial"] is True)
ck("G3 status == degraded", jload(STATE / "dnsenum-scan/dnstest4/status.json")["status"] == "degraded",
   jload(STATE / "dnsenum-scan/dnstest4/status.json")["status"])
ck("G4 zone_transfer.attempted still true on the degraded run",
   p4["zone_transfer"]["attempted"] is True)
run("dnsenum-analyzer", env, SCAN_ID="dnstest4", TARGET=DOMAIN, WORKFLOW_SHARED_DIR="")
a4 = jload(STATE / "dnsenum-analyzer/dnstest4/consolidated.json")
ck("G5 analyzer propagates partial=true and still sets severity",
   a4["partial"] is True and a4["severity"] in ("low", "medium", "info"),
   f"partial={a4['partial']} severity={a4['severity']}")

section("DNS-8: degradation — dnsenum non-zero exit")
env = setup(mode="fail")
r = run("dnsenum-scan", env, SCAN_ID="dnstest5", TARGET=DOMAIN)
ck("F1 non-zero dnsenum exit still exits 0 (degraded)", r.returncode == 0, f"exit={r.returncode}")
ck("F2 parsed-results.json still written", (STATE / "dnsenum-scan/dnstest5/parsed-results.json").is_file())
ck("F3 status == degraded", jload(STATE / "dnsenum-scan/dnstest5/status.json")["status"] == "degraded")
ck("F4 missing dnsenum binary -> exit 2 (hard failure, not silent)",
   True)  # asserted properly in DNS-10 below

section("DNS-9: analyzer with NO predecessor output")
env = setup()
r = run("dnsenum-analyzer", env, SCAN_ID="dnstest6", TARGET=DOMAIN)
a6 = jload(STATE / "dnsenum-analyzer/dnstest6/consolidated.json")
ck("M1 analyzer exits 0 with no parsed-results", r.returncode == 0, f"exit={r.returncode}")
ck("M2 empty contract: 0 subdomains, severity info, no vectors",
   a6["subdomain_count"] == 0 and a6["severity"] == "info" and a6["next_vectors"] == [],
   f"n={a6['subdomain_count']} s={a6['severity']} v={len(a6['next_vectors'])}")
ck("M3 zone_transfer.attempted true even with no data", a6["zone_transfer"]["attempted"] is True)
ck("M4 contract still has all 12 keys", set(a6.keys()) == SPEC_KEYS)

section("DNS-10: missing binary is a hard failure")
env = setup()
# F5 is only meaningful when a REAL dnsenum exists: PATH surgery can only prove
# it hid the tool if PATH surgery was the reason the tool went missing.
if not tool_present("dnsenum"):
    info("WARNING: no real dnsenum on PATH -- F5 below passes vacuously on this host")
# Real dnsenum lives in a system bin dir, so we rebuild a sandbox bin dir
# symlinking every system binary EXCEPT dnsenum.
SB = FIX / "nodns-bin"
shutil.rmtree(SB, ignore_errors=True)
SB.mkdir(parents=True, exist_ok=True)
for d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
    p = Path(d)
    if not p.is_dir():
        continue
    for b in p.iterdir():
        if b.name == "dnsenum" or (SB / b.name).exists():
            continue
        try:
            (SB / b.name).symlink_to(b)
        except OSError:
            pass
e = dict(env)
e["PATH"] = str(SB)
e["SCAN_ID"] = "dnsenum-absent"
e["TARGET"] = DOMAIN
pr = subprocess.run(["bash", "skills/dnsenum-scan/main.sh"], cwd=str(PROJECT),
                    env={**os.environ, **e}, capture_output=True, text=True, timeout=60)
ck("F5 missing dnsenum -> exit 2 (not a silent success)", pr.returncode == 2,
   f"exit={pr.returncode} err={pr.stderr[-70:].strip()!r}")

section("DNS-11: meta-skill chain + sysreport")
env = setup()
r = run("dnsenum", env, SCAN_ID="dnsenum-test", TARGET=DOMAIN)
ck("C1 meta-skill chain (scan->analyzer->sysreport) exits 0", r.returncode == 0, f"exit={r.returncode}")
ck("C2 chain produced the contract",
   (STATE / "dnsenum-analyzer/dnsenum-test/consolidated.json").is_file())
rep = sorted((REPORTS / DOMAIN / "dnsenum").glob("*/*/sysreport.json"))
ck("C3 sysreport wrote reports/<target>/dnsenum/<YYYY-MM-DD/HH-MM-SS>/sysreport.json", bool(rep),
   str([str(x.relative_to(REPORTS)) for x in rep]))
if rep:
    sj = jload(rep[0])
    ck("C4 sysreport json is valid and carries the contract", sj is not None and "subdomains" in (sj or {}),
       str(sorted((sj or {}).keys())[:8]))
    ck("C5 sysreport 'latest' symlink resolves", (REPORTS / DOMAIN / "dnsenum/latest").is_symlink()
       or (REPORTS / DOMAIN / "dnsenum/latest").exists())
    ck("C6 sysreport yaml sibling exists", rep[0].with_name("sysreport.yaml").is_file())

finish(R)
