#!/usr/bin/env python3
"""Offline verification harness for the report-html dual-result (5 scenarios).

  1. dns present (19 subdomains, past-cap, unsafe names), shared dir TAINTED
  2. dns present but subdomain_count == 0        -> SUBDOMAINS empty state
  3. no dns source at all                       -> "Not run", exit 0
  4. pre-existing source absent (nmap only)     -> no crash
  5. </script> injection probe in a subdomain name

Drives the REAL skills/report-html/sub-processes/generate-report.sh against a
synthetic state dir, so nothing is scanned and nothing leaves the box. All work
happens in a temp sandbox (STATE_DIR / REPORTS_DIR / WORKFLOW_SHARED_DIR point
there), leaving the repo's real state/ and reports/ untouched -- proven on exit.

NOT a live scan. See README.md.
"""
import json
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _harness import (  # noqa: E402
    PROJECT, Reporter, finish, new_workspace, run_bash,
)

GEN = PROJECT / "skills/report-html/sub-processes/generate-report.sh"
BASE = "verifyreport01"
TARGET = "example.com"
SLUG = "example-com"
TS = "2026-09-25/18-00-00"

R = Reporter("report-html dual result + subdomain child reports")
WS = new_workspace("report-html")
FIX = WS.root

ck = R.ck
section = R.section


def w(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(obj if isinstance(obj, str) else json.dumps(obj))


def build_state(subs, subdomain_count=None):
    WS.reset(WS.state, WS.shared, WS.reports)
    state = WS.state
    shared = WS.shared
    reports = WS.reports

    w(state / f"dnsenum-analyzer/{BASE}--dns-analyzer--{SLUG}/consolidated.json", {
        "scan_id": f"{BASE}--dns-analyzer--{SLUG}", "target": TARGET,
        "started_at": "2026-09-25T18:00:00Z", "domain": TARGET,
        "subdomains": subs,
        "subdomain_count": len(subs) if subdomain_count is None else subdomain_count,
        "ns": ["a.iana-servers.net", "b.iana-servers.net"], "mx": ["mail.example.com"],
        "zone_transfer": {"attempted": True, "success": False, "records": []},
        "severity": "low", "next_vectors": [], "partial": False,
    })
    w(state / f"nmap-analyzer/{BASE}--analyzer--{SLUG}/consolidated.json", {
        "scan_id": "ROOT-NMAP-MARKER", "target": TARGET,
        "started_at": "2026-09-25T18:00:00Z", "severity": "low",
        "ports": [{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}],
    })
    # expanded per-subdomain runs
    w(state / f"httpx-analyzer/{BASE}--exp-httpx-dns-analyzer-aaaaaaaa--host00-example-com/consolidated.json",
      {"scan_id": "EXP-HTTPX-HOST00", "target": "host00.example.com", "severity": "info",
       "live_web_server": True, "tech_stack": ["Nginx", "PHP"],
       "endpoints": [{"url": "https://host00.example.com", "status_code": 200}]})
    w(state / f"nuclei-analyzer/{BASE}--exp-nuclei-dns-analyzer-bbbbbbbb--host00-example-com/consolidated.json",
      {"scan_id": "EXP-NUCLEI-HOST00", "target": "host00.example.com", "severity": "high",
       "total_matched": 2, "severity_counts": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
       "findings": [{"severity": "high", "name": "Exposed .git dir", "template_id": "git-exposure"},
                    {"severity": "medium", "name": "Verbose header", "template_id": "verbose-header"}]})
    w(state / f"whatweb-analyzer/{BASE}--exp-whatweb-dns-analyzer-cccccccc--host02-example-com/consolidated.json",
      {"scan_id": "EXP-WHATWEB-HOST02", "target": "host02.example.com", "severity": "info",
       "technologies": [{"name": "Nginx", "version": "1.24.0"}]})
    w(state / f"httpx-analyzer/{BASE}--exp-httpx-dns-analyzer-aaaaaaaa--host01-example-com/consolidated.json",
      {"scan_id": "EXP-HTTPX-HOST01", "target": "host01.example.com", "severity": "info",
       "live_web_server": False, "tech_stack": [], "endpoints": []})

    # TAINTED shared dir (last-writer-wins simulation)
    w(shared / "nmap-analyzer/consolidated.json",
      {"scan_id": "TAINTED-SHARED-NMAP", "target": "host00.example.com", "severity": "critical",
       "ports": [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh-T AINTED"}]})
    w(shared / "httpx-analyzer/consolidated.json",
      {"scan_id": "TAINTED-SHARED-HTTPX", "target": "host00.example.com", "severity": "critical",
       "live_web_server": True, "tech_stack": ["TAINTED-TECH"],
       "endpoints": [{"url": "https://host00.example.com", "status_code": "TAINTED-STATUS"}]})
    w(shared / "dnsenum-analyzer/consolidated.json",
      {"scan_id": "TAINTED-SHARED-DNS", "target": "host00.example.com", "domain": "host00.example.com",
       "subdomains": [{"name": "TAINTED-SUBDOMAIN", "ip": "9.9.9.9", "source": "bruteforce"}],
       "subdomain_count": 1, "ns": ["TAINTED-NS"], "mx": [],
       "zone_transfer": {"attempted": True, "success": True, "records": []},
       "severity": "critical", "next_vectors": [], "partial": False})
    return state, shared, reports


def run_gen(state, shared, reports, extra_env=None):
    env = {"SCAN_ID": f"{BASE}--report-html--{SLUG}", "TARGET": TARGET,
           "STATE_DIR": str(state), "REPORTS_DIR": str(reports),
           "WORKFLOW_SHARED_DIR": str(shared), "REPORT_TS": TS}
    if extra_env:
        env.update(extra_env)
    return run_bash(str(GEN), env)


def embedded(path: Path):
    html = path.read_text()
    m = re.search(r"const REPORT_DATA = (\{.*?\});\n", html, re.S)
    return html, json.loads(m.group(1)) if m else None


# ===========================================================================
section("SCENARIO 1: dns present, 19 subdomains, TAINTED shared dir")
# Unsafe names sit at positions 3,4,5 — INSIDE the cap — so the guard is
# genuinely exercised (placing them after the cap would pass vacuously).
subs = [
    {"name": "host00.example.com", "ip": "198.51.100.1", "source": "bruteforce"},
    {"name": "host01.example.com", "ip": "198.51.100.2", "source": "bruteforce"},
    {"name": "../../../../etc/evil", "ip": "1.2.3.4", "source": "bruteforce"},
    {"name": "..", "ip": "1.2.3.4", "source": "bruteforce"},
    {"name": "-leading.example.com", "ip": "1.2.3.4", "source": "bruteforce"},
    {"name": "host02.example.com", "ip": "198.51.100.3", "source": "bruteforce"},
    {"name": "host03.example.com", "ip": "198.51.100.4", "source": "bruteforce"},
    {"name": "host04.example.com", "ip": "198.51.100.5", "source": "bruteforce"},
    {"name": "host05.example.com", "ip": "198.51.100.6", "source": "bruteforce"},
    {"name": "host06.example.com", "ip": "198.51.100.7", "source": "bruteforce"},
    {"name": "host07.example.com", "ip": "198.51.100.8", "source": "bruteforce"},
    {"name": "host08.example.com", "ip": "198.51.100.9", "source": "bruteforce"},
    {"name": "host09.example.com", "ip": "198.51.100.10", "source": "bruteforce"},
    {"name": "host10.example.com", "ip": "198.51.100.11", "source": "bruteforce"},
    {"name": "host11.example.com", "ip": "198.51.100.12", "source": "bruteforce"},
    {"name": "host12.example.com", "ip": "198.51.100.13", "source": "bruteforce"},
    {"name": "host13.example.com", "ip": "198.51.100.14", "source": "bruteforce"},
    {"name": "host14.example.com", "ip": "198.51.100.15", "source": "bruteforce"},
    {"name": "www.example.com", "ip": "198.51.100.99", "source": "xml"},
]
state, shared, reports = build_state(subs)
p = run_gen(state, shared, reports)
out = reports / TARGET / "report-html" / TS
parent = out / "report.html"
ck("R1 exit 0 (dns present + tainted shared dir)", p.returncode == 0, f"exit={p.returncode}")
ck("R2 parent report written at spec path report-html/YYYY-MM-DD/HH-MM-SS/report.html",
   parent.is_file(), str(parent.relative_to(FIX)))
html, data = embedded(parent)

section("root-scoped resolution (last-writer-wins taint)")
ck("T1 nmap source is the ROOT run (scan_id ROOT-NMAP-MARKER)",
   data["sources"]["nmap"].get("scan_id") == "ROOT-NMAP-MARKER",
   str(data["sources"]["nmap"].get("scan_id")))
ck("T2 httpx source is ABSENT (no root httpx run) — not the tainted shared copy",
   data["sources"]["httpx"] == {"present": False}, json.dumps(data["sources"]["httpx"])[:80])
ck("T3 dns source is the ROOT run, not TAINTED-SHARED-DNS",
   data["sources"]["dns"].get("scan_id") == f"{BASE}--dns-analyzer--{SLUG}")
ck("T4 zero TAINTED bytes anywhere in the rendered HTML",
   "TAINTED" not in html)
ck("T5 overall severity computed from root sources only (low, not critical)",
   data["overall_severity"] == "low", data["overall_severity"])

section("dns source + sections")
ck("D1 sources.dns.present is true", data["sources"]["dns"].get("present") is True)
ck("D2 dns section renders NS/MX/AXFR data",
   data["sources"]["dns"]["ns"] and data["sources"]["dns"]["mx"])
ck("D3 subdomain_count propagated to the parent", data["sources"]["dns"]["subdomain_count"] == 19)
ck("D4 <section id=\"section-dns\"> in markup", 'id="section-dns"' in html)
ck("D5 <section id=\"section-subdomains\"> in markup", 'id="section-subdomains"' in html)
ck("D6 renderDns dispatch wired", "renderDns(data.sources" in html)
ck("D7 renderSubdomains dispatch wired", "renderSubdomains(data)" in html)
ck("D8 timeline sourceMeta entry 'DNS Enumeration (dnsenum)'",
   "key: 'dns',    label: 'DNS Enumeration (dnsenum)'" in html)

section("unsafe subdomain names")
cards = data["subdomains"]
card_names = {c["name"] for c in cards}
child_dirs = {d.name for d in (out / "subdomains").iterdir()} if (out / "subdomains").is_dir() else set()
ck("U1 no card created for traversal name '../../../../etc/evil'",
   "../../../../etc/evil" not in card_names)
ck("U2 no child dir for traversal name", "../../../../etc/evil" not in child_dirs)
ck("U3 no card for '..'", ".." not in card_names)
ck("U4 no card for '-leading.example.com'", "-leading.example.com" not in card_names)
ck("U5 unsafe-name skips are logged", "unsafe name" in p.stderr,
   f"{p.stderr.count('unsafe name')} skip line(s)")
ck("U6 nothing escaped the reports dir (no etc/ dir created)",
   not (FIX / "etc").exists())

section("cap behaviour")
children = sorted((out / "subdomains").glob("*/report.html"))
ck("C1 7 child reports: 10 in-cap minus 3 rejected unsafe names", len(children) == 7, f"n={len(children)}")
ck("C2 subdomain_total reported as 19", data["subdomain_total"] == 19)
ck("C3 subdomains_additional == 19 - 7 == 12", data["subdomains_additional"] == 12,
   str(data["subdomains_additional"]))
ck("C4 past-cap host14 has no child report", not (out / "subdomains/host14.example.com").exists())
ck("C5 past-cap www.example.com (16th) has no child report",
   not (out / "subdomains/www.example.com").exists())

section("card fields + link resolution")
broken = [c["name"] for c in cards if not (out / c["report"]).is_file()]
ck("L1 every card link resolves to an existing file via file:///", not broken, str(broken))
c0 = next(c for c in cards if c["name"] == "host00.example.com")
ck("L2 card shows ip, status, tech, top vulns",
   c0["ip"] == "198.51.100.1" and c0["http_status"] == 200
   and "Nginx" in c0["tech"] and c0["vuln_total"] == 2
   and c0["top_vulns"][0]["severity"] == "high", json.dumps(c0)[:160])
c2 = next(c for c in cards if c["name"] == "host02.example.com")
ck("L3 whatweb-only child card: no status, versioned tech, 0 vulns",
   c2["http_status"] is None and any("1.24.0" in t for t in c2["tech"]) and c2["vuln_total"] == 0,
   json.dumps(c2)[:160])
c3 = next(c for c in cards if c["name"] == "host03.example.com")
ck("L4 all-empty child card: has_data=false, 'Not probed' path",
   c3["has_data"] is False and c3["vuln_total"] == 0 and c3["tech"] == [], json.dumps(c3)[:160])

section("child report scoping")
ch = out / "subdomains/host00.example.com/report.html"
chhtml, chdata = embedded(ch)
ck("L5 child is scoped to its own subdomain (no parent/tainted leakage)",
   "ROOT-NMAP-MARKER" not in chhtml and "TAINTED" not in chhtml
   and chdata["target"] == "host00.example.com")
ck("L6 child marks never-run sources absent (nmap/testssl/dns)",
   chdata["sources"]["nmap"] == {"present": False}
   and chdata["sources"]["testssl"] == {"present": False}
   and chdata["sources"]["dns"] == {"present": False})
ck("L7 child carries only its own httpx+nuclei data",
   chdata["sources"]["httpx"].get("scan_id") == "EXP-HTTPX-HOST00"
   and chdata["sources"]["nuclei"].get("scan_id") == "EXP-NUCLEI-HOST00")
ck("L8 child severity = worst of its own sources (high)", chdata["overall_severity"] == "high",
   chdata["overall_severity"])
ck("L9 child back-link to parent is ../../report.html",
   chdata.get("parent_report") == "../../report.html")
ck("L10 child back-link target exists", (ch.parent.parent.parent / "report.html").is_file())

# ===========================================================================
section("SCENARIO 2: dns present, subdomain_count == 0 (empty state)")
state, shared, reports = build_state([], subdomain_count=0)
p2 = run_gen(state, shared, reports)
parent2 = reports / TARGET / "report-html" / TS / "report.html"
ck("E1 exit 0 with zero subdomains", p2.returncode == 0, f"exit={p2.returncode}")
ck("E2 parent written", parent2.is_file())
html2, data2 = embedded(parent2)
ck("E3 sources.dns.present true, subdomain_count 0", data2["sources"]["dns"]["present"] is True
   and data2["sources"]["dns"]["subdomain_count"] == 0)
ck("E4 subdomains key present but empty (real 'none found' state)",
   data2.get("subdomains") == [], json.dumps(data2.get("subdomains")))
ck("E5 subdomain_total 0 and no 'additional' note", data2["subdomain_total"] == 0
   and data2["subdomains_additional"] == 0)
ck("E6 no child reports dir created", not (parent2.parent / "subdomains").exists()
   or not list((parent2.parent / "subdomains").iterdir()))
ck("E7 template has the 'No subdomains discovered.' empty state",
   "No subdomains discovered." in html2)

# ===========================================================================
section("SCENARIO 3: NO dns source at all (degradation)")
state, shared, reports = build_state([])
shutil.rmtree(state / "dnsenum-analyzer")
shutil.rmtree(shared / "dnsenum-analyzer")
p3 = run_gen(state, shared, reports)
parent3 = reports / TARGET / "report-html" / TS / "report.html"
ck("N1 exit 0 with NO dns consolidated (and no shared dns)", p3.returncode == 0, f"exit={p3.returncode}")
ck("N2 parent still written", parent3.is_file())
html3, data3 = embedded(parent3)
ck("N3 sources.dns == {present: false}", data3["sources"]["dns"] == {"present": False},
   json.dumps(data3["sources"]["dns"]))
ck("N4 'subdomains' key ABSENT -> section hidden (not a broken empty state)",
   "subdomains" not in data3)
ck("N5 other sources still render (nmap root marker present)",
   data3["sources"]["nmap"].get("scan_id") == "ROOT-NMAP-MARKER")
ck("N6 timeline still lists DNS Enumeration -> 'Not run' branch is used",
   "key: 'dns',    label: 'DNS Enumeration (dnsenum)'" in html3)
ck("N7 no child reports written", not (parent3.parent / "subdomains").exists()
   or not list((parent3.parent / "subdomains").iterdir()))

# ===========================================================================
section("SCENARIO 4: pre-existing source absent -> no crash (regression)")
# nmap missing too: only the dns source exists
shutil.rmtree(state / f"nmap-analyzer/{BASE}--analyzer--{SLUG}")
p4 = run_gen(state, shared, reports)
ck("G1 exit 0 when nmap is the ONLY missing root source", p4.returncode == 0, f"exit={p4.returncode}")
_, data4 = embedded(reports / TARGET / "report-html" / TS / "report.html")
ck("G2 nmap renders as absent, overall severity none", data4["sources"]["nmap"] == {"present": False}
   and data4["overall_severity"] == "none", data4["overall_severity"])

# ===========================================================================
section("SCENARIO 5: </script> injection probe in a subdomain name")
state, shared, reports = build_state([
    {"name": "</script><img src=x onerror=alert(1)>", "ip": "1.2.3.4", "source": "bruteforce"},
    {"name": "ok.example.com", "ip": "198.51.100.7", "source": "bruteforce"},
])
p5 = run_gen(state, shared, reports)
parent5 = reports / TARGET / "report-html" / TS / "report.html"
ck("X1 exit 0 with a </script> subdomain name", p5.returncode == 0, f"exit={p5.returncode}")
html5, data5 = embedded(parent5)
card_names5 = {c["name"] for c in data5.get("subdomains", [])}
child5 = parent5.parent / "subdomains"
child_names5 = {d.name for d in child5.iterdir()} if child5.is_dir() else set()
ck("X2 the </script> name gets neither a card nor a child report dir",
   "onerror" not in json.dumps(data5.get("subdomains", []))
   and not any("onerror" in n for n in child_names5),
   f"cards={sorted(card_names5)} children={sorted(child_names5)}")
ck("X3 safe sibling subdomain still reported", "ok.example.com" in card_names5, str(card_names5))
# the raw dns source is embedded verbatim -> check whether it can break out
ck("X4 NO raw </script> sequence from the injected name in the HTML",
   "</script><img" not in html5,
   "BREAKOUT" if "</script><img" in html5 else "clean")
ck("X5 REPORT_DATA still parses after injection (JSON not corrupted)",
   data5 is not None)

finish(R)
