#!/usr/bin/env python3
"""Parse nikto display output into the JSON structure the engine analyzer expects.

nikto only writes its `-Format json` output file when the whole scan completes
(7280 tests can take hours). When the engine enforces a timeout, nikto dies
before writing anything. But nikto streams findings to its display output in
real time, so we can recover partial results by parsing that log.

Usage:
    python3 nikto-log-parse.py <display-log> <target> <port> [json] [txt] [cgi]

Reads a nikto display log (stdout+stderr captured together) and emits, on
stdout, a JSON array of host objects in nikto's own shape:

    [{
      "host": "<target>", "ip": "", "port": "<port>",
      "server_banner": "...",
      "vulnerabilities": [
        {"id": "OSVDB-999986", "osvdb": "999986", "url": "/", "msg": "...", "reference": ""}
      ]
    }]

Finding lines look like:
    + [999986] /: Retrieved via header: 1.1 geosuite.erictelm2m.com (Apache/2.4.66).
    + [999992] /: Server is using a wildcard certificate: *.erictelm2m.com. See: https://...
"""
import json
import re
import sys

FINDING_RE = re.compile(
    r"^\s*\+\s+\[(\d{4,6})\]\s+(\S+):\s*(.*?)(?:\.\s*See:\s*(\S+))?\.?\s*$"
)

# OSVDB ids that are informational banner grabs, not real findings.
NOISE_IDS = {"999986", "999987", "999988", "999989", "999990"}
# Diagnostic lines that look like findings but are engine chatter.
CHATTER = re.compile(
    r"^(Target|Start Time|End Time|Scan terminated|No CGI Directories|"
    r"ERROR|WARNING|1 host.*tested|Nikto v|hosts? tested|"
    r"max-?time|cgi|mutate|evasion)", re.I
)


def parse_log(path: str) -> list[dict]:
    findings = []
    server_banner = ""
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                m = FINDING_RE.match(line)
                if not m:
                    continue
                osvdb, url, msg, ref = m.groups()
                osvdb = osvdb.lstrip("0") or "0"
                if osvdb in NOISE_IDS:
                    if "Apache" in msg or "nginx" in msg or "IIS" in msg:
                        server_banner = msg.strip()
                    continue
                if CHATTER.search(msg):
                    continue
                if not msg.strip():
                    continue
                findings.append({
                    "id": f"OSVDB-{osvdb}",
                    "osvdb": osvdb,
                    "url": url,
                    "msg": msg.strip(),
                    "reference": ref or "",
                })
    except FileNotFoundError:
        pass
    return findings, server_banner


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: nikto-log-parse.py <log> <target> <port> [scan_mode]", file=sys.stderr)
        return 2
    log_path, target, port = sys.argv[1], sys.argv[2], sys.argv[3]
    findings, server_banner = parse_log(log_path)
    host = {
        "host": target,
        "ip": "",
        "port": port,
        "server_banner": server_banner,
        "vulnerabilities": findings,
    }
    print(json.dumps([host]))
    return 0


if __name__ == "__main__":
    sys.exit(main())