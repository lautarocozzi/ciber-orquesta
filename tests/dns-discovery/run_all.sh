#!/usr/bin/env bash
# Single entrypoint for the offline dns-discovery verification harnesses.
#
#   bash tests/dns-discovery/run_all.sh              # all harnesses
#   bash tests/dns-discovery/run_all.sh dns_verify   # one harness by name
#
# Exits non-zero if ANY harness fails. Totals are parsed from each harness's
# own summary line, so this runner never has to re-derive a pass count.
#
# All harnesses are OFFLINE: stubbed scanner binaries and synthetic state in a
# temp sandbox. See README.md.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(cd "$HERE/../.." && pwd)"

# The harnesses resolve the repo from their own path; this is just a guard so a
# mislocated run fails loudly instead of silently testing nothing.
for marker in engine skills workflows; do
    if [ ! -e "$PROJECT/$marker" ]; then
        echo "FATAL: $PROJECT does not look like the repo (missing $marker/)" >&2
        exit 2
    fi
done

ALL=(dns_verify report_verify engine_expansion)
SELECTED=("$@")
if [ ${#SELECTED[@]} -eq 0 ]; then
    SELECTED=("${ALL[@]}")
fi

cd "$PROJECT" || exit 2

# --- preflight: syntax -------------------------------------------------
preflight_fail=0
for name in "${SELECTED[@]}"; do
    if [ ! -f "$HERE/$name.py" ]; then
        echo "FATAL: unknown harness '$name' (known: ${ALL[*]})" >&2
        preflight_fail=1
        continue
    fi
    if ! python3 -m py_compile "$HERE/$name.py" 2>&1; then
        echo "FATAL: $name.py failed py_compile" >&2
        preflight_fail=1
    fi
done
[ "$preflight_fail" -ne 0 ] && exit 2
echo "preflight: python3 -m py_compile OK (${#SELECTED[@]} harness(es))"
python3 -V

# --- repo write-protection snapshot ------------------------------------
# The harnesses route everything through STATE_DIR/REPORTS_DIR and assert the
# real generated dirs are untouched on exit. This is the independent check.
snapshot() {
    for d in state reports events notifications; do
        if [ -d "$PROJECT/$d" ]; then
            find "$PROJECT/$d" -type f -printf '%P %s %T@\n' 2>/dev/null | sort
        fi
    done
}
BEFORE="$(snapshot)"

TOTAL_PASS=0
TOTAL_FAIL=0
FAILED_HARNESSES=()

echo
echo "########################################################################"
echo "# offline dns-discovery verification harnesses"
echo "# repo: $PROJECT"
echo "########################################################################"

for name in "${SELECTED[@]}"; do
    script="$HERE/$name.py"
    [ -f "$script" ] || continue
    echo
    echo "========================================================================"
    echo "== $name.py"
    echo "========================================================================"
    out="$(python3 "$script" 2>&1)"
    rc=$?
    printf '%s\n' "$out"

    line="$(printf '%s\n' "$out" | grep -E '^=== RESULT: [0-9]+ passed, [0-9]+ failed' | tail -1)"
    if [ -n "$line" ]; then
        p="$(printf '%s' "$line" | sed -E 's/^=== RESULT: ([0-9]+) passed.*/\1/')"
        f="$(printf '%s' "$line" | sed -E 's/^=== RESULT: [0-9]+ passed, ([0-9]+) failed.*/\1/')"
        TOTAL_PASS=$((TOTAL_PASS + p))
        TOTAL_FAIL=$((TOTAL_FAIL + f))
        printf '  >> %-16s %3d passed, %3d failed\n' "$name" "$p" "$f"
    else
        # No summary line => the harness crashed before reporting.
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
        printf '  >> %-16s CRASHED (no summary line, exit %d)\n' "$name" "$rc"
        FAILED_HARNESSES+=("$name")
        continue
    fi
    [ "$rc" -ne 0 ] && FAILED_HARNESSES+=("$name")
done

AFTER="$(snapshot)"
echo
if [ "$BEFORE" != "$AFTER" ]; then
    echo "FATAL: a run modified the repo's real state/reports/events/notifications:" >&2
    diff <(printf '%s\n' "$BEFORE") <(printf '%s\n' "$AFTER") | head -20 >&2
    FAILED_HARNESSES+=("repo-write-guard")
fi
echo "repo write guard: state/reports/events/notifications $( [ "$BEFORE" = "$AFTER" ] \
    && echo UNCHANGED || echo MODIFIED )"

echo
echo "========================================================================"
printf 'TOTAL: %d passed, %d failed across %d harness(es)\n' \
    "$TOTAL_PASS" "$TOTAL_FAIL" "${#SELECTED[@]}"
if [ ${#FAILED_HARNESSES[@]} -ne 0 ]; then
    echo "FAILED HARNESSES: ${FAILED_HARNESSES[*]}"
    echo "NOTE: these are OFFLINE checks (stubbed tools / synthetic state)."
    echo "      They do NOT prove a live end-to-end scan works. See README.md."
    exit 1
fi
echo "ALL HARNESSES PASSED (offline; not a live-scan proof -- see README.md)"
exit 0
