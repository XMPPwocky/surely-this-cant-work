#!/bin/bash
# Compare benchmark results against a baseline.
# Usage: scripts/check-bench-regression.sh <baseline> <new-results>
# Exit 0 if no regressions, 1 if any found (>20% slower).

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <baseline-file> <new-results-file>"
    exit 2
fi

BASELINE="$1"
NEW_RESULTS="$2"
THRESHOLD=120  # 120% = 20% regression threshold

if [ ! -f "$BASELINE" ]; then
    echo "ERROR: Baseline file not found: $BASELINE"
    exit 2
fi

if [ ! -f "$NEW_RESULTS" ]; then
    echo "ERROR: Results file not found: $NEW_RESULTS"
    exit 2
fi

# Extract @BENCH lines from new results (file may contain full QEMU output)
extract_bench_lines() {
    grep -o '@BENCH [^ ]*' "$1" 2>/dev/null | sed 's/@BENCH //' || true
}

# Parse key=value from a file into an associative array
declare -A baseline_vals
declare -A new_vals

while IFS='=' read -r key val; do
    [ -n "$key" ] && baseline_vals["$key"]="$val"
done < <(cat "$BASELINE")

while IFS='=' read -r key val; do
    [ -n "$key" ] && new_vals["$key"]="$val"
done < <(extract_bench_lines "$NEW_RESULTS")

# Compare
regressions=0
printf "\n%-35s %10s %10s %8s  %s\n" "Benchmark" "Baseline" "New" "Change" "Status"
printf "%-35s %10s %10s %8s  %s\n" "-----------------------------------" "----------" "----------" "--------" "------"

for key in "${!baseline_vals[@]}"; do
    base="${baseline_vals[$key]}"
    if [ -n "${new_vals[$key]+x}" ]; then
        new="${new_vals[$key]}"
        if [ "$base" -gt 0 ] 2>/dev/null; then
            pct=$(( new * 100 / base ))
            change="+$(( pct - 100 ))%"
            if [ "$pct" -gt "$THRESHOLD" ]; then
                status="REGRESSION"
                regressions=$((regressions + 1))
            else
                status="ok"
            fi
        else
            change="n/a"
            status="ok"
        fi
        printf "%-35s %10s %10s %8s  %s\n" "$key" "${base}ns" "${new}ns" "$change" "$status"
    else
        printf "%-35s %10s %10s %8s  %s\n" "$key" "${base}ns" "MISSING" "-" "WARN"
    fi
done

echo ""
if [ "$regressions" -gt 0 ]; then
    echo "FAILED: $regressions regression(s) detected (>20% slower)"
    exit 1
else
    echo "PASSED: No regressions detected"
    exit 0
fi
