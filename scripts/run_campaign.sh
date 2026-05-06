#!/usr/bin/env bash
# GapFuzz campaign. Aggregates results into all_runs.jsonl.
#
# Usage:
#   ./run_campaign.sh [N]                       # full Phase 1 + Phase 2
#   ./run_campaign.sh [N] --phase1-only         # baseline mode
#
# When --phase1-only is given, output goes to all_runs_phase1.jsonl
# instead, so the two campaigns can be compared without overwriting.
set -u

N=${1:-50}
EXTRA_ARGS="${2:-}"

if [[ "$EXTRA_ARGS" == "--phase1-only" ]]; then
    OUT=data/all_runs_phase1.jsonl
    MODE_TAG=" [phase1-only]"
    LOGDIR=run_logs_phase1
else
    OUT=data/all_runs.jsonl
    MODE_TAG=""
    LOGDIR=run_logs
fi
> "$OUT"
mkdir -p "$LOGDIR"
rm -f "$LOGDIR"/run_*.log

CONS=0
DIV=0
ERR=0

# Pre-flight health check: ryu /dp/trace endpoint must respond.
# A silent ryu crash mid-campaign produces 0-record runs that the
# script would otherwise count as "consistent" (false negatives).
ryu_alive() {
    curl -sf -o /dev/null --max-time 3 \
        "http://127.0.0.1:8080/dp/trace/0000000000000001?bridge=s1&flow=in_port=3,dl_type=0x0800,nw_dst=10.0.0.99"
}

if ! ryu_alive; then
    echo "[FATAL] ryu /dp/trace endpoint unreachable at start. Aborting."
    exit 1
fi

for i in $(seq 1 "$N"); do
    ts=$(date +%H:%M:%S)
    log_file="$LOGDIR/run_$(printf '%03d' "$i").log"

    if ! ryu_alive; then
        printf "[%s] run %3d: \033[1;31mryu DOWN — aborting campaign\033[0m\n" \
            "$ts" "$i"
        ERR=$((ERR+1))
        break
    fi

    if python -m gapfuzz.run --config config.yaml --templates templates/ \
            $EXTRA_ARGS > "$log_file" 2>&1; then
        # tag each result line with run number and timestamp
        while IFS= read -r line; do
            python -c "
import json,sys
r = json.loads(sys.argv[1])
r['run'] = $i
r['ts'] = '$ts'
print(json.dumps(r))
" "$line" >> "$OUT"
        done < results.jsonl

        # one-line summary for this run
        runline=$(grep -E '"class"' results.jsonl | head -1)
        if grep -q '"DP_DIVERGENT"\|"CP_DIVERGENT"\|"BOTH_DIVERGENT"' results.jsonl; then
            DIV=$((DIV+1))
            printf "[%s] run %3d: \033[1;31mDIVERGENT\033[0m\n" "$ts" "$i"
            grep -E '"class"' results.jsonl | sed 's/^/    /'
        else
            CONS=$((CONS+1))
            printf "[%s] run %3d: consistent\n" "$ts" "$i"
        fi
    else
        ERR=$((ERR+1))
        printf "[%s] run %3d: \033[1;33mERROR\033[0m (see %s)\n" "$ts" "$i" "$log_file"
    fi
done

echo
echo "===== Campaign summary$MODE_TAG ====="
echo "  consistent runs: $CONS / $N"
echo "  divergent  runs: $DIV / $N"
echo "  errored    runs: $ERR / $N"
echo "  full log: $OUT"
