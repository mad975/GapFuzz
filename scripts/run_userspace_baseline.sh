#!/usr/bin/env bash
# Phase-1-only baseline campaign with the OF-user-space oracle (§7.4 ablation).
#
# Output:
#   all_runs_phase1_userspace.jsonl
#   run_logs_phase1_userspace/run_NNN.log
#
# Usage:
#   ./run_userspace_baseline.sh [N]   (default N=50)
set -u

N=${1:-50}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

# shellcheck disable=SC1091
source venv-gapfuzz/bin/activate

OUT=data/all_runs_phase1_userspace.jsonl
LOGDIR=run_logs_phase1_userspace
> "$OUT"
mkdir -p "$LOGDIR"
rm -f "$LOGDIR"/run_*.log

CONS=0
DIV=0
ERR=0

# Pre-flight: ovs-ofctl reachable, ONOS reachable.
if ! sudo -n ovs-ofctl -O OpenFlow13 dump-flows s1 > /dev/null 2>&1; then
    echo "[FATAL] sudo -n ovs-ofctl dump-flows s1 failed. Aborting."
    exit 1
fi
for ip in 172.18.0.11 172.18.0.12 172.18.0.13; do
    code=$(curl -sf -o /dev/null -w '%{http_code}' \
        -u onos:rocks "http://$ip:8181/onos/v1/devices/of:0000000000000001" \
        || echo "FAIL")
    if [[ "$code" != "200" ]]; then
        echo "[FATAL] ONOS $ip not reachable (http=$code). Aborting."
        exit 1
    fi
done

for i in $(seq 1 "$N"); do
    ts=$(date +%H:%M:%S)
    log_file="$LOGDIR/run_$(printf '%03d' "$i").log"

    if python -m gapfuzz.run --config config.yaml --templates templates/ \
            --phase1-only --oracle-mode=userspace \
            > "$log_file" 2>&1; then
        while IFS= read -r line; do
            python -c "
import json,sys
r = json.loads(sys.argv[1])
r['run'] = $i
r['ts'] = '$ts'
r['oracle_mode'] = 'userspace'
print(json.dumps(r))
" "$line" >> "$OUT"
        done < results.jsonl

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
echo "===== Userspace-oracle baseline summary ====="
echo "  consistent runs: $CONS / $N"
echo "  divergent  runs: $DIV / $N"
echo "  errored    runs: $ERR / $N"
echo "  full log: $OUT"
