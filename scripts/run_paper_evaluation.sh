#!/usr/bin/env bash
# Paper-evaluation campaign for GapFuzz.
# Runs N=50 full + N=50 phase1-only (baseline) sequentially.
#
# Usage:
#   nohup ./run_paper_evaluation.sh > paper_evaluation.log 2>&1 &
#
# Outputs:
#   data/all_runs.jsonl         (full mode, 50 runs)
#   data/all_runs_phase1.jsonl  (baseline mode, 50 runs)
#   paper_evaluation.log   (this script's stdout/stderr)

set -u

N=${N:-50}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

# ---- venv activation -------------------------------------------------------
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    if [[ -f "venv-gapfuzz/bin/activate" ]]; then
        # shellcheck disable=SC1091
        source venv-gapfuzz/bin/activate
    else
        echo "[ERROR] venv-gapfuzz not found and no active venv. Aborting." >&2
        exit 1
    fi
fi

log() {
    printf '[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*"
}

# ---- pre-checks ------------------------------------------------------------
log "=== Pre-checks ==="

# 1. ONOS cluster reachable
for ip in 172.18.0.11 172.18.0.12 172.18.0.13; do
    code=$(curl -sf -o /dev/null -w '%{http_code}' \
        -u onos:rocks "http://$ip:8181/onos/v1/devices/of:0000000000000001" \
        || echo "FAIL")
    if [[ "$code" != "200" ]]; then
        log "[FAIL] ONOS $ip not reachable (http=$code). Aborting."
        exit 1
    fi
    log "[OK]   ONOS $ip reachable"
done

# 2. Ryu trace endpoint
url="http://127.0.0.1:8080/dp/trace/0000000000000001?bridge=s1&flow=in_port=3,dl_type=0x0800,nw_dst=10.0.0.99"
if ! curl -sf "$url" > /dev/null 2>&1; then
    log "[FAIL] Ryu trace endpoint unreachable at $url. Aborting."
    exit 1
fi
log "[OK]   Ryu trace endpoint reachable"

# 3. Sudo NOPASSWD for ovs-appctl
if ! sudo -n ovs-appctl version > /dev/null 2>&1; then
    log "[FAIL] sudo -n ovs-appctl requires password. Aborting."
    exit 1
fi
log "[OK]   sudo NOPASSWD for ovs-appctl"

# 4. Backup previous results
ts=$(date +%Y%m%d_%H%M%S)
for f in data/all_runs.jsonl data/all_runs_phase1.jsonl; do
    if [[ -f "$f" ]]; then
        cp "$f" "${f}.bak.${ts}"
        log "[OK]   Backed up $f -> ${f}.bak.${ts}"
    fi
done

# ---- campaign 1: full mode -------------------------------------------------
log ""
log "=== Campaign 1/2: full mode (Phase 1 + lifetime + Phase 2), N=$N ==="
t0=$(date +%s)
./scripts/run_campaign.sh "$N"
t1=$(date +%s)
log "Campaign 1/2 done in $(( (t1 - t0) / 60 )) minutes"

# ---- campaign 2: phase1-only baseline --------------------------------------
log ""
log "=== Campaign 2/2: phase1-only baseline (Phase 1 + lifetime), N=$N ==="
t0=$(date +%s)
./scripts/run_campaign.sh "$N" --phase1-only
t1=$(date +%s)
log "Campaign 2/2 done in $(( (t1 - t0) / 60 )) minutes"

# ---- summary ---------------------------------------------------------------
log ""
log "=== Done ==="
log "Outputs:"
log "  data/all_runs.jsonl          ($(wc -l < data/all_runs.jsonl) lines)"
log "  data/all_runs_phase1.jsonl   ($(wc -l < data/all_runs_phase1.jsonl) lines)"
