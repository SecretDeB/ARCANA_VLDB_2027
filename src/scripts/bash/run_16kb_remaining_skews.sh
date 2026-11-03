#!/bin/bash
# Runs the 16 KB partitioned experiment (Exp 3, all gamma_bar) for the remaining skews one after another, unattended.
# Each skew: server + client of run_sweep_wulver_baseline_16kb.sh, results in output/results/baseline_comparison_16kb/exp3_16kb_s<skew>,
# logs in .../driver/. A skew that hangs or crashes is stopped after its time limit and the next one starts; a skew's
# part files (re-creatable, ~3 GB per gamma_bar) are deleted when it ends.
#   nohup bash scripts/bash/run_16kb_remaining_skews.sh > ../../output/results/baseline_comparison_16kb/driver.log 2>&1 &
#   SKEW_LIST="0.6 0.3 0"   LIMIT_H="0.6:10 0.3:14 0:18" (hours per skew)   PART_GB=250 (both roles)
#   GAMMAS="30 35 40 45 50" runs only those gamma_bar (for every skew in SKEW_LIST); TAG_SUFFIX=_b names the results folder exp3_16kb_s<skew>_b
set -m   # each background run gets its own process group, so a stuck one can be stopped with all its helpers
cd "$(dirname "$0")/../.." || exit 1
RUN="${RUN:-scripts/bash/run_sweep_wulver_baseline_16kb.sh}"
SKEW_LIST="${SKEW_LIST:-0.6 0.3 0}"
LIMIT_H="${LIMIT_H:-0.6:10 0.3:14 0:18}"
BUILD_WAIT="${BUILD_WAIT:-120}"      # the server builds first; the client must not build at the same time
export PART_GB="${PART_GB:-250}"
OUT="../../output/results/baseline_comparison_16kb"
DATA="${YCSB_ROOT:-../../Python_Codes/output/data/YCSB}/keysize_256"
mkdir -p "$OUT/driver"

limit_for() {   # <skew> -> seconds
    local kv h=12
    for kv in $LIMIT_H; do [ "${kv%%:*}" = "$1" ] && h="${kv#*:}"; done
    echo $((h * 3600))
}

for skew in $SKEW_LIST; do
    tag="exp3_16kb_s${skew}${TAG_SUFFIX}"   # TAG_SUFFIX=_b writes a resumed skew to its own results folder
    log="$OUT/driver/$tag"
    limit="$(limit_for "$skew")"
    echo "[$(date '+%F %T')] skew $skew: start (limit $((limit / 3600)) h, PART_GB=$PART_GB, free: $(df -h /project/ss797/kk675 | awk 'NR==2{print $4}'))"
    RUN_TAG="$tag" SKEWS="$skew" bash "$RUN" server 3 > "$log.server.log" 2>&1 &
    S=$!
    sleep "$BUILD_WAIT"
    RUN_TAG="$tag" SKEWS="$skew" bash "$RUN" client 3 > "$log.client.log" 2>&1 &
    C=$!
    t="$BUILD_WAIT"; gone=0
    while kill -0 "$S" 2>/dev/null || kill -0 "$C" 2>/dev/null; do
        sleep 30; t=$((t + 30))
        if [ "$t" -ge "$limit" ]; then echo "[$(date '+%F %T')] skew $skew: time limit reached, stopping it"; break; fi
        # the server script ended but the client is still waiting for it: give it 10 minutes, then stop it
        if ! kill -0 "$S" 2>/dev/null && kill -0 "$C" 2>/dev/null; then
            gone=$((gone + 30))
            if [ "$gone" -ge 600 ]; then echo "[$(date '+%F %T')] skew $skew: server finished, client still waiting - stopping it"; break; fi
        fi
    done
    kill -- "-$S" "-$C" 2>/dev/null; kill "$S" "$C" 2>/dev/null   # the runs and everything they started
    pkill -f "./bin/server" 2>/dev/null; pkill -f "./bin/client" 2>/dev/null
    sleep 5
    rm -f "$DATA"/skew_"$skew"/*_bpart*of*.csv
    echo "[$(date '+%F %T')] skew $skew: done (results: $OUT/$tag)"
done
echo "[$(date '+%F %T')] all skews finished"
