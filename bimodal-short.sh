#!/bin/sh
# Gap series with short gaps: 10 processes, 0.05 s between runs.
# Usage: sh bimodal-short.sh > /tmp/bimodal-short.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1
for i in $(seq 1 10); do
    echo "=== short-run $i start=$(date +%s.%N)"
    env CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot
    echo "=== short-run $i end=$(date +%s.%N)"
    sleep 0.05
done
