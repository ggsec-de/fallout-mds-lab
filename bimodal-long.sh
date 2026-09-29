#!/bin/sh
# Long-horizon series: 5 runs, 5 s idle before each, ROUNDS=32 per run.
# Question: does a low-rate (post-idle) process recover inside one process?
# Usage: sh bimodal-long.sh > /tmp/bimodal-long.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1
for i in $(seq 1 5); do
    echo "=== long-run $i start=$(date +%s.%N)"
    env CSEQ=1 NC=1 SLOT=61 FRESH=1 ROUNDS=32 timeout 30 taskset -c 1 ./fallout-oneshot
    echo "=== long-run $i end=$(date +%s.%N)"
    sleep 5
done
