#!/bin/sh
# Gap series with pre-warm: 5 s idle, then a 50 ms spin on cpu1, then the harness.
# Usage: sh bimodal-warm.sh > /tmp/bimodal-warm.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1
for i in $(seq 1 10); do
    echo "=== warm-run $i start=$(date +%s.%N)"
    taskset -c 1 timeout 0.05 sh -c 'while :; do :; done'
    env CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot
    echo "=== warm-run $i end=$(date +%s.%N)"
    sleep 5
done
