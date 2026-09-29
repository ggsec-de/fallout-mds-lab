#!/bin/sh
# Scan series: every process runs the 8 majority rounds and then one full
# 64-class scan, so a cold process reports where (if anywhere) the
# transient deposit landed. 15 runs, 5 s idle before each.
# Usage: sh scan-runs.sh > /tmp/scan-runs.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

A="env CPU=1 CSEQ=1 CSEQ_SCAN=1 NC=1 SLOT=61 FRESH=1 timeout 20"
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    sleep 5
    echo "=== scan-run $i start=$(date +%s.%N)"
    $A taskset -c 1 ./fallout-oneshot | grep -E "timing:|majority_rounds|scan best"
done
echo "== scan done"
