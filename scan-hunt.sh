#!/bin/sh
# Scan hunt: 25 processes in the gap regime; each reports a clean pre-round
# 64-class scan plus the usual majority rounds, so a cold process shows
# where (if anywhere) the transient deposit landed.
# Usage: sh scan-hunt.sh > /tmp/scan-hunt.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

A="env CPU=1 CSEQ=1 CSEQ_SCAN=1 NC=1 SLOT=61 FRESH=1 timeout 20"
i=1
while [ $i -le 25 ]; do
    sleep 5
    echo "=== hunt run $i start=$(date +%s.%N)"
    $A taskset -c 1 ./fallout-oneshot | grep -E "timing:|majority_rounds|scan\(pre\)"
    i=$((i+1))
done
echo "== hunt done"
