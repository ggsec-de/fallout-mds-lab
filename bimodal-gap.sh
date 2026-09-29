#!/bin/sh
# Bimodality run series with gaps: 10 processes, 5 s sleep between runs.
# Usage: sh bimodal-gap.sh > /tmp/bimodal-gap.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1
for i in $(seq 1 10); do
    f1=$(cat /sys/devices/system/cpu/cpu1/cpufreq/scaling_cur_freq)
    echo "=== gap-run $i start=$(date +%s.%N) freq1=$f1"
    env CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot
    echo "=== gap-run $i end=$(date +%s.%N) freq1=$(cat /sys/devices/system/cpu/cpu1/cpufreq/scaling_cur_freq)"
    sleep 5
done
