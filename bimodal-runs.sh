#!/bin/sh
# Bimodality run series: 20 back-to-back processes, full log with clock.
# Usage: sh bimodal-runs.sh > /tmp/bimodal-runs.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1
for i in $(seq 1 20); do
    f0=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq)
    f1=$(cat /sys/devices/system/cpu/cpu1/cpufreq/scaling_cur_freq)
    echo "=== run $i start=$(date +%s.%N) freq0=$f0 freq1=$f1"
    env CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot
    echo "=== run $i end=$(date +%s.%N) freq1=$(cat /sys/devices/system/cpu/cpu1/cpufreq/scaling_cur_freq)"
done
