#!/bin/sh
# Cold-state census: one probe process per interval, logging the verdict,
# the timing witness, uptime, load and CPU temperature with timestamps,
# to find what precedes the low-rate windows. No root needed.
# Usage: sh cold-census.sh [minutes] [interval_seconds]
#        defaults: 60 probes, 60 s between probes.
cd /home/detox/CPU/labs/mds || exit 1

N=${1:-60}
IV=${2:-60}
A="env CPU=1 CSEQ=1 CSEQ_SCAN=1 NC=1 SLOT=61 FRESH=1 timeout 20"

i=1
while [ $i -le "$N" ]; do
    up=$(cut -d' ' -f1 /proc/uptime)
    load=$(cut -d' ' -f1 /proc/loadavg)
    temp=$(cat /sys/class/thermal/thermal_zone0/temp 2> /dev/null)
    echo "=== census $i time=$(date +%s) iso=$(date -Iseconds) uptime=$up load=$load temp=$temp"
    $A taskset -c 1 ./fallout-oneshot | grep -E "timing:|majority_rounds|scan\(pre\)"
    i=$((i+1))
    [ $i -le "$N" ] && sleep "$IV"
done
echo "== census done"
