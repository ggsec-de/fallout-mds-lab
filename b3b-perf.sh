#!/bin/sh
# B3b root probe: extended fill-buffer/MLP counters per process in the gap
# regime, looking for a counter signature of the cold state that the first
# event set (cycles/instructions/machine_clears/l1d.replacement) missed.
# Degrades gracefully: without usable perf it still records rates.
# Usage: sudo sh b3b-perf.sh > /tmp/b3b-probe.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

A="env CPU=1 CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20"
EV="cycles,instructions,mem_load_retired.l1_hit,mem_load_retired.l1_miss,mem_load_retired.fb_hit,l1d_pend_miss.pending,l1d.replacement"

HAVE_PERF=0
if perf stat -e "$EV" -o /dev/null true 2> /dev/null; then
    HAVE_PERF=1
elif perf stat -e "cycles,instructions" -o /dev/null true 2> /dev/null; then
    EV="cycles,instructions"
    HAVE_PERF=1
    echo "note: full event set unsupported, falling back to $EV"
else
    echo "note: perf unusable here, running without counters"
fi
echo "== event set: $EV"

for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    sleep 5
    echo "=== b3b run $i start=$(date +%s.%N)"
    if [ "$HAVE_PERF" = 1 ]; then
        perf stat -e "$EV" -o /tmp/b3b-perf-$i.txt -- \
            $A taskset -c 1 ./fallout-oneshot 2> /dev/null | \
            grep -E "timing:|cseq slot=61 round=|majority_rounds"
    else
        $A taskset -c 1 ./fallout-oneshot 2> /dev/null | \
            grep -E "timing:|cseq slot=61 round=|majority_rounds"
    fi
    if [ "$HAVE_PERF" = 1 ]; then
        echo "--- counters run $i"
        grep -E "l1_hit|l1_miss|fb_hit|pend_miss|replacement|cycles|instructions|seconds" \
            /tmp/b3b-perf-$i.txt | head -10
    fi
done
echo "== b3b done"
