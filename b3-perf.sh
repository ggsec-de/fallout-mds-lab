#!/bin/sh
# B3 root probe: per-process PMU counters and an exact APERF/MPERF clock
# sample in the gap regime (5 s idle before each run), so low-rate processes
# can be compared with hot ones on counter data instead of witnesses.
# Run as root:  sudo sh b3-perf.sh > /tmp/b3-probe.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

A="env CPU=1 CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20"
EV="cycles,instructions,machine_clears.memory_ordering,l1d.replacement"

echo "== environment"
uname -r
HAVE_PERF=0
if command -v perf > /dev/null 2>&1; then
    perf --version
    HAVE_PERF=1
else
    echo "perf: not installed (msr clock only; install linux-perf for counters)"
fi

modprobe msr 2> /dev/null
if [ -r /dev/cpu/1/msr ]; then
    echo "msr node: readable"
    HAVE_MSR=1
else
    echo "msr node: NOT readable (continuing without clock samples)"
    HAVE_MSR=0
fi

if [ "$HAVE_PERF" = 1 ]; then
    echo "== perf event availability"
    perf list 2> /dev/null | grep -E "machine_clears|l1d\.replacement" | head -10
    if ! perf stat -e "$EV" -o /dev/null true 2> /dev/null; then
        EV="cycles,instructions"
        echo "note: event list unsupported, falling back to $EV"
    fi
fi

echo "== series: 10 runs, 5 s idle before each"
for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 5
    echo "=== b3 run $i start=$(date +%s.%N)"
    if [ "$HAVE_MSR" = 1 ]; then
        ./msr-freq 1 1 60 > /tmp/b3-msr-$i.txt 2>&1 &
        M=$!
    fi
    if [ "$HAVE_PERF" = 1 ]; then
        perf stat -e "$EV" -o /tmp/b3-perf-$i.txt -- \
            $A taskset -c 1 ./fallout-oneshot 2> /dev/null | \
            grep -E "timing:|cseq slot=61 round=|majority_rounds"
    else
        $A taskset -c 1 ./fallout-oneshot 2> /dev/null | \
            grep -E "timing:|cseq slot=61 round=|majority_rounds"
    fi
    if [ "$HAVE_MSR" = 1 ]; then
        kill $M 2> /dev/null
        wait $M 2> /dev/null
    fi
    if [ "$HAVE_PERF" = 1 ]; then
        echo "--- counters run $i"
        grep -E "cycles|instructions|machine_clears|l1d|seconds" \
            /tmp/b3-perf-$i.txt | head -8
    fi
    if [ "$HAVE_MSR" = 1 ]; then
        echo "--- clock run $i (min/max MHz over window)"
        awk 'NR>1 { if (min == "" || $4 < min) min = $4;
                    if ($4 > max) max = $4 }
             END { print "min=" min " max=" max " samples=" NR-1 }' \
            /tmp/b3-msr-$i.txt
    fi
done
echo "== b3 done"
