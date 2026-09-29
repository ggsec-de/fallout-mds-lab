#!/bin/sh
# Placement vs the bimodal rate regime (2026-09-28).
#
# B3/B3b closed the PMU question: a cold process is counter-identical to the
# hot ones (cycles, instructions, machine clears, fill-buffer and MLP events
# all inside the hot ranges). Nothing in the core explains it. The one lead
# left in the record is that DRAM latency is ANTI-correlated with the rate,
# which points outside the core -- at placement.
#
# This probe is the cheapest test of that: ADDRDUMP=1 makes every process
# print its stack L1 set and its oracle_lo page, so a burst can be correlated
# against hot/cold. Then the same burst under `setarch -R` (ASLR off), where
# every process gets the same layout. If the bimodality collapses with ASLR
# off, the variable is per-process virtual/physical placement -- L2/LLC
# conflicts across the 65 oracle pages -- and the cold state becomes testable
# instead of merely waited for.
#
# No root needed. Interpretation is one-sided: bimodality surviving with ASLR
# off refutes placement; it vanishing is consistent with placement and is not
# by itself proof, since `setarch -R` changes more than the oracle's address.
#
# Usage: sh aslr-run.sh [n] > /tmp/aslr-run.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

N=${1:-20}
echo "build md5: $(md5sum fallout-oneshot | cut -d' ' -f1)"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "governor: $(cat /sys/devices/system/cpu/cpu1/cpufreq/scaling_governor)"
echo "aslr(kernel): $(cat /proc/sys/kernel/randomize_va_space)"
echo "n per phase: $N"

# Pre-warm. Under the powersave governor the core idles at 800 MHz, which
# inflates every latency in TSC ticks: a hot reload reads 90..126 instead of
# ~33 and geometry_ok() can fail outright, which shows up as a missing
# majority_rounds line. The deliberately idle bimodal-*.sh series is a
# different experiment and must NOT be warmed; this one must.
warm() {
    taskset -c 1 sh -c 'i=0; while [ $i -lt 3000000 ]; do i=$((i+1)); done' \
        >/dev/null 2>&1
}

phase() {
    label=$1
    pre=$2
    echo "########## $label ##########"
    i=1
    while [ $i -le $N ]; do
        warm
        printf "%-8s run %2d: " "$label" $i
        env ADDRDUMP=1 CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 60 \
            $pre taskset -c 1 ./fallout-oneshot 2>&1 \
            | grep -E "^arm2:|^timing:|majority_rounds" \
            | sed -e 's/^arm2: .*stack_set=/stack_set=/' \
                  -e 's/ excluded=.*$//' \
                  -e 's/^timing: //' \
            | tr '\n' ' '
        echo
        i=$((i+1))
    done
}

phase "aslr-on"  ""
phase "aslr-off" "setarch -R"
echo "== aslr-run done"
