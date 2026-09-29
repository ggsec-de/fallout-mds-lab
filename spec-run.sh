#!/bin/sh
# Arm B, SPEC=1: a mispredicted branch instead of a fault (2026-09-28).
# Kocher bounds-check bypass ported from
# labs/foreshadow/harness/mispredict_gadget.h. The shadow load never faults
# and never retires.
#
# Prior against this arm, recorded so a null is read correctly:
# l1tf-mp-probe.c measured that L1TF does NOT forward in the misprediction
# window on this silicon. That is a statement about the terminal-fault
# forward, not about the store buffer, and the gadget itself is sound
# (256/256 on present targets), so this leg is untested rather than refuted.
#
# GATE, enforced in-process because the misprediction rate is state-dependent:
#   leg 1  plant 0x42 architecturally, store off -> must recover class 61
#   leg 2  plant 0x00, store off -> class 63 repeatable, class 61 at the floor
# Leg 2 measures the class-61 false-positive rate the negative sentence rests
# on. Gate failure is VOID, not negative.
#
# In SPEC_TARGET=present, class 63 hot is CORRECT: it is the transient
# liveness control (the shadow load's own 0x00 reaching the oracle). In
# noncanon and protnone there is no data source, so 63 goes dark and the gate
# is the only liveness control.
#
# FENCE/LFENCE are NOT diagnostic here: they destroy the speculation window as
# well as the store-buffer window. The load-bearing controls are
# SPEC_STORE=none and gate leg 2.
#
# Usage: sh spec-run.sh > /tmp/spec-run.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

echo "build md5: $(md5sum fallout-oneshot | cut -d' ' -f1)"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "governor: $(cat /sys/devices/system/cpu/cpu1/cpufreq/scaling_governor)"
echo "online: $(cat /sys/devices/system/cpu/online)"

# The core idles at 800 MHz under the powersave governor and only ramps to
# 3.7 GHz when busy, which inflates every latency in TSC ticks and was seen to
# push the hot reload from ~33 to ~72. Each cell is pre-warmed, and the
# timing: line is kept in the log so every measurement carries its own clock
# witness: hot must read ~32..36.
warm() {
    taskset -c 1 sh -c 'i=0; while [ $i -lt 3000000 ]; do i=$((i+1)); done' \
        >/dev/null 2>&1
}

cell() {
    label=$1
    shift
    echo "== $label x2"
    for i in 1 2; do
        warm
        printf "   "
        env "$@" timeout 180 taskset -c 1 ./fallout-oneshot 2>&1 \
            | grep -E "^timing:|spec gate|majority_rounds|verdict:|stray" \
            | grep -vE "^spec slot=[0-9]+ round=" \
            | tr '\n' ' '
        echo
    done
}

echo "########## gate legs alone ##########"
warm
echo "-- SPEC_SELFTEST=1 (plant 0x42 -> class 61 must come back)"
env SPEC=1 SPEC_SELFTEST=1 timeout 180 taskset -c 1 ./fallout-oneshot 2>&1 \
    | grep -E "spec target=|spec gate|verdict:"
warm
echo "-- SPEC_SELFTEST=2 (plant 0x00 -> 63 hot, 61 at the floor)"
env SPEC=1 SPEC_SELFTEST=2 timeout 180 taskset -c 1 ./fallout-oneshot 2>&1 \
    | grep -E "spec target=|spec gate|verdict:"

# Targets in order of prior: noncanon is the only trigger that has ever
# produced class 61 on this box.
for tgt in noncanon present protnone; do
    echo "########## SPEC_TARGET=$tgt ##########"
    cell "$tgt slot=61 store=late  (signal)" SPEC_TARGET=$tgt SLOT=61
    cell "$tgt slot=61 store=none  (floor)"  SPEC_TARGET=$tgt SLOT=61 SPEC_STORE=none
    cell "$tgt slot=63 store=late  (liveness, present only)" SPEC_TARGET=$tgt SLOT=63
    cell "$tgt slot=61 store=early (recorded)" SPEC_TARGET=$tgt SLOT=61 SPEC_STORE=early
done

echo "########## recorded, outside the sentences ##########"
cell "present slot=61 tflush=1" SPEC_TARGET=present SLOT=61 SPEC_TFLUSH=1
cell "noncanon slot=61 vflush=0" SPEC_TARGET=noncanon SLOT=61 SPEC_VFLUSH=0
cell "noncanon slot=61 delay=400" SPEC_TARGET=noncanon SLOT=61 SPEC_DELAY=400

echo "== stock hot base, same build, sanity x2"
for i in 1 2; do
    printf "   "
    env CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 60 taskset -c 1 ./fallout-oneshot 2>&1 \
        | grep -E "majority_rounds"
done
echo "== spec-run done"
