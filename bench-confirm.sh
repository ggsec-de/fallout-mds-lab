#!/bin/sh
# Confirmation pass on the DOCUMENTED bench (2026-09-29).
#
# The 2026-09-28 results were taken with the powersave governor and CPU3
# online. This re-runs the load-bearing cells with governor=performance and
# CPU3 (cpu1's SMT sibling) offline, which is the bench state REPRODUCE.md
# describes. No pre-warm is needed or used here: under the performance
# governor a cold selftest reads hot=34 straight away, so the timing: line in
# every run is the witness that this actually held.
#
# Also does the >=10 process burst on the SPEC/noncanon positive that was
# queued in todo.md, to characterise its rate the way the CSEQ base is
# characterised.
#
# Usage: sh bench-confirm.sh > /tmp/bench-confirm.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

echo "build md5: $(md5sum fallout-oneshot | cut -d' ' -f1)"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "governor: $(cat /sys/devices/system/cpu/cpu1/cpufreq/scaling_governor)"
echo "online: $(cat /sys/devices/system/cpu/online)"
echo "cpu1 thread siblings: $(cat /sys/devices/system/cpu/cpu1/topology/thread_siblings_list)"

one() {
    label=$1
    shift
    printf "%-38s " "$label"
    env "$@" timeout 180 taskset -c 1 ./fallout-oneshot 2>&1 \
        | grep -E "^timing:|majority_rounds|spec gate:|trig gate: (PASS|FAIL)|verdict:" \
        | grep -vE "round=" \
        | tr '\n' ' '
    echo
}

echo
echo "########## stock hot base, sanity ##########"
for i in 1 2; do one "cseq base" CSEQ=1 NC=1 SLOT=61 FRESH=1; done

echo
echo "########## SPEC + noncanon: the positive, 10-process burst ##########"
i=1
while [ $i -le 10 ]; do
    one "spec noncanon s61 store ($i/10)" SPEC=1 SPEC_TARGET=noncanon SLOT=61
    i=$((i+1))
done

echo
echo "########## SPEC + noncanon: floors and the timing control ##########"
for i in 1 2 3; do one "spec noncanon s61 store=none" SPEC=1 SPEC_TARGET=noncanon SLOT=61 SPEC_STORE=none; done
for i in 1 2; do one "spec noncanon s61 store=early" SPEC=1 SPEC_TARGET=noncanon SLOT=61 SPEC_STORE=early; done

echo
echo "########## SPEC: the other two targets ##########"
for i in 1 2; do one "spec present s61 store" SPEC=1 SPEC_TARGET=present SLOT=61; done
for i in 1 2; do one "spec present s63 liveness" SPEC=1 SPEC_TARGET=present SLOT=63; done
for i in 1 2; do one "spec protnone s61 store" SPEC=1 SPEC_TARGET=protnone SLOT=61; done

echo
echo "########## value swap, 2x2 ##########"
for c in 0x42 0x24; do
    for s in 61 27; do
        one "swap canary=$c slot=$s store" SPEC=1 SPEC_TARGET=noncanon SLOT=$s CANARY=$c
    done
done
for c in 0x42 0x24; do
    for s in 61 27; do
        one "swap canary=$c slot=$s none" SPEC=1 SPEC_TARGET=noncanon SLOT=$s CANARY=$c SPEC_STORE=none
    done
done

echo
echo "########## Arm A spot check ##########"
for t in assist demand; do
    for i in 1 2; do one "$t s61 store" CSEQ=1 TRIGGER=$t SLOT=61 FRESH=1; done
    for i in 1 2; do one "$t s63 liveness" CSEQ=1 TRIGGER=$t SLOT=63 FRESH=1; done
done

echo
echo "########## stock hot base, sanity again ##########"
for i in 1 2; do one "cseq base" CSEQ=1 NC=1 SLOT=61 FRESH=1; done
echo "== bench-confirm done"
