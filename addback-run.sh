#!/bin/sh
# Add-back contrasts for the stock-arm suppressor, one build (2026-09-27):
# poison (al=0x2a before the faulting load), vf (stock test/jz + clflush
# branch before the store), prologue (skip_to lea/mov before the block),
# vaddr (fault address depends on the victim byte). Base and stock arms are
# the controls on the same binary.
# Usage: sh addback-run.sh > /tmp/addback-run.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

run2() {
    label=$1
    shift
    echo "== $label x2"
    env "$@" CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot | grep -E "timing:|majority_rounds"
    env "$@" CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot | grep -E "timing:|majority_rounds"
}

run2 "base"
run2 "poison" CSEQ_POISON=1
run2 "vf" CSEQ_VF=1
run2 "prologue" CSEQ_PROLOGUE=1
run2 "vaddr" CSEQ_VADDR=1

echo "== stock control x2 (VALUE=1)"
env VALUE=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot | grep -E "timing:|majority_rounds"
env VALUE=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot | grep -E "timing:|majority_rounds"
echo "== addback done"
