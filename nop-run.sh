#!/bin/sh
# NOP-vs-poison discriminator: is the suppressor the extra instruction
# (timing/window) or the partial-register semantics of the poison?
# Usage: sh nop-run.sh > /tmp/nop-run.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

run2() {
    label=$1
    shift
    echo "== $label x2"
    env "$@" CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot | grep -E "majority_rounds"
    env "$@" CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot | grep -E "majority_rounds"
}

run2 base
run2 poison CSEQ_POISON=1
run2 noppre CSEQ_NOPPRE=1
echo "== nop-run done"
