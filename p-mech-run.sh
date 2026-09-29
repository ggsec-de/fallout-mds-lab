#!/bin/sh
# Poison-mechanism nail: partial al (cold expected), full eax (merge broken),
# dl companion (control), nop (control), base (control). One build, two
# processes per arm.
# Usage: sh p-mech-run.sh > /tmp/p-mech-run.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

run2() {
    label=$1
    shift
    echo "== $label x2"
    env "$@" CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot | grep -E "majority_rounds"
    env "$@" CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot | grep -E "majority_rounds"
}

run2 "base"
run2 "poison_al" CSEQ_POISON=1
run2 "poison_full" CSEQ_POISON_FULL=1
run2 "poison_other" CSEQ_POISON_OTHER=1
run2 "nop" CSEQ_NOPPRE=1
echo "== p-mech done"
