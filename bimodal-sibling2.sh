#!/bin/sh
# Sibling retest, interleaved: alternate cpu0-idle (arm A) and cpu0-busy
# (arm B) runs inside one timeline, so a cold window can be attributed to
# the phase instead of to the passage of time. 12 pairs, 5 s idle before
# every run (arm B's gap runs with the spinner up -- noted as a confound).
# Usage: sh bimodal-sibling2.sh > /tmp/bimodal-sibling2.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

A="env CPU=1 CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20"

run() {
    $A taskset -c 1 ./fallout-oneshot | grep -E "timing:|cseq slot=61 round=|majority_rounds"
}

i=1
while [ $i -le 12 ]; do
    sleep 5
    echo "== pair $i arm A (cpu0 idle) start=$(date +%s.%N)"
    run
    taskset -c 0 sh -c 'while :; do :; done' &
    SP=$!
    sleep 5
    echo "== pair $i arm B (cpu0 busy) start=$(date +%s.%N)"
    run
    kill $SP 2> /dev/null
    wait $SP 2> /dev/null
    i=$((i+1))
done
echo "== sibling2 done"
