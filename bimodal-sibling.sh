#!/bin/sh
# Sibling/uncore load contrast (menu item 4): the gap regime (5 s idle
# before each run) with cpu0 idle vs cpu0 busy (spinner). Tests whether
# package/uncore activity moves the class-61 rate on cpu1.
# Usage: sh bimodal-sibling.sh > /tmp/bimodal-sibling.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

A="env CPU=1 CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20"

echo "== A: cpu0 idle (10 runs, 5 s gaps)"
for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 5
    $A taskset -c 1 ./fallout-oneshot | grep -E "timing:|cseq slot=61 round=|majority_rounds"
done

echo "== B: cpu0 busy spinner (10 runs, 5 s gaps)"
taskset -c 0 sh -c 'while :; do :; done' &
SP=$!
sleep 1
for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 5
    $A taskset -c 1 ./fallout-oneshot | grep -E "timing:|cseq slot=61 round=|majority_rounds"
done
kill $SP 2> /dev/null
wait $SP 2> /dev/null
echo "== sibling done"
