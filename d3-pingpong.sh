#!/bin/sh
# D3 same-CPU time-sharing: victim and attacker both runnable on cpu1, so
# the scheduler alternates them at slice granularity; the attacker samples
# right after every switch-in, a window far tighter than D2's process-exit
# gap. Floor is the no-victim arm in the same regime.
# Usage: sh d3-pingpong.sh > /tmp/d3-pingpong.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

A="env CPU=1 CSEQ=1 NOSTORE=1 NC=1 SLOT=61 FRESH=1 timeout 20"

echo "== floor: attacker alone on cpu1"
for i in 1 2; do
    $A taskset -c 1 ./fallout-oneshot | grep -E "cseq slot=61 round=|majority_rounds"
done

echo "== D3a: victim store+yield on cpu1 (background), attacker cpu1 x6"
taskset -c 1 ./mds-victim 0x42 6 1 y > /dev/null 2>&1 &
VP=$!
sleep 0.3
i=1
while [ $i -le 6 ]; do
    $A taskset -c 1 ./fallout-oneshot | grep -E "cseq slot=61 round=|majority_rounds"
    i=$((i+1))
done
kill $VP 2>/dev/null
wait $VP 2>/dev/null

echo "== D3b: victim store only (no yield) on cpu1, attacker cpu1 x4"
taskset -c 1 ./mds-victim 0x42 5 1 s > /dev/null 2>&1 &
VP=$!
sleep 0.3
for i in 1 2 3 4; do
    $A taskset -c 1 ./fallout-oneshot | grep -E "cseq slot=61 round=|majority_rounds"
done
kill $VP 2>/dev/null
wait $VP 2>/dev/null

echo "== D3c: victim store+yield on cpu2 (other core), attacker cpu1 x3"
taskset -c 2 ./mds-victim 0x42 4 2 y > /dev/null 2>&1 &
VP=$!
sleep 0.3
for i in 1 2 3; do
    $A taskset -c 1 ./fallout-oneshot | grep -E "cseq slot=61 round=|majority_rounds"
done
kill $VP 2>/dev/null
wait $VP 2>/dev/null

echo "== floor end: attacker alone on cpu1"
for i in 1 2; do
    $A taskset -c 1 ./fallout-oneshot | grep -E "cseq slot=61 round=|majority_rounds"
done
