#!/bin/sh
# D4: SIGSTOP/SIGCONT alternation on cpu1. The victim is FROZEN (not
# exited) while the attacker samples, so no exit-path teardown turnover
# sits between the victim's last stores and the attacker's faulting loads.
# Usage: sh d4-stop.sh > /tmp/d4-stop.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

A="env CPU=1 CSEQ=1 NOSTORE=1 NC=1 SLOT=61 FRESH=1 timeout 20"

echo "== floor: attacker alone"
for i in 1 2; do
    $A taskset -c 1 ./fallout-oneshot | grep -E "majority_rounds"
done

echo "== D4: victim store+yield on cpu1, frozen during each attacker run"
taskset -c 1 ./mds-victim 0x42 60 1 y > /dev/null 2>&1 &
VP=$!
sleep 1
i=1
while [ $i -le 15 ]; do
    kill -STOP $VP 2> /dev/null
    $A taskset -c 1 ./fallout-oneshot | grep -E "majority_rounds"
    kill -CONT $VP 2> /dev/null
    sleep 0.2
    i=$((i+1))
done
kill -CONT $VP 2> /dev/null
kill $VP 2> /dev/null
wait $VP 2> /dev/null

echo "== D4 sanity: attacker WITH store under the same alternation"
taskset -c 1 ./mds-victim 0x42 10 1 y > /dev/null 2>&1 &
VP=$!
sleep 1
for i in 1 2; do
    kill -STOP $VP 2> /dev/null
    env CPU=1 CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot | grep -E "majority_rounds"
    kill -CONT $VP 2> /dev/null
    sleep 0.2
done
kill $VP 2> /dev/null
wait $VP 2> /dev/null

echo "== floor end: attacker alone"
for i in 1 2; do
    $A taskset -c 1 ./fallout-oneshot | grep -E "majority_rounds"
done
echo "== d4 done"
