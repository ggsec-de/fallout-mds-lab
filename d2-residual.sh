#!/bin/sh
# D2 same-CPU residual: a victim burst on cpu1 exits, the attacker starts
# right after on cpu1 and samples with NOSTORE. The only 0x42 in the system
# is the victim's, so any class-61 signal is a residual from its context.
# This is the shape MD_CLEAR (VERW on context switch) is meant to kill.
# Usage: sh d2-residual.sh > /tmp/d2-residual.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

A="env CPU=1 CSEQ=1 NOSTORE=1 NC=1 SLOT=61 FRESH=1 timeout 20"

echo "== control: no victim, attacker nostore cpu1"
for i in 1 2; do
    $A taskset -c 1 ./fallout-oneshot | grep -E "round=|majority_rounds"
done

for mode in b s l; do
    echo "== victim mode=$mode 0x42 cpu1 300ms -> attacker cpu1 right after"
    for i in 1 2 3 4 5 6; do
        taskset -c 1 ./mds-victim 0x42 0.3 1 $mode > /dev/null 2>&1
        $A taskset -c 1 ./fallout-oneshot | grep -E "round=|majority_rounds"
    done
done

echo "== control: victim mode=b 0x42 on cpu2 (other core), attacker cpu1"
for i in 1 2 3; do
    taskset -c 2 ./mds-victim 0x42 0.3 2 b > /dev/null 2>&1
    $A taskset -c 1 ./fallout-oneshot | grep -E "round=|majority_rounds"
done

echo "== control end: no victim"
for i in 1 2; do
    $A taskset -c 1 ./fallout-oneshot | grep -E "round=|majority_rounds"
done
