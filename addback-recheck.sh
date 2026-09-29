#!/bin/sh
# Recheck of the add-back arms with exit codes (the first addback run had
# two runs without a majority line): vf, prologue, poison x6.
# Usage: sh addback-recheck.sh > /tmp/addback-recheck.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

for arm in "CSEQ_VF=1 vf" "CSEQ_PROLOGUE=1 prologue" "CSEQ_POISON=1 poison"; do
    set -- $arm
    var=$1
    label=$2
    echo "== $label x6"
    i=1
    while [ $i -le 6 ]; do
        out=$(env "$var" CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot 2>&1)
        rc=$?
        maj=$(printf '%s\n' "$out" | grep -E "majority_rounds" | tail -1)
        echo "$label run $i rc=$rc $maj"
        i=$((i+1))
    done
done
echo "== recheck done"
