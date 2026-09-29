#!/bin/sh
# Arm A, the non-SIGSEGV triggers (2026-09-28).
#
#   TRIGGER=assist  page_atk present, madvise(MADV_COLD) clears the PTE
#                   accessed bit before every attempt -> microcode A-bit
#                   assist, the load retires, faults=0.
#   TRIGGER=demand  page_atk present, madvise(MADV_DONTNEED) -> demand-zero
#                   minor #PF that the kernel resolves, the load retires.
#
# Slot 61 is the canary class and the signal. Slot 63 is the retiring load's
# own 0x00 byte: it is the liveness control, NOT a control arm, and the
# negative sentence requires it repeatable. Every process prints its own
# witness line ("trig gate:"); a run without the witness is VOID, not
# negative, because MADV_COLD silently skips the shared zero page.
#
# The floor for these arms is their OWN nostore run: they carry 1-2 syscalls
# per attempt, so their rate is not comparable to the CSEQ base.
#
# Two processes per cell, as every sentence in this lab requires.
# Usage: sh assist-run.sh > /tmp/assist-run.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

echo "build md5: $(md5sum fallout-oneshot | cut -d' ' -f1)"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

cell() {
    label=$1
    shift
    echo "== $label x2"
    for i in 1 2; do
        printf "   "
        env "$@" timeout 180 taskset -c 1 ./fallout-oneshot 2>&1 \
            | grep -E "trig gate: (PASS|FAIL)|majority_rounds|verdict:" \
            | tr '\n' ' '
        echo
    done
}

for t in assist demand; do
    echo "########## TRIGGER=$t ##########"
    cell "$t slot=61 store   (signal)"    CSEQ=1 TRIGGER=$t SLOT=61 FRESH=1
    cell "$t slot=61 nostore (floor)"     CSEQ=1 TRIGGER=$t SLOT=61 FRESH=1 NOSTORE=1
    cell "$t slot=63 store   (liveness)"  CSEQ=1 TRIGGER=$t SLOT=63 FRESH=1
    cell "$t slot=63 nostore (liveness)"  CSEQ=1 TRIGGER=$t SLOT=63 FRESH=1 NOSTORE=1
    cell "$t slot=61 fence"               CSEQ=1 TRIGGER=$t SLOT=61 FRESH=1 CSEQ_FENCE=1
    cell "$t slot=61 lfence"              CSEQ=1 TRIGGER=$t SLOT=61 FRESH=1 CSEQ_LFENCE=1
done

echo "== stock hot base, same build, sanity x2"
for i in 1 2; do
    printf "   "
    env CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 60 taskset -c 1 ./fallout-oneshot 2>&1 \
        | grep -E "majority_rounds"
done
echo "== assist-run done"
