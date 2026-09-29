#!/bin/sh
# Poison deconfound (2026-09-29).
#
# The 2026-09-27 "suppressor" reading (the al/eax poison kills the class-61
# signal) is confounded: both arms also change the faulting load's address.
# The al write replaces the low address byte with 0x2a; the full eax write
# replaces the whole address (0x2a, canonical) and turns the #GP into a #PF,
# a fault family that is cold everywhere else in this binary. The dl write
# (POISON_OTHER) keeps the address but only shows that a non-destination
# write does not suppress.
#
# This script runs the clean controls added to fallout-oneshot.c:
#   CSEQ_POISON_KEEP       al=0x2a write, fault address held in a pinned
#                          spare register (r8) -> address does not move
#   CSEQ_POISON_FULL_KEEP  full eax=0x2a write, same address discipline
#   CSEQ_LOADOFF=<hex>     faulting-load page offset override (the store
#                          stays at OFFSET) -> the address moves alone
# Cells: each variable (destination-register write / load offset / store-
# load offset match) flips alone, plus the original confounded arm for
# reproduction. SLOT=21 cells test the notebook sentence "the dependent
# chain consumes 0x2a (class 21)": class 21 is what the transform produces
# from a surviving 0x2a, so it measures whether the poison reaches the
# chain at all.
#
# Reading: POISON_KEEP hot  -> the write does not suppress; the cold
#        original arm was the address change (suppressor claim retracted).
#        POISON_KEEP cold  -> the destination write survives as a
#        candidate with the address held constant.
#        LOADOFF=0x2a cold -> the load offset alone reproduces the cold.
#        OFFSET=0x2a cells separate "offsets mismatch" from "absolute
#        offset 0x2a is a cold locus".
#
# Two processes per cell; full output kept (per-round hits included, the
# archived bench-confirm log filtered them out). Build md5 is logged.
#
# Usage: sh poison-deconf.sh > /tmp/poison-deconf.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

echo "build md5: $(md5sum fallout-oneshot | cut -d' ' -f1)"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "governor: $(cat /sys/devices/system/cpu/cpu1/cpufreq/scaling_governor)"
echo "online: $(cat /sys/devices/system/cpu/online)"
echo "cpu1 thread siblings: $(cat /sys/devices/system/cpu/cpu1/topology/thread_siblings_list)"

one() {
    label=$1
    shift
    echo "########## $label"
    env "$@" timeout 60 taskset -c 1 ./fallout-oneshot 2>&1
    echo
}

echo "== base, before"
one "base (1/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1
one "base (2/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1

echo "== the confounded arm, reproduced"
one "CSEQ_POISON=1 (1/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_POISON=1
one "CSEQ_POISON=1 (2/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_POISON=1

echo "== clean: destination write, address preserved"
one "POISON_KEEP (1/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_POISON_KEEP=1
one "POISON_KEEP (2/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_POISON_KEEP=1

echo "== clean: full-width write, address preserved"
one "POISON_FULL_KEEP (1/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_POISON_FULL_KEEP=1
one "POISON_FULL_KEEP (2/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_POISON_FULL_KEEP=1

echo "== clean: load offset changed alone (store stays at 0x40)"
one "LOADOFF=0x2a (1/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_LOADOFF=0x2a
one "LOADOFF=0x2a (2/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_LOADOFF=0x2a

echo "== both variables, explicitly (original arm, decomposed)"
one "LOADOFF=0x2a + KEEP (1/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_LOADOFF=0x2a CSEQ_POISON_KEEP=1
one "LOADOFF=0x2a + KEEP (2/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_LOADOFF=0x2a CSEQ_POISON_KEEP=1

echo "== absolute offset 0x2a, store/load still matched"
one "OFFSET=0x2a (1/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 OFFSET=0x2a
one "OFFSET=0x2a (2/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 OFFSET=0x2a
one "OFFSET=0x2a + KEEP (1/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 OFFSET=0x2a CSEQ_POISON_KEEP=1
one "OFFSET=0x2a + KEEP (2/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 OFFSET=0x2a CSEQ_POISON_KEEP=1

echo "== class-21 check (does the poison reach the chain?)"
one "POISON slot=21 (1/2)" CSEQ=1 NC=1 SLOT=21 FRESH=1 CSEQ_POISON=1
one "POISON slot=21 (2/2)" CSEQ=1 NC=1 SLOT=21 FRESH=1 CSEQ_POISON=1
one "POISON_KEEP slot=21 (1/2)" CSEQ=1 NC=1 SLOT=21 FRESH=1 CSEQ_POISON_KEEP=1
one "POISON_KEEP slot=21 (2/2)" CSEQ=1 NC=1 SLOT=21 FRESH=1 CSEQ_POISON_KEEP=1

echo "== base, after (sanity)"
one "base (1/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1
one "base (2/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1
echo "== poison-deconf done"
