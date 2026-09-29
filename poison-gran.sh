#!/bin/sh
# Poison deconfound, part 2: match granularity (2026-09-29, same build).
#
# Part 1 (poison-deconf-20260929.txt) showed: the destination-register write
# does not suppress when the fault address is held constant (POISON_KEEP,
# POISON_FULL_KEEP 8/8 x2); moving the load offset alone to 0x2a with the
# store at 0x40 reproduces the cold signal (LOADOFF=0x2a 0/8 x2); moving
# store and load together to 0x2a restores it (OFFSET=0x2a 8/8 x2). So the
# suppressing variable is the store/load offset relation. This script asks
# HOW MUCH has to match, with the load moved alone (store stays at 0x40):
#   0x41    same 64-byte line as the store, one byte off
#   0x1040  different line, same L1 set (set 1)
#   0x80    different line, different set (set 2)
# Two processes per cell; base sanity at the end.
#
# Usage: sh poison-gran.sh > /tmp/poison-gran.txt 2>&1
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

echo "== load at 0x41: same 64B line as the store at 0x40, one byte off"
one "LOADOFF=0x41 (1/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_LOADOFF=0x41
one "LOADOFF=0x41 (2/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_LOADOFF=0x41

echo "== load at 0x1040: different line, same L1 set 1"
one "LOADOFF=0x1040 (1/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_LOADOFF=0x1040
one "LOADOFF=0x1040 (2/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_LOADOFF=0x1040

echo "== load at 0x80: different line, different set 2"
one "LOADOFF=0x80 (1/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_LOADOFF=0x80
one "LOADOFF=0x80 (2/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1 CSEQ_LOADOFF=0x80

echo "== base, sanity"
one "base (1/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1
one "base (2/2)" CSEQ=1 NC=1 SLOT=61 FRESH=1
echo "== poison-gran done"
