#!/bin/sh
# Value-swap test for the SPEC/noncanon positive (2026-09-28).
#
# The question a store-conditioned hot class cannot answer on its own: is the
# signal the stored VALUE, or something positional that happens to co-occur
# with the store? Swap the canary and the hot class must MOVE with it, and the
# old class must go cold.
#
#   0x42 -> (0x42 ^ 0x3f) & 0x3f = 61
#   0x24 -> (0x24 ^ 0x3f) & 0x3f = 27
#
# 27 is not 0, 1, 3, 47, 48 or 63, and is not adjacent to 61, so neither the
# excluded sets nor the +0x1040 stride preheat can carry it.
#
# Usage: sh spec-swap.sh > /tmp/spec-swap.txt 2>&1
cd /home/detox/CPU/labs/mds || exit 1

echo "build md5: $(md5sum fallout-oneshot | cut -d' ' -f1)"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "governor: $(cat /sys/devices/system/cpu/cpu1/cpufreq/scaling_governor)"
echo "online: $(cat /sys/devices/system/cpu/online)"

warm() {
    taskset -c 1 sh -c 'i=0; while [ $i -lt 3000000 ]; do i=$((i+1)); done' \
        >/dev/null 2>&1
}

echo "== 2x2 swap, SPEC_TARGET=noncanon, store=late"
for c in 0x42 0x24; do
    for s in 61 27; do
        printf "canary=%s slot=%2d store=late : " $c $s
        warm
        env SPEC=1 SPEC_TARGET=noncanon SLOT=$s CANARY=$c \
            timeout 180 taskset -c 1 ./fallout-oneshot 2>&1 \
            | grep -E "^timing:|majority_rounds" | tr '\n' ' '
        echo
    done
done

echo "== floors for both canaries (store=none)"
for c in 0x42 0x24; do
    for s in 61 27; do
        printf "canary=%s slot=%2d store=none : " $c $s
        warm
        env SPEC=1 SPEC_TARGET=noncanon SLOT=$s CANARY=$c SPEC_STORE=none \
            timeout 180 taskset -c 1 ./fallout-oneshot 2>&1 \
            | grep -E "majority_rounds" | tr '\n' ' '
        echo
    done
done
echo "== spec-swap done"
