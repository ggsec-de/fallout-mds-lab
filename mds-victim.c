/*
 * MDS cross-context victim: keep a secret byte churning through the
 * load-fill path on a chosen logical CPU so that whichever buffer holds it
 * (fill buffer / load port) is resident when the attacker's faulting load
 * samples on the SMT sibling.
 *
 * Usage: mds-victim [value] [seconds] [cpu] [mode]
 *   value   secret byte, default 0x42
 *   seconds run time, default 5
 *   cpu     logical CPU to pin to, default 2 (sibling of cpu0 on this box)
 *   mode    l = clflush+load (default), s = store only, b = store+clflush+load,
 *           y = store + periodic sched_yield (same-CPU ping-pong partner)
 *
 * Modes:
 *   l  clflush the secret line then load it: every load misses, so the
 *      fill buffer holds the line's data during the fetch.
 *   s  store the secret byte in a tight loop: the store buffer churns the
 *      byte for residual same-CPU sampling.
 *   b  store, clflush, load: both buffers see the byte each iteration.
 *   y  like s but yields the CPU regularly, so a same-CPU attacker gets
 *      switched in right after the victim's stores.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#define PAGE_OFFSET 0x40
#define BATCH       100000

static double now_s(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    long value = 0x42;
    double secs = 5.0, t0, t1, tend;
    int cpu = 2, b;
    char mode = 'l';
    volatile uint8_t *page;
    cpu_set_t set;
    unsigned long long iters = 0;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 1)
        value = strtol(argv[1], NULL, 0);
    if (argc > 2)
        secs = strtod(argv[2], NULL);
    if (argc > 3)
        cpu = (int)strtol(argv[3], NULL, 0);
    if (argc > 4)
        mode = argv[4][0];
    if (value < 0 || value > 255) {
        fprintf(stderr, "value must be a byte\n");
        return 2;
    }

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        fprintf(stderr, "sched_setaffinity(%d): %s\n", cpu, strerror(errno));
        return 2;
    }

    page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        return 2;
    }
    page[PAGE_OFFSET] = (uint8_t)value;
    asm volatile("mfence" ::: "memory");

    printf("mds-victim: cpu=%d value=0x%02lx class=%ld offset=0x%x "
           "mode=%c page=%p secs=%.1f\n",
           cpu, value, (value ^ 0x3f) & 0x3f, PAGE_OFFSET,
           mode, (void *)page, secs);

    t0 = now_s();
    tend = t0 + secs;
    t1 = t0;
    while (now_s() < tend) {
        double t;

        for (b = 0; b < BATCH; b++) {
            if (mode == 's' || mode == 'y') {
                *(volatile uint8_t *)(page + PAGE_OFFSET) =
                    (uint8_t)value;
                if (mode == 'y' && (b & 0xffff) == 0xffff)
                    sched_yield();
            } else if (mode == 'b') {
                *(volatile uint8_t *)(page + PAGE_OFFSET) =
                    (uint8_t)value;
                asm volatile("clflush (%0)" :: "r"(page + PAGE_OFFSET)
                             : "memory");
                (void)*(volatile uint8_t *)(page + PAGE_OFFSET);
            } else {
                asm volatile("clflush (%0)" :: "r"(page + PAGE_OFFSET)
                             : "memory");
                (void)*(volatile uint8_t *)(page + PAGE_OFFSET);
            }
        }
        iters += BATCH;
        t = now_s();
        if (t - t1 >= 1.0) {
            printf("mds-victim: t=%.0fs iters=%llu\n", t - t0, iters);
            t1 = t;
        }
    }
    printf("mds-victim: done iters=%llu rate=%.0f/s\n",
           iters, iters / (now_s() - t0));
    return 0;
}
