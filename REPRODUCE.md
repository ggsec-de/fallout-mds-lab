> Historical record: consult [REVIEW_NOTES.md](REVIEW_NOTES.md) for interpretation corrections and [README.md](README.md) for the current overview. Original measurements have not been rerun for this documentation update.

# MDS / Fallout-class reproduction — minimum recipe and conditions

Companion to `README.md` (results and history). This is the short path for
an external reviewer: what to run, what to expect, what kills the signal,
and which machine states move the numbers. Commands run on the kali lab
host as user `detox`, in `~/CPU/labs/mds`.

## 1. Why a 2019 bug still reproduces here (and not on a modern laptop)

MDS (incl. the Fallout/MSBDS shape: a faulting load sampling recently
stored data) is closed on any machine with the microcode and kernel
mitigation active. This box is deliberately kept vulnerable:

- CPU: Intel i3-6100 (Skylake, 2C/4T), microcode 0xba, kernel cmdline has
  `dis_ucode_ldr` (no early microcode load).
- `/sys/devices/system/cpu/vulnerabilities/mds` reads:
  `Vulnerable: Clear CPU buffers attempted, no microcode; SMT vulnerable`.
- Lab cmdline: `pti=off isolcpus=1 nmi_watchdog=0
  rcupdate.rcu_cpu_stall_suppress=1 msr.allow_writes=on vdso=0
  dis_ucode_ldr intel_idle.max_cstate=1 processor.max_cstate=1 no5lvl
  clearcpuid=308,295,514 no_timer_check`.
- Bench: governor `performance`, CPU3 offline, runs pinned with `taskset`.
- Topology: siblings are (cpu0, cpu2); cpu1's sibling (cpu3) is offline,
  so every single-process number below was taken on a core without SMT
  traffic.

A machine showing `Mitigation: Clear CPU buffers` (or `MDS_NO`) reads 0
everywhere; there that is the correct outcome, not a failed replication.

## 2. Build

    make -C labs/mds fallout-oneshot

Record `md5sum fallout-oneshot` with every session. Results are per-build:
a rebuild can flip marginal arms, and a FAILED build leaves the old binary
in place (check the `cc` line before trusting runs).

## 3. The primitive, minimal form

    env CSEQ=1 NC=1 SLOT=61 FRESH=1 timeout 20 taskset -c 1 ./fallout-oneshot

Per execution: store canary 0x42 (class 61) on the victim page -> setjmp ->
faulting non-canonical load (`0x9876543214321000`, #GP) -> the sampled
byte steers the index `(v ^ 0x3f) & 0x3f` -> one oracle slot is touched ->
longjmp. 64 executions per round, 8 rounds, majority per round.

PASS in a warmed burst:

- `cseq slot=61 round=N hits=NN/64` around 50..64 for most rounds,
- `majority_rounds=8/8` for most processes.

## 4. Controls on the same build (all with `NC=1 FRESH=1`)

| arm | observed |
|---|---|
| base (store) | 8/8, hits 50..64 |
| `NOSTORE=1` | 0/8 twice |
| `CSEQ_FENCE=1` | 0/8 twice |
| `CSEQ_LFENCE=1` | 0/8 twice |
| no `NC` (PROT_NONE fault) | 0/10 |
| stock VALUE arm + NC | 0/8 twice (suppressor = the al poison; see README) |
| `CSEQ_POISON=1` | 0/8 x6 then x2 (the suppressor, found 2026-09-27) |
| `CSEQ_NOPPRE=1` | 8/8 twice (nop in the same place -- not the timing) |

Root counters (perf 7.1.5) on the gap regime show no PMU signature for the
low-rate state: a 0/8 process is counter-identical to hot ones (cycles,
instructions, machine clears, elapsed; ~3.22 GHz average from
cycles/elapsed). See `README.md` (B3) and `b3-probe-20260927.txt`.

## 5. Rate regime — the part that decides a replication attempt

- The per-execution rate moves between ~0% and ~100% across processes
  (typical 25..95%; one B3b process read 0/512 executions while its
  nineteen neighbours read ~100%).
- Bursts (back-to-back runs) read 85..95%/execution; a single process
  after seconds of idle can read 30..50%; an occasional 5 s-idle process
  reads ~35% average and shows as `majority_rounds=0/8`.
- The same 5 s-idle regime later gave 5x 32/32 all-hot: the low-rate state
  is intermittent system state, not a deterministic idle-time effect.
- No timing witness explains it: the clock is full in every process
  (`timing:` hot=32..36, including the 0/8 process) and DRAM latency is
  anti-correlated with rate (0/8 process cold=320, an all-hot run
  cold=772).
- Method: bursts of >=10 runs, 8 rounds x 64 executions, majority per
  round, report rates and the whole distribution; pre-warm when running
  after idle; keep the series scripts with the numbers.

## 6. Known artifacts and traps

- +0x1040 stride prefetch preheats the next slot: never use the adjacent
  class as a control (the "zero-mode always hot" reading was this).
- Downclocked core (powersave/800 MHz) inflates hot latencies in TSC
  ticks; check the `timing:` line (`hot` must be ~32..36).
- A failed build leaves the old binary; runs then measure the old harness.
- Two-run rule for sentences; per-build rule for contrasts.
- Full-scan VALUE runs walk slots sequentially and preheat; suspicious.
- Shared zero page: `clear_refs` and `MADV_COLD` both skip it, so the
  accessed bit of a read-only anonymous page cannot be cleared and the
  advice is a silent no-op. The run then looks like a clean negative while
  measuring nothing. `page_atk` is `memset` at setup and `trig gate:` is the
  witness; no witness means VOID, not negative.
- Compiler-chosen registers can trip the suppressor. Written in C, the SPEC
  gadget compiled to `mov spec_bound_p,%rax; mov (%rax),%rax; ...;
  movzbl (%rdi),%eax` -- RAX written twice before a shadow load targeting
  EAX, the second writer being the CLFLUSH'd bound load, i.e. a DRAM miss
  still in flight exactly when the forward would have to happen. The
  destination is pinned to `%rdx` in asm for that reason. Check the gadget
  with `objdump -d` after every build; the rule cannot be read off the C.
- A bare `clflush` helper is used for the SPEC gate line. `flush_line()`
  ends in `mfence`, which drains the store buffer; inside the inner loop
  that silently reinvents the measured `CSEQ_FENCE` killer.

## 7. File map

- `fallout-oneshot.c` — harness (CSEQ / VALUE / MATRIX / PROBE modes).
- `ref-rate.c`, `ref-mirror.c` — rate baselines, `make ref-rate-inline`.
- Rate-regime series: scripts `bimodal-runs.sh`, `bimodal-short.sh`,
  `bimodal-gap.sh`, `bimodal-warm.sh`, `bimodal-long.sh`; logs
  `bimodal-run-20260927.txt`, `bimodal-short-20260927.txt`,
  `bimodal-gap-20260927.txt`, `bimodal-warm-20260927.txt`,
  `bimodal-long-20260927.txt`.
- `mds-victim.c` — cross-context victim (modes l/s/b: clflush+load,
  store-only, store+clflush+load).
- `d1-cross.sh`, `d2-residual.sh`, `d3-pingpong.sh`, `d4-stop.sh` —
  stage-D cross-context scripts; logs `d1-cross-20260927.txt`,
  `d2-residual-20260927.txt`, `d3-pingpong-20260927.txt`,
  `d4-stop-20260927.txt`.
- `addback-run.sh`, `addback-recheck.sh`, `nop-run.sh`, `p-mech-run.sh` —
  suppressor bisection; logs `addback-run-20260927.txt`,
  `addback-recheck-20260927.txt`, `nop-run-20260927.txt`,
  `p-mech-run-20260927.txt`.
- `scan-hunt.sh` — deposit hunt (clean pre-round scans); logs
  `scan-runs-20260927.txt`, `scan-hunt-20260927.txt`,
  `scan-hunt2-20260927.txt`.
- `bimodal-sibling.sh` + `bimodal-sibling-20260927.txt` — cpu0-load
  contrast in the gap regime.
- `msr-freq.c`, `b3-perf.sh` — root probes: APERF/MPERF clock and PMU
  counters per process in the gap regime (operator runs with sudo).
- `b3b-perf.sh` + `b3b-probe-20260927.txt` — extended fill-buffer/MLP
  counter pass (root; `perf_event_paranoid=3` on this box).
- `assist-run.sh`, `spec-run.sh`, `spec-swap.sh` — the 2026-09-28
  non-faulting triggers; logs `assist-run-20260928.txt`,
  `spec-run-20260928.txt`, `spec-swap-20260928.txt`.
- `README.md` — full result history, retractions, next questions.

## 9. Cross-context (stage D) — measured negative on this box (2026-09-27)

The working primitive above is strictly same-thread: its own store, its
own faulting load, a ~us window. Two cross-context shapes were built and
both read the NOSTORE floor:

- D1 sibling, concurrent: `mds-victim` hammers 0x42 through clflush+load
  on cpu2 (~11M iter/s) while the NOSTORE attacker samples on the sibling
  cpu0 (`d1-cross.sh`). Six processes 0/8, per-round hits 0..1/64 — the
  same as the no-victim control (0..1/64). Wrong-value control and the
  attacker-with-store sanity (8/8, hits 43..56) behave as expected. No
  cross-SMT signal in this shape.
- D2 same-CPU residual: a 300 ms victim burst on cpu1 exits, the attacker
  starts immediately after on cpu1 (`d2-residual.sh`). Modes
  store+clflush+load, store-only, clflush+load: 18 processes, every round
  0/64 (single stray 1/64), same as the controls. The kernel's
  clear-on-switch attempt plus buffer turnover leave nothing the faulting
  load can name at this gap scale.
- D3 same-CPU time-sharing: victim and attacker both runnable on cpu1
  (store+yield and store-only victim modes; `d3-pingpong.sh`): 17
  processes, every round 0/64 (single stray 1/64), identical to the floor
  arms. No switch-in residual at slice granularity either.
- D4 frozen-victim alternation (`d4-stop.sh`): the victim is frozen with
  SIGSTOP while each attacker run samples (no exit-path teardown): 15 runs
  at the floor, store sanity 8/8 twice.

Consequence: on this box/microcode the class-61 channel is demonstrable
self-thread only. All four cross-context shapes (sibling, post-exit
residual, same-CPU time-shared, frozen alternation) read the NOSTORE
floor; a finer window would need the scheduler held in the kernel.

## 10. Non-faulting triggers (added 2026-09-28)

`TRIGGER=<t>` selects the sampling shape; `NC=1` remains an alias for
`TRIGGER=noncanon`. All of these are SLOT-only. Build md5 for the numbers
below: `41bfb756804cf1f5bbe6a08af6d10018`.

    # accessed-bit assist: page_atk present, MADV_COLD per attempt, load retires
    env CSEQ=1 TRIGGER=assist SLOT=61 FRESH=1 taskset -c 1 ./fallout-oneshot

    # demand-zero minor #PF: MADV_DONTNEED per attempt, load retires
    env CSEQ=1 TRIGGER=demand SLOT=61 FRESH=1 taskset -c 1 ./fallout-oneshot

    # mispredicted branch, no fault at all (SPEC conflicts with CSEQ and FRESH)
    env SPEC=1 SPEC_TARGET=noncanon SLOT=61 taskset -c 1 ./fallout-oneshot

Every conflicting combination is a hard error, never a silent preference:
`NC=1` with `TRIGGER=assist|demand`, `SPEC=1` with `CSEQ=1` or `FRESH=1`,
and any new arm without `SLOT`.

Both new families print their own in-process witness and a run without it is
VOID rather than negative:

- `trig gate:` for assist and demand. Expect `referenced_kb before=12
  after_clear=8 after_touch=12 minflt_delta=0` for assist (the advice cleared
  exactly one page and no fault was taken) and `after_touch=8
  minflt_delta=1` for demand (the page was dropped, so the re-fault maps the
  shared zero page, which `Referenced:` does not count).
- `spec gate1/gate2` for SPEC. Expect `gate1 ... c61=64/64` and
  `gate2 ... c63=64/64 c61=0/64`.

Expected, two processes per cell:

| arm | slot 61 | slot 63 |
|---|---|---|
| `assist` store / nostore | 0/8 | 8/8 / 8/8 |
| `demand` store / nostore | 0/8 | 8/8 / 8/8 |
| `SPEC noncanon` store | **8/8** | dark |
| `SPEC noncanon` `SPEC_STORE=none` | 0/8 | dark |
| `SPEC noncanon` `SPEC_STORE=early` | 0/8 | dark |
| `SPEC present` store | 0/8 | 8/8 |
| `SPEC protnone` store | 0/8 | dark |

Value-swap control for the SPEC positive (`sh spec-swap.sh`): with
`CANARY=0x42` slot 61 is 8/8 and slot 27 is 0/8; with `CANARY=0x24` slot 27
is 8/8 and slot 61 is 0/8; all four `SPEC_STORE=none` floors are 0/8. If the
hot class does not move with the canary, the signal is positional and the
SPEC positive does not hold.

Pre-warm matters here. Under the `powersave` governor the core idles at
800 MHz and a hot reload reads ~72 TSC ticks instead of ~33; the scripts spin
on CPU1 before each cell and keep the `timing:` line in the log so every
measurement carries its own clock witness.

## 8. Reviewer's falsification checklist

1. Check `/sys/devices/system/cpu/vulnerabilities/mds`. Mitigated or
   `MDS_NO`: expect 0, stop — the channel is closed by design.
2. On this box: run section 3 in a burst of 10 processes. Expect most
   processes 8/8, hits ~50..64; controls in section 4 at 0/8.
3. Run one process after 5 s idle: 30..50% is possible and is NOT a
   failed reproduction; re-run in a burst.
4. Flip the store off (`NOSTORE=1`): the signal must vanish. If it does
   not, the harness is invalid.
