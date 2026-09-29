# Exploring Fallout / MDS on Skylake

An educational CPU security lab by **Maciej — GG Advanced IT Security UG**.

This project explores how CPU vulnerabilities are investigated: reproduce a known demonstration, establish a measurable signal, vary conditions, and use controls to separate observations from explanations. The starting point is Fallout / Microarchitectural Store Buffer Data Sampling (MSBDS, CVE-2018-12126).

The experiments use a known canary written by the test program on an Intel Core i3-6100. They include successful and unsuccessful configurations, and a branch-misprediction variant with no architecturally delivered exception.

**This is a learning and reproduction project, not a new vulnerability disclosure.** The positive results concern the program's own stores in its own thread. Kernel, SGX, and other-process secret extraction have not been demonstrated here.

## Main result

The strongest recorded result is a store-conditioned, value-dependent cache signal from a speculative load targeting a noncanonical address.

The [29 September confirmation](bench-confirm-20260929.txt) records **10/10 processes with 8/8 majority rounds** for the SPEC/noncanonical positive. The same pass includes controls and a canary swap:

| Experiment | Recorded outcome |
|---|---|
| Noncanonical target, late store | 10/10 processes, each 8/8 majority rounds |
| Same target, no store | 0/8 in three processes |
| Same store placed earlier | 0/8 in two processes |
| Canary `0x42` | Class 61 repeatable, class 27 not repeatable |
| Canary `0x24` | Class 27 repeatable, class 61 not repeatable |
| Swap controls without stores | No repeatable signal |
| Present zero-valued target | Canary class absent; zero class repeatable |
| SPEC with `PROT_NONE` | Canary class not repeatable |
| Accessed-bit / demand-zero experiments | Canary class absent; zero class repeatable |

The signal follows the stored value. This is stronger than observing a repeatedly hot cache location, but does not uniquely identify the internal CPU structure that supplied the value.

The earlier fault-driven CSEQ path also produces a signal, with substantial variability between processes. Four cross-context experiments remained at the no-store background level. These negatives apply to the tested configurations.

## Mechanism

The program stores a canary on one page. A later load uses another address with a matching page offset. In SPEC mode, the load executes on a wrongly predicted branch and is discarded before retirement. Its dependent instructions can nevertheless leave a cache footprint.

```text
Own canary store
       |
       v
Mispredicted branch -> noncanonical load -> class-dependent cache access
       |                                          |
       v                                          v
Wrong path discarded                       timed reload measurement
```

The oracle has 64 classes separated by `0x1040` bytes:

```c
class = (value ^ 0x3f) & 0x3f;
```

It observes a **six-bit class**, not an arbitrary complete byte. Class 61 is consistent with `0x02`, `0x42`, `0x82`, or `0xC2`.

## Reading the measurements

- Default: 8 rounds, 64 attempts per round.
- A majority round requires more than 32 hits out of 64.
- `majority_rounds=8/8` does **not** mean 512/512 successful attempts.
- One SPEC attempt contains 30 gadget invocations, including five malicious-index invocations. Its unit differs from a single CSEQ faulting attempt.
- The archived confirmation script filters out raw round counts. Its log does not establish perfect per-load reliability or a throughput ceiling.
- Failed calibration or trigger gates mean an invalid experiment (`VOID`), not a negative result.

## Recorded environment

| Item | Recorded configuration |
|---|---|
| Processor | Intel Core i3-6100, Skylake |
| Microcode | `0xba`, as documented for the lab |
| Operating system | Linux x86-64 |
| Recorded MDS status | `Vulnerable: Clear CPU buffers attempted, no microcode; SMT vulnerable` |
| Confirmation bench | `performance` governor, CPU3 offline, measurements on CPU1 |
| Confirmation build MD5 | `41bfb756804cf1f5bbe6a08af6d10018` |
| Latest included confirmation | 2026-09-29 |

These are historical experiment conditions, not requirements proven sufficient on other machines. CPU, microcode, kernel, compiler, instruction layout, and runtime state can affect reproduction. This repository does not establish behavior on every mitigated processor.

## Build and run

Run from this directory on Linux x86-64. Requirements: GCC, GNU Make, and standard Linux userspace tools. The main harness uses system headers and inline assembly; it does not require SGX-Step or `cacheutils.h`.

```sh
make fallout-oneshot
sha256sum fallout-oneshot
objdump -d fallout-oneshot > fallout-oneshot.dis
env SELFTEST=1 CPU=1 ./fallout-oneshot
```

Check build success before running: a failed build can leave an older executable behind. Select an available logical CPU and record its topology. The self-test checks the measurement setup; it is not evidence of a leak.

On the recorded lab configuration, the central comparison is:

```sh
# Positive: late store
env SPEC=1 SPEC_TARGET=noncanon SLOT=61 CPU=1 ./fallout-oneshot

# No-store control
env SPEC=1 SPEC_TARGET=noncanon SPEC_STORE=none SLOT=61 CPU=1 ./fallout-oneshot

# Same store, earlier
env SPEC=1 SPEC_TARGET=noncanon SPEC_STORE=early SLOT=61 CPU=1 ./fallout-oneshot

# Changed canary: expected class moves to 27
env SPEC=1 SPEC_TARGET=noncanon CANARY=0x24 SLOT=27 CPU=1 ./fallout-oneshot
```

Preserve complete output, including gate results and round hit counts. Repeat controls and both sides of the value swap. One positive run is not the full experiment.

The [detailed recipe](REPRODUCE.md) records historical settings and additional modes. Existing series scripts retain the original `/home/detox/CPU/labs/mds` directory and CPU choices: adapt those before reuse. Individual commands above do not depend on that directory. Scripts also require POSIX shell utilities, `taskset`, and `timeout`; PMU/MSR workflows have additional requirements.

## Difference from the reference

The reference FalloutV1 demo reconstructs a known string using a 256-entry oracle, a noncanonical load, signal recovery, and repeated last-hit collection. This lab adds class-based measurements, explicit controls, alternate triggers, build and timing records, and process-to-process variability experiments.

Original Fallout research demonstrated kernel-data disclosure and KASLR attacks. Those achievements belong to the original research and are not claimed here. Branch-based exception suppression is an established technique, not a novelty claim of this lab.

## Lessons and open questions

The practical lessons are to test the decoder independently, change the stored value, remove the store, compare aliasing conditions, inspect generated assembly, and treat prefetching and timing as experimental variables.

Read [REVIEW_NOTES.md](REVIEW_NOTES.md) alongside the historical documents. In particular, the CSEQ poison controls also change the load address; they do not isolate a destination-register-only suppressor. Majority results must not be described as perfect per-attempt recovery.

Open questions include the exact microarchitectural source of the observed value, intermittent low-rate CSEQ runs, and whether a separately designed experiment can cross a security boundary.

## Files

- [EXPERIMENTS.md](EXPERIMENTS.md): original chronological notebook, including superseded interpretations.
- [REPRODUCE.md](REPRODUCE.md): historical reproduction procedure.
- [fallout-oneshot.c](fallout-oneshot.c): main CSEQ/SPEC harness.
- [bench-confirm.sh](bench-confirm.sh) and [confirmation log](bench-confirm-20260929.txt): latest comparison matrix.
- [spec-swap.sh](spec-swap.sh) and [swap log](spec-swap-20260928.txt): value-dependence control.
- [PUBLISHING.md](PUBLISHING.md): exact file selection and packaging notes.

## References and attribution

- Minkin et al., [Fallout: Reading Kernel Writes From User Space](https://arxiv.org/abs/1905.12701), 2019: original research.
- Hanna Hayik, [Fallout / FalloutV1](https://github.com/hannaHayik/Fallout): reference demonstration investigated here.
- [IAIK ZombieLoad](https://github.com/IAIK/ZombieLoad): cache utilities acknowledged by that demonstration.

The SPEC training shape was adapted through the adjacent Foreshadow lab's misprediction gadget; it is not claimed as an original branch-training technique. Historical reference-check builds require separate upstream files and are not needed by the main harness.

No repository-wide license was selected in this documentation pass. Preserve third-party terms separately from any license chosen for original contributions.
