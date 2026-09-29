> Historical record: consult [REVIEW_NOTES.md](REVIEW_NOTES.md) for interpretation corrections and [README.md](README.md) for the current overview. Original measurements have not been rerun for this documentation update.

# Fallout one-shot (MSBDS)

Known-vulnerability lab for CVE-2018-12126 on the i3-6100 (microcode 0xBA).
A canary byte is stored to a present page. A faulting load from a second page,
which never held that byte, indexes a set-separated reload oracle. This is not
a kernel leak and it does not use a sibling thread.

Build and run on the lab host, pinned to logical CPU 1 (sibling of CPU 3):

```bash
make
./fallout-oneshot
```

`SELFTEST=1` checks timing and the architectural decoder, then exits.

Overrides: `CPU`, `ROUNDS` (1..64, default 8), `CANARY` (default `0x42`,
low-six-bit class `0x02`).

The binary in this tree is the PROT_NONE experiment. `page_atk` is mapped
`PROT_NONE`. The default arm writes no page-table hint; `TRIGGER=assist` and
`TRIGGER=demand` (2026-09-28, see below) use `madvise` instead of
`/proc/self/clear_refs`, which is process-wide and would clear the accessed
bits of the oracle pages too. `verdict: PASS` requires
the store arm to fault on every attempt, a majority of those rounds to see
the canary class hot, and neither control arm to see that class hot.

Page offset `0x40` is L1 set 1. The older miss is at offset `0xC0`, set 3.
The canary class is set 2. The miss is not timed against the fault, so it
does not establish that a store-buffer entry was still sampleable.

What has been shown is the decoder, and a dependent transient signal on the
probe that does not store the canary. `SELFTEST` is an architectural touch
plus the same-set alias on an immediate reload. It does not take the fault.
Other accesses to set 0 remain an alternative signal source that the canary
runs do not rule out. The geometry probe does not establish that effect for
every access or for the fault path.

`PROBE=1` has no canary store. `fixed` writes oracle class `0x15` with an
immediate after the faulting load: class 21 was hot 8/8, so an access there
can survive the handler. `dep` puts `0x2a` in `al` first, then xors `0x15`.
Class 21 rather than 63 means the index is not that preserved poison, and
the low six bits of the value the xor consumed are 0. The following `and`
with `0x3f` does not show that the whole byte is `0x00`. This reading assumes
the handler skips the gadget, so the class 21 access does not retire. The
store arm adds a store and an address dependency, so this probe does not
rule out a miss of that access on those attempts. The handler sets RIP past
the oracle load, so that access does not retire. On the recorded canary-arm
runs with the same handler, class 21 was cold, which narrows a set-21
alternative to the probe sequence and does not close it. `dep` shows that
the faulting load supplies a value into the dependency chain: preserved
poison would have been class 63. That rules out "a dependent signal on this
path is always wiped". It does not say what the value is.

`VALUE=1` without `SLOT` is still one trial per class. Class 21 means `al`
stayed `0x2a`. Class 63 means the low six bits consumed by the xor are 0,
not that the byte is `0x00`. Class 61 means those bits are 2, so the byte
is one of `0x02`, `0x42`, `0x82`, `0xC2`. A hit on class 0 is
`v & 0x3f == 0x3f` and is not interpreted. The 2026-09-27 full scan showed
class 63 on nostore, fence, and store, 8/8 of those single trials, with
class 61 cold. That 8/8 is eight samples of the role, not a per-execution
rate. It does not show that this CPU or microcode never forwards a
store-buffer entry.

`MATRIX=1` aims `TRIALS` executions (default 64) at one slot per round, for
slots 21, 63, and 61, on nostore, fence, and store. A majority round is
`hits * 2 > TRIALS`. Repeatable in one process is `majority_rounds * 2 > ROUNDS`.
Either pre-registered sentence needs two processes. The negative sentence,
only if both runs have slot 63 repeatable on nostore and store and slot 61
repeatable on neither: in that sequence both arms show a signal consistent
with zero low six bits after the faulting load, and the canary class is not
observed. The positive sentence, only if both runs have slot 61 repeatable
on store and not on nostore: a signal consistent with class 61 after the
faulting load, with the store present as a condition, local to this
geometry, and not an origin claim. Two `MATRIX=1` processes on 2026-09-27
met the negative rule and not the positive one: slot 63 was repeatable on
nostore and store (8/8 majority rounds, 61..64 hits out of 64), slot 61 was
0/64 on both. `PROBE=1 SLOT=21` was 64/64 on fixed and dep in both processes.
That negative sentence is the `PROT_NONE` `#PF` sequence.

`NC=1` changes only the fault address, to non-canonical
`0x9876543214321000` plus the store's page offset. That is a `#GP`. The
oracle stride, the xor key, and the same two-process rule stay. A sentence
from `NC=1` is about that `#GP` sequence, not about the earlier `#PF` run.
Two `MATRIX=1 NC=1` processes on 2026-09-27 met the same negative rule:
slot 63 repeatable on nostore and store, slot 61 at 0/64 on both. The
positive sentence does not apply.

`VFLUSH=1`, `GADGET=ref`, and `NC=1` were each run twice. In every one of
those sequences slot 63 was repeatable on nostore and store and slot 61 was
0/64. The negative sentence applies to each sequence. The Hayik FalloutV1
binary on this host printed 40 of 41 characters of its own password through
a 4096-byte oracle and a last-hit recover. That output is not a class-61
rate.
No TSX only distinguishes this run from the paper's TSX variant.

## Batch 1 results (2026-09-27, CPU 1)

`git apply` reported success and left upstream `main.c`. Those identical
binaries were discarded. The numbers below are from `main-checks.c` copied
over `main.c`, built `-O0` except the one `-O2` line, pinned to CPU 1.

| build | leaked | bytes |
| --- | --- | --- |
| baseline | `MicroArchitecturalStoreBufferDataSampling` | 41/41 |
| case flip, three runs | `mICROaRCHITECTURALsTOREbUFFERdATAsAMPLING` | 41/41 |
| store `0x41` | 41 times `A` | 41/41 |
| no store | all `_` | 0 |
| offset `i*10+1` | all `_` | 0 |
| pre-touch | `_icroArchitecturalStoreBufferDataSampling` | 40/41 |
| case flip `-O2` | `H____CHITECTURALsTOREbUFFERdATAsAMPLING` | 37 |
| log | full password, `faults=41000`, one hit index per logged recover | 41/41 |

The earlier `ref-mirror` reload of class 2 is not a measurement of a forwarded
`0x42`. That byte touches `oracle + 0x42 * 0x1040`, a different line of the
same set from `oracle + 2 * 0x1040`. RIDL stays closed.

Stride only (`ref-checks/main-stride.c`), one run, CPU 1, `-O0`: the oracle
stride is `0x1040` in the touch and in the last-hit recover. `setjmp` and
the non-canonical base stay. The window is `setjmp`, `movzx eax`,
`imul eax, eax, 0x1040`, `maccess`. Leaked password 41/41.

`ref-rate`, two processes, same host: byte `0x41` at offset 200, one page
held for the whole run, `victim[0] = 0` before the loop. Slot 65
(the line `byte * 0x1040`) was not repeatable on store, 0/8 majority rounds
in both processes. Slot 0 was repeatable on nostore and on store, so set 0
does not separate the store from its absence. Slot 1 was 64/64 on both arms
and is discarded: it shares a set with slot 65, and the measurement load of
slot 65 heats it. Last-hit over 1000 trials can assemble the password from
a rare hit. A majority of 64 reloads under 150 cycles does not see that
line. The mirror stays `-O0`. Pre-touch drops the first byte and leaves the
other 40. Earlier zeros on slot 61 and on class 2 watched different loci
than the `byte * 0x1040` line: for byte `0x42`, class 2 shares that line's
L1 set (set 2) but not the line itself, and slot 61 of the VALUE key is a
different set altogether (61). The ABSENT sentences on those two loci are
not in the dossier. The line for byte `0x42` has not been shown hot. The
verdict on that cut was nits. RIDL stays closed. No store-buffer origin
claim.

`TIMES=1` on that store path, same one page: 16 of 64 slot-65 reloads were
under 150 (38..48). The other 48 were about 230..450, plus 934 and 1140.
The one slot-0 reload was 272. Slot 1 was not measured. 16/64 is not a
majority. A last-hit across 1000 trials can still catch those hits.

`TIMES=1 FRESH=1` is that store path with a new page on every attempt and
no write at offset 0. Slot 65: 62 of 64 reloads under 150 (36..46); the
first two were 594 and 244. The one slot-0 reload was 270. Fresh pages
move the same line from 16/64 to a majority. Page lifetime is the knob
between the long-lived page and the stride-only last-hit run.

`TIMES=1 FRESH=1 NOSTORE=1`: the same 64 reloads with no store. None of the
64 were under 150 (238..418, plus 1204). The one slot-0 reload was 276.
On a fresh page the exact line of `0x41` is hot with the store and cold
without it. No origin claim.

`FENCE=1` is the control between those two: one `mfence` between the store
and the fault, run as `TIMES=1 FRESH=1 FENCE=1`, two processes.
Pre-registered: if both runs drop slot 65 to about 0/64 (KILL), the sampled
value needs the un-drained store and the hot line does not survive the
store becoming globally visible. If both runs keep a majority hot
(SURVIVES), the hot line outlives the drained store and that sequence does
not support the store-buffer-entry reading. A mixed rate is not evidence
for either sentence. The `fence` arm in `fallout-oneshot.c` is not this
control: it runs on the long-lived `page_v` in the 64-class VALUE oracle,
where the store arm had no signal to kill (slot 61 was 0/64).

`LFENCE=1` is the same control with `lfence` in place of `mfence`: an
ordered delay that does not wait for the store to become globally visible.
Pre-registered for `TIMES=1 FRESH=1 LFENCE=1`, two processes: STILL-HOT if
both runs keep a majority hot (about 62/64; the mfence kill is then
specific to drain/global visibility, not to the added delay), DIES if both
runs read about 0/64 (distance alone can kill the rate in this sequence and
the mfence sentence stays sequence-local). A mixed rate is not evidence for
either sentence.

Result (2026-09-27, CPU 1, same build, two processes): `TIMES=1 FRESH=1`
reproduced the ceiling, 62/64 under 150 (hot reloads 104..126; the first two
1474 and 450; the one slot-0 reload 398). `TIMES=1 FRESH=1 FENCE=1` was
0/64 in both processes (first: 444..506 plus 1524 and 1774, slot 0 at 168;
second: 478..598, slot 0 at 500). The KILL reading applied on the fence
pair.

`LFENCE=1`, same build, two processes: also 0/64 in both (first: 446..558
plus 1314, 1636, 688, 624 and 1216, slot 0 at 528; second: 440..528 plus
1734, 642 and 882, slot 0 at 500). The pre-registered DIES reading applies:
an ordered separation that does not wait for store visibility also kills
the rate. The fence pair alone therefore does not separate drain from
distance; the fresh-page store must stand directly before the fault, and
the first ordered separation (lfence or mfence) closes the window. That
matches the recipe's -O0 adjacency requirement and the `-O2` control in
Batch 1; it does not by itself name the in-flight state that holds the
byte. The floor (no store, fresh page) stays 0/64.

The class-key binary (`fallout-oneshot.c`) got the same fresh-page knob and
was re-run the same day: `FRESH=1 VALUE=1 SLOT=61`, two processes, and
`FRESH=1 GADGET=ref VALUE=1 SLOT=61`, two processes (two of those runs were
repeated after the selftest geometry gate flaked at 152 and 166 cycles vs
the 150 threshold on a downclocked box; re-runs passed). Class 61 (low six
bits of the transient byte equal 2, the canary class) was 0/64 in all three
arms in all four runs, exactly as on the long-lived page. A paired control,
`FRESH=1 VALUE=1 SLOT=63` (low six bits 0, the zero-like arrival), read
64/64 on nostore and 56..64/64 on fence and store: the fault path still
delivers its zero-like value on fresh pages at full rate, so the detector
is alive and the store byte simply never reaches the index in that
sequence. Page lifetime, the knob that moves the byte-key line from 16/64
to a majority, does not revive the class key. The class-key detector stays
out of the dossier for the recipe's line (slot-61 hygiene note above);
these runs are a detector note, not a counter-example to the fresh-page
byte-key result.

Two more knobs went into `ref-rate.c` on the same day. `NOPS=<n>` (8, 32,
128, 512) inserts plain nops between the store and the fault, no fence
semantics; one process per n is a record and the boundary value gets a
second process before any sentence: if the rate stays near 62/64 up to 512
nops the mfence and lfence kills are about ordering semantics, not
distance; if it collapses at 8 or 32, plain distance closes the window.
`CLASSKEY=1` (TIMES only) swaps the byte index for the transform
`((b ^ 0x3f) & 0x3f) * STRIDE` and measures slot 62, the same transform
the class-key binary uses; two processes, `TIMES=1 FRESH=1 CLASSKEY=1` with
a `NOSTORE=1` control: slot 62 hot on store and cold on nostore means the
transform survives in this working sequence (and the class-key negatives
elsewhere come from that binary's other differences); slot 62 cold on store
means the transform itself removes the byte from the index.

Result, same build (2026-09-27, CPU 1). Nops sweep, one process per value,
boundary repeated: `NOPS=8`: 40/64 then 23/64; `NOPS=32`: 62/64 then 2/64;
`NOPS=128`: 0/64 twice; `NOPS=512`: 0/64 once. The no-knob ceiling on the
same build was 58/64 (62/64 twice earlier in the day). Plain distance does
kill the rate reliably at 128 nops and above, while 8..32 nops are unstable
across processes (2..62): the sample window in this sequence is short (tens
of cycles) and jitter-sensitive, so the mfence and lfence kills are
consistent with plain distance and are not provably about ordering
semantics alone. The 8..32 boundary needs a steadier box before a sentence;
today's runs had visible frequency drift (selftest flakes, hot values
90..150).

`CLASSKEY=1`, two processes (uncontrolled box): slot 62 was 0/64 on store
in both, reloads 160..202 (none under 150), and the `NOSTORE=1` control was
0/64. That pair was recorded as NEGATIVE at the time; it did not survive
the controlled re-run below (62/64 and 62/64 on store, 1/64 without), so
the pair was the artifact and that NEGATIVE reading is withdrawn.

The companion measurement was implemented the same day (CLASSKEY mode also
reloads slot 63, the zero-mode target of the transform, in the same
attempt): slot 63 hot with slot 62 cold means the touch still happens with
a zero-like value and the byte is what dies; both cold means no visible
touch in this configuration.

Evening batch on the uncontrolled box (same day, before the reboot): run
pairs flipped (62/64+64/64 then 0/64+0/64; ceilings 39, 0, 33, 49, 33/64
at 800 MHz, powersave). That batch was not usable and drove the controlled
re-run below.

Controlled re-run (2026-09-27 evening, after reboot): `performance`
governor, CPU3 offline, `intel_pstate` active, `clk_khz` logged (mostly
800000, once 3699793; the instantaneous read is not representative, the
conditions are). Ceiling x3: 63, 62 and 54/64. `CLASSKEY=1` x2: slot 62 =
62/64 and 62/64, companion slot 63 = 64/64 and 64/64; `NOSTORE`: slot 62 =
1/64, slot 63 = 64/64. The class transform survives in this sequence: the
store byte reaches slot 62 and needs the store, while the zero-mode touch
at slot 63 happens with and without it. `FENCE=1`, `LFENCE=1` and the
no-store floor re-read 0/64 each. `NOPS=8`: 13/64 then 62/64 (bistable
across processes), `NOPS=32`: 61/64 and 58/64, `NOPS=128`: 22/64 (0/64
twice before), `NOPS=512`: 0/64: small nop counts are a sub-cycle lottery,
not a clean distance window; large counts degrade the rate. The class-key
binary re-run on the same box, same hour: class 61 = 0 majority rounds on
all three arms on the fresh page and on the long-lived page (two processes
each), class 63 = 8/8 everywhere. So that binary's class-61 negative is a
property of its own sequence (PROT_NONE fault, poison, offset 0x40, -O2
asm), not of the box and not of the transform; bisecting it (NC=1,
`GADGET=ref`, offsets, canary) is the next cut if the thread is pursued.
Those last five words are kept for the record; the bisection was run and
closed below.

Bisection results (same controlled box, two processes per cut unless
noted). Class-key binary: `NC=1` 0/8 on all arms; `GADGET=ref` 0/8;
`CANARY=0x41` with slot 62 0/8; `OFFSET=0xC8` (offset 200 like ref-rate)
0/8, plus `GADGET=ref` at that offset 0/8 once. `ref-rate` with the new
`CANARY` knob measured the byte class on both values the same hour: canary
0x41 -> slot 62 = 62/64, 62/64, 63/64, 62/64 on store (four runs) and 1/64
without; canary 0x42 -> slot 61 = 62/64, 61/64, 58/64, 62/64 on store
(three runs) and 0/64 without. So value, class set, offset, fault type and
gadget are all cleared on both sides; the remaining axes are the code and
trap choreography: `ref-rate` is a `-O0` C sequence with `setjmp`/
`maccess`, the class-key binary is `-O2` monolithic asm with RIP-skip and
the `0x2a` poison. The three single-variable cuts that followed used the
controlled box, one variable per cut, two processes, `FRESH=1 VALUE=1
SLOT=61`: `-O0` alone, `-O2` with the `0x2a` poison removed (xor kept),
and `-O2` with `SETJMP=1` instead of RIP-skip (poison kept) each gave slot
61 at 0/64 on store, faults 64/64. None of the three moves class 61.

What still differs between the hot `ref-rate` class-key and the cold
class-key binary: (a) `setjmp` sits between the store and the fault in
`ref-rate`, while `SETJMP=1` places it before the store; (b) the oracle
touch in `ref-rate` goes through the out-of-line `maccess` call, the
class-key binary touches inline; (c) the faulting load is `movzbl` into
`eax` in `ref-rate`, `movb` into `al` (base register is the destination)
in the class-key binary; (d) the store is a C statement in `ref-rate` and
an asm instruction in the class-key binary; (e) the oracle arrays differ
in size (256 slots vs 64 classes) while the measured lines sit at the
same offset. Queue, one variable per cut: inline the `maccess` touch in
`ref-rate`; a `ref-rate`-shaped C attempt cloned into the class-key
binary; then the load width. New knobs: `ref-rate` takes `CANARY=<hex>`,
the class-key binary takes `OFFSET=<hex>`, `NOPOISON` is a compile flag,
`SETJMP=1` selects longjmp, `INLINE_ACCESS` builds the inline-touch
`ref-rate-inline`, `CSEQ=1` selects the cloned attempt.

Cut (a) and (b) results (controlled box, 2026-09-27 evening). (a)
`ref-rate` with the `maccess` touch inlined (`ref-rate-inline`,
`-DINLINE_ACCESS`): class-key slot 62 = 62/64 in both processes with the
usual companion 63 = 64/64; the out-of-line call is not what makes
`ref-rate` hot. (b) `CSEQ=1` clones the `ref-rate`-shaped attempt into the
class-key binary (C store, `setjmp` between store and fault, C index, call
touch, longjmp handler): with the no-access fault slot 61 stayed 0/8 three
times; with the non-canonical fault (`NC=1`) the same clone read slot 61
at 8/8 majority rounds in four of five processes (offsets 0x40 and 0xC8
alike), with occasional cold processes in between; `NOSTORE=1` read 0/8
and canary 0x41 with slot 62 read 8/8, 4/8 and 0/8 in three processes. The
process-level outcome is bimodal, so this is not yet a rate. Stock arms
with `SETJMP=1` and `NC=1` stayed 0/8 twice: the clone shape and the
non-canonical fault are both needed, and which stock-arm property
suppresses the signal (poison, `MISS_BLOCK`, the `vf` branch, RIP-skip,
the asm store, the setjmp placement) is the next bisection. The class-key
binary can be made to pop; `ref-rate`'s stable 62/64 stays the clean
positive.

Rate estimate on the hot base (10 processes each): `NC=1` slot 61
repeatable in 8 of 10 processes (8/8 rounds in the hot ones); `PROT_NONE`
0 of 10. The process-level outcome is bimodal, so a per-process rate is
the wrong form for it.

Suppression bisection, corrected (same box, one build per batch; the
initial reading did not survive the rebuild): on the current build,
`CSEQ+NC` as the hot base read `CSEQ_BLOCK=1` 8/8 and 7/8, `CSEQ_ASMSTORE`
7/8 and 8/8, `CSEQ_RIP=1` 8/8 in all ten processes and `CSEQ_SJFIRST=1`
8/8 in all ten; `CSEQ_FENCE=1` and `CSEQ_LFENCE=1` read 0/8 twice each,
`NOSTORE=1` 0/8 twice, `CSEQ` with the no-access fault 0/8 in ten
processes, and the stock VALUE arms with `NC=1` 0/8 twice. On the previous
build `CSEQ_RIP` and `CSEQ_SJFIRST` had read 0/8 twice; those readings are
withdrawn as build artefacts: a cosmetic rebuild (an added no-op barrier
call and a longer log line) flipped both to hot. So the class-key
arrangement that pops is wide (store, then `setjmp`, then the
non-canonical fault, longjmp, any of the tested recovery shapes), the
robust killers are the barrier, the missing store and the no-access fault,
and the stock arms stay cold across builds; the remaining candidates were
the `movb`-into-`al` load shape (the base register is the destination) and
the asm index chain; both were then added to `CSEQ` on the next build and
both stayed hot (`CSEQ_LOADAL` 8/8 twice, `CSEQ_ASMCHAIN` 8/8 twice, base
8/8 twice and stock arms 0/8 twice on that build). The suppressor is FOUND
(2026-09-27, builds `211c7846` then `758a23f7`; logs
`addback-run-20260927.txt`, `addback-recheck-20260927.txt`,
`nop-run-20260927.txt`). Adding the remaining stock properties to `CSEQ`
one at a time: `CSEQ_VF` (test/jz + conditional clflush before the store)
6/6 hot with one 3/8 regime dip; `CSEQ_PROLOGUE` (skip_to lea/mov before
the block) hot with one rc=1 selftest flake and one 1/8 dip; `CSEQ_VADDR`
(fault address depending on the victim byte) 8/8 twice; and `CSEQ_POISON`
(`movb $0x2a, %al` right before the faulting load) 0/8 six times on
`211c7846` and 0/8 twice on `758a23f7`. A NOP in the poison's place does
not suppress (`CSEQ_NOPPRE`, `758a23f7`, 8/8 twice), so the killer is not
the extra instruction. The follow-up trio (build `ce5d5c07`) refines it:
`CSEQ_POISON_FULL` (a full-width `movl $0x2a, %eax` before the load) is
ALSO 0/8 twice, while `CSEQ_POISON_OTHER` (the same partial write to `dl`)
and the NOP are both 8/8 twice: the suppressor is any preceding write to
the faulting load's DESTINATION register (full or partial) -- with a fresh
writer in flight at the destination, the dependent chain consumes 0x2a
(class 21), not the transient byte. Results are per-build: log the build
with every contrast.

Companion artifact, withdrawn reading: in CLASSKEY mode the companion slot
63 sits one 0x1040 stride above the primary slot and is preheated by the
hardware stride prefetch: with the primary at 62 it reads 63..64/64 hot
with and without the store, with the primary at 61 it reads 9..30/64. The
"zero-mode touch always hot" reading is withdrawn; a companion must use a
non-adjacent slot. The same stride pattern flags the one-trial-per-class
full-scan VALUE runs (sequential 0x1040 walks) as suspect for prefetch
preheating.

An accessed-bit assist (present attacker page, `clear_refs`, the load
retires) was a separate binary. Its hot zero is the architectural byte, not
evidence of a transient gadget. PROT_NONE logs with the blocker at offset 0
and the victim byte at offset 7 aliased oracle class 0, so their hot class 0
is not a forwarded zero either. The retirement race remains a hypothesis.
That 2026-09-27 assist run is superseded by `TRIGGER=assist` below: it was
confounded twice over (offset 7 and the blocker at offset 0 are both L1 set
0, and the run had no witness that the accessed bit ever cleared), so it was
never a negative -- it was VOID.

Rate regime (bimodality), measured 2026-09-27 on binary md5
`9e4a88968c08611fbcddd6c79c8b988e` (`CSEQ=1 NC=1 SLOT=61 FRESH=1`,
`taskset -c 1`; scripts `bimodal-*.sh`, logs `bimodal-*-20260927.txt`):

| series | gaps | n | verdicts | per-round hits (of 64) |
|---|---|---|---|---|
| tight | ~1.5 ms | 20 | 19x 8/8, 1x 5/8 | 22..64 |
| short | 50 ms | 10 | 10x 8/8 | 44..63 |
| gap | 5 s | 10 | 7x 8/8, 4/8, 6/8, 0/8 | 15..63 |
| warm | 5 s + 50 ms spin | 10 | 10x 8/8 | 39..64 |
| long | 5 s, ROUNDS=32 | 5 | 5x 32/32 | 53..64 |

- The class-61 rate per execution swings between ~0% and ~100% across
  processes: typical cold ~25..45%, typical hot 85..100% (the late-session
  series read 61..64/64). One B3b process read 0/512 executions (0/64 in
  all eight rounds) while the next nineteen read 61..64/64: the state
  flips, the channel returns. Low-rate processes start low and stay low or
  ramp within the run (34 38 39 36 43 43 48 49); high-rate processes read
  55..64 from round zero. The same 5 s-idle regime later produced 5x 32/32
  all-hot, so the low-rate state is intermittent system state, not a
  deterministic idle-time effect.
- No timing witness explains it: the clock is full in every process
  (`timing:` hot=32..36 at process start, including the 0/8 process), and
  DRAM latency is anti-correlated with rate (0/8 process cold=320; an
  all-hot 32/32 run cold=772). Clock and DRAM state are not the variable.
- Methodology consequence: a single process started after idle can read
  30..50%; measure in bursts, pre-warm, vote per round and report rates.
  The two-run rule applies to sentences; these series hold the regime
  together with the numbers.

Root probes (B3), same build, perf 7.1.5 installed (`b3-perf.sh`, log
`b3-probe-20260927.txt`; 10 processes, 5 s gaps):

| run | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| maj | 8/8 | 8/8 | 8/8 | 8/8 | 0/8 | 8/8 | 8/8 | 8/8 | 8/8 | 8/8 |
| avg hits/64 | 57 | 57 | 60 | 60 | 20 | 54 | 58 | 60 | 59 | 63 |

- Run 5 is the cold process (0/8, hits 13..28/64, ~30%). Its counters are
  indistinguishable from the hot runs: cycles 12.14M (hot 12.02..12.39M),
  instructions 14.44M (14.43..14.48M), machine_clears.memory_ordering 533
  (454..574), elapsed 3.77 ms (3.71..3.87 ms); average core clock from
  cycles/elapsed ~3.22 GHz in both. Same work, same clock: no frequency,
  no serialization, no extra clear event in the low-rate state.
- l1d.replacement is the only outlier: 146,283 in the cold run, the
  maximum of the set (hot 135,308..143,120), but it does not track rate
  across the hot runs (run 6 at 84% has the second-lowest count), so it is
  recorded as an observation, not a cause.
- The msr-freq APERF/MPERF min/max numbers are unusable as delivered: the
  sampler window (60 ms around a ~4 ms run) is dominated by idle time and
  MPERF behaviour during idle distorts the ratio (max reads 4.7..7.4 GHz).
  Cycles/elapsed from perf already answer the clock question.

B3b, extended fill-buffer/MLP counters (same regime, `b3b-perf.sh`, log
`b3b-probe-20260927.txt`; events l1_hit/l1_miss/fb_hit/
l1d_pend_miss.pending/l1d.replacement): run 1 read 0/512 (0/64 in all
eight rounds -- the most extreme cold process so far), runs 2..20 read
61..64/64. Every counter of the cold run sits inside the hot ranges
(l1_hit 3.70M, l1_miss 46.8k, fb_hit 38.3k, pend 2.35M, instructions
14.49M). The only deltas -- cycles +2.3% (12.60M vs max hot 12.31M) and
seconds at the top edge -- are exactly what a few hundred extra reload
misses cost when the deposits fail: consequences of the cold outcome, not
a signature.

Deposit hunt (2026-09-27, build `1c970839`, `scan-hunt.sh`, log
`scan-hunt-20260927.txt`): `CSEQ_SCAN` adds a clean pre-round 64-class scan
per process (a post-round scan was tried first and withdrawn -- the rounds'
own deposits contaminated it). 25 gap-regime processes all read 8/8 hot
(61..64/64): the cold state did not return that evening (83 consecutive hot
processes across the late series); the hot-process pre-scan reads best=61
with 1..3 classes under threshold and fixes the baseline. The tool is in
place: fire `scan-hunt.sh` when a cold window returns and it will show
whether the deposit landed on another class or nowhere. A second 25-run
refire (log `scan-hunt2-20260927.txt`) was all-hot again: the cold window
did not return that evening (~110 consecutive hot processes).

Sibling/uncore contrast (2026-09-27, build `211c7846`, `bimodal-sibling.sh`
and `bimodal-sibling2.sh`; logs `bimodal-sibling-20260927.txt`,
`bimodal-sibling2-20260927.txt`): the gap regime with cpu0 idle vs a cpu0
spinner read 10x 8/8 (hits 51..64) vs 9x 8/8 + one 7/8 (~40%). The
interleaved retest (12 A/B pairs inside one timeline) read 24x 8/8 with
hits 62..64 in BOTH arms -- late-session rates had drifted to the ceiling.
No cold process appeared in either phase, so cpu0 load does not by itself
move the class-61 rate; the cold state stayed absent and the contrast
remains untestable for it.

Cross-context attempts (stage D), same build md5 `9e4a88968c08611fbcddd6c79c8b988e`:

- D1 sibling, concurrent (`d1-cross.sh`, log `d1-cross-20260927.txt`):
  `mds-victim` hammers 0x42 through clflush+load on cpu2 (~11M iter/s)
  while the NOSTORE attacker samples on the sibling cpu0. Six processes
  0/8, per-round hits 0..1/64 — identical to the no-victim control
  (0..1/64). Wrong-value victim (0x43) and the cpu2-victim/cpu1-attacker
  control also read the floor. Attacker WITH its own store under the same
  victim load: 8/8, hits 43..56 (bench alive). No cross-SMT signal in
  this shape.
  (Honest note: the phase meant as victim-on-other-core ran with the
  victim still on cpu2 — `mds-victim` pins itself to its default cpu2 and
  overrides the shell's `taskset -c 1`; the banner in the log says
  `cpu=2`. The no-shared-core contrast is the cpu2-victim/cpu1-attacker
  control in D2 instead.)
- D2 same-CPU residual (`d2-residual.sh`, log `d2-residual-20260927.txt`):
  a 300 ms victim burst on cpu1 exits, the attacker starts immediately
  after on cpu1 with NOSTORE. Modes store+clflush+load, store-only and
  clflush+load: 18 processes, every round 0/64 (single stray 1/64),
  same as the controls. The kernel's clear-on-switch attempt plus buffer
  turnover leave nothing the faulting load can name at this gap scale.
- D3 same-CPU time-sharing (`d3-pingpong.sh`, log
  `d3-pingpong-20260927.txt`): victim and attacker both runnable on cpu1
  (victim in store+yield mode, then store-only), so the scheduler
  alternates them at slice granularity and the attacker samples right
  after every switch-in. 17 processes: every round 0/64 except single
  stray 1/64s, identical to the floor arms before and after. The
  no-shared-core arm (victim on cpu2) is at the floor too.
- D4 frozen-victim alternation (`d4-stop.sh`, log `d4-stop-20260927.txt`):
  the victim is SIGSTOPped (not exited) while each attacker run samples,
  removing the exit-path teardown between the victim's last stores and the
  attacker's loads. 15 attacker runs at the floor (0/8), store sanity 8/8
  twice, floors 0/8.
- Summary: the class-61 primitive reproduced here is strictly same-thread
  (own store, own fault, ~us window). All four cross-context shapes tested
  (sibling concurrent, post-exit residual, same-CPU time-shared switch-in,
  frozen-victim alternation) read the NOSTORE floor on this box/microcode;
  the clear-on-switch attempt and buffer turnover leave nothing the
  faulting load can name.

## Non-faulting triggers (2026-09-28), build md5 `41bfb756804cf1f5bbe6a08af6d10018`

Three shapes were added to the one binary, so every contrast below shares a
build: `TRIGGER=assist`, `TRIGGER=demand` (the load retires, no SIGSEGV) and
`SPEC=1` (a mispredicted branch, the load never faults and never retires).
`NC=1` is kept as an alias for `TRIGGER=noncanon`, so every earlier log keeps
its meaning.

Build discipline for this change, because a cosmetic rebuild has flipped arms
here before: rebuilding the unchanged source reproduced `1c970839` byte for
byte, so the toolchain is deterministic and any later difference is caused by
the edit. After the edit, `leak_cseq` (166 insns), `measure_slot`,
`maccess_line`, `scan_round`, `attempt` and `cseq_store_canary` are identical
modulo relocations. The `REPRODUCE.md` §4 control table was re-run on the new
build before any new number was recorded: base 10/10 processes at 8/8,
`NOSTORE` 0/8, `CSEQ_FENCE` 0/8, `CSEQ_LFENCE` 0/8, `CSEQ_POISON` 0/8,
`CSEQ_NOPPRE` 8/8, no-`NC` PROT_NONE 0/8 -- every cell as recorded.

### Trigger table

| trigger | kind | faults | class 61 | class 63 |
|---|---|---|---|---|
| `noncanon` `#GP` | fault | 512/512 | **8/8** | -- |
| `protnone` `#PF` | fault | 512/512 | 0/8 | -- |
| `demand` `#PF` not-present | fault, resolves | 0 | 0/8 | 8/8 |
| `assist` (accessed bit) | no fault | 0 | 0/8 | 8/8 |
| `SPEC` + `noncanon` | no fault | 0 | **8/8** | dark |
| `SPEC` + `present` | no fault | 0 | 0/8 | 8/8 |
| `SPEC` + `protnone` | no fault | 0 | 0/8 | dark |

### Arm A, assist and demand: NEGATIVE (`assist-run-20260928.txt`)

`TRIGGER=assist` maps `page_atk` present and calls `madvise(MADV_COLD)` before
every attempt, so the load takes a microcode accessed-bit assist and retires.
`TRIGGER=demand` uses `MADV_DONTNEED`, so the load takes a demand-zero minor
`#PF` that the kernel resolves. Two processes per cell, and every process
prints its own witness.

Both read the pre-registered NEGATIVE: class 63 repeatable 8/8 on store AND
nostore (the retiring load's own `0x00` reaching the oracle -- the liveness
control), class 61 at 0/8 on store, nostore, fence and lfence, `faults=0`
throughout, and the stock hot base 8/8 twice on the same build. On this build
and geometry, neither non-SIGSEGV path produces the canary class; what is
observed is the retiring load's own zero byte. This says nothing about the
`#GP` arm.

The witness is the load-bearing part, and it is why the 2026-09-27 assist run
is withdrawn rather than counted. `clear_refs` and `MADV_COLD` both skip the
shared zero page (`vm_normal_page()` returns NULL), so a freshly `mmap`'d
anonymous page that has only ever been READ cannot have its accessed bit
cleared at all: the advice is a no-op, no assist happens, class 63 goes hot,
class 61 stays cold, and the run looks like a clean negative while measuring
nothing. `page_atk` is therefore `memset` at setup, and `trig gate:` checks
per process that the advice cleared exactly one page (`Referenced:` 12 -> 8
-> 12 kB; deltas, because the kernel merges the mapping into a larger VMA) and
that the minor fault count moves the right way -- 0 for assist, 1 for demand,
which also stops a reclaimed page from passing as an assist. A run without
that witness is VOID, not negative.

### Arm B, misprediction: POSITIVE on noncanon (`spec-run-20260928.txt`)

`SPEC=1` replaces the fault with a Kocher bounds-check bypass ported from
`labs/foreshadow/harness/mispredict_gadget.h`, shimmed onto this binary's own
`maccess_line`/`reload_time` rather than `libsgxstep/cache.h`. The gate is
enforced in-process before any scoring, because the misprediction rate is
state-dependent: leg 1 plants `0x42` architecturally with the store off and
must recover class 61; leg 2 plants `0x00` and must give class 63 with class
61 at the floor. **Every process in every run passed the gate at c61 = 64/64
on leg 1 and c61 = 0/64 on leg 2** -- the ported gadget is exact in this
binary and the class-61 false-positive rate is zero.

Results, two processes per cell:

- `SPEC_TARGET=noncanon`, slot 61: **8/8 and 8/8 with the store**, 0/8 and 0/8
  with `SPEC_STORE=none`. Also 8/8 twice with `SPEC_VFLUSH=0` and 8/8 twice
  with `SPEC_DELAY=400`.
- `SPEC_STORE=early` (same store, earlier in the inner loop): 0/8 twice.
- `SPEC_TARGET=present`, slot 61: 0/8 twice, while slot 63 is 8/8 twice. The
  shadow path is demonstrably live and the canary class still never appears.
- `SPEC_TARGET=protnone`: 0/8 twice, class 63 dark as expected.
- Stock hot base on the same build: 8/8 twice, before and after.

No `stray_fault` verdict was printed in any run, so the branch was never
architecturally taken and the shadow load never faulted.

**Value-swap test (`spec-swap-20260928.txt`), the decisive control.** A
store-conditioned hot class could still be positional. Swapping the canary
moves the hot class with it:

| | slot 61 | slot 27 |
|---|---|---|
| `CANARY=0x42` | **8/8** | 0/8 |
| `CANARY=0x24` | 0/8 | **8/8** |

with all four `SPEC_STORE=none` floors at 0/8. `0x24 ^ 0x3f = 27`, which is
not 0, 1, 3, 47, 48 or 63 and is not adjacent to 61, so neither the excluded
sets nor the `+0x1040` stride preheat can carry it.

What this shows, kept narrow: the VALUE of a store reaches the dependent chain
of a load that never faults and never retires, with the store as a necessary
condition, on the non-canonical target, local to this geometry and this build.
It is not a store-buffer ORIGIN claim -- the swap proves value-keying, not
which microarchitectural structure supplied the byte -- and it does not
discriminate partial store-to-load forwarding from MDS. That `SPEC_STORE=early`
is at the floor while `late` is 8/8 is consistent with a residency window
rather than a static artifact, and is recorded as such.

**This contradicts nothing in the Foreshadow record, and is not the same
question.** `l1tf-mp-probe.c` measured that L1TF does NOT forward in the
misprediction window on this silicon, and that stands: it is a statement about
the terminal-fault forward. The store-forward measured here is a different
mechanism and answers the other way -- for this leak the fault is NOT
required.

**Caveat on bench state.** These runs were taken with the `powersave` governor
and CPU3 online, not the documented bench (`performance`, CPU3 offline). The
clock witness is in every log line (`hot` 30..38, i.e. the core was ramped;
two early gate runs at `hot` 70..74 were the 800 MHz idle state and are
superseded). All contrasts are internally consistent and the control table
passed, but a confirmation pass in the documented bench state is the obvious
next step and needs root.

### Confirmed on the documented bench (2026-09-29), same build

The 2026-09-28 caveat is closed. Bench restored to what `REPRODUCE.md`
describes: governor `performance`, CPU3 offline, so `cpu1`'s
`thread_siblings_list` is just `1` and there is no SMT traffic on the
measuring core. (`cpupower` is not installed on this host; the governor was
set by writing `scaling_governor` directly. `scaling_cur_freq` still reads
800000 at idle because `intel_pstate` reports the real frequency -- the
witness that matters is that a cold `SELFTEST=1` now reads `hot=34` five
times out of five with no pre-warm, against 90..126 under `powersave`.)

Every cell reproduced, `hot` 34..36 throughout (`bench-confirm.sh`,
`bench-confirm-20260929.txt`):

- stock hot base 8/8, twice before and twice after the pass;
- `SPEC_TARGET=noncanon` slot 61 with the store: **10/10 processes at 8/8**
  -- this is also the >=10 process burst that was queued, and the rate is at
  the ceiling, unlike the CSEQ base which shows the documented bimodality;
- floors: `SPEC_STORE=none` 0/8 three times, `SPEC_STORE=early` 0/8 twice;
- `SPEC_TARGET=present` slot 61 0/8 twice with slot 63 at 8/8 twice (live
  shadow path, no canary class); `protnone` 0/8 twice;
- value swap 2x2 exactly as before (`0x42` -> 61 hot / 27 cold, `0x24` -> 27
  hot / 61 cold), all four `SPEC_STORE=none` floors 0/8;
- `assist` and `demand`: slot 61 0/8, slot 63 8/8, gate PASS in every run.

Nothing moved between the two bench states, so the 2026-09-28 numbers stand
as recorded and the powersave/CPU3-online caveat on them is withdrawn.
