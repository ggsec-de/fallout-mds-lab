# Interpretation notes — 2026-09-29

These notes take precedence over conflicting historical statements in EXPERIMENTS.md, REPRODUCE.md, or source comments. The first pass came from source and saved-log review; the CSEQ poison item was then resolved by a hardware run on 2026-09-29 (build `89b604d2b79db9556074e5d27dc18a19`; logs `poison-deconf-20260929.txt`, `poison-gran-20260929.txt`) -- see the resolution section. Recorded result files were not changed; the harness gained three knobs.

## CSEQ poison controls change the address

In `leak_cseq`, the poison variants pass `atk` using the `"a"(atk)` constraint. The address is therefore in RAX. Writing `0x2a` to AL before `movb (%1), %al` changes the address low byte, including its page offset. Writing `0x2a` to EAX zero-extends into RAX and changes the address to canonical `0x2a`.

These tests change both destination-register state and the load address; the full-width variant also changes the fault shape. Suppression remains a recorded observation, but a destination-register-only cause is not established. This does not invalidate the separate SPEC value-swap observation.

## Resolution: poison deconfound (2026-09-29, hardware run)

The address-preserving controls were added to `fallout-oneshot.c`
(`CSEQ_POISON_KEEP`, `CSEQ_POISON_FULL_KEEP`, `CSEQ_LOADOFF=<hex>`) and run
on the documented bench, two processes per cell (build
`89b604d2b79db9556074e5d27dc18a19`).

- Destination-register write with the address preserved: 8/8, 8/8 (`al`)
  and 8/8, 8/8 (`eax`), hits 62..64/64. The write does not suppress; the
  "destination-register suppressor" reading is withdrawn.
- Load offset moved alone (store stays at 0x40): 0/8, 0/8 at 0x2a and
  0/8, 0/8 at 0x41 (one byte off, same line). The offset change alone
  reproduces the cold.
- Store and load moved together to 0x2a: 8/8, 8/8; with the write added,
  8/8, 8/8.
- Match granularity: 0x41 (one byte off) 0/8, 0/8; 0x1040 (+1 page, same
  page offset) 8/8, 8/8; 0x80 0/8, 0/8.

Corrected sentence: on this build and geometry the class-61 signal needs
the faulting load at the STORE'S PAGE OFFSET, byte-precise in the low 12
bits; bits above bit 11 do not participate. The original poison arms were
cold because the al write rebased the load's offset from 0x40 to 0x2a (and
the eax write additionally replaced the fault shape with a #PF). The
class-21 reading ("the chain consumes 0x2a") is refuted: class 21 stays
0/8 on both arms. Which structure does the low-12-bit match is an open
question (a store-buffer partial-address match is a candidate, not an
origin claim).

## Majority results are not exact success rates

The 29 September log retains majority summaries, not per-round hit vectors. `8/8` means each round exceeded 32 hits in 64 attempts. It does not establish a 100% per-attempt ceiling. Each SPEC attempt includes five malicious-index invocations, so SPEC and CSEQ attempts are different units.

## Evidence scope

- The oracle masks to six bits. A class is not a unique full byte.
- The value swap supports store-value dependence, not unique identification of a store-buffer source.
- Cross-context tests were at background level. Buffer clearing and turnover are possible explanations, not causes isolated by these tests.
- Page-reference and minor-fault checks strengthen the assist/demand setup, but do not directly count internal microcode assists.
- Statements that all mitigated machines must produce zero were not established by a mitigated/unmitigated comparison in this lab.
- Initial reference-demo string results are reported in the notebook; their full Batch 1 raw output is not included among the top-level archived logs.

The primary achievement remains a repeatable, store-conditioned, value-keyed class signal on the tested SPEC/noncanonical path without an architecturally delivered exception.
