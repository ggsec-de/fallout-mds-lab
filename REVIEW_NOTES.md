# Interpretation notes — 2026-09-29

These notes take precedence over conflicting historical statements in EXPERIMENTS.md, REPRODUCE.md, or source comments. They come from source and saved-log review, not a new hardware run. Source and recorded result files were not changed.

## CSEQ poison controls change the address

In `leak_cseq`, the poison variants pass `atk` using the `"a"(atk)` constraint. The address is therefore in RAX. Writing `0x2a` to AL before `movb (%1), %al` changes the address low byte, including its page offset. Writing `0x2a` to EAX zero-extends into RAX and changes the address to canonical `0x2a`.

These tests change both destination-register state and the load address; the full-width variant also changes the fault shape. Suppression remains a recorded observation, but a destination-register-only cause is not established. A control retaining the address in a separate register would be needed to isolate that question. This does not invalidate the separate SPEC value-swap observation.

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
