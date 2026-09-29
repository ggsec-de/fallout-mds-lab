# GitHub publication guide

Suggested repository name: `fallout-mds-lab`

Suggested GitHub description:

> Educational Fallout/MDS lab on Skylake: reproduction, speculative execution experiments, measurement controls, and documented results.

Suggested topics: `cpu-security`, `microarchitecture`, `transient-execution`, `side-channel`, `mds`, `fallout`, `security-research`, `educational`.

## Recommended upload

Create a standalone repository from the **top-level files in this `labs/mds` directory**, keeping their flat layout. This includes the public README, historical notebook, review notes, reproduction guide, five C sources, Makefile, scripts, and dated evidence logs. Keep the historical record with the project so readers can inspect unsuccessful experiments too.

Do not upload the entire parent CPU workspace. The exact top-level selection is listed below.

## Small initial version

If you prefer a shorter first release, include these files. Bare `make` needs all five C sources in this list; the README's `make fallout-oneshot` builds only the main harness.

```text
README.md
EXPERIMENTS.md
REVIEW_NOTES.md
REPRODUCE.md
PUBLISHING.md
Makefile
fallout-oneshot.c
ref-mirror.c
ref-rate.c
mds-victim.c
msr-freq.c
bench-confirm.sh
bench-confirm-20260929.txt
spec-run.sh
spec-run-20260928.txt
spec-swap.sh
spec-swap-20260928.txt
assist-run.sh
assist-run-20260928.txt
```

The small version preserves the main positive and its controls, but omits files named in the historical notebook. Include the complete top-level set for a fully inspectable research archive.

## Portability

The main harness is self-contained. The series scripts preserve the original absolute working directory `/home/detox/CPU/labs/mds` and CPU assumptions. Before running one on another machine, adapt its `cd` line and verify its CPU selection against the local topology. These scripts are archived experiment recipes, not a portable installer. The README includes direct commands that work from the checkout directory.

`perf` is needed by the optional PMU scripts. MSR diagnostics use `/dev/cpu/*/msr` and require appropriate access; they are not prerequisites for the basic SPEC test. The historical build hash identifies the recorded binary, not a guarantee that a rebuild with another toolchain produces it.

## Leave out of the initial upload

- `ref-checks/`: separate reference-demo modifications requiring an external FalloutV1 checkout and `cacheutils.h`; not needed by the core harness. Establish the exact upstream version and applicable terms before distributing those copies.
- Compiled executables, object files, core dumps, generated disassembly, temporary output, and editor settings.
- Parent-directory `tasks/`, agent instructions, unrelated labs, private machine configuration, or credentials.

Do retain the dated `.txt` evidence files. Do not blanket-ignore `.txt` files.

## Attribution and licensing

The README links the original paper, reference demo, and acknowledged cache-utility project. No LICENSE/COPYING file was found in the inspected local lab. The inspected upstream repository root did not present a license file; this is not a completed audit of every upstream directory or dependency.

No blanket license has been added or inferred. Choose terms for original contributions and retain applicable notices for borrowed material. Excluding `ref-checks/` does not by itself complete a provenance review of the remaining sources.

## Exact full top-level selection

The following manifest was checked against this directory during preparation. Publish these files at the new repository root; no subdirectory relocation is required.

```text
addback-recheck-20260927.txt
addback-recheck.sh
addback-run-20260927.txt
addback-run.sh
aslr-run.sh
assist-run-20260928.txt
assist-run.sh
b3-perf.sh
b3-probe-20260927.txt
b3b-perf.sh
b3b-probe-20260927.txt
bench-confirm-20260929.txt
bench-confirm.sh
bimodal-gap-20260927.txt
bimodal-gap.sh
bimodal-long-20260927.txt
bimodal-long.sh
bimodal-run-20260927.txt
bimodal-runs.sh
bimodal-short-20260927.txt
bimodal-short.sh
bimodal-sibling-20260927.txt
bimodal-sibling.sh
bimodal-sibling2-20260927.txt
bimodal-sibling2.sh
bimodal-warm-20260927.txt
bimodal-warm.sh
cold-census.sh
d1-cross-20260927.txt
d1-cross.sh
d2-residual-20260927.txt
d2-residual.sh
d3-pingpong-20260927.txt
d3-pingpong.sh
d4-stop-20260927.txt
d4-stop.sh
EXPERIMENTS.md
fallout-oneshot.c
Makefile
mds-victim.c
msr-freq.c
nop-run-20260927.txt
nop-run.sh
p-mech-run-20260927.txt
p-mech-run.sh
PUBLISHING.md
README.md
ref-mirror.c
ref-rate.c
REPRODUCE.md
REVIEW_NOTES.md
scan-hunt-20260927.txt
scan-hunt.sh
scan-hunt2-20260927.txt
scan-runs-20260927.txt
scan-runs.sh
spec-run-20260928.txt
spec-run.sh
spec-swap-20260928.txt
spec-swap.sh
```
