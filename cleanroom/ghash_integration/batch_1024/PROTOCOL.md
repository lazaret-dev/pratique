# Fixed batch: 20 VMs, two paired GHASH trials per VM

This user-authorized regression batch fixes twenty default Ubuntu 24.04 native
x86 jobs, at most five concurrently, fail-fast disabled. Every VM has two trials:
sealed original GHASH test1 -> focused DATA1024 controls1 -> sealed original
GHASH test2 -> focused DATA1024 controls2. Both linear focused reports follow
all four native phases. No first outcome suppresses the next valid stage.
There are forty paired trials / eighty planned native child slots. Setup,
timeout and partial/missing outcomes remain explicit. No replacement, model
selection, retry, stop on a signal or hidden third trial. No Rust, crypto, API,
dependency, lifecycle, seeds, clock, crop, confirmation or threshold change.
The A+B0 diagnostics stay local/deferred, and PR10 stays e2dd/HOLD.

The original authority is the existing exact ignored selector
`crypto::timing::ghash_multiplication_is_constant_time`, eight internal GHASH
comparisons with the original fresh-input confirmation policy and three-second
budget. This is not a broader crypto suite. Its binary SHA is
15b3f3e3dba2ce5faa4137e8c8346280fa60e4ba55d06b9a0f90e7a538895256,
from artifact13657075157, 481087129-byte ZIP SHA
08f96335668f5f4ab67b2fad10f5c9b275bd1558d9d976f3e99f8dabece6ab40.
The unchanged existing run_case normal helper records the original stdout,
initial and fresh reports, full final failure summary, footer and child exit.
Exit101 with all eight rows, proper rechecks/final summary and failed one-test
footer is an expected timing finding, not a collector error. Rounded printed
t-values cannot support exact original-judge replay; confirmation comes only
from that unchanged final summary. H128, H0/ones, DATA and prepared-H 1024/2049
rows stay distinct. Unconfirmed first flags/rechecks are retained.

Every original is followed by the unchanged focused DATA1024 selector, ungated,
even when original child exit is0/101, original collection is incomplete, or
the preceding focused/control-health result fails, provided immutable staging,
source, core and process cleanup remain valid. It retains all five rows × two
seeds × three seconds, negative/matched-positive/sensitivity/early-exit controls
and the existing 1.5–2.5% final calibration band. Its d8a2... ELF and0ec7... probe
come from the already reviewed artifact13685577428, 115643042-byte ZIP SHA
316b529d8fbcdcaa358b091ffe352ea8fd81aee99385db2fbd8e6fb725c1a144.
The complete hashes and original thirteen source inputs remain in the unchanged
focused frozen_identity.json. New identity.json pins the five unchanged focused
files at f1dff4a5 separately from each new coordinator/job head. Artifact source
head664 and production source e2dd are never substituted into GITHUB_SHA.

Both archives download once per VM. The coordinator picks one allowed logical
CPU once. It prepares both repeat directories before the native window using
separate unchanged focused.py subprocesses, per-trial RUNNER_TEMP/archive
hardlinks (copy fallback) and disjoint output directories. The same selected
CPU is inherited via taskset and asserted in both prepared settings and native
cases. Original and focused binaries/probe are rehashed before use. The new
matrix variable1–20 is separate from unused legacy helper variables1–3.
The full initial affinity is retained; a hypervisor can hide physical topology
and reuse physical hosts. Two trials on one VM are correlated. Identical public
seed prefixes across executions are intentional, not forty new independent
fixtures or physical CPUs. Raw export/fixture validation inherent in the
frozen binaries remains; new linear CSV reports run only after all native work.

Each owned Python subprocess gets its own process group. Wrapper-level timeout
terminates then kills that group, including the ELF grandchild, before another
native phase can start. Cleanup failures are explicit and invalidate further
native execution rather than overlap measurements. Raw files and partial phase
records are preserved. Trial2, both reports, VM summary and one unique artifact
per VM use unconditional workflow steps. Summary/report failure never deletes
earlier data. Source-only fixtures exercise failure continuation, path/env/core
isolation, expected101 timing failures, timeout group cleanup, lineage, missing
slots, categories and fixed audit coverage. They execute no archived program.

The job cap is20 minutes. Pre-upload caps sum18: checkout1 + source fixtures1 +
download/stage3 + native trial1 five + native trial2 five + both reports2 +
summary1, leaving two nominal minutes for upload/overhead. Per-trial outer
watchdogs are110 seconds original and175 seconds focused; each cleanup uses at
most two2-second waits. Their worst budget293 seconds fits each five-minute
trial step. The original helper retains its own170-second timeout; the outer
110-second watchdog makes excessive original duration explicitly incomplete,
without changing timing criteria. Each linear report has45 seconds plus cleanup,
two reports fit98 seconds of their two-minute step. Typical execution is much
shorter. Download/setup failure is retained, never replaced with another VM.

Native summaries assess all forty paired slots, including missing/incomplete
entries, and separate original completed findings, focused complete/healthy,
complete/unhealthy and incomplete. CPU family/model/full flags/XCR0 are grouped
with VM identifiers; rates are empirical and clustered within VM. Workflow green
is not a gate verdict. An original DATA1024 confirmation plus healthy focused
literal confirmation can establish only narrow comparison prerequisites, not
causal/security closure. Focused quiet after an original flag remains an
observer/layout limitation. Every prior failure remains evidence.

All forty focused ten-pair sets and original logs stay in the twenty artifacts.
No descriptive sorting/statistics/RNG replay runs on the native critical path.
Post-CI full focused raw priority is any original/confirmed nonpositive finding
or positive miss, plus the fixed audit VM1/6/11/16 trial1. Audit slots are not
replaced if incomplete. Original raw samples are not available from the sealed
binary: its logs are not falsely called raw reconstruction. Coverage of checked
metadata, original logs and reconstructed focused samples is reported separately.
The aggregate helper fills every missing VM/trial slot rather than inferring
quiet from absent artifacts. Independent exact local review precedes any root
publication/native authorization; actual outcomes require independent review.
