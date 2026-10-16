# Prepare original native240 and owner32 for6ab versus G

Local preparation only. Baseline G is
`185db90c9cabd26c0af09765636ef15bf6d35f79`; the candidate is
`6ab0f064b69087add3be1cb2bf5604fbaf42dffa`. Candidate SDK ELF/map/build and
actual Linux gate receipts remain null. Nothing was uploaded, built or run.
The independent Arc-content prototype and opt2 are not part of this candidate.

[Native preparation](post185-combined-native-preparation.json) retains all15
original hotpath scenes,90 grouped-PMU windows,150 plain windows and four
build commands. Counts, checksums, zero-allocation checks, CPU/nice placement,
toolchain and flags, paired order, original compare/W rule and failure policy
are unchanged. The runner changes only the baseline label E→G and scope text.
The analyzer changes only labels, scope and local evidence paths. Native
whole-process counters include setup/priming/teardown; the public library
probe does not execute SinglePoll, private socket Rc or owner-clock work.
It remains useful for library regressions, not proof of those owner savings.

[Owner32 preparation](post185-combined-owner32-preparation.json) retains the
original low200/s and high-unpaced UDP workloads, three stat pairs and five
plain pairs per load (12 PMU plus20 plain windows). The original f0b39 driver,
f7c7d8 loadgen, upstream, analysis imports, normalization and decisions are
byte-identical. Only baseline/candidate identities, paths, scope and the
source-bound anticipated related-test count change in the wrapper.961 is an
expected count from the new five-group plan, not a completed test claim.
The actual gate is null. Every32-window argv is declared in the
[binding manifest](post185-combined-screen-preparation.json).

The owner wrapper rejects the preparation status before creating output.
The original native wrapper has external gate/SDK prerequisites rather than
an internal status check: do not invoke it from this preparation. A ready
plan must separately bind the actual gate receipt, exact original-SDK triple,
source receipt and pretransfer result, then receive the exclusive slot after
all preceding timing/raw audits/transfers have ended. Native240 must complete
its original raw/postflight release before owner32 acquires its own slot.

Canonical directories match DNS's existing queue:
`root/source-cached-zero-frame` and `root/source-post185-combined`, with SDKs
`root/private/sdk-cached-zero-frame` and `root/private/sdk-post185-combined`
under `/home/ubuntu/dnsmasq-perf-20261015`. Both manifests were rebound from
Git locally:162 native inputs and179 SDK inputs per side. All four adapted
scripts parse; exact declared substitutions reproduce their bytes; protocol
fields and eight original analysis-module hashes were compared unchanged.
The ninth unchanged input is the original72d836d1 hot15 probe, copied privately
without regeneration. DNS independently reproduced the four substitutions,
both source manifests and the32-window matrix from the original inputs.

The subsequently available961 gate receipt has a different identity schema
from the old940 receipt. Its local SHA is
`ff6e767b30e3cde7a68c0640abf61fc4c3ee45bdd59a537db475369e0b311255`.
The preparation wrapper now checks its actual status
`PASS_FRESH_ORIGINAL_FIVE_RELATED_GROUPS_AND_QUIET`, `research=[]` and
`wrapper_exited`, retaining the source/count checks. The runtime gate binding
and candidate SDK remain null; this schema correction does not enable a run.

Preserve every failure/partial capture and stop. No replacement windows,
historical E/G pooling, new threshold, scene, observer or estimator is added.
These preparations are screens, not full qualification or deployment.
