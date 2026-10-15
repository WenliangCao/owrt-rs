# Fixed E PGO training and profile-use build; prepared only

This is the next bounded experiment after the successful
[SDK smoke3](PGO_SDK_SMOKE3_RESULT.md). The
[machine-readable plan](pgo-training-plan.json) and
[driver](../../../../../tools/dnsmasq/pgo_train.py) freeze one pass through the
original 11 scene definitions and one profile-use SDK build. No training or
use build has run. Execution waits for root's next explicit non-timing
reservation; existing SDK and native work must finish first.

The source remains accepted E `4f869c885b47dcf60d56c872e5b0b3c62237beea`.
Reuse only smoke3's verified generate ELF
`3ba940df09f96606af3e4fc8f27c11a2b50788c5cc0e13cd8ca71357dbb381ad`.
Its build receipt and completed smoke state are hashed prerequisites. No
smoke raw file or merged profile may enter training. No source prototype,
compiler tuning, linker or hardening change is combined with this experiment.

## Frozen workloads and weighting

| Scene | Existing workload parameters | Expected daemon profiles |
| --- | --- | ---: |
| udp-hit | 200/s, warmup5s, workload20s, hit | 1 |
| udp-miss | 200/s, warmup5s, workload20s, miss | 1 |
| udp-mixed | 200/s, warmup5s, workload20s, mixed | 1 |
| tcp-hit | 200/s, warmup5s, workload20s, hit | 1 |
| tcp-miss | 200/s, warmup5s, workload20s, miss | 1 |
| dhcp-home6 | 100/s, warmup5s, workload20s, six clients | 1 |
| dhcp | 100/s, warmup5s, workload20s, 150 clients | 1 |
| startup-small | seven hosts, six leases, 20 starts, 1000ms period | 20 |
| config-small | seven hosts, six leases, 20 config replacements, 1000ms period | 21 |
| hup-small | seven hosts, six leases, 20 HUPs, 1000ms period | 1 |
| hup-large | 999 hosts, 150 leases, 20 HUPs, 1000ms period | 1 |

Use the original scene order, once each. DNS retains its existing 800-name
A/AAAA70/30 selection, client counts, upstream delay/TTL, parent-cache prewarm
and warmup. Only the two case-script `--name-prefix m6a.test` occurrences
become `--name-prefix pgo.test`. The existing load generator already supports
this argument and is not recompiled. Root/out-directory relocation uses the
same substitution as the existing Oracle runner, without changing workloads.

Each scene gets a fresh process/state directory and a distinct
`profiles/SCENE/%p.profraw` output. Normal helper execution yields 50 profiles:
seven traffic daemons and 43 lifecycle daemons. Config's initial daemon is an
additional process, not one of the 20 visible-change rows. Merge exactly the
recorded 50 paths with default unit weights; no files are sampled, discarded
or reweighted after observing results. Counts include startup, prewarm,
warmup, workload and normal shutdown. This intentionally follows the fixed
single-pass mix; it does not equalize instruction volume among scenes.

The suffix separates DNS training keys from evaluation. DHCP and lifecycle
fixtures retain their original names/IDs but use fresh state; no stronger
claim of disjoint identities is made for those fixtures. Future evaluation
must retain original inputs and cannot feed back into this frozen profile.

## Existing tools and minimal training adaptations

The driver reuses the existing `SCENES`, correctness `validate`,
`archive_window`, case shell script, load generator, upstream, resource probe,
netns helper and nice10 launcher. Five existing workload ELF hashes and all
source/helper hashes are fixed in the plan. The netns helper admits only new
loopback-only namespaces. The controller owns the case process groups and
bounded 100-second case deadlines; no production guard or router is involved.

Only the lifecycle helper is rebuilt for training: a private copy replaces
its old `end_child` block with the separately committed
[exit-status fragment](PGO_LIFECYCLE_EXIT_GATE.md). The plan binds original,
fragment and generated-source hashes plus the existing SDK compiler command;
the build receipt binds the resulting helper ELF before collection. Original
measurement helper bytes and historical results remain unchanged.

The same endpoint records initial config shutdown, normal shutdown, abnormal
exit, wait errors and forced-KILL cleanup. Only normal status0 passes. Local
real-child tests cover exit0, exit7, exit127, SIGKILL/SIGTERM termination,
already-reaped child, and ignored TERM followed by the existing timeout/KILL.
The source reviewer confirmed that all existing reap paths pass through this
endpoint. Unexpected helper crash/clock failure can still miss records; the
controller rejects missing exit/profile/PID sets and nonzero helper status.

The daemon's internal `_exit` children do not run the profiler atexit handler.
Their coverage remains an explicit gap; this adaptation observes the
foreground daemons launched by the lifecycle helper, not those internal
children. No manual profile-flush hook is added to the product.

## Collection gates and failure retention

Every case records argv/environment, case exit status, original COMPLETE and
correctness evidence. The original validator checks traffic scheduling,
completion/error counters, upstream counts, DHCP DORA/renewal boundaries and
lifecycle markers. The driver adds exact prewarm completion/prefix checks,
normal-zero lifecycle exit rows, and exact nonempty profile membership for
the recorded daemon PIDs. Wrong, extra or missing profiles stop the pass.

The traffic case uses `set -e` and writes COMPLETE only after successful
`wait "$daemon"`. Lifecycle exits are now explicit per-PID records. All
process groups are cleaned before a case is archived. Failed cases, logs and
profiles remain in the attempt; an unsuccessful cleanup leaves its active
group and unarchived runtime path visible. No failed scene is replaced or
rerun in the same attempt. The controller never merges a partial pass.

The original tools emit CPU, timestamps and resource observations. These raw
outputs are retained, but this driver computes no CPU/latency comparison and
claims no performance acceptance from instrumented collection.

## Merge and profile-use build

After all 11 scenes and all 50 profile identities pass, the matched
LLVM22.1.8 `llvm-profdata` merges the explicit frozen file list and displays
all function counts. Both commands must exit0 without diagnostics, with
positive profile activity. A training receipt binds the plan, generate ELF,
collection receipt, every raw profile and the merged bytes/hash.

The separate [use Cargo wrapper](../../../../../tools/dnsmasq/pgo_train_cargo.py)
accepts only `use`. It rejects an incomplete or foreign training receipt,
wrong generate ELF, changed merged bytes or plan mismatch before compiling.
It preserves original recipe flags and adds only the absolute
`-Cprofile-use=...` and `-Cllvm-args=-pgo-warn-missing-function` options. The
same fixed rustc discovery binding from smoke3 is retained.

Build from the original canonical prepared source slot
`root/private/sdk-build-slot`, with a fresh private use Cargo target. The
original E receipt locks source/epoch/path identity. Existing SDK builder,
lock, Git inventories, map/prestrip retention, APK extraction and ELF audits
remain unchanged. The **use** ELF/APK must meet the original 2,200,000 /
1,200,000-byte budgets and baseline static PIE/RELRO/NX layout. Unlike the
generate diagnostic, use has no size exception. Its bound map/prestrip hashes
are checked, and its same-link map must contain neither profiler runtime nor
`__llvm_profile_` symbols; fresh target storage and effective flags also keep
the use build separate from instrumentation.

Preserve all build diagnostics, including missing-function warnings. Explicit
profile hash/control-flow/staleness mismatches stop the attempt. A successful
build is labelled `trained-use-built-unqualified`; it does not establish
complete profile coverage, frozen-C correctness, resource acceptance or a
speedup. Those later gates and the original 11-scene evaluation are separate.

Local tests passed for exact scene/case adaptation, the otherwise easily
missed initial config daemon, abnormal/missing profiles, and modified/foreign
profile rejection before the capture-only Cargo stub. The real-child exit
fixture also passed all seven exit/error/forced-cleanup cases. Loop's initial
read-only review found no blocking issue in collection retention, profile
membership, canonical path use or budget interpretation. None of these local
checks is an actual training result.

The frozen attempt is `dns/private/pgo-train1`; its controller command appears
in the plan. Upload only its listed small input files after the reservation is
released. Profiles, generated helper/use ELFs, maps and raw logs stay private;
commit only tooling, secret-free manifests and derived outcomes. This plan
does not authorize additional passes, evaluation-driven retraining or router
deployment.
