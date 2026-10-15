# PGO training completed; use artifact rejected by size budgets

The fixed E training pass completed all 11 scenes with all correctness and
normal-exit/profile gates satisfied. Exactly 50 raw profiles were merged, and
the profile-use SDK build succeeded. The experiment then stopped at the
unchanged release size gate: both ELF and APK exceed their budgets. The
artifact is retained and unselected; no qualification or performance run
followed.

| Size | Frozen E | PGO use | Existing budget | Over budget |
| --- | ---: | ---: | ---: | ---: |
| ELF bytes | 2,136,859 | 2,288,419 | 2,200,000 | 88,419 |
| APK bytes | 1,162,059 | 1,293,382 | 1,200,000 | 93,382 |

Use ELF SHA256:
`0910b49aa24e6fba72e7a45aaf2de2490fe60ab0eda23e1e71ad86b663cb9127`.
Use APK SHA256:
`ea0c484dc8f7d7b5020b78a106842bbee38f55843f14a8700f58d7448e6e4ee2`.
The use ELF grew 151,560 bytes relative to E; the APK grew 131,323 bytes.
No weight, optimization level, source, linker, hardening or budget was changed
after observing this failure.

## Frozen collection and profile provenance

Root explicitly released the non-timing window after the preceding native
screen. The plan was committed in `113c2ae`, SHA256
`1ff57e91a438a2b56e161d688fc19e65aa9214c6c0827c8a7aa20a344be9af26`.
Collection used CPU0, the same accepted E source, smoke3's verified generate
ELF, original workload tools and the separately bound training-only lifecycle
exit helper. No router or deployment was involved.

| Scene | Valid cases | Normal daemon profiles |
| --- | ---: | ---: |
| udp-hit | 1 | 1 |
| udp-miss | 1 | 1 |
| udp-mixed | 1 | 1 |
| tcp-hit | 1 | 1 |
| tcp-miss | 1 | 1 |
| dhcp-home6 | 1 | 1 |
| dhcp | 1 | 1 |
| startup-small | 1 | 20 |
| config-small | 1 | 21 |
| hup-small | 1 | 1 |
| hup-large | 1 | 1 |

All scenes ran exactly once in the original order with unchanged rates,
durations, populations, prewarm and correctness checks. DNS used `pgo.test`;
the original evaluation suffix remains `m6a.test`. Lifecycle marker rows,
traffic completion/error/upstream checks and DHCP DORA/renewal boundaries
passed. Config's initial daemon was included in its 21 explicit exit records.
Every profile matched its required PID set, was nonempty and had a recorded
SHA256. No abnormal wait, signal exit, forced cleanup or missing profile was
accepted. All case process groups exited.

The matched LLVM22.1.8 tool merged only the explicit 50 recorded files with
default unit weights. Smoke profiles and evaluation traffic were not included.
The merged file is 929,880 bytes, SHA256
`71adfc9533505fbe8ec7f564ad7029626e7cb504cd5287c246b1897d9d46b723`.
Merge/show exited zero with empty stderr. Show reports 2,838 functions, 42,472
blocks and total count383,086,342. These are collected-profile facts, not
coverage completeness or performance evidence. Internal `_exit` children
still bypass the profiler's atexit output.

## Build gates, diagnostics and cleanup

The use build retained canonical `root/private/sdk-build-slot`, a fresh use
Cargo target, exact source/epoch/SDK/compiler identities and original release
settings. Its only added flags were the bound absolute `-Cprofile-use` path
and `-Cllvm-args=-pgo-warn-missing-function`. There were no PGO missing-function,
hash/control-flow mismatch or stale-profile warnings in the retained compile
log. Ordinary source/SDK warnings, including the ignored SDK `runas.so`
LD_PRELOAD warning, are retained without filtering.

The SDK builder completed ET_DYN/AArch64, static PIE, no interpreter/needed
libraries, RELRO/bind-now/NX stack and no writable-executable load checks. The
controller then failed the size assertion before its later validation steps.
A separate read-only completion audit subsequently checked map/prestrip/ELF
hashes and confirmed the same-link map contains no profiler runtime or
`__llvm_profile_` symbols. These post-failure checks do not convert the failed
size gate into a passing qualification. The use artifact was not run, so its
runtime protections and functional equivalence have not been independently
established.

All five external commands succeeded: helper build, collection, merge, show
and use build. The controller's final status is **failed at the size gate**.
Final read-only checks verified unchanged 179 source and 106 SDK files, all
50 raw profiles, merged bytes and fixed tools. No training/controller/daemon
process remained; the temporary runtime directory was gone, the recipe was
restored and the SDK lock was available. Root and loop received the explicit
reservation release.

All profiles, logs, generated helper, use ELF/APK and maps remain in Oracle
private `dns/private/pgo-train1`. A 190,843-byte compressed textual receipt/log
bundle was copied locally; privileged read-only access was needed for the
daemon's root-owned logs. The same-link map was subsequently copied during the
released non-timing interval for local size analysis. No profile or binary
was committed to Git.

[Complete derived outcome](pgo-training-result.json) retains every scene,
profile identity, original correctness count, build receipt, compiler warning,
failure and cleanup check. All raw observer timing remains unanalyzed; no CPU,
cycles, IPC or latency conclusion is drawn. Representative profile collection
and a compilable use artifact have been demonstrated, but the retained artifact
fails the release size contract and has not passed full correctness or device
acceptance.
