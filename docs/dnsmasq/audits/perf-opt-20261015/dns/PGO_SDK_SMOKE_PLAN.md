# Fixed E SDK PGO smoke gate; prepared, not executed

The [concrete plan](pgo-sdk-smoke-plan.json) freezes accepted E
`4f869c885b47dcf60d56c872e5b0b3c62237beea`, the unchanged SDK recipe/linker,
the corrected external SDK builder, fresh private paths, exact Cargo argv,
and the static-answer startup/profile check. Root must explicitly release
Oracle after the fresh-address/singleton `9e1856a6` timing reservation before
any build or runtime command starts. No PGO Oracle operation has run here.

This gate ends after an instrumented daemon exits normally and its profile
merges and displays successfully. It does not train, build with profile-use,
time workloads, select a candidate, or access a router. The small smoke
profile must never be reused as training data.

The [execution controller](../../../../../tools/dnsmasq/pgo_sdk_smoke.py) is now
prepared locally. After explicit host release, place the plan, wrapper and
controller in the fresh attempt's `inputs` directory and execute the plan's
`controller_argv`. The controller creates its wrapper/sibling compiler symlink,
uses the original builder's SDK lock for each of the two sequential builds,
and retains the root-coordinated build reservation until both pass. It does
not take the same lock outside the builder, which would deadlock the child.
No other SDK build may be inserted between these two reserved invocations.

## Prepared inputs and local verification

[The Cargo wrapper](../../../../../tools/dnsmasq/pgo_smoke_cargo.py) uses the
existing SDK builder's `--cargo` / recipe `V1_CARGO` seam. It runs after the
recipe has set `RUSTFLAGS`; it verifies that exact string and appends only
`-Cprofile-generate=ABSOLUTE_PRIVATE_PATH` in generate mode. Control mode
forwards the original flags byte-for-byte. The recipe, static PIE adapter,
opt3/fat-LTO/codegen1 settings and hardening are unchanged.

Only the builder's exact version/clean commands and recipe release-build argv
are accepted. A build checks the pinned target/toolchain, static PIE adapter
hash and relevant environment. Its fresh, exclusive-create invocation receipt
binds plan/wrapper/cargo/rustc hashes, argv, original flags and effective flags.
The runtime/phase ordering is an execution-controller responsibility: the
wrapper alone does not enforce the baseline-reproduction or Oracle-release
gate.

Three [local integration tests](../../../../../tools/dnsmasq/test_pgo_smoke_cargo.py)
passed with `python3 -m unittest discover -s tools/dnsmasq -p test_pgo_smoke_cargo.py -v`.
They expand the actual package Makefile through `BuildPackage`, invoke the
actual wrapper and use a capture-only Cargo stub. They verify control/generate
flags, receipt/executed argv agreement, metadata/clean forwarding, rejection
of ambient codegen overrides and unknown commands, and preservation of a
pre-existing receipt. No compiler, linker or SDK build ran in these tests.
Loop's independent local argv/environment review found no compatibility
blocker and identified the phase-ordering responsibility above.

The controller enforces that ordering: only a validated exact control receipt
is recorded as passed, and generate requires that pass. It preserves every
command's output and return status, validates runtime RELRO/NX mappings and
profile identity, and records matched merge/show output. Four additional local
[controller checks](../../../../../tools/dnsmasq/test_pgo_sdk_smoke.py) cover
control hash/budget rejection, the generate-only budget exception without
relaxing hardening, synthetic ELF/map coverage and cleanup after a launcher
exits while its descendant remains alive. Cleanup checks the owned process
group independently of the leader's exit; it does not infer that the whole
group exited from a successful `wait` on its leader. These checks use no SDK,
compiler, profile runtime, network namespace or remote host.
Loop's final read-only review confirmed the cleanup correction and found no
remaining static blocker; actual SDK/runtime results remain to be established.

Loop separately verified the Oracle tool at
`/home/ubuntu/.rustup/toolchains/1.98.1-aarch64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-gnu/bin/llvm-profdata`:
LLVM `22.1.8-rust-1.98.1-stable`, SHA256
`c7160d195180796edf7cc4c3f087f72b5425fc9ec2d9734b956a265e506f982e`.
This updates the remote availability gap from the earlier local-only plan;
the tool must still be rehashed immediately before use. Nothing was installed.

## Execution after explicit host release

1. Create the plan's fresh `dns/private/pgo-sdk-smoke1` attempt, upload only the
   frozen small inputs, copy the wrapper as `wrapper/cargo`, and create sibling
   `wrapper/rustc` pointing to the pinned compiler. Rehash all inputs. Verify E's
   research Git inventory/source digest, recipe/linker, corrected builder and
   helper, SDK, rustc/cargo versions and files, target profiler archive and the
   matched merge tool. Retain these read-only observations in the attempt.
2. Run the exact control argv/environment in `stages[0]`. Require a successful
   SDK receipt, unchanged source, valid static PIE/hardening layout, and
   `baseline_matches_expected == true` for ELF SHA256
   `8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27`.
   Assert this before starting generate; a mismatch stops the attempt.
3. Run `stages[1]` with its separate Cargo target and fresh output. Require the
   same source/recipe/SDK identities and exact effective-flags receipt, retaining
   the same-link map and prestrip artifact. Reuse the existing ELF audit:
   ET_DYN, AArch64, no interpreter or needed libraries, RELRO, bind-now, NX stack,
   no writable/executable load. Record instrumentation size/overhead; this ELF
   is diagnostic, so do not interpret it as meeting release size/performance.
4. Create the exact runtime configuration in the plan. Use the existing
   `run_isolated.sh` to enter new network/mount/PID namespaces and enable only
   loopback. Start the generate ELF in foreground with the plan's
   `LLVM_PROFILE_FILE`; retain stdout/stderr and live executable identity.
   Readiness has a bounded 10-second deadline. Query only the fixed local A and
   AAAA record, checking IDs, successful DNS envelopes and expected addresses.
   There is no upstream, external network, DHCP helper script or workload loop.
5. After readiness, retain `/proc/PID/maps` and verify the live ELF's GNU_RELRO
   range is read-only, no executable mapping is writable, and stack is not
   executable. Derive ranges from the bound ELF's program headers/load base;
   do not claim runtime protection from command-line flags alone.
6. Send SIGTERM and wait at most 10 seconds for status zero. Require exactly one
   nonempty raw profile for that foreground daemon PID, with no unexpected file
   in the compile-time default profile directory. Preserve failures and cleanup
   evidence if timeout/crash/write failure occurs; forced cleanup is not a
   passing normal-exit result. No manual profiling hook, changed exit path or
   weakened linker/hardening fallback is permitted.
7. Rehash the matched merge tool. Merge only the explicitly recorded raw file
   with the plan's `merge` argv, then run its `show --all-functions --counts`
   argv. Require successful parsing and positive function/counter activity.
   Retain raw/merged size and SHA256, both complete command outputs, final source
   and tool rehashes, and proof the namespace/controller/daemon processes ended.

Use the existing SDK `build.json` receipts plus one small smoke receipt linking
the control/generate builds, wrapper invocations, runtime config/query evidence,
live ELF/maps, exit status, raw profile, merge/show commands and tool hashes.
Keep artifacts and raw profile data private. Stop on any failed gate and retain
the complete attempt; do not replace failures or change compiler/linker/runtime
strategy in this attempt.
