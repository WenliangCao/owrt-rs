# Narrow PGO research plan; no experiment started

PGO is a separate compiler experiment worth preparing, with no evidence yet
that it improves this daemon. Existing release settings already use opt3,
fat LTO, one codegen unit, panic-abort and stripping. Keep those settings and
the static PIE SDK link unchanged. Do not combine this experiment with the
A53 tuning or decoded-name-buffer prototypes.

This local review performed only version/help, source and archive-symbol
inspection. It did not install tools, compile, train, time, contact Oracle or
a router, or change product/recipe files. [The observation receipt](pgo-local-preflight.json)
binds inspected files and local tools. The main A53/name-buffer work remains
independent.

## What is available, and what remains unproved

| Item | Local evidence / boundary |
| --- | --- |
| Compiler | Rust 1.98.1, commit `48a229ceaefd4985c50990b14116b6d856af0985`, LLVM 22.1.8. Its own help exposes `-Cprofile-generate`, `-Cprofile-use`, and `-pgo-warn-missing-function`. |
| Merge tool | `llvm-tools-preview` is not installed locally. Xcode supplies Apple LLVM 21.0.0 `llvm-profdata`; this is not the matched LLVM 22.1.8 tool. Obtain/verify the pinned toolchain's tool on the eventual build host before proceeding. Nothing was installed in this review. |
| Target runtime | The installed `aarch64-unknown-linux-musl` target contains `libprofiler_builtins-32af23de7a5fb6a7.rlib`, 788,576 bytes, SHA256 `e4f497ea63ecf965949028c36c9fa7adfffaa3a185b807008be74314811fdde0`. Symbol inspection finds initialization, atexit registration and file-write functions. Runtime presence does not prove SDK static PIE compatibility. |
| Runtime boundary | The archive references ELF start/section symbols, `_DYNAMIC`, libc allocation/file/mapping/locking functions and `atexit`. Exact SDK/BFD linkage, startup relocation, writable counter sections after GNU_RELRO protection, and successful profile emission/merge are untested. Do not replace the linker, disable hardening, rebuild std or change libc to bypass a failure. |
| Documentation | The local installed PGO workflow chapter belongs to Rust 1.99.0/LLVM 23.1.1. It is supporting workflow documentation only; the flag/runtime observations above come from pinned 1.98.1. Full compiler-rt C sources are not locally installed. |
| Process coverage | Foreground daemon shutdown returns normally after SIGTERM. Helper/config-lookup children use `_exit`, which skips the runtime's ordinary atexit write. Their counters must not be claimed as collected. TCP service runs in the owner process. Future child-profile work would be a separately scoped diagnostic change. |

The canonical SDK receipt already records Rust 1.98.1/LLVM 22.1.8 on an
AArch64 Linux host. This review did not inspect that host's merge tool or
profiler runtime; local Darwin tool presence is not remote-host proof.

## Smallest build adaptation

Use the existing `perf_opt_sdk_build.py`, its lock, source/Git inventory,
SDK identity checks, same-link map, artifact extraction and ELF audit.
External `RUSTFLAGS` cannot inject PGO: that builder clears them and the
OpenWrt recipe sets them again.

For a future authorized run, use the existing `--cargo`/`V1_CARGO` seam for one
small, separately hashed research wrapper. It forwards `--version` and `clean`
unchanged, and for the recipe's exact release build appends only the selected
PGO options to the `RUSTFLAGS` already set by the recipe. Reject an unexpected
target, feature, existing PGO flag, mode or relative profile path. The wrapper
directory also needs `rustc` pointing to the pinned real compiler because the
builder asks `cargo.with_name('rustc')` for its version. Record real cargo,
rustc and wrapper hashes as well as effective flags; a version-only report is
insufficient for this injected step.

No product or recipe edit is needed. Keep one frozen source/build-slot path
and its remap flags across the phases; use fresh output directories and
separate Cargo targets for control, generate and use to prevent stale
instrumented objects. Keep `CARGO_BUILD_TARGET=aarch64-unknown-linux-musl`,
all existing opt/LTO/link/strip settings, feature set, SDK and Rust version
identical. Do not add cargo-pgo, nightly, build-std or another product dependency.

Proposed independent source is accepted E
`4f869c885b47dcf60d56c872e5b0b3c62237beea`, whose retained SDK ELF SHA256 is
`8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27`.
Freeze that selection before any run. A pass-through control build must first
reproduce the expected baseline identity; retain and resolve any mismatch.

## Bounded execution sequence for a later run

1. Verify the actual build host's pinned rustc/cargo, profiler archive and
   `SYSROOT/lib/rustlib/HOST/bin/llvm-profdata` versions/hashes. Preserve source,
   SDK and wrapper identities before building. Availability is an open gate.
2. Build one generate artifact with only
   `-Cprofile-generate=/absolute/private/attempt/profraw` appended. Inspect
   map/prestrip/runtime objects and the final ELF under the existing static
   PIE/RELRO/NX requirements. Run one short isolated foreground configuration
   and orderly SIGTERM exit, with a fresh writable profile directory and
   `LLVM_PROFILE_FILE=/absolute/private/attempt/smoke/%p.profraw`. Confirm the
   expected process wrote nonempty raw data, and the matched merge/show tools
   can read it. No training or performance claim follows from this smoke gate.
3. If that gate passes, train once on each of the 11 classes below. Use the
   instrumented real daemon, existing clients/configuration/lifecycle helpers,
   fresh state and one profile directory per scene/run. The `%p` filename
   expansion must have passed the smoke check before relying on it for
   lifecycle children. Preserve every profile and completion status. Exclude
   the smoke profile from training. Do not train with synthetic stage-cut ELFs.
4. Merge exactly the raw files listed in the frozen training manifest using
   `llvm-profdata merge -o /absolute/private/attempt/merged.profdata FILE...`.
   Preserve the exact argv, merge diagnostics, raw hashes and merged hash.
   Use default unit weights for the fixed single pass; rates/counts below
   define the workload mixture. Do not retune weights after seeing evaluation.
5. Build one use artifact with
   `-Cprofile-use=/absolute/private/attempt/merged.profdata`
   and `-Cllvm-args=-pgo-warn-missing-function`. Preserve all diagnostics;
   reject unexpected source/CFG/hash mismatches and report missing-function
   coverage rather than hiding it. The packaged application and owrt-ubus
   sources receive PGO flags; prebuilt std/libc are not newly instrumented.
6. Verify the use build is uninstrumented using effective flags, same-link map
   and prestrip inspection. Apply existing ELF/APK size and resource budgets
   to the use artifact; the instrumented training artifact is never a release
   candidate. Run the normal correctness gates against frozen C, then compare
   the uninstrumented control/use pair with the unchanged original 11-scene,
   five-pair evaluation and original W/direction/resource rules. Native or
   Oracle screening does not replace A53 acceptance. No router run or change
   is authorized by this plan.

## Training coverage and evaluation separation

The original scene definition is `perf_opt_device_run.py:20`; preserve its
class boundaries and cardinalities in one predeclared training pass:

| Classes | Fixed workload shape |
| --- | --- |
| UDP hit, miss, mixed | 200/s, 5 s warmup + 20 s workload; 800-name hit pool, A/AAAA 70/30, 32 clients. Preserve the UDP parent-cache prewarm for hit/mixed. |
| TCP hit, miss | Same rate/duration/type mix; eight clients. Preserve parent-cache prewarm for hit. |
| DHCP home6, DHCP 150 | 100/s, 5 s warmup + 20 s workload; six/150 clients and the existing renewal setup. |
| startup-small, config-small, HUP-small | Seven non-marker hosts, six leases, 20 repeats, existing 1000 ms period. |
| HUP-large | 999 non-marker hosts, 150 leases, 20 repeats, existing 1000 ms period. |

Use a training-only equal-length DNS suffix such as `pgo.test`; keep evaluation
on its frozen `m6a.test` inputs. Merely changing the seed is insufficient:
`m6a_loadgen.c` uses `sequence % cache_names` for hit keys, so all seeds traverse
the same 800 names. Keep training fixtures, generated configs, lease/hosts
state and outputs in a distinct fresh private tree. Where existing fixture
generators fix identities, do not claim disjoint record keys without an
explicit separately hashed training-input adaptation. Fresh process/state
and excluding all evaluation data from the profile are mandatory regardless.

Training collects branch/value counts, not performance results. Freeze its
inputs, weights, retry policy and success checks before execution. Evaluate
only after the profile is frozen; neither failed evaluations nor holdout
requests may be folded back into this profile. Any new training corpus starts
a separately retained attempt. A helper `_exit` coverage gap must remain
visible even if all 11 owner-facing scenarios complete.

## Receipt additions, not a new framework

Retain the existing build receipt fields: Git/source digest, source-file
hashes, epoch, SDK files/archive, toolchain, builder/helper, commands, map,
prestrip, APK/extracted ELF identities and ELF layout. Attach one small PGO
receipt, referenced by SHA256 from the experiment manifest, containing:

- mode and exact added/effective flags; real compiler/cargo, Cargo wrapper,
  merge tool and target profiler archive versions/hashes;
- control/generate/use build-receipt and ELF hashes, all bound to the same
  product source and SDK; the training daemon's live executable hash;
- training plan/driver/config/input hashes, scene/run order, rates/counts,
  weights, exits/correctness statuses and explicit process/coverage gaps;
- every raw profile's relative path, size and SHA256; exact merge argv/log
  hashes; merged profile size/SHA256 and use-build diagnostics;
- evaluation plan/tool/input hashes and existing per-window receipts, which
  reference only the frozen control/use artifacts and never modify training.

Raw profiles, instrumented ELFs, maps and logs remain private. Commit tooling,
secret-free manifests and derived findings only. This preparation does not
prioritize PGO ahead of the current main experiments or establish a benefit.
