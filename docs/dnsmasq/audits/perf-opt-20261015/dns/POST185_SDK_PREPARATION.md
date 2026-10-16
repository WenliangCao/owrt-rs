# Local preparation for the next two SDK entries

This preparation performs no build, upload, Oracle read, device operation or
test execution. Root will choose the source and execution order after the
current C/185 profile and its original raw audit finish. Both entries remain
disabled in the [machine preparation](post185-sdk-preparation.json). No full44
recipe or new measurement tool is added.

| Entry | Exact source | SDK inputs | Purpose |
| --- | --- | ---: | --- |
| 185 allocation diagnostic | `7c5b4c586e571eae875a0cb0e1ebfc88e2e1e7db` | 180 | Original whole-owner allocation counts only |
| Post185 combined | `6ab0f064b69087add3be1cb2bf5604fbaf42dffa` | 179 | Unqualified product experiment after profile-based selection |

All 359 input files were read locally and matched their exact Git blobs. The
inventory follows the existing `build_package.inputs` path order and scope;
the diagnostic's additional input is the original meter module. The control
fixture under `tools/` and the executable map wrapper are bound separately.
Research Git identity files and source manifests are prepared privately, with
their hashes and complete source SHA256 maps in the machine preparation.
The combined source manifest is byte-identical to correctness's prepared
`2b02edc3…6143` inventory.

## Original canonical SDK entry

Each entry records its full original builder argv with a separate fresh source
and output path. Both use the existing `sdk-builder-5e6c41f6/perf_opt_sdk_build.py`
SHA `f4540b1c…85f33` and helper SHA `f280b97d…9310`, the original SDK, Cargo path,
canonical `sdk-build-slot` and `sdk-cargo-target`. No new builder or wrapper is
introduced. The recipe still uses opt3, empty features, Rust1.98.1, one build
job, the original allocator and SDK locking, source checks, recipe restoration,
strip policy, package layout and static hardening. The diagnostic meter
forwards to that same System allocator.

Cargo manifests, lockfile, Rust toolchain, package Makefile, linker wrapper and
package helpers match the frozen185 source byte-for-byte for both entries.
The separate803 opt2 experiment and all compiler/feature/allocator changes are
excluded. Original size-budget reporting stays intact. Any eventual diagnostic
ELF/APK sizes are retained for identity and build checks only; they cannot be
published as product size or release evidence. Its CPU and latency are also
excluded from performance claims.

For6ab, correctness preparation `ee6d24e8`, SHA `a52b27a4…f2bc`, provides the
original five groups. The projected total is961 (840 library,82 binary,17
allocations,18 live ignored library and4 live ignored binary). That projection
is not a pass receipt. Fresh same-source listings, outputs and independently
verified actual counts must be bound before the selected SDK build. No prior
185 qualification or timing result transfers to6ab.

For7c, source review `98367eec`, SHA `ccbd9bc4…5bc6`, verifies the exact original
meter and control. The minimal main hooks preserve185's underlying behavior,
including post-send reply recycling. This is an excluded diagnostic child,
not a product candidate. Root's later selected order still controls whether
its build and original count controls run.

## Original meter/control entry

The [meter entry receipt](cached-zero-frame-allocation-meter-entry.json) binds
the unchanged125-line meter (`e62ae10c…c1c4`),52-line standalone Rust fixture
(`ad669923…3c86`), count controller (`823f0547…21be1`), original7c93 companion,
and original four parser controls. The original controller's fixed legacy
labels and CLI are recorded explicitly. A private copy preserves the frozen
import bundle; the current generic device-controller revision is not silently
substituted. No new three-window device plan or fresh health result is claimed.

The retained standalone JSON (`2b3f4a07…87e8`) was read and checked, without
rerunning compilation or execution. Its cached step is `[2,2,1,72,72]` and its
cached-only whole turn `[1,1,3,3,1,80,80]`. Only histogram bucket2 contains1;
nested steps are0 and the deliberate unscoped negative control is1. A real
measured window instead requires unscoped0 and nested0, one process/thread,
the original complete traffic/identity checks and actual final daemon exit0.

The actual cached-query count includes eligible prewarm hits and is never
replaced by5000. Cached steps, conditional cached-only turns and all normal
owner-turn rows remain separate. Requested/released bytes are allocator traffic,
not live heap, RSS, USS or physical copying. Startup/report/shutdown boundaries
and the original negative controls remain unchanged. No new source, compiler
or runtime evidence is inferred from the retained host control.

Before any later execution, freeze the selected source/order and real receipt
identities, verify the original source/tool/SDK identities and quiet locks,
and use fresh outputs. Preserve any failure and every artifact identity;
do not substitute another source, optimization level, tool or favorable run.
