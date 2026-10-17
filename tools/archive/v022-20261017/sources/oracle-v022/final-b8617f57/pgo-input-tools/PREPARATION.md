# Original PGO tooling recovery

All eight `training-plan.json` inputs were recovered byte for byte from the
local Git object database into `exact-original/`. `recovery.json` records each
Git blob and SHA256. No Oracle command, build, training, profile merge, or
product-source change was executed for this preparation.

`preparation-checks.json` records successful local import resolution, exact
11-scene equality, seed 539365398, expected 50 raw profiles, and reproduction
of both original derived-source hashes:

- original generated case: `169f6c5985c735817d4d11c63259900273d7147164609a3252a4d239f7d4631c`
- original generated lifecycle: `49666bd37b81a2a089db389b6b9543d52156f3c4b865c54f0d5e479b8d27cb48`

The case hash includes the old absolute output/runtime paths. Relocating it
for b861 changes that hash; compute the new hash with the unchanged
`pgo_train.training_case()` and new paths, retaining this original evidence.
The lifecycle source is path independent and remains reproducible directly.

## Files and dependencies

Training's complete nonstandard Python import closure is present:
`pgo_train.py` imports `perf_opt_device_run.py`, `perf_opt_oracle_run.py`, and
`pgo_sdk_smoke.py`; the oracle helper imports the device module. The remaining
imports are Python standard library. `pgo_train_cargo.py` has no local imports.
The shell case and two lifecycle C fragments complete the eight original
inputs. Python imports were tested without running module entrypoints.

For generate, the already preserved sibling `pgo_generate.py` imports the
recovered `pgo_sdk_smoke.py` and copies sibling `pgo_smoke_cargo.py`; place these
in the same stage inputs directory. They are not part of the eight-item
training input identity and must retain their separate generate-stage hashes.

Execution additionally needs:

- Frozen b861 source, its new exact baseline build receipt, plain ELF, map,
  prestrip, and SDK input identities; the old K baseline is evidence only.
- The selected unchanged SDK builder beside its matching `build_package.py`,
  source recipe/static-PIE linker, map wrapper, pinned Cargo/rustc/llvm-profdata.
- Five workload ELF helpers rebuilt from `workload-original/`, with actual
  new binary hashes recorded before the new training plan is frozen.
- The lifecycle helper built by the original controller from its two inputs.
- Linux `/proc`, passwordless `sudo -n`, `taskset`, `kill`, `/bin/sh`, GNU
  `/usr/bin/time`, and ordinary shell tools (`awk`, `cat`, `date`, `mkdir`,
  `readlink`, `sha256sum`, `sleep`, `wc`). Training collection requires root,
  hostname beginning `instance-`, and the fresh loopback-only net namespace.

Do not run the recovered device/oracle controller entrypoints; training imports
only their scene validation and archive helpers. No router operation is needed.

## Five original workload sources and rebuild

`workload-original/source-identity.json` binds each C source to its Git blob,
SHA256, and old binary SHA256. `measurement-tools.original.json` is the frozen
measurement manifest recovered from
`archive/perf/final-cleanup-20261017/owrt-perf-opt-20261015`.

All five original builds use:

```sh
"$STAGING_DIR/bin/aarch64-openwrt-linux-musl-gcc" \
  -O2 -std=c11 -Wall -Wextra -Werror -static SOURCE.c -o OUTPUT
```

There are no explicit extra link libraries. The compiler supplies the normal
static musl/runtime libraries. `nice10` uses `perf_opt_nice10.c`; its exact
original command is recorded in the previous session
`prior-session-record.jsonl`,
line 252, timestamp 2026-10-14T22:08:57.872Z, with these same flags and no `-l`.

The minimal script `rebuild-workload.sh SDK_DIRECTORY NEW_OUTPUT_DIRECTORY`
verifies source hashes, refuses an existing output directory, builds each
helper once, retains stdout/stderr separately, and writes actual binary hashes.
It has only been checked with `sh -n`; it has not been executed. A relocated
same-source build is not assumed to reproduce the old ELF hash. Preserve and
record actual output identity instead of copying the old hash into a new plan.

The PGO-specific lifecycle helper separately uses the original plan's
`-Os -static -Wall -Wextra -Werror` command. Do not substitute the five-tool
flags for that command.

## Original path and build gates

`check_baseline_paths()` requires all of the following:

1. Baseline status `built-unqualified` with `source_unchanged=true`.
2. Equal `source`, `source_commit`, `source_date_epoch`, and `source_digest`
   between the plan and baseline, plus the expected control ELF hash.
3. Exactly one `OWRT_DNSMASQ_BUILD_DIR` value across baseline commands, equal
   to `plan.build_slot`. The assertion text mentions frozen E historically;
   its actual check uses the plan value and permits the new stable b861 path.
4. `cargo_targets.control == baseline.shared_cargo_target`.
5. Every stage argv's `--source`, `--build-slot`, and `--cargo-target` values
   equal the corresponding plan values.

`check_build()` requires source/build-helper identities, unchanged source,
map-wrapper identity, AArch64 static PIE ET_DYN without interpreter/NEEDED,
BIND_NOW/RELRO/NX and no W+X load, single `dnsmasq-rs` artifact hash, map and
prestrip hashes. The wrapper receipt must bind mode, plan/wrapper/tool hashes,
rustc environment, exact recipe flags, and only the declared generate suffix.
Control additionally requires exact baseline reproduction and existing budget.
This function is for control/generate; profile-use has its own checks in
`pgo_train.execute()`.

The original profile-use gate rechecks source/SDK/layout equality, 2.5 MB ELF
and 1.4 MB APK limits from the plan, absence of profiler runtime in the use
link map, wrapper and profile identities, exact profile-use flags, and no
profile missing/hash/control-flow mismatch diagnostics. The old functions do
not enforce the newer all-Rust/Cargo-warning gate; the execution owner must
apply that independent gate to retained build output.

Collection still stops on any scene failure and requires exactly 50 unique
raw profiles with clean process exits: seven network scenes each one,
startup 20, config 21, and two HUP scenes each one. All files are merged once
with unit weight. Smoke profiles remain excluded. No gate was weakened here.
