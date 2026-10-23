# procd / fw4 platform boundary follow-up

The business roots of procd and fw4 again enforce `forbid(unsafe_code)`.
Process operations use narrow platform APIs; no safe generic fork callback
or persistent single-thread snapshot is used as proof.

## Process ownership

`ProcessOwner` checks the current main-thread identity, blocks the complete
kernel signal mask and asks Linux `unshare(CLONE_VM)` to reject a shared address
space on each sensitive operation. A registered procd `Process` capability
keeps its fixed callbacks private. `spawn_instance` consumes the `Command`,
installs the setup and spawns while the guard is held. The final child hook
restores the caller's original mask before exec. The firmware worker accepts
only its fixed owned string/map request and always exits with status 1.

The unsafe registration is confined to `platform/entry.rs`. Its contract covers
all callback input values, application atfork/signal/allocator/NSS hooks,
inherited locks and mutable shared state. Both fork paths reject unwinding.
Before a registered child callback executes, the platform forgets the inherited
panic hook without invoking its destructor and installs an immediate-exit hook.
No child panic can return into the supervisor's frames.

The tty hook needs no process credential: path conversion finishes in the
parent and the fixed child hook performs only open/dup2/close, session and
terminal syscalls. It accepts no application callback.

## Watchdog and environment compatibility

The startup adapter consumes WDTFD once before any business descriptor creation.
The pinned Rust 1.98.1 Unix runtime initializes standard descriptors, signal
state, stack mappings and arguments, but retains no descriptor numbered 3 or
higher. This is an explicit toolchain-bound startup assumption, based on
[`rt.rs`](https://raw.githubusercontent.com/rust-lang/rust/1.98.1/library/std/src/rt.rs),
[`sys/pal/unix/mod.rs`](https://raw.githubusercontent.com/rust-lang/rust/1.98.1/library/std/src/sys/pal/unix/mod.rs)
and [`stack_overflow.rs`](https://raw.githubusercontent.com/rust-lang/rust/1.98.1/library/std/src/sys/pal/unix/stack_overflow.rs).
Re-audit these startup paths before changing the toolchain. F_GETFD establishes
validity only; ownership comes from the trusted preinit-to-exec handover and
its entry position. The standalone `-h <rules>` path still leaves WDTFD alone.

WDTFD values 0, 1 and 2 now fail with EBADF after environment removal, without
closing a standard stream. This deliberately tightens malformed handover input:
standard streams may have process-global Rust borrowers and cannot safely be
adopted as exclusive watchdog owners. Normal preinit handover uses a separate
open descriptor. Duplicating it is avoided because final-reference magic close
must retain its original meaning. Non-PID1 opening remains deferred until its
first explicit watchdog operation.

DBGLVL, QUIET, TTY and upgrade exports use the checked environment API. All
upgrade environment failures follow the existing watchdog/chroot cleanup path;
successfully applied UPGRADE_* values retain the previous failed-exec behavior.

## Validation

All compilation and tests run through mbx on Oracle. No router was modified.
The work directory is `/home/ubuntu/owrt-platform-boundary-20261023`.

- `procd-boundary-tests.log`: 91 library tests, 7 standalone process fixtures,
  and the existing watchdog example test passed.
- `procd-boundary-owner-final.log`: explicit AArch64 target through the isolated
  test runner; 7 process fixtures plus 3 low-descriptor rejection cases passed.
  Tests check child SigBlk against the parent, live-thread rejection after
  registration, no child on rejection, post-join recovery, real CLOEXEC at
  exec, final pipe EOF, descriptor reuse, and deferred watchdog handover.
- `procd-boundary-clippy-final.log` and `fw4-boundary-clippy.log`: all-target
  Clippy with warnings denied passed (procd includes all features).
- `fw4-boundary-tests.log`: 21 tests passed.

Musl builds passed. The actual 25.12.6 image and the candidate both passed
`procd_bundle` (2 rows, 16 checks); fw4 passed all 31 upstream golden cases.
Artifact and source identities are recorded in
`PROCD_FW4_PLATFORM_BOUNDARY_20261023.json`. The original 2026-10-22 ledgers remain historical
snapshots; this follow-up changes their referenced process boundaries.
