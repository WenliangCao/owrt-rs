# PGO smoke1: Cargo launcher setup failed before compilation

The fixed controller `47275549` ran after root explicitly released Oracle.
It stopped in the control build's `cargo clean`, before Rust compilation or
linking. The log reports that Cargo could not execute `rustc -vV` because it
could not find the executable. No control ELF, generate build, instrumented
runtime or raw profile was produced. Exact-E reproduction and PGO/static-PIE
feasibility therefore remain unestablished.

The wrapper selected the toolchain's direct `bin/cargo`, replacing the stock
rustup Cargo proxy used by the existing SDK build. Its metadata `--version`
call succeeded, as did the separately addressed pinned compiler version.
Direct Cargo then lacked the proxy's compiler-discovery environment during
the clean step. The local capture-only Cargo stub had checked argv/flags but
could not expose this integration error.

All three version commands passed; the control builder returned 1 after its
clean command returned 101. The controller did not advance to generate or
retry. SDK preparation had copied the frozen source, but no Rust compiler was
started. No release budget, linker, hardening or recipe change was attempted.

Cleanup was independently checked: no smoke process remained, the SDK lock
was available, the existing recipe was restored, all 179 source and 106 SDK
file hashes still matched, and generate/runtime directories did not exist.
The SDK reservation was released to root's three queued builds.

[The derived failure receipt](pgo-sdk-smoke1-failure.json) binds the original
plan/controller, version observations, partial build, failed command and
cleanup. Full outputs remain in Oracle private `dns/private/pgo-sdk-smoke1`;
small receipts and failure-log text were also retained locally. Smoke1 will
not be overwritten. Root subsequently authorized a separate launcher repair,
a real pinned-toolchain discovery regression, and a fresh smoke2 attempt
after the next explicit SDK release.
