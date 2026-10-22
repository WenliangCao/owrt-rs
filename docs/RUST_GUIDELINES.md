# Rust development standard

Microsoft's [Pragmatic Rust Guidelines](https://microsoft.github.io/rust-guidelines/agents/all.txt)
are the standard for all Rust development, refactoring, code review and maintenance
in this repository. This document applies that standard to OpenWrt compatibility
work; it does not replace the complete upstream guidance.

## Reference identity and updates

Reviewed on 2026-10-22:

- Official complete text: <https://microsoft.github.io/rust-guidelines/agents/all.txt>.
- Source revision: [`19723b30aadf1854fef6a56c2da2395dc03255c1`](https://github.com/microsoft/rust-guidelines/tree/19723b30aadf1854fef6a56c2da2395dc03255c1),
  published by [the successful 2026-09-25 workflow](https://github.com/microsoft/rust-guidelines/actions/runs/36133501033).
- Retrieved complete text: 136,201 bytes; SHA-256
  `e69533b0541a5d185ad9d8304f5eb5cf4b033135b7046f89c499b6126dced3b6`.
- The upstream [`agents_summary.sh`](https://github.com/microsoft/rust-guidelines/blob/19723b30aadf1854fef6a56c2da2395dc03255c1/scripts/agents_summary.sh)
  generates `all.txt` from individual guideline files. A checked-in source copy
  of `all.txt` alone is not evidence of the published document's identity.

Read the applicable rules before changing a subsystem. Recheck the official
source when updating this policy or encountering a new design question. Review
upstream changes deliberately, then update this identity and any affected local
decisions. Do not vendor the entire third-party document or silently switch the
review baseline. If upstream is temporarily unavailable, use this recorded
baseline and state the retrieval limitation in the review.

## Rules for each change

- **Soundness and platform boundaries:** `M-UNSOUND`, `M-UNSAFE`,
  `M-UNSAFE-IMPLIES-UB`, `M-FFI-TRANSLATES`. Prefer safe `std`/`rustix` APIs.
  Keep unavoidable ABI operations in the existing platform modules. Explain
  pointer validity, lengths, lifetimes, descriptor ownership, concurrency and
  target layout for each unsafe operation. A safe interface must uphold these
  requirements for every safe caller. Compatibility never justifies UB.
- **Failure behavior:** `M-PANIC-IS-STOP`, `M-PANIC-ON-BUG`,
  `M-PANIC-MESSAGE`, `M-PANIC-CONTINUATION`. Malformed network packets, config,
  peer disconnects, entropy failure and filesystem errors are recoverable
  conditions where the existing contract permits recovery. Use explicit error
  results, retain upstream status codes, and bound resource use. Reserve panics
  for programming errors with useful diagnostics; do not recover from a panic
  and continue with potentially inconsistent daemon state.
- **Small APIs:** `M-RUST-SHAPED`, `M-SIMPLE-ABSTRACTIONS`, `M-DI-HIERARCHY`,
  `M-STRONG-TYPES`, `M-STRONG-TYPES-GUARD`. Preserve OpenWrt semantics while
  using Rust ownership and clear types. Validate invariants at boundaries.
  Prefer small functions and concrete types; introduce traits, builders,
  macros or new crates only when the actual use cases warrant them.
- **Documentation and diagnostics:** `M-CANONICAL-DOCS`, `M-MODULE-DOCS`,
  `M-DOCUMENTED-MAGIC`, `M-PUBLIC-DEBUG`, `M-PUBLIC-DISPLAY`,
  `M-LOG-STRUCTURED`. Document changed public interfaces, relevant errors,
  panic/safety/abort conditions, and non-obvious ABI or protocol constants.
  Keep secrets out of diagnostics and `Debug` output; test redaction when
  introducing a sensitive type's formatter. Preserve observable log formats.
  Keep research history in evidence reports, not API documentation
  (`M-NO-META-DESIGN-DOCUMENTATION`).
- **Reliable tests:** `M-TAUTOLOGICAL-TESTS`, `M-MOCKABLE-SYSCALLS`,
  `M-INTEGRATION-TESTS`, `M-TEST-UTIL`. Test observable contracts against
  independent fixtures, matching upstream behavior or captured redacted
  evidence. Include relevant malformed input, boundary, timeout and failure
  cases. Make time, entropy and I/O controllable with the smallest useful
  seam. Isolate temporary files, sockets and process state; avoid sleep-based
  ordering when synchronization is available. Public-API-only tests belong
  under `tests/`; internal unit tests may stay beside the implementation.
  Keep test bypasses out of production builds. Do not copy an implementation
  into its expected result or assert constants merely against themselves.
- **Measured performance:** `M-HOTPATH`, `M-MEM-REUSE`,
  `M-INITIAL-CAPACITY`, `M-BOX-DST`, `M-THROUGHPUT`. Apply
  `RESEARCH_GUIDANCE_FROM_FABLE.md` before experiments. Preserve fairness,
  bounded memory and protocol ordering while measuring CPU, allocation,
  latency and throughput. Do not claim an optimization from intuition alone.

## Applicability to this repository

These are explicit compatibility constraints and adoption decisions, not a
claim that all existing code already conforms. Document any additional
deviation with the rule ID, concrete reason and a condition for revisiting it.

| Rules | Current application and revisit condition |
| --- | --- |
| `M-CARGO-WORKSPACE`, `M-CRATES-IN-WORKSPACE`, `M-CRATES-FLAT-FOLDER` | Existing SDK recipes copy standalone component trees; release and PGO gates depend on source paths, lockfiles and artifact identities. Keep this layout during compatibility/security work. Plan workspace inheritance and flattening separately, with all package recipes and frozen artifact gates revalidated. |
| `M-LATEST-EDITION`, `M-MSRV` | New crates use the latest stable edition supported by the pinned toolchain. Keep existing 2021 crates during unrelated fixes. Edition migration must separately audit newly unsafe environment/process APIs and rerun host/target gates. `rust-toolchain.toml` remains the compiler source of truth. |
| `M-MIMALLOC-APPS`, `M-TARGET-CPU`, `M-FAST-HASHER` | Preserve the validated musl allocator and target baseline until representative target measurements justify a change. Never use a build host's native CPU as a router target assumption. Only consider a faster hasher for demonstrably trusted internal keys; network-controlled keys still require collision resistance. |
| `M-ERRORS-CANONICAL-STRUCTS`, `M-APP-ERROR` | Preserve libuci/ubus/protocol error values and existing public callers. Do not add an error framework or backtrace payload to compatibility errors as a side effect of a bug fix. New independent APIs follow upstream error guidance; evolve existing ones only with caller and resource-cost review. |
| `M-LOG-STRUCTURED`, `M-LOG-NOT-PRINT` | Keep syslog and CLI output contracts consumed by OpenWrt tooling. New internal events use named fields where the existing logger supports them; introducing a telemetry dependency requires a concrete need. |
| `M-SINGLE-ITEM-PATH`, `M-DOC-INLINE`, `M-SMALLER-CRATES` | Prefer one documented path for new API items and inline owned reexports. Existing aliases, module names and crate splits change only with their callers and packaging tests. |
| `M-OOBE`, `M-TYPES-SEND`, async/runtime guidelines | These services explicitly target Linux/OpenWrt. Do not add cross-platform stubs or an async runtime to satisfy an inapplicable use case. Preserve deliberate single-thread ownership; never assert `Send`/`Sync` unsafely to bypass a boundary. Apply async-specific rules if async code is introduced. |

## Validation and incremental review

For changed Rust code, run relevant tests and compiler/Clippy checks on the
remote Linux host (`ssh oracle`) or CI, using `mbx` for every Cargo build,
check, test, benchmark and lint invocation. Use locked dependencies and the
pinned compiler. Diagnose apparent cache misses with `mbx explain --last`.
The Mac is for editing, Git and formatting; do not compile there.

`M-STATIC-VERIFICATION` is the target for our checks. Preserve existing
`forbid(unsafe_code)`, `unsafe_op_in_unsafe_fn` and
`clippy::undocumented_unsafe_blocks` gates. Baseline additional recommended
compiler/Clippy lints per component before enforcing them; fix actionable
findings in focused changes instead of adding blanket suppressions. Local
overrides use `#[expect(..., reason = "...")]` (`M-LINT-OVERRIDE-EXPECT`)
unless generated code or macros require `allow`. Use dependency advisory
checks for dependency changes, feature-combination checks for changed features,
and Miri for supported unsafe abstractions; explicitly report unsupported
FFI/target coverage. These additional gates are an adoption target, not a
statement that every existing CI job already runs them.

Initial review priorities, in order:

1. External input, authorization, path traversal, resource limits and platform
   ownership/soundness; correct confirmed defects with regression tests first.
2. Deterministic failure tests and parallel-test isolation at touched I/O,
   entropy and clock boundaries.
3. Missing public API/failure documentation and safely redacted diagnostics in
   shared `ubus`, `uci` and platform modules.
4. API alias cleanup, edition/lint adoption and workspace consolidation only
   when separately scoped work justifies their compatibility and release cost.

Reviews record the changed behavior, relevant rule IDs or justified deviations,
exact validation commands/results and untested target-specific paths. Do not
claim full-project compliance from a partial review. Commit small, meaningful
units without mixing broad formatting or naming churn into behavior changes.

For a whole-project review, enumerate every tracked `.rs` file, including
examples, tests, fuzz targets and standalone tools. Store the ledger under
`docs/reviews/`: current line count and SHA-256, actual full-reading status,
applicable rule IDs, and a file-specific conclusion or retention reason.
Record the original full-read snapshot and subsequent reviewed patches when
the source changes; a search hit or an automatic inventory is not a full read.
Read the complete official guideline text in untruncated segments and retain
its identity and reading ranges. Keep reading coverage distinct from test,
differential, performance and deployment qualification.

The [2026-10-22 inventory](reviews/RUST_REVIEW_INVENTORY_20261022.json) indexes
the detailed ledgers and their source identities. On Linux, `make test`,
`make check-rust`, `make fmt-check` and `make check-benchmark` use the shared
`mbx` cache. Default/all-feature targets, doctests and normal examples are
checked; process-owner tests run in private namespaces. Exact-C fixtures and
hardware-dependent cases need their separately recorded inputs and results;
an ignored test is never counted as executed merely because its binary built.
