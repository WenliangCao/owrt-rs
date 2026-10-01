# Private reverse candidate: backward and ordinary allocation checks

The unchanged private product source **`62894d6`** passes the existing forward
cache corpus and typed forward-transfer contract. Native and SDK-linked musl
test executables also pass their complete library/main suites inside Linux
network namespaces. These checks do not promote the reverse implementation to
main or qualify local/DHCP coexistence, reverse transfer or performance.

| Check | Native AArch64 | AArch64 musl |
| --- | --- | --- |
| Existing forward cache corpus | 22,571 commands, zero differences | Not rerun |
| Existing typed forward transfer | 36 cases / 307 observations, zero differences | 36 cases / 307 observations, zero differences |
| Isolated library tests | 393 passed, 16 ignored | 393 passed, 16 ignored |
| Isolated main tests | 7 passed | 7 passed |
| All-target Clippy, warnings denied | Pass after source-tool assembly correction | Pass after source-tool assembly correction |

## Existing C expectations and isolation

The forward replay uses the saved exact-C outputs from the retained inline16
oracle directory. Its 21 original scenario configurations, all 22,571 command
inputs and their input hashes are checked before executing the newly compiled
Rust primitive driver. No C process or multi-target cohort is rerun. Every
saved C input/output and new Rust output has a retained hash.

The original allowance for relative order **across different generic RR
types** remains unchanged: 138 such rows are recorded separately. Order within
each type, payload, expiry, negative status, reply TTL and stale flag still
compare exactly. This existing forward allowance says nothing about the
unqualified order of multiple reverse PTR targets. A one-TTL mutation is
detected, and a missing output row is rejected.

The unchanged transfer comparator verifies the original plan, baseline identity
and all 216 C stdout hashes, then uses the existing 36 cases / 307 observations.
Its counter mutation and short-output checks still pass. The library binaries
are built by the ordinary build-host user outside sudo, then executed inside
`run_isolated.sh`. An independently hashed cargo replay shim supplies that
already-built library artifact to the comparator's build step; its saved
provenance records the actual prior build command and checks the ELF hash. It
does not run cargo inside the namespace, alter source, modify expected rows or
substitute probe results. Full library/main tests use the same verified ELFs.

The first native and musl all-target Clippy attempts both exited 101 because
the frozen product archive contained only `components/`, while several probe
bins use `include!` for files in `tools/dnsmasq/`. Both stderr logs are retained.
Extracting the exact `62894d6` tools archive supplied those missing dependencies;
the second attempts pass without a component-source edit or warning waiver.

## Actual layout and ordinary allocations

An independent untimed allocator audit reuses the original five ordinary cases
and historical expected vectors from
[the typed-transfer audit](TCP_CACHE_TRANSFER_RESULT.md). The unchanged
original tool completes all 15 baseline/ordinary/capture runs. A separate
instrumented-module wrapper then compares the immediate forward baseline
`7a9cadd` and candidate `62894d6` in ten ordinary runs, including explicit
deallocation counts. All vectors match and every cache lifetime ends with
zero outstanding requested bytes.

| Type | Size / alignment, both sources |
| --- | --- |
| Cache | 168 / 8 bytes |
| Slot | 160 / 8 bytes |
| Entry | 120 / 8 bytes |
| Record | 56 / 8 bytes |

| Ordinary commit case | Alloc / realloc calls | Requested bytes | Live-byte change | Dealloc calls / bytes |
| --- | --- | --- | --- | --- |
| Empty | 0 / 0 | 0 | 0 | 0 / 0 |
| One address | 3 / 0 | 245 | 245 | 0 / 0 |
| 128 addresses | 263 / 0 | 30,342 | 17,946 | 6 / 12,396 |
| Invalid CNAME | 1 / 0 | 8 | -9 | 2 / 17 |
| Failed transaction | 0 / 0 | 0 | 0 | 0 / 0 |

Layout access is appended only to a generated copy of the cache module; the
product source remains byte-identical. The allocator's original preparation
and cases are unchanged. Its initial missing-tool-path exit 2 is also retained,
followed by a successful run from a separate copy of the same-commit tooling.

These are native AArch64 requested allocation deltas around ordinary forward
commits. They do not measure reverse lookup/insertion allocations, mixed
populations, musl allocator behavior, RSS, OOM, service memory or CPU speed.
Reverse lookup remains an O(capacity) scan; no timing run was conducted.

## Retained identities

The product archive is
`d20889ad0c6ccfbecc5737bfb533e3b5691730e571f4c379ccb102c0a0a38134`;
the cache source is
`959592939af416989e4d7821a01f7ce54fcb368c8fdc9b85d3501f0cbd8d7f44`.
Component file hashes are rechecked after execution. Test ELF, tool, wrapper,
baseline, report and manifest identities are listed in
[the derived JSON](REVERSE_CACHE_BACKWARD_RESULT.json).

The 350-file backward archive is mirrored under ignored
`private/dnsmasq-rewrite/reverse-backward-20261001/backward-62894d6-01/`.
The independent 108-file allocation/layout archive is under ignored
`private/dnsmasq-rewrite/reverse-resource-static-20261001/evidence-01/`.
Each mirror is verified against its remote SHA manifest. Commands, every
attempt, saved inputs/outputs and tested binaries remain private. This work
does not modify main, access a physical router or change deployment state.
