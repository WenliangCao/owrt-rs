# PGO SDK smoke3 passed; training and performance remain untested

Smoke3 reproduced the frozen E ELF exactly, then built and ran its
profile-generate variant with the unchanged SDK recipe, static PIE linker and
hardening. The isolated foreground daemon answered the two fixed local
queries, exited normally on SIGTERM, wrote one raw profile, and the matched
LLVM tool merged and read it successfully. This establishes the narrow
instrumentation/collection path, not an optimized profile-use artifact or a
performance benefit.

Root's conditional authorization and loop's explicit release followed the
three completed native screens. This attempt used CPU0 and the SDK reservation;
the separately authorized correctness work could run on CPU2. No timing,
representative training, profile-use build, router access or deployment was
performed. The SDK reservation was released after final cleanup.

## Build identities and unchanged gates

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| Exact E control | 2,136,859 | `8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27` |
| Generate diagnostic | 4,194,409 | `3ba940df09f96606af3e4fc8f27c11a2b50788c5cc0e13cd8ca71357dbb381ad` |
| Raw profile | 577,080 | `b18c037e4c31d1a5d13147098ec97be4e7dd992f09b5dea1e322c4059c7f8247` |
| Merged profile | 924,952 | `2e92f1f1bbf516d4474b35fcf75aeb39b0d410ed75947d71edbe040fbb877840` |

The fixed plan SHA256 is
`4b0995debd455f38a680b44b04725737d5dd7609aa19c3dfbaaea1a1cbd9eea1`;
controller/source tooling was committed before execution in `3b4abe0b`.
Control and generate have identical 179-file source inventories and SDK
identities. Their effective flags differ only by
`-Cprofile-generate=/home/ubuntu/dnsmasq-perf-20261015/dns/private/pgo-sdk-smoke3/profraw-default`.
Both retained opt3, fat LTO, codegen1, panic-abort, stripping, original SDK/BFD
and static PIE adapter. The wrapper pinned the same Rust 1.98.1 compiler for
Cargo discovery; no expected ELF hash or protection check was relaxed.

Both SDK artifacts passed ET_DYN/AArch64, no interpreter or needed libraries,
RELRO/bind-now/NX stack and no writable-executable load checks. The generate
ELF is 2,057,550 bytes (+96.29%) larger; its APK is 2,006,244 bytes. It exceeds
the existing 2,200,000-byte ELF and 1,200,000-byte APK budgets, exactly as its
receipt reports. This excluded instrumentation artifact is not a release
candidate. Release/profile-use budgets are unchanged, and no profile-use
size or memory conclusion is available.

## Runtime and profile evidence

The existing isolator created fresh network, mount and PID namespaces. The
foreground daemon was PID3 inside the namespace and its live executable hash
matched the generate artifact. It returned the fixed A `192.0.2.1` and AAAA
`2001:db8::1` answers for `pgo-smoke.test`, preserving IDs and TTL120.
The config had no upstream; the corresponding warning is retained as expected.

Runtime mappings established read-only coverage of the full GNU_RELRO page
range, no writable-executable mapping and a non-executable stack. SIGTERM
produced status zero, the normal exit log, and no forced cleanup. Exactly one
nonempty `runtime/3.profraw` was present; the compile-time default output
directory remained empty. There was no helper child or manual flush hook.

The matched `llvm-profdata` SHA256 was rechecked as
`c7160d195180796edf7cc4c3f087f72b5425fc9ec2d9734b956a265e506f982e`
(LLVM22.1.8 for Rust1.98.1). Merge and `show --all-functions --counts` both
exited zero with empty stderr. Show reported IR instrumentation, 2,838
functions, 42,472 blocks, maximum function count293 and total count10,862.
These are profile format/activity checks, not representative coverage. This
smoke profile must not be reused as training data.

All eight recorded controller commands succeeded in the fixed order: three
tool versions, control build, generate build, isolated runtime, merge and
show. Final checks found no smoke process, an available SDK lock, both recipe
restorations, unchanged 179 source / 106 SDK file hashes, and unchanged bound
tools/artifacts. All owned process groups exited. Root and loop were notified
that no further PGO work would run automatically.

## Preserved failures and remaining work

[Smoke1](PGO_SDK_SMOKE1_FAILURE.md) failed before compilation when direct Cargo
could not find rustc. Restoring the stock proxy and explicitly pinning the same
compiler fixed discovery. [Smoke2](PGO_SDK_SMOKE2_FAILURE.md) compiled but failed
the exact-E gate after moving the Cargo path-dependency source location.
Restoring the original prepared build path reproduced exact E in smoke3.
Neither earlier failure was overwritten or excluded from the record.

The remaining separate questions are representative 11-scene training,
profile-use compilation/diagnostics, complete frozen-C correctness and
resource/size qualification, and any CPU/cycles/latency benefit. This result
does not answer those questions or authorize deployment.

[Complete derived result](pgo-sdk-smoke3-result.json) binds both build receipts,
effective flags, runtime query/protection/exit evidence, profile identities,
all command outputs and cleanup. Raw profiles, maps, logs and binaries remain
in Oracle private `dns/private/pgo-sdk-smoke3`. Only 130,165 compressed bytes
of textual receipts/profile-show output were copied locally after completion.
