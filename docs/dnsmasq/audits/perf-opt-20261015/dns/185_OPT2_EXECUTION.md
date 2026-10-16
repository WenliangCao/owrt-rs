# Actual803 original gates and profile2 SDK

The original five fresh Linux groups passed957 tests: lib836, bin82,
allocations17, lib-ignored-live18 and bin-ignored-live4. Actual logs and the
original test listings matched all fiveG185 name sets. These were fresh803
binaries, with no inherited pass and no test rerun. The original dev/test
entry and its release-environment metadata remain unchanged.

The independently reviewed opt2 builder completed once with exit0. Both actual
lib/bin rustc commands show opt-level2, codegen1, panicabort and stripsymbols;
the final bin uses fatLTO. The original allocator, features, linker, hardening
and budget were preserved. The canonical opt3 builder was not modified.

| Actual artifact | Bytes | Original limit | Result |
| --- | ---: | ---: | --- |
| Shipping ELF | 2,046,747 | 2,200,000 | PASS |
| APK | 1,126,646 | 1,200,000 | PASS |

Source179 and Git identity were rehashed. Static AArch64 PIE, RELRO, BIND_NOW,
NX stack and no writable executable load passed. SDK inputs remained unchanged;
the original helper completed recipe restoration with no leftover backup.
Current recipe hashes are recorded without claiming a missing pre-build hash
snapshot. Original fakeroot loader warnings remain in the compile log.

The related archive contains46 payload entries plus its manifest, including
all three test ELFs and the originalG receipt/logs. The SDK archive contains39
payload entries plus its manifest, including shipping ELF, APK, map, prestrip,
compile/readelf/extract logs and extracted package payload. Every downloaded
file was rehashed. Full identities and private paths are in the
[execution result](185-opt2-execution-result.json).

The postflight observed both workers exited, no research/exactC processes and
all three build locks available. Independent actual-result review and final
transfer/handoff are still pending in this checkpoint. No performance timing,
runtime-hardening acceptance or deployment was performed.

After review and necessary pretransfers, the authorized next steps are original
exact-SDK owner32 and freshG/803 device ten in parallel. Native240 is excluded
because its original probe compilation fixes opt3. Bare1df remains a separate
subsequent experiment.
