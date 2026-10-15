# Repeated SDK preparation repair

The first D attempt (`root/private/sdk-d`) failed the existing prepared-source
SHA check before compilation; no artifact from it was qualified. The reused
owned build slot still contained C's `cache.rs` (`df81dd0e…`) and `cache_tests.rs`
(`cfa5788c…`) instead of D's `ca58d871…` / `39b5f1a…`. Both `.prepared_*` markers
were present. OpenWrt's prepare stamp does not include this external source path.

This is the real integration reproducer: build C in the stable owned slot, then
request D via the unchanged recipe and source-binding builder. `make prepare`
returns without recopying the external snapshot; the existing hash assertion
rejects it. The failed command/log/source manifest remains under sdk-d.

Separate fix `5e6c41f6` invalidates only that owned slot's prepare markers under
the SDK lock. The recipe now recopies the snapshot, while the external Cargo
cache survives. Compiler/profile/package flags are unchanged. The same source
checks run after prepare and after build; they were not weakened.

The fresh integration rerun (`root/private/sdk-d-fresh-prepare`) removed exactly
the two recorded prepare markers, passed all 179 Git-bound input checks, built
D ELF `4167609f…` (2,136,859 bytes), and verified source/SDK files unchanged.
This is the regression check against the actual stale-slot failure, rather than
a mock of marker deletion. Its [receipt](candidate-d-build.json) includes builder,
helper, source and artifact hashes. The builder ran from a separate private tool
directory, keeping the frozen D source tree and all in-flight C files untouched.
