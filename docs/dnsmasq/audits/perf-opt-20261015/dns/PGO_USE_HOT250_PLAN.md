# One profile-use build with hot callsite threshold250

The first fixed-profile use artifact failed both release size budgets. Its
[same-link map analysis](PGO_USE_SIZE.md) locates most net growth in trained
caller bodies. Root authorized one follow-up build, changing only the backend
hot callsite threshold to250. There is no threshold search, new training,
reweighting, source prototype or optimization-level change.

The rationale is explicitly upstream LLVM22 evidence:
[`InlineCost.cpp`](https://raw.githubusercontent.com/llvm/llvm-project/release/22.x/llvm/lib/Analysis/InlineCost.cpp)
initializes the hot callsite threshold to3000;
[`InlineCost.h`](https://raw.githubusercontent.com/llvm/llvm-project/release/22.x/llvm/include/llvm/Analysis/InlineCost.h)
defines the O3 aggressive threshold as250. The generic inline CLI default225
is a different setting. These source constants are not a direct observation
of the pinned Rust compiler's internal defaults. Its local hidden help only
establishes option availability. Context7 found the LLVM library but no
matching snippet; the linked upstream release/22.x source was read directly.

The [frozen plan](pgo-use-hot250-plan.json) retains source E, all 50 raw profile
identities and merged profile SHA256
`71adfc9533505fbe8ec7f564ad7029626e7cb504cd5287c246b1897d9d46b723`.
It binds the prior rejected use build, original E receipt, canonical prepared
source path and exact former use flags. A fresh output/target lives under
`dns/private/pgo-use-hot250`; only one SDK build is permitted.

The [wrapper](../../../../../tools/dnsmasq/pgo_hot250_cargo.py) reuses the
original use-wrapper argument/environment/profile gates and appends exactly:

```text
-Cllvm-args=-hot-callsite-threshold=250
```

The preceding `-Cllvm-args=-pgo-warn-missing-function` remains present. A real
pinned Rust1.98.1 test compiles a tiny arithmetic library to LLVM IR with both
arguments. The valid pair succeeds; an invalid boolean in the first argument
is still rejected when followed by valid250, and an invalid integer in the
second argument is also rejected. This demonstrates that repeated
`-Cllvm-args` reach LLVM rather than the latter silently replacing the former.
[Raw argument-check evidence](pgo-hot250-llvm-args-check.json) is retained;
no product workload or performance measurement is involved.

The [controller](../../../../../tools/dnsmasq/pgo_hot250_build.py) rehashes the
50 raw files, merged profile, receipts, original source/SDK and tools before
building, then repeats the checks afterward. It preserves every output,
compiler diagnostic and process cleanup result. The effective invocation must
equal the prior use flags plus only that one argument. Fixed threshold250 is
checked explicitly; other values are rejected.

The unchanged SDK builder retains its normal lock, original opt3/fat-LTO/
codegen1/panic/strip recipe, static PIE adapter and hardening. The resulting
ELF/APK must fit the original 2,200,000 /1,200,000-byte budgets and match the
baseline static PIE/RELRO/NX layout. Map/prestrip/ELF identities and absence of
profiler runtime are checked. Missing-function diagnostics remain visible;
profile hash/CFG/staleness errors or any budget/hardening failure stop this
attempt without workaround.

The two local tests passed: capture-only Cargo verifies the exact single-flag
delta and rejects another threshold, while the real compiler checks both LLVM
arguments. No new product build has run at plan freeze. After commit and
read-only review, root authorized this one non-timing SDK build, with the SDK
reservation held through postflight and then released for the queued54bd
build. Passing these build gates yields an unqualified research artifact;
full correctness and independent performance evaluation are later work.
