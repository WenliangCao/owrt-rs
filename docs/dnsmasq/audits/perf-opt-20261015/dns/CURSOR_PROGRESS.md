# C name-lookup reuse screen

Base: frozen B `9b91a192583282fa546811977ee124d5873dd2db`.
Branch `perf/dnsmasq-cursor-20261015`; worktree
`/Users/USER/Developer/owrt-perf-cursor-20261015`.
This is a prototype, not a qualified candidate. Do not change A or B.

The real SDK release instruction profile attributes a substantial group of
samples to `Cache::names_for`. The annotated range contains a scalar FNV shard
loop followed by one bulk standard-library hash call and control-byte lookup;
there is no evidence of repeated `Hasher::write_u8` calls. The hot static API
already calls `has_cname` before ordinary cache lookup, so its read-only name
index search can be redundant. The prototype preserves the first inspection
and reuses only a missing or singleton selection. Multiple records retain the
normal lookup, including rotation; the hint owns no Arc/list references.

Current scope:

- A query-local `NameLookup` retains a borrow of the immutable question Name.
  The owning Cache address and its nonempty root-vector identity reject moves,
  swaps and replacement; the hint is only passed within the synchronous
  `answer_local_or_cached` call while its Cache borrow remains active.
- A saturating u64 index revision invalidates hints before each mutable
  name-index accessor and `clear`. `u64::MAX` disables reuse permanently.
  Constructor initializes it, snapshots copy it but have different owner/root
  identity. Direct index replacement occurs only in constructor or clear.
- Actual lookup still performs fresh expiry/stale/CNAME validity checks and
  the original LRU promotion. No actual lookup is moved before local answers.
  The single-slot handle generation is also checked before reuse.
- No new allocation, cache limit, hash algorithm, shard count, allocator or
  compiler setting is introduced. The Cache inline layout grows by one u64;
  actual shipped memory/code size remains to be measured if selected.
- `service.rs`/`daemon.rs` only carry the private optional hint. The event-loop
  owner confirmed these two functions are available for this experiment.

Native macOS DNS unit tests: 378 passed, 5 existing ignored fixture probes.
Four new tests cover no premature promotion, expiry at real lookup, membership
change with a still-live old handle, different questions, swapped/moved caches,
saturated revision, and no extra Many-list Arc/COW. Full Linux and frozen C
gates are mandatory if the counter screen passes; the existing A stale_metadata
investigation must not be bypassed.

Oracle sources are isolated under `dns/baseline-b` and `dns/candidate-cursor1`.
One-job native diagnostic builds are in progress; the same whole-DnsDaemon v2
probe will measure allocation and instruction counts first. No timing is
authorized. If ordinary gains cannot exceed expected device variation, reject
the added state and retain the experiment as evidence.

## Resumed screen

Recovered the pre-interruption cursor2 source and counters without replacing
any observations. Commit `71e7178d` retains the ordinary multi-record lookup
loop and returns no hint for a Many index. Its product source SHA matches the
completed isolated Oracle source `dns/candidate-cursor2`. The new assertion
only confirms that Many inspections return no hint. Three-pass whole-API
instruction changes against B: singleton hit −10.72%, miss −18.22%, dynamic
CNAME −5.28%, eight-record RRset +0.41%, hosts +0.71%, and 400 configured CNAMEs
−0.007%. The original cursor1 RRset regression was +1.87%. These are native
instruction counters, not accepted timing. The exact v2 fixture, derived
counts, and raw hashes are committed in `hotpath_probe_v2.rs` and
`cursor2-screen.json`; raw files and executables remain private.

Allocation counts and requested bytes are unchanged in nine of ten scenes.
An uppercase singleton hit avoids the redundant canonicalization allocation
(six to five calls including the fixture's question parsing, 291 to 268
requested bytes per operation). Eight-record rotation keeps its original
Arc ownership and allocation counts.

The user explicitly approved the independent stale compatibility fix
`b1136023`; this branch carries it separately as `c01cef6b`. New native macOS
DNS tests pass: 379 passed, five existing fixture tests ignored. Native quiet
timing will compare B plus that fix to cursor2 plus the same fix. Initial new
build selection failed before compilation because the host's default rustc
was 1.98.0; the retained retry explicitly selects the existing 1.98.1 toolchain.
No fixture expectations were changed. Full frozen Linux/exact-C gates and
same-build SDK/device acceptance remain mandatory.
