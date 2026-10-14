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
