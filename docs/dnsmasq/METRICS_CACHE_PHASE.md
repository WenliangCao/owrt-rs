# Cache metrics: caller-owned cumulative counters

This phase implements real counter updates in the cache primitive and verifies
ordered snapshots against the full exact C reference. Product Daemon/ParentDns
integration is still pending; `enable-ubus` is not enabled by this change.
It makes no performance or production-acceptance claim.

## API and ownership

`dns::cache::CacheCounters { inserted: u32, live_freed: u32 }` belongs beside one
cache in its owner. Reading/copying it is a snapshot, not a destructive drain.
It is independent of ubus enablement. There is no new Arc, lock, atomic, heap
allocation or field in `Cache` itself.

| API | Operation / counter effect |
| --- | --- |
| `insert_counted(record, now, ttl, &mut counters)` | Run the existing insertion. Before a capacity spill, increment live_freed once if the chosen LRU victim's expiry is strictly later than now. Removing an entire RRset still counts one victim selection. |
| `insert_negative_counted(record, now, soa_ttl, fallback, &mut counters)` | Retain the existing SOA/fallback rules, then use the same counted insertion. |
| `commit_counted(&mut counters)` | Increment inserted for each successfully committed record after discarding outdated CNAMEs. Pending inserts, failed transactions and discarded CNAMEs do not count. |
| `clear_counted(&mut counters)` | Clear the existing cache and reset exactly these two u32 windows, matching cache_reload. |
| Existing `start_insert`, lookup and publication operations | Preserve their behavior. Aborting pending state does not reset counters; ordinary expiry/conflict/publication removals do not count as capacity-pressure live frees. |

Both additions wrap modulo 2^32. Pressure removal happens immediately in C;
its counter therefore remains incremented even when a later long-name allocation
limit or another insertion causes the transaction to fail. Counting only after
successful commit would lose that side effect.

The existing `insert`, `insert_negative`, `commit` and `clear` APIs remain
available with their original results and cache effects. They do not maintain
an external owner's statistics. A production owner must consistently use the
counted variants, including reload, rather than mix the two APIs.

`Metrics::set(Metric, u32)` publishes an engine-owned cumulative value or gauge
without incrementing, consuming or resetting it. It lets ParentDns construct a
snapshot from cache/lease/TCP owners while preserving each owner's window. It
does not create a second counter loop or turn unimplemented engines into zeros.

## Planned product attachment points

| Owner / file | Next integration step |
| --- | --- |
| Cache primitive, `dns/cache.rs` | Implemented here. No Cache/Slot/Entry layout change. |
| Daemon cache owner, `dns/daemon.rs` | Keep one `CacheCounters` beside its `Option<Cache>`; initialize it with the cache. Replace cache reload's `clear` with `clear_counted`. |
| Daemon `insert_cache_record` helper | Pass the counters into the dynamic `cache.insert_counted` path. A matching local hosts/DHCP target allocates no dynamic record and must not invent an insertion. |
| Daemon negative/positive insertion commit sites | Call `commit_counted`; preserve all existing `start_insert` abort paths without resetting the cumulative values. |
| ParentDns/main snapshot | Copy inserted/live_freed into the matching two Metrics slots. Leave other DNS/DHCP/lease/TCP values and their reset windows independent. |

These attachment points are not marked complete by this phase. The shared
main/Daemon and upstream/admission files remain with their respective owners.

## Exact C ordered evidence

`cache_metrics_driver.c` includes the unchanged, hash-verified exact `cache.c`
and links the remaining audited reference objects and matching libubus/libubox.
It runs actual `read_opts`, `cache_init`, insertion/commit/lookup and
`cache_reload`, then prints the real C metric values after each input step.
It starts no listener and supplies no replacement cache implementation.

`cache_metrics_diff.py` compares **25 scenarios / 215 ordered snapshots**.
Every C scenario runs three times before Rust; all C/C traces are identical.
The Rust fixture uses counted production methods and simultaneously compares
their return values and record/expiry results with the preserved ordinary API.
Expectations come from C, never from the Rust fixture.

The corpus covers pending/aborted/failed transactions, successful multi-record
commit, ordinary replacement, full-RRset pressure spill, a long-name failure
after live eviction, dangling and valid CNAMEs, negative/generic records,
expiry equality and stale boundaries, finite and unlimited stale retention,
lookup expiry, reset, and u32 wrap. Only the explicit wrap case seeds equal
initial counter state in both fixtures. Every other value results from actual
cache operations. Configuration omits enable-ubus, demonstrating the counters
are internal behavior rather than conditional on publication.

- Positive control: **215/215**, exit 0.
- Negative control: **214 pass / 1 fail**, exit 1. It changes one expected C
  commit count; actual C stdout remains unmodified in the evidence directory.
- Cache/cache-answer related unit tests: **26/26**, including regression cases
  for pressure-before-failure, reset and the counted negative-insertion path.
- The fixture verifies that publishing each cache snapshot leaves a sentinel
  unrelated Metrics field unchanged.

On the AArch64 build host `size_of::<Cache>()` is 168 bytes and the separate
caller-owned `CacheCounters` is 8 bytes. Cache fields are unchanged. The owner
will retain eight additional bytes when integrated; no throughput, CPU, total
memory or target-device cost conclusion follows from these layout measurements.
EPS1's private B0/candidate snapshots were not replaced or modified. If retained,
that candidate must later rebase onto the counted caller integration and repeat
its applicable correctness and cost gates.

Raw inputs/configuration, all three C outputs per case, Rust outputs, build
logs, identities and binaries are under ignored
`private/dnsmasq-rewrite/cache-metrics-20261001/`. Reproduce on the Linux build
host with matching reference dependencies:

```sh
python3 tools/dnsmasq/cache_metrics_diff.py \
  --reference-build "$EXACT_C_BUILD" \
  --cargo "$PINNED_CARGO" \
  --output private/cache-metrics
```

Use `--inject-error` with a fresh output directory for the negative control.
Live product UDP/TCP/cache-reload snapshots, other DNS counters and complete
ubus publication acceptance remain open.

## Daemon cache caller integration

The daemon now owns one `CacheCounters` alongside its cache. Positive, negative,
CNAME and independent SOA insertions pass it through the existing local-blocker
helper; both commit sites and reload use counted methods. Local hosts/DHCP
targets, cache hits and aborted transactions do not invent committed records.
`cache_counters()` returns a non-consuming snapshot. Cache reinitialization and
hosts reload reset only these two cache-window values.

The expanded `cache_answer_diff.py --with-metrics` invokes actual C
`extract_addresses`/`answer_request`/`cache_reload`, and the production Rust
daemon cache methods. It preserves the earlier 205-command semantic corpus and
adds pressure at capacity 150, 160 unexpired inserts, subsequent hits and reset.
After every operation, it reads and compares the actual C/Rust counters.

- **764 ordered observations**, including **164 DNS queries and 382 metric
  snapshots**, all match. Each side records 95 cache hits, 69 misses, 188 reply
  insertion events and 30 reloads. An insertion event may commit multiple records.
- The deliberate counter mutation produces **763 matches / one mismatch**,
  exits 1 and leaves the original output files intact.
- The C calibration independently requires initial/reset 0/0, first commit
  1/0 and the completed pressure trace 160 inserted / 10 live freed.
- Main/host stage regression: 328 library tests passed, six ignored;
  six main tests passed; fmt and musl all-targets Clippy passed. Ignored tests
  are separate from this explicitly executed C oracle.

Raw evidence is in
`private/dnsmasq-rewrite/cache-daemon-metrics-20261001/`: `reference-01`,
`gate-02`, `calibration-01`. `gate-01` retains a build setup failure: the remote
default Rust was 1.98.0, so Rust did not execute; `gate-02` pins 1.98.1. Final
format-only changes and the local unit regression do not replace the recorded
oracle source hashes. This establishes counted caller behavior, not real ubus
publication or full DNS/TCP cache equivalence.
