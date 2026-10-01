# TCP snapshot representation: correctness and allocation screen

Four private representations pass the existing exact-C cache primitive corpus
while a snapshot stays alive across every operation. Allocation accounting is
complete; formal timing has **not run**. No representation is accepted for the
product by this screen. The frozen criteria remain in
[`TCP_SNAPSHOT_SCREEN_V1.md`](TCP_SNAPSHOT_SCREEN_V1.md).

The baseline is commit `e77d966d0bf92e5296f73ee3e54fdaf960ed7781`, before the
TCP writeback journal. Its cache SHA-256 is
`8c73672d4ebe3959d8172cecf5b951afef61f23ec568c52b27f6b00ae081e9a5`.
The tools copy this source, `wire.rs` and the lease trait declarations into
private variant trees. Literal transformations assert every expected edit
point. Product source is not changed. Rust is native Linux aarch64 1.98.1,
release optimization, LTO and one codegen unit; allocation instrumentation
has separate binaries.

## Correctness and calibration

Each of `deep`, `compact`, `shared` and `top` passes 21 scenarios and 22,571
operations, with zero mismatches. This covers primitive pending insertion,
commit/abort, eviction, expiry, TTL clamps/stale records, CNAME generations,
name case, long names and answer rotation. A clone is retained until each
operation finishes, exercising shared-entry and top-level detachment.

The C outputs are reused unchanged from the calibrated
`cache-expiry-eps1/counted-3277404/legacy-b0-01` corpus. Preparation verifies
every input against the current corpus generator and verifies the exact C
source hashes. C is not rerun and Rust never supplies an expected answer.
Each representation has 138 allowed cross-type Generic RR ordering
variations. Ordering within one RR type, data, absolute expiry, reply TTL,
negative status and stale flags remain exact. The negative control changes
one reply TTL: 12 matching rows, one detected failure and exit status 1.

These are cache primitive gates. They do not establish TCP service snapshot,
clock, writeback, failure isolation or complete protocol equivalence.

## Requested heap and allocation work

Values are allocator-requested live bytes, not RSS/PSS or exclusive physical
memory. Snapshot columns include **20 simultaneous images and their first
mutable lookup**. The prepared input records and measurement buffers are
outside these deltas. All 16 allocation runs finish 20 successful operations
each: 320 completions, zero errors, and balanced snapshot and parent drops.

| Capacity / occupancy | Representation | Parent live bytes | 20 snapshots after lookup | Snapshot peak extra |
| --- | --- | ---: | ---: | ---: |
| 150 / empty | deep | 24,000 | 480,000 | 480,020 |
| 150 / empty | compact | 21,600 | 432,000 | 432,020 |
| 150 / empty | shared | 4,800 | 96,000 | 96,020 |
| 150 / empty | top | 24,184 | 483,680 | 483,700 |
| 150 / full | deep | 51,338 | 954,120 | 954,249 |
| 150 / full | compact | 48,938 | 906,120 | 906,249 |
| 150 / full | shared | 52,538 | 460,140 | 460,269 |
| 150 / full | top | 51,522 | 957,800 | 957,872 |
| 1,000 / full | deep | 358,792 | 6,695,200 | 6,695,329 |
| 1,000 / full | compact | 342,792 | 6,375,200 | 6,375,329 |
| 1,000 / full | shared | 366,792 | 3,401,200 | 3,401,329 |
| 1,000 / full | top | 358,976 | 6,698,880 | 6,699,009 |
| 10,000 / full | deep | 3,386,856 | 62,936,480 | 62,936,609 |
| 10,000 / full | compact | 3,226,856 | 59,736,480 | 59,736,609 |
| 10,000 / full | shared | 3,466,856 | 29,996,480 | 29,996,609 |
| 10,000 / full | top | 3,387,040 | 62,940,160 | 62,940,289 |

The original slots inline a 120-byte `Entry`, generation and two optional
indices, for 160 bytes per slot. Encoding those two indices as
`Option<NonZeroUsize>` reduces slots to 144 bytes. Sharing entries moves the
entry payload to an `Arc` allocation and reduces the slot to 32 bytes. The
cache header remains 168 bytes and `Record` remains 56 bytes. Top-level
`Arc<Cache>` makes the image handle eight bytes, but mutable lookup detaches
the complete cache.

At full capacities 1,000 and 10,000:

- `compact` reduces snapshot live bytes by 4.78% and 5.08%. It fails the
  frozen 20% snapshot-memory target even before CPU measurement.
- `shared` reduces snapshot live bytes by 49.20% and 52.34%, while parent
  live bytes increase by 8,000 and 80,000 bytes (2.23% and 2.36%). Population
  adds one allocation per entry: 7,012/70,015 allocation calls against
  6,012/60,015 for `deep`; reallocations stay 2,200/22,000. For 20 snapshots,
  clone allocations fall from 80,040/800,040 to 40,040/400,040. First lookups
  have 80 allocations in both. This passes the deterministic memory gates;
  population CPU and tail latency may still reject the candidate.
- `top` performs no allocation when cloning the handle, but the first
  mutable lookups perform 80,140/800,140 allocations and retain slightly
  more heap than `deep`. It fails the snapshot-memory target.

Snapshot peak counters reset before the group. In raw allocation vectors,
indices 0–3 mean allocation calls, reallocations, requested allocated bytes
and live-byte change. Index 4 is a historical peak counter difference; its
population value is **not** used as a population-window peak. The separately
reported `peak_extra_requested` is the snapshot-group peak above its starting
live bytes.

## Evidence and remaining gate

The reproducible tool is
[`tcp_snapshot_screen.py`](../../tools/dnsmasq/tcp_snapshot_screen.py), with
[`tcp_snapshot_screen.rs`](../../tools/dnsmasq/tcp_snapshot_screen.rs).
Phases are `prepare`, `gate`, `allocation`, `timing` and `summarize`.
`prepare` requires a frozen source root/cache hash, the existing C corpus,
the exact C source tree and the pinned compiler. `timing` requires a prior
passing gate and an explicitly coordinated quiet-window label; none has been
used for this result. All three fixed round orders and four profiles remain
unchanged.

[`TCP_SNAPSHOT_SCREEN_ALLOCATION.json`](TCP_SNAPSHOT_SCREEN_ALLOCATION.json)
records source/binary identities, all derived allocation rows and evidence
hashes. Raw evidence is ignored under
`private/dnsmasq-rewrite/tcp-cache-20261001/snapshot-screen/`, notably
`native/private/screen-01/{manifest,gate,allocation,allocation-result}.json`
and their per-invocation logs. The first remote archive extraction failed
because an earlier experiment owned its `private` directory as root. The
failure is retained in `preparation-failure-01.json`; this run uses a new
owned subtree and leaves the earlier experiment intact.

CPU fields emitted by allocation binaries are diagnostic and are not used
as performance evidence. Population CPU, combined snapshot/lookup CPU,
p50/p95 wall cost and throughput remain pending a coordinated timing window.
The later TCP journal's fixed header and allocation costs are outside this
frozen source. There is no C-versus-Rust speedup claim, complete component
resource acceptance or router measurement here.
