# C-only host cost diagnostic v2 — frozen before measurement

2026-10-01. This is a small source-cost investigation, not the paired acceptance
run in `PERFORMANCE_PROTOCOL.md`. It does not establish C's capacity ceiling,
set a future Rust offered load, modify the protocol's 15%/10% goals, or permit
cross-window Rust speedup claims. Router performance still requires a separate
authorized target measurement.

## Why v2 supersedes v1 before any formal cost result

The v1 functional calibration correctly failed: exact `rfc1035.c:432–434,454`
classifies RFC 5737 IPv4 and `2001:db8::/32` as rebind responses. Keeping both
those payloads and `stop-dns-rebind` cannot yield successful positive cache
traffic. `calibration-02` retained 1 success / 3 errors / 1 timeout; none of its
latency values is a performance result.

V2 changes only positive fixture RDATA: IPv4 uses the isolated benchmarking
range documented in [RFC 2544](https://www.rfc-editor.org/rfc/rfc2544.html), and
IPv6 uses the documentation prefix from
[RFC 9637](https://www.rfc-editor.org/rfc/rfc9637.html). The exact C classifier
allows these payloads. No packets are addressed to either range: all actual
socket endpoints remain loopback. Rebind protection, ID/source validation,
limits, counts, rates, rounds, CPU windows and acceptance criteria remain
unchanged. No domain exception or disabled security check is introduced.
This is a C-only diagnostic fixture correction; `PERFORMANCE_PROTOCOL.md`'s
future paired acceptance plan is not silently rewritten.

## Source questions

- `cache.c:1174–1260`: a cache query scans a name hash bucket, checks expiry and
  CNAME validity, compares names and changes LRU links. `answer_request` first
  searches CNAME/NXDOMAIN and then the requested address family. Measure the
  hit path's user/kernel split and sampled functions; do not assume hash lookup
  dominates socket and protocol work.
- `cache.c:518–602,737–781`: when the LRU tail is occupied, each insertion first
  scans every bucket for expired records and then spills a conflicting RRset.
  The full scan is O(records + buckets). A full, mostly unexpired mixed cache
  tests whether that work is large enough to motivate a different expiry
  index; no Rust saving is inferred from complexity alone.
- `forward.c:2036–2196` and `dnsmasq.c`'s TCP fork/caching pipe: normal TCP
  sessions reuse upstream connections, but downstream sessions still incur
  fork/close and cache IPC work. Count the full C process tree, not only the
  listening parent. The same field cannot mix live children with already
  reaped CPU a second time.

## Fixed fixture and work

Reference: exact native Linux C 2.93-r1 `nodhcpv6` ELF
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`,
source archive/patch identity from the delivery ledger, recipe's six COPTS,
existing `-O2 -g` native build and matching libubus/libubox dependencies.
No Rust daemon is run in this diagnostic.

All names are synthetic `.test`; seed is `0x293001`. Only the frozen fixture
answer payloads use the benchmark/documentation addresses described below. Configuration keeps cache
capacity 1000, EDNS 1232, `dns-forward-max=150`, positive upstream TTL 120,
`neg-ttl=30`, `max-tcp-connections=20`, `stop-dns-rebind`, default source/ID
checks and random source ports. No hosts/resolver input, query logs, capture,
fuzz, compilation or concurrent agent workload is allowed in measured windows.
C, client and controlled upstream have RLIMIT_NOFILE 1024. The deterministic
upstream serves A `198.18.0.7`, AAAA `3fff::7` and no-SOA NXDOMAIN; it listens
on loopback IPv4/IPv6 UDP/TCP with nominal reply delay 1 ms. The measured client
and selected upstream transport are IPv4; record types remain 70% A / 30% AAAA.

| Scenario | Formal requests per round | Predeclared offered schedule and concurrency | Cache/connection state |
|---|---:|---|---|
| UDP hot | 100,000 | 10,000/s, 32 clients, at most one pending query per client | 800 names (560 A / 240 AAAA), prefilled and warmed for 5 s; every formal query should hit |
| UDP mixed | 100,000 | 10,000/s, 32 clients | 70,000 positive hits from 128 hot names, 20,000 globally unique positive misses, 10,000 negative replies from 64 prefilled NXDOMAIN names; 808 unused positive filler entries make the cache full before the 5 s warmup |
| TCP miss | 20,000 | 2,000/s, 8 clients | Unique formal names, 100 queries per downstream connection, 200 connections; 5 s separate-name warmup; record connect latency separately |

The mixed A/AAAA schedule is independent of its hit/miss/negative class. Full
request vectors and hashes are generated from the frozen seed before each run.
Its warmup uses the same class mix with disjoint unique names, so the full-cache
insertion path is exercised before formal collection as well as the hit path.
All three formal schedules cover 10 s. Three fresh-daemon rounds are run per
scenario in the fixed order `(hot,mixed,tcp)`, `(mixed,tcp,hot)`, `(tcp,hot,mixed)`.
This reduced C-only diagnostic is not the protocol's five interleaved C/Rust
rounds or its 70%-of-C-capacity comparison.

A response delay never changes the planned times or request count. Actual
send, receive, validation and planned times are retained, exposing backlog and
caller overhead separately. This is an offered-load measurement, not a claimed
throughput ceiling. Per-query timeout is 2 s. A formal round requires every
planned request sent/completed successfully, zero wrong answers/timeouts,
exact expected upstream counts (0 / 20,000 / 20,000), and p95 send lateness
below 5 ms; any failed window is retained and not used as a clean baseline.
Positive answer TTL must stay within the elapsed warmup/window bound; record
flags, IDs, addresses, qtype/class, RCODE and EDNS semantics are validated.

## Counters and boundaries

Use four available CPUs with fixed affinity: C process tree on the first,
upstream on the second, generator on the third, observer/perf on the fourth.
Record the actual affinity/topology, kernel, compiler, ELF/dependency identities
and idle-host check. Coordinate with other agents before each formal run.

`perf stat` attaches to the C parent with default child inheritance and events
initially disabled. FIFO enable/disable acknowledgements bound the formal
window; warmup is excluded. Collect task-clock, cycles, instructions, context
switches, migrations and faults. The window includes completion and bounded
child/IPC drain; retain that drain duration separately. Cross-check C CPU
against `/proc` user/system plus waited-child counters at quiescent boundaries,
with their 100 Hz quantization recorded. Upstream, generator and observer CPU
are separate, never added to C's numerator or silently subtracted from RTT.

At 50 ms intervals retain C-tree RSS, PSS, USS (Private_Clean + Private_Dirty),
FD/thread/process counts and parent-versus-child components. These are sampled
peaks, not proof of an absolute instantaneous maximum. RSS is not exclusive
memory. Record per-round p50/p95 and p99 only with at least 10,000 valid samples,
planned-to-receive latency, actual-send-to-receive latency, validation overhead,
upstream scheduled-versus-actual delay, completion throughput and CPU/completion.
All raw samples and all rounds remain private; do not replace them with an
average that hides a tail or memory outlier. Check process/socket/FD cleanup.

One additional profile-only run per scenario uses the same fixture/schedule
and `perf record -F 997 --call-graph dwarf`; its instrumented latency/CPU is not
mixed into the baseline rounds. Keep perf data and stderr/lost-sample reports,
then inspect self cost by DSO/symbol. Fewer than 100 useful C samples means the
function ranking is inconclusive; do not silently lengthen or choose a better
window after seeing it. No 30-minute stability claim is made by these 10 s
windows; that protocol gate remains open.

Before formal work, calibrate normal/wrong-data/drop response counters and
require deliberate failures to produce a failed result. Separately calibrate
perf's units, FIFO start/stop and inherited child CPU with a controlled process
that consumes a known amount of process CPU. A missing/invalid counter or lost
counter scope blocks measurement rather than being replaced with zero.

The control/acknowledgement and default inheritance semantics are checked
against the installed perf 6.17.13 help and the primary
[Linux perf-stat documentation](https://github.com/torvalds/linux/blob/v6.17/tools/perf/Documentation/perf-stat.txt).
The shared protocol's later product-size, long-growth, paired-resource and
physical-target gates remain separate.
