# Private TCP reference: paired host-cost feasibility

The qualified private TCP implementation can plausibly exercise the existing
hot/mixed/TCP **DNS service** workload, after a C-first workload gate and a new
measurement contract. It cannot run the existing C-only harness unchanged.
This note proposes that contract; it freezes no new experiment and implements
or runs nothing. The [composition review](TCP_SNAPSHOT_COMPOSITION_REVIEW.md)
and every primitive-candidate rejection remain unchanged.

Use private source `dff7a39` (runtime changes at `ab98013`), with native release
ELF SHA-256
`79479efd1a6efb3c35b4abed87caaa91f98190eae56d9e6ddeadc0f209680786`.
Its [qualified service gates](TCP_STREAM_IMPORT_REFERENCE_RESULT.md) establish
the scoped snapshot/writeback behavior, not this load's resource cost. C stays
the native 2.93-r1 ELF
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
Neither is the stock image ELF. Pin the existing native build recipes, Rust
1.98.1/O3/LTO and C GCC 13.3/O2, dependencies, compiler/tool hashes, kernel,
topology and source archives. Do not substitute current main or rebuild one
side silently. The worktree's later report-only commits change no component.

## Direct-reuse blockers and smallest common fixture

[dns_c_cost.py](../../tools/dnsmasq/dns_c_cost.py) checks a C-only ELF identity,
uses C `SIGUSR1` log metrics, and considers one remaining process sufficient
to drain children. Rust rejects the fixture's `log-facility` directive, installs
no SIGUSR1 handler, and remains one process while TCP threads/pipes are active.
Changing only the executable argument would therefore be invalid.

A small prospective fixture variant can omit `log-facility` on **both** sides,
capture their stderr, and enable the same existing UBus metrics object with
one private ubusd. This preserves DNS inputs while changing the observation
configuration explicitly. Freeze that new config/tool/sidecar identity before
any cost window; old calibration hashes do not authorize the new harness.
No query logging or DNS-doctor subscriber belongs in measured windows.

Keep v3's seed `0x293001`, cache 1000, EDNS 1232, forward limit 150, TCP limit
20, positive/negative TTL 120/30, rebind/source/ID checks and random ports.
Retain its corrected response payloads; do not revert to the older protocol's
RFC 5737/2001:db8 payloads rejected by C's rebind check. Actual endpoints stay
loopback in the existing isolation wrapper. Both variants use identical
normalized configuration, request bytes, cache preparation and connection
rules; runtime ports/paths are recorded explicitly.

| Scenario | Formal work per window | State and delivery |
| --- | ---: | --- |
| H: UDP hot | 100,000 at 10,000/s | 800 prefilled names; 70/30 A/AAAA; 32 clients |
| M: UDP mixed | 100,000 at 10,000/s | Full cache: 128 hot + 64 negative + 808 filler; 70/20/10 hit/unique/negative; 32 clients |
| T: TCP misses | 20,000 at 2,000/s | 8 clients; 100 queries/connection; 200 downstream and upstream connections |

Each fresh daemon gets the unchanged five-second warmup; unique warmup names
are disjoint from formal names. TCP inherits a warmed parent cache at every
admission. This exercises full snapshot, worker insertion and parent import,
amortized over 100 misses/connection. It does not cover short connections,
cached TCP traffic, mixed RR payloads, DHCP, reload or saturation.

Before cost collection, run each workload once with counters disabled, C first
and then Rust, preserving all outputs as functional evidence. Require exact
ID/flags/RCODE/questions/addresses/EDNS and the original elapsed-time TTL
bound, every planned request delivered, and the original upstream class/item
rules. Keep negative-LRU and wrong-answer/drop controls; deliberate failure
must exit nonzero. Negative retrievals under concurrency are separately
observed, not forced to C's historical 16/17: each unique positive forwards
once, no positive hot name forwards, and negative retrievals must follow the
C-established cache model. Any unexplained cache-work difference blocks a
benefit claim; do not normalize away extra forwards or weaker caching.

## Complete service accounting

Keep one CPU for the entire daemon process tree/thread group, one each for
upstream and generator, and one for observer/perf/ubusd. A Rust worker must not
gain extra cores. Retain RLIMIT_NOFILE 1024, 150 forwards and 20 active TCP
slots. Before execution, record common service-wide memory/task/aggregate-FD
budgets from the reserved host resources. Per-process NOFILE equality alone
does not establish equal aggregate fork-versus-thread headroom. Unfilled
numeric budgets are a freeze blocker, not values to select after Rust runs.

Attach perf after warmup, with counters initially disabled, and retain FIFO
enable/disable acknowledgements. Count parent plus all worker CPU, including
admission cloning, IPC, cleanup and bounded drain. Extend the existing known-
CPU calibration to threads already alive before attach, threads created after
enable by another worker, and completed/joined threads, as well as C forks.
At quiescent boundaries cross-check C parent user/system plus waited-child
CPU; cross-check Rust process-level CPU once, without adding per-thread totals
again. Keep the existing 50 ms/10% cross-check tolerance and report resolution.
Task samples can aid attribution, not replace completed-worker accounting.

UBus provides parent cache insertions and `tcp_connections`, but no equivalent
of every C log field. After clients close, keep CPU enabled until bounded
polling observes zero active slots, insertion delta equal to actual upstream
responses, no C children, and stable baseline tasks/FDs. Rust metrics dispatch
precedes another pipe drain, so one metrics response is insufficient. Keep
the five-second drain bound. Charge daemon-side observation work consistently
on both sides and report polling counts/drain separately; sidecar CPU stays
separate. Missing per-server retry/failure or exact TCP high-water counters
cannot become zero: use independent fixture item/connection checks, retain
C-only supplemental diagnostics outside timing, and mark remaining gaps.

Sample process leaders' smaps/FDs/thread counts every 50 ms plus scan time,
retaining actual timestamps, parent/children and vanished reads. Count Rust's
shared address space and FD table once; count C's process tables separately.
FD sums mean descriptor entries, not distinct open-file descriptions. Keep
USS/PSS/RSS separate; summed C RSS double-counts shared mappings. These are
sampled maxima, not absolute peaks. Retain baseline/final samples and verify
bounded daemon exit, empty process group and socket/FD cleanup. Instrument
sidecar resources separately; do not subtract their overhead from RTT.

## Fixed cost proposal and interpretation

For a bounded **paired diagnostic**, retain those existing offered rates,
not a claimed 70% of C capacity. Propose five interleaved pairs per scenario:
30 fresh formal windows, 2,200,000 requests total. Generate and archive all
pair/scenario positions from the fixed seed before collection, alternating
C/Rust order; keep five-second warmup, at least ten-second formal schedule,
two-second query timeout, 30-second client deadline, five-second drain/exit
bounds and p95 send lateness below 5 ms. Retain every failure and partial
schedule; stop on functional/instrumentation failure without replacement.

Preserve [PERFORMANCE_PROTOCOL.md](PERFORMANCE_PROTOCOL.md)'s 5% CPU/p95/
throughput regression guard and private-memory allowance `max(64 KiB, 5% of
C)`. Predeclare per-pair ratios, worst-pair guards and the ratio range used to
identify differences smaller than observed spread; publish absolute values
and all pairs, never pooled percentiles or selected medians. Keep p50/p95 and
p99 only for at least 10,000 samples; 200 connection samples do not qualify.
This subset cannot satisfy the protocol's cache/mixed/**DHCP** geometric-mean
15% CPU or mixed/DHCP 10% memory objectives. Its C capacity calibration,
30-minute stability, failure/resource-pressure and target gates remain open.

Exactly one additional profile-only TCP window per implementation could use
the same work, separate from formal results. The Rust release is stripped;
matching symbol/debug evidence is currently missing. Resolve that identity
before promising snapshot attribution; a different profile ELF is separately
pinned and never mixed into the formal series. Preserve lost-sample counts
and require at least 100 verified snapshot-stack samples for ranking that
phase; otherwise report its share unresolved, with no longer/retry window.
Classify admission cache/config/hosts cloning, worker cache work, and parent
import by verified call stacks, not all allocator samples. LTO/inlining or too
few snapshot samples may leave its CPU fraction unresolved. Smaps alone also
cannot divide Rust USS into cache copies, stacks, buffers and allocator slack.
The minimal diagnostic measures service cost; it does not supply exact
snapshot-exclusive heap or establish a causal speedup from primitive timings.

The [nine C windows](C_COST_RESULT.md), their corpora, identities, calibrated
validators and retained profiles remain useful historical evidence. **None is
a new paired denominator**: configuration/observer boundaries change, there
was no contemporary Rust partner, and those three rounds are not this five-
pair schedule. All C/Rust formal pairs and scope calibrations must be fresh.
This does not reopen any rejected window or alter a primitive threshold.

Outstanding blockers are the common observation adapter/config functional
gate, thread CPU/drain/resource calibration, numeric shared budgets, frozen
run manifest and symbolic attribution evidence. OOM, native-wire saturation,
large malformed transfers, musl-image service and production resource behavior
remain unqualified. No product promotion or new timing follows from this note.
