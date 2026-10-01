# C-only host cost diagnostic result — 2026-10-01

The frozen v3 diagnostic has **9 accepted formal windows: 660,000 planned,
sent and successful requests; zero incorrect answers, timeouts or unsent
requests**. Three separate profile windows completed. This is a C cost baseline
on an isolated Linux build host, not a C/Rust comparison, a capacity ceiling,
a completed optimization gate or router performance evidence. No new workload,
build, candidate selection or physical-device operation was run for this report.

The clearest source-cost finding is the full-cache insertion scan: C scans all
cache buckets before evicting an unexpired LRU record. `cache_scan_free` accounts
for 11.07% of sampled self cycles in mixed traffic and 21.54% in TCP misses.
This supports investigating expiry indexing while preserving C's conflict,
CNAME, TTL and eviction behavior. It does not establish a Rust saving.

## Frozen inputs, identities and accepted sequence

[C_COST_DIAGNOSTIC_V3.md](C_COST_DIAGNOSTIC_V3.md) defines inputs and gates.
Cache capacity 1000, positive TTL 120 s, negative TTL 30 s, EDNS 1232,
forward limit 150, TCP-child limit 20, rebind protection and default source/ID
checks are unchanged. All actual socket endpoints are namespace loopback;
measured transport is IPv4 UDP/TCP with A/AAAA questions. There is no IPv6
transport, DHCP, failure, reload or long-duration cost conclusion from these
three scenarios. Upstream nominal delay is 1 ms.

C is the pinned native Linux dnsmasq 2.93-r1 nodhcpv6 build, SHA256
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`,
`-O2 -g -Wall -W`, with recipe COPTS `HAVE_UBUS`, `HAVE_POLL_H`,
`NO_DHCP6`, `NO_AUTH`, `NO_IPSET`, `NO_ID`. The 1,650,080-byte debug ELF
is not the target image's ELF and is not a target-size comparison. Compiler:
Ubuntu GCC 13.3.0; kernel `6.17.0-1020-oracle`, aarch64; perf 6.17.13.
C/upstream/client/observer affinities are CPUs 0/1/2/3. Four Neoverse-N1 cores
were observed during later artifact analysis; contemporaneous results record
the affinities and architecture, but not a complete CPU topology dump.
The measure-02 load-before sample was 0.00/0.00/0.00. It is one idle-host
observation, not proof that the host had no unobserved activity.

Measurement tool SHA256:
`78bc4fe9a77a6f4c1ddc9cc00c0e57f46710a958376200ac51fa74ad2be7a86d`;
frozen v3 plan SHA256:
`4dd4c9653880b573f48d9161e1251882723b4952da17990d117d68dd0df69c9f`.
Dependency hashes remain in the private series summaries (libubox, libubus,
libc and loader); no dependency identity was changed for this analysis.

The fixed sequence is H1,M1,T1; M2,T2,H2; T3,H3,M3. H1 is the originally
accepted `measure-01/round-1-hot`, reused exactly as v3 permitted. Its original
summary hash is
`eb92b6e62261b7acbee69e70cc0394b1f9f045bbc1ca0c3ac6700c79eabef5ef`.
The other eight windows are in `measure-02`; there was no fastest-window
selection. H/M are 100,000 requests at 10,000/s with 32 clients; T is 20,000
requests at 2,000/s with eight clients and 100 queries per connection.
Each fresh-daemon window has its predeclared five-second warmup.

## Formal correctness, delivery and latency

Every H/M row below is 100,000/100,000/100,000 planned/sent/success;
every T row is 20,000/20,000/20,000. Errors/timeouts/unsent are 0/0/0 in every
row. Throughput divides completed requests by at least the full 10-second
offered schedule through client completion. It is not saturation throughput.
Latency units are ms; RTT starts at actual send, planned latency at scheduled
send. Every RTT distribution has at least 20,000 samples, so p99 is retained.
Caller validation happens after receipt and is reported separately below.

| Window | Completed/s | Upstream total (negative) | RTT p50 / p95 / p99 | Planned p50 / p95 / p99 | Send lateness p95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| H1 | 9999.75 | 0 (0) | 0.106 / 0.248 / 0.471 | 0.168 / 0.537 / 1.279 | 0.297 |
| M1 | 9998.10 | 20016 (16) | 0.176 / 2.064 / 2.476 | 0.337 / 2.351 / 2.621 | 0.659 |
| T1 | 1999.38 | 20000 (0) | 2.292 / 2.664 / 3.500 | 2.649 / 3.446 / 4.167 | 1.046 |
| M2 | 9998.58 | 20016 (16) | 0.181 / 2.089 / 2.476 | 0.338 / 2.366 / 2.630 | 0.668 |
| T2 | 1999.35 | 20000 (0) | 2.287 / 2.694 / 3.523 | 2.651 / 3.473 / 4.192 | 1.043 |
| H2 | 9999.78 | 0 (0) | 0.137 / 0.227 / 0.364 | 0.238 / 0.431 / 0.583 | 0.218 |
| T3 | 1999.35 | 20000 (0) | 2.299 / 2.705 / 3.520 | 2.657 / 3.466 / 4.143 | 1.043 |
| H3 | 9999.80 | 0 (0) | 0.128 / 0.217 / 0.387 | 0.225 / 0.409 / 0.673 | 0.201 |
| M3 | 9998.26 | 20017 (17) | 0.196 / 2.120 / 2.453 | 0.351 / 2.354 / 2.634 | 0.584 |

Mixed forwards are exactly 20,000 distinct positive misses plus 16/16/17
negative retrievals. No positive hot name reaches upstream; each unique
positive goes upstream once. Negative names may be evicted by LRU pressure
before their TTL expires. All received upstream queries have sent replies;
C retry/failure counters remain zero, and parent cache insertion deltas equal
the actual forwards, including completed TCP cache IPC. These insert counts
apply to this one-RR/no-SOA-negative fixture, not arbitrary SOA or multi-RR data.
T1/T2/T3 each open and close 200 downstream connections and use 200 upstream
connections, confirming the frozen reuse pattern.

## CPU and separate caller/upstream costs

C CPU includes the inherited process tree and bounded child/cache-IPC drain;
warmup is outside the perf enable/disable window. Each drain check includes a
100 ms wait (observed 100.46–101.00 ms), not 100 ms of C CPU. perf counters all
ran 100% of their recorded window. `/proc` values below are separate 100 Hz
cross-checks: parent user/system plus waited-child user/system, sampled only
at quiescent boundaries. They are not added to perf task-clock a second time.
The cross-check differs from perf by at most the frozen 10%/50 ms tolerance.

| Window | C CPU µs/completion | /proc parent user / system s | /proc reaped children user / system s | Client CPU s | Upstream CPU s | Observer CPU s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| H1 | 39.10 | 0.26 / 3.51 | 0.00 / 0.00 | 9.555262 | 0.000252 | 0.143793 |
| M1 | 47.69 | 0.72 / 3.85 | 0.00 / 0.00 | 8.258249 | 1.162879 | 0.148574 |
| T1 | 228.85 | 0.80 / 0.23 | 1.11 / 2.45 | 2.459867 | 1.539611 | 0.406722 |
| M2 | 48.03 | 1.13 / 3.47 | 0.00 / 0.00 | 8.292172 | 1.158259 | 0.150049 |
| T2 | 228.53 | 0.80 / 0.23 | 1.19 / 2.36 | 2.435885 | 1.564862 | 0.405693 |
| H2 | 40.65 | 0.62 / 3.27 | 0.00 / 0.00 | 9.939518 | 0.000475 | 0.143785 |
| T3 | 230.66 | 0.80 / 0.23 | 1.18 / 2.42 | 2.423619 | 1.567520 | 0.402624 |
| H3 | 40.63 | 0.61 / 3.27 | 0.00 / 0.00 | 9.894521 | 0.000441 | 0.146044 |
| M3 | 48.36 | 0.61 / 4.02 | 0.00 / 0.00 | 8.845650 | 1.152907 | 0.152875 |

Observer CPU includes its sampler thread, orchestration and serialization
inside its recorded boundary; it excludes the separate perf process. Client
CPU includes response validation but excludes corpus preparation. Upstream
CPU is its snapshot-to-snapshot delta. These boundaries differ slightly from
perf's; none is added to C or subtracted from RTT. Client hot-path CPU uses
9.56–9.94 s per 10 s schedule on its assigned core, which further prevents
interpreting these runs as C's capacity ceiling. perf's own CPU and the
client/upstream/observer memory, FD and thread peaks were not recorded.

| Window | Upstream actual delay p50 / p95 / p99 ms | Client validation p50 / p95 µs | TCP connect p50 / p95 ms |
| --- | ---: | ---: | ---: |
| H1 | — (no forwards) | 19.16 / 30.68 | — |
| M1 | 1.127 / 2.022 / 2.086 | 17.12 / 29.12 | — |
| T1 | 1.664 / 1.930 / 2.014 | 19.84 / 34.52 | 0.299 / 0.530 |
| M2 | 1.140 / 2.018 / 2.084 | 17.20 / 30.48 | — |
| T2 | 1.661 / 1.934 / 2.019 | 19.92 / 34.92 | 0.335 / 0.552 |
| H2 | — (no forwards) | 19.84 / 31.48 | — |
| T3 | 1.668 / 1.946 / 2.029 | 19.96 / 34.68 | 0.316 / 0.523 |
| H3 | — (no forwards) | 19.60 / 31.28 | — |
| M3 | 1.126 / 1.999 / 2.078 | 18.12 / 30.76 | — |

Upstream formal-delay samples are reconstructed from the retained complete
`delay_ns` array using before/after `delay_count`, excluding prefill/warmup.
They measure fixture receipt through completion of its nominal 1 ms sleep;
actual downstream send is later. The measured 1.126–2.022 ms p50/p95 range
reflects scheduling and fixture overhead as well as the intentional sleep.
RTT includes this waiting time. TCP connect has 200 samples, so no p99 is
reported. Close latency, instruction/cycle/context-switch/fault counters and
full precision remain in the derived JSON. CPU migrations were zero; UDP
windows had zero recorded page faults; TCP had 14,546–15,146 faults per window.

## C process-tree resources and cleanup

Values are **sampled maxima**, in KiB for memory. USS is Private_Clean plus
Private_Dirty; summed RSS includes shared pages and is not exclusive memory.
PSS distributes shared mappings. Per-field maxima need not occur at the same
instant. Each process has one thread; a T peak of nine threads means parent
plus eight children, not a multithreaded parent. Sampling is every 50 ms plus
read time; 200–212 samples were retained per formal window.

| Window | USS / PSS / RSS KiB | FDs | Threads / processes | Observed children | Processes vanished during sampling |
| --- | ---: | ---: | ---: | ---: | ---: |
| H1 | 704 / 747 / 2340 | 11 | 1 / 1 | 0 | 0 |
| M1 | 708 / 751 / 2344 | 17 | 1 / 1 | 0 | 0 |
| T1 | 2028 / 2593 / 11744 | 160 | 9 / 9 | 8 | 5 |
| M2 | 708 / 750 / 2328 | 17 | 1 / 1 | 0 | 0 |
| T2 | 2040 / 2607 / 11736 | 161 | 9 / 9 | 8 | 7 |
| H2 | 704 / 747 / 2340 | 11 | 1 / 1 | 0 | 0 |
| T3 | 1932 / 2533 / 11732 | 160 | 9 / 9 | 8 | 2 |
| H3 | 708 / 751 / 2344 | 11 | 1 / 1 | 0 | 0 |
| M3 | 704 / 747 / 2340 | 17 | 1 / 1 | 0 | 0 |

TCP child exits race some `/proc` reads (5/7/2 observations); missing processes
are not silently charged zero as an exact peak. C's separately dumped TCP
high-water counter is eight children. Parent FD sampled peaks are 19/21/19;
child-tree peaks are 141/142/141. Child USS peaks are 1736/1756/1640 KiB,
while the sum's independently observed maximum is shown above. Full
parent/child resource components are retained in the JSON.

The final sample of every window is one parent, one thread and 11 FDs; TCP
children and their cache IPC have drained. Final USS is 700–708 KiB. SIGTERM
then exits C with status 0 and an empty process group within the five-second
bound in every formal/profile window. Process exit closes its FDs/sockets;
there is no separate post-exit socket-inode scan or shutdown latency profile.
The harness closes its fixture/client processes. This is bounded-window
cleanup evidence, not proof of zero leaks in every failure path. No 30-minute
long-growth experiment or sustained resource-pressure experiment was run.

## Independent profiles and source-cost interpretation

One instrumented profile per scenario used the same frozen schedule with
`perf record -F 997 --call-graph dwarf`; all three also passed the functional
and counter gates (220,000 successful requests total). Their timing and CPU
are excluded from the nine baseline windows. Recorded lost samples are zero.
Full saved perf data was later decoded with no minimum-percent filter; the
DSO counts below sum to every recorded sample. This is sample share, whereas
the symbol percentages following it are perf's period-weighted self cycles.
Neither metric is elapsed-time share or a future achievable speedup.

| Profile | All samples | C executable | libc | Kernel | vDSO |
| --- | ---: | ---: | ---: | ---: | ---: |
| hot | 3240 | 971 (29.97%) | 285 (8.80%) | 1961 (60.52%) | 23 (0.71%) |
| mixed | 4482 | 1316 (29.36%) | 1013 (22.60%) | 2139 (47.72%) | 14 (0.31%) |
| tcp | 4530 | 1349 (29.78%) | 1338 (29.54%) | 1838 (40.57%) | 5 (0.11%) |

Each has more than 100 C-executable samples; the coarse rankings are usable,
without treating small percentage differences as precise. Relevant findings:

- Hot: `cache_find_by_name` is 5.42% self (179 samples); `answer_request`
  1.85%, `check_dns_listeners` 1.79%, `set_dns_listeners` 1.72%. Kernel work
  is spread across socket polling, send/receive, wakeups and packet handling.
  Lookup changes alone cannot be claimed to remove the majority of this cost.
- Mixed: `cache_scan_free` is 11.07% self (498 samples). Exact
  `cache.c:518–635,737–781` removes conflicts and, under full-cache pressure,
  walks every bucket for expired records before spilling an LRU RRset:
  O(records + buckets) on that scan. The frozen full-cache fixture repeatedly
  reaches it. Rust's existing `cache.rs` also performs a global scan at this
  pressure trigger; changing language has not removed the algorithmic work.
- TCP: `cache_scan_free` is 21.54% self (972 samples). Its retained stack
  separates insertion through child `extract_addresses`/`tcp_request` and
  parent `cache_recv_insert`; the parent-only CPU numerator would miss most
  TCP CPU (reaped children account for 3.55–3.60 of 4.58–4.63 `/proc` CPU s).
  Connection handling and IPC must remain inside any future paired boundary.
- Native libc: `__subtf3`, `__trunctfdf2`, `__floatditf` sum to 18.96% self
  in mixed and 26.17% in TCP; `difftime` itself adds 1.36%/1.16%.
  Retained stacks tie much of this work to `is_expired` and cache scans.
  This is the host glibc implementation's cost. The image uses musl;
  these percentages cannot be transferred to the router or presented as
  target Rust gains from integer time arithmetic.

A justified next candidate is a bounded expiry index separate from the name
index and LRU: it could replace a repeated whole-cache expiry scan with
O(log N) maintenance and work proportional to actually expired entries.
The implementation must preserve same-name/RRset invalidation, CNAME target
identity, stale policy, pending-insert visibility and LRU pressure behavior;
index storage must fit the same resource budget. This report does not choose
a design or claim benefit before differential correctness and a frozen paired
comparison. Hot socket/dispatch work is a separate candidate; no threading,
async framework or batching win follows automatically from the profile.

## Calibration, rejected evidence and reproducibility

All previous failures remain failures:

| Evidence | Status and reason |
| --- | --- |
| calibration-01 | Failed before DNS work: perf ACK handling did not accept its C-string NUL; cleanup exit -2 obscured the original error. No accepted CPU or DNS result. |
| calibration-02 / v1 | Failed: with rebind protection enabled, documentation-address fixture data was rejected. 1 success, 3 errors, 1 timeout. No performance result. |
| calibration-03 / v2 | Passed deliberate controls: 3 successes, 1 wrong-address error, 1 timeout; client exit 1. Inherited perf CPU 204.945 ms versus known parent+two-child 206.171 ms. |
| measure-01 mixed / v2 | Rejected by frozen expected-forward-count 20,000; actual 20,017 despite all 100,000 replies being correct. V3 corrected the counter model prospectively, not this window's status. |
| calibration-04 / v3 | Passed: negative query → cache hit → 1000 other insertions → negative retrieval before TTL → hit; forward counts 1/1/1/2/2. Same deliberate 3/1/1 result and failed-client exit. Inherited perf CPU 205.259 ms versus known 206.498 ms. |

The read-only [dns_c_cost_audit.py](../../tools/dnsmasq/dns_c_cost_audit.py)
independently recomputes CSV counts, nearest-rank latency distributions,
throughput, upstream per-item/count/delay windows, raw perf counters and CPU
scope, sampled peaks, corpus/config hashes, profile sample totals and reuse
identity. It does not replay absent captured response packets or invent new
protocol coverage. Its success path passed all nine windows and three
profiles; deliberately changed CSV status, corpus truncation and resource
peak each exited 1 without writing a successful result. Those audit controls
are retained in private `analysis/audit-calibration.json`.

Private raw root: `private/dnsmasq-rewrite/c-cost-diagnostic-20261001/`.
The remote source root is the task-owned `dnsmasq-c-cost-20261001/private/`.
[Derived JSON and raw artifact SHA256 index](C_COST_RESULT.json) contains every
formal/profile directory, precise measurements, hashes for its CSV/config/
corpus/resource/perf/log/result files, and all accepted/rejected summary hashes.
No ELF, packet corpus, configuration or address is committed in that index.
`analysis/*-self-full.txt` is postprocessing of the retained profile files,
not a new profile window. Reproduce the derived JSON offline with:

```sh
python3 tools/dnsmasq/dns_c_cost_audit.py \
  private/dnsmasq-rewrite/c-cost-diagnostic-20261001 \
  --output private/dnsmasq-rewrite/c-cost-diagnostic-20261001/analysis/audited.json
```

The target size gate remains separately open: existing 574f5ed B0 Rust ELF
989,991 bytes versus image C 269,305 bytes; the retained DYN1 candidate is
870,915 bytes, still +601,610 bytes versus C. [DYN1_RESULT.md](DYN1_RESULT.md)
records its scoped gates and -12.03% relative-to-B0 size result. It is not the
default and has no demonstrated runtime benefit. These pre-existing artifacts
are not products of the C-only windows or current-source rebuilds.

Functional equivalence and optimization acceptance remain separate and
incomplete. The shared protocol's paired representative scenarios, identical
dependencies/budgets, resource-pressure/long-growth gates, current target
build and authorized physical-target measurements still require evidence.
