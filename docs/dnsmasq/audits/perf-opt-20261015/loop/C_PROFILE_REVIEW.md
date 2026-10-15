# Exact candidate C residual attribution

Fresh Oracle counter-only profiles bind candidate C
`b4c4a8e40698feb7aa57da09699bb2988ac1cf4bb54345474a9f659a12edcda1`
to its own map `9ed8e0a304e0a3333bb9f23d685171802c61f5688ec734e209a7622ade17da0a`
and source `f7f7a2edd9f2ecfac72953e43cfc873a354b468b`.
[The receipt](owner-profile-c.json) records all identities, samples, counts,
historical A comparisons and transfer provenance. No product or tool changed.

UDP hit/miss/mixed and TCP miss each completed 1000 warmup plus 4000 measured
queries, with no wrong replies, timeouts, transport errors or skipped work.
The existing driver used fresh loopback-only namespaces, daemon CPU 2,
upstream CPU 1 and client CPU 3. The exact root snapshot's driver and analyzer
hashes matched the local tools. ELF/map/process identities, unchanged process
mappings and perf enable/disable ACK brackets all passed; no lost samples were
reported. Unmapped user samples are explicitly retained vDSO addresses,
not guessed symbols in the target ELF.

These are sampled **self instruction proportions**, not exact CPU shares or
inclusive function costs. C ran with the existing nice10 wrapper; retained A
receipts show nice0. The windows are unpaired and have different code layouts,
kernel activity and possible sampling skid. Their instrumented elapsed times
are excluded from acceptance.

| Scene / sampled function | A proportion | C proportion |
| --- | ---: | ---: |
| UDP hit, `Cache::names_for` | 15.36% | 18.64% |
| UDP miss, `Cache::insert_at_counted` | 10.01% | 11.09% |
| UDP miss, local answerer | 10.20% | 6.90% |
| UDP mixed, `Cache::names_for` | 6.82% | 10.72% |
| UDP mixed, `Cache::insert_at_counted` | 4.74% | 4.29% |
| TCP miss, `Cache::insert_at_counted` | 18.29% | 18.12% |

The result supports continuing cache insertion/name lookup investigation.
It does not establish a speedup or regression in any row. For example, the
large inlined UDP send section moves from 12.99% to 0.51% of samples, while the
full instrumented miss instruction total changes only +1.19%; treating that
section delta as eliminated CPU would be unjustified. All full PMU totals and
the twelve largest user sections per scene are retained in the receipt.

The hypothesis that mixed A/AAAA names force the hint's `Many` fallback does
not explain this frozen hit workload. `m6a_loadgen.c:224–233` assigns qtype
deterministically from the same index used in the hot name. All 4000 retained
measurement records confirm 800 distinct names: 560 A-only and 240 AAAA-only,
with no name observed under both types. All 40 sampled wire replies contain
one answer RR. This does not directly measure the internal hint-hit rate;
the initial `inspect_name` still needs a `names_for` lookup even when the hint
is successfully reused later.

## Concrete syscall result

A fifth fresh UDP-miss window used the existing strace mode and also completed
all 5000 warmup/measured queries. It observed exactly 5000 upstream sockets,
each created with NONBLOCK and CLOEXEC atomically, and **zero FIONBIO and zero
F_SETFD calls**. A's earlier exact-SDK trace had 5000 of each setup call. This
confirms the selected mechanism in the complete C daemon.

| Selected syscall | A | C |
| --- | ---: | ---: |
| `ppoll` | 19,879 | 19,996 |
| `recvmsg` | 9,993 | 9,999 |
| `socket`, `sendto`, `recvfrom`, `close`, `sendmsg` | 5,000 each | 5,000 each |
| `ioctl` / `fcntl` setup | 5,000 each | 0 each |
| Total selected calls | 64,872 | 54,995 |

The net difference is 9877 calls because poll/terminal-receive counts vary
with scheduling. No syscall count is itself a measured latency or CPU saving.
C still makes 9998 zero-timeout ppolls, 9996 with one fd. Applying the prior
native one-fd count screen to C's separate 826,621,047-instruction miss window
projects about 1.98% before safe generation/error bookkeeping; the single-owner
container projection is about 0.37%. These estimates remain narrow mechanism
screens. They do not replace final device variation or prove all residual
work irreducible. Full-cache insertion remains a concrete unresolved direction.

## Evidence and transfer boundary

All five raw outputs remain on Oracle. Their regular-file archive SHA256 is
`ff961409258ac7e428b0381a9393e87e0f87ba4fe69390c3d189f0af00c15430`;
transient perf FIFOs were excluded. The copied archive and all analyzer inputs
were verified locally.

One 9,489,587-byte archive transfer had already occurred when the coordinator
requested deferring bulk transfers during the active device series. Its local
file creation/last-write timestamps are 2026-10-15 10:18:26.868264 through
10:18:27.492215 UTC; the SCP tool call lasted 0.980613 seconds. These are file
observations, not packet-level timestamps. The coordinator was notified to
assess the overlap and identified `candidate-c-udp-miss-r1-rust`, whose wall
window is 10:18:19–10:18:49 UTC. The transfer is near the warmup/measurement
boundary, and the CPU endpoint covers it; an exact wall-to-monotonic offset is
unavailable. The complete attempted series remains retained with no sample
exclusion or replacement. This review makes no device-validity decision.
No further bulk transfer was performed.
