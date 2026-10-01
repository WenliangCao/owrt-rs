# Shared-entry inline RDATA: correctness and allocation pass

The single new `shared_inline16` candidate passes its correctness and
allocation prerequisites. It removes the extra population allocation per
entry for the fixed A/AAAA workload, while retaining the earlier shared-entry
snapshot heap savings. **Timing has not run and the representation is not
accepted or adopted.** The earlier V1 and chunk32 rejections are unchanged.

The frozen plan is [TCP_SNAPSHOT_INLINE16_V1.md](TCP_SNAPSHOT_INLINE16_V1.md).
The source remains exact `e77d966d0bf92e5296f73ee3e54fdaf960ed7781`, compiled
with native aarch64 Rust 1.98.1, O3/LTO and one codegen unit. Product source,
`Name`, the original C corpus and the old screen tools/results are unchanged.
The safe private RDATA wrapper uses inline storage through 16 bytes and an
owned boxed slice beyond that. Direct slice constructors avoid temporary
payload allocations; no new unsafe code or dependency is introduced by the
candidate. The existing separate allocator instrumentation is reused.

## Correctness and actual layout

Deep and candidate each match all **22,571 exact-C operations in 21
scenarios**, with the same 138 permitted cross-type Generic RR ordering
variations. The retained image's complete debug state is checked before and
after every operation, including pending commits, aborts, expiry, eviction,
reuse, CNAME links and rotation. C expected outputs were reused unchanged,
after verifying the inputs and source hashes.

Both variants also pass 14 byte-storage cases: lengths 0, 1, 4, 15, 16, 17
and 257, each with both parent/snapshot drop orders. These use real cache
entry mutation through `Arc::make_mut` in the candidate, check retained data
and authority independence, replace the entry, and verify balanced live-byte
accounting after both objects drop. The changed-TTL negative control detects
one mismatch among 13 rows and exits 1; a missing observation is rejected.

Measured structure sizes match the frozen predictions:

| Representation | Cache | Slot | Entry | Record | RDATA value |
| --- | ---: | ---: | ---: | ---: | ---: |
| deep | 168 | 160 | 120 | 56 | 24 |
| shared_inline16 | 168 | 32 | 120 | 56 | 24 |

The candidate's full entry occupies a requested 136-byte Arc allocation,
including its counters. The RDATA enum does not enlarge the entry. `Name`
and the separate name index retain their existing allocations and behavior.

## Requested heap and allocation calls

All eight allocation runs complete 20 snapshot/lookups each: 160 completions,
zero errors and balanced snapshot/parent drops. Snapshot values include all
20 simultaneous images and their first real mutable lookup. Prepared inputs
and measurement buffers remain outside the same deltas as the earlier V1
screen. Requested bytes are not RSS/PSS or exclusive physical memory.

| Capacity / occupied | Representation | Parent live bytes | 20 snapshots after lookup | Snapshot peak extra |
| --- | --- | ---: | ---: | ---: |
| 150 / 0 | deep | 24,000 | 480,000 | 480,020 |
| 150 / 0 | shared_inline16 | 4,800 | 96,000 | 96,020 |
| 150 / 150 | deep | 51,338 | 954,120 | 954,249 |
| 150 / 150 | shared_inline16 | 51,494 | 460,140 | 460,269 |
| 1,000 / 1,000 | deep | 358,792 | 6,695,200 | 6,695,329 |
| 1,000 / 1,000 | shared_inline16 | 359,792 | 3,401,200 | 3,401,329 |
| 10,000 / 10,000 | deep | 3,386,856 | 62,936,480 | 62,936,609 |
| 10,000 / 10,000 | shared_inline16 | 3,396,856 | 29,996,480 | 29,996,609 |

Full-profile parent increases are 156 / 1,000 / 10,000 bytes, or
0.304% / 0.279% / 0.295%. Snapshot live heap falls 49.20% and 52.34% at
capacities 1,000 and 10,000. All deterministic heap guards pass.

| Capacity / occupied | Population allocations, both | Reallocations, both | Deep clone allocations | Candidate clone allocations | First lookup allocations, both |
| --- | ---: | ---: | ---: | ---: | ---: |
| 150 / 0 | 1 | 0 | 20 | 20 | 20 |
| 150 / 150 | 909 | 330 | 12,040 | 6,040 | 80 |
| 1,000 / 1,000 | 6,012 | 2,200 | 80,040 | 40,040 | 80 |
| 10,000 / 10,000 | 60,015 | 22,000 | 800,040 | 400,040 | 80 |

Nonempty inline payloads eliminate one payload allocation, offsetting the
entry Arc allocation in this address workload. Empty negative payloads had
no allocation to remove, and payloads over 16 bytes still allocate their
heap slice; both retain the additional Arc allocation compared with deep.
These measurements therefore do not qualify arbitrary mixed-RR population.

## Evidence and pending decision

The reproducible tools are `tcp_snapshot_inline16_screen.py` and its Rust
driver, payload gate and RDATA fragment. Their generated sources, compiler
and binary hashes, negative controls, raw outputs and all invocation logs
remain under ignored
`private/dnsmasq-rewrite/resume-inline-rdata-20261001/private/inline16-evidence/`.
The final evidence directory is `inline16-02`; `inline16-01` retains the
initial prepare-only artifact from before adding explicit architecture and
complete-allocation-matrix guards. It ran no comparisons or costs. Both tool
archives, the exact source archive and an evidence checksum manifest remain
in the sibling `inline16-preparation/` directory.

[The JSON report](TCP_SNAPSHOT_INLINE16_ALLOCATION.json) contains the derived
results and all primary source/artifact identities. The remote working root
is `/home/ubuntu/dnsmasq-tcp-inline16-20261001/work01`. Its `private/inline16-02`
directory has passing `gate.json` and `allocation-result.json`, and no timing
result. All allocation CPU/wall fields remain diagnostic only.

The next decision requires the unchanged 24-run schedule in a root-coordinated
quiet window. The 5% population CPU, 5% capacity-150 p95, and 20% combined
snapshot/lookup CPU requirements are still unmeasured. The 5% steady heap and
20% snapshot heap requirements have passed. No timing round, production
representation, full service resource claim or router action is authorized
by these allocation results alone.
