# Measured reverse name-index footprint

The frozen untimed study completes **16/16 process runs**, with every measured
phase matching [the pre-execution growth model](REVERSE_INDEX_ALLOCATION_PLAN.md).
It quantifies a necessary correctness cost: `62894d6` omits reverse name-index
entries and has the known expiry bug; `0eaaef8` indexes those entries. The older
source is not an equivalent implementation or a performance candidate.

Both sources use native AArch64 Linux, rustc 1.98.1 and capacity 8. All cases
finish with zero outstanding requested cache bytes; sizes remain Cache168,
Slot160, Entry120 and Record56. No product source or allocator behavior changed.

| Case | Requested live bytes after first commit, old / fixed | Added index live bytes | Additional requests over the complete lifetime |
| --- | ---: | ---: | ---: |
| Empty | 1280 / 1280 | 0 | 0 |
| Single IPv4 PTR | 1325 / 1570 | 245 | 245 |
| Single IPv6 PTR | 1337 / 1582 | 245 | 245 |
| Reverse target shared with a forward record | 1583 / 1583 | 0 | 17 |
| Three distinct PTR targets | 1351 / 1678 | 327 | 327 |
| Four distinct PTR targets | 1364 / 1928 | 564 | 768 |
| Two reverse records at one target | 1338 / 1583 | 245 | 254 |
| Expiry and reuse | 1325 / 1570 | 245 initially | 295 |

A first target adds a 9-byte canonical key, a 32-byte slot vector and a
204-byte initial table: three allocations, 245 bytes. Three distinct targets
still fit that table. The fourth grows it to 400 bytes and frees the old
204-byte table, explaining the difference between retained and requested bytes.

Sharing an existing forward target needs no additional retained capacity in
this fixture. Reverse commit allocates/frees a temporary 9-byte key; the later
forward lookup clones two slot indices rather than one, requesting/freeing an
additional 8 bytes without an additional allocation call. That 17-byte complete
lifetime difference was included in the model before compilation or measurement.

Expiry removes the target's key and slot vector but retains the empty table.
After cleanup the sources retain 1312 and 1516 requested bytes respectively:
the extra 204 bytes are table capacity. Reusing it requires only a 9-byte key
and 32-byte slot vector. Final cache destruction frees everything in both
sources. Every measured phase sums exactly to its complete lifetime vector.

The existing counter implementation was reused, including its separately
audited deallocation observations. The generated cache copies add only borrowed
layout/index-shape accessors. Record inputs, result buffers and phase boundaries
were frozen before running the two binaries. All sixteen cells ran once; no
failure, extra round, changed model or threshold adjustment was required.

Plan commits: `600e42e`, then the source-derived forward-lookup refinement
`f15c0a9`. Final tool/plan freeze: `f566a32`. Exact source, tool, meter, binary,
result and archive hashes are in
[the derived JSON](REVERSE_INDEX_ALLOCATION_RESULT.json). The 78 retained files
were copied from oracle and independently verified against its SHA manifest;
raw evidence remains under ignored
`private/dnsmasq-rewrite/reverse-index-resource-20261001/private/evidence-01/`.

These are allocator-requested bytes for the stated small direct-record cases,
not RSS, allocator overhead or full-service peak memory. The study has no CPU
timer, throughput run, improvement threshold, network exchange or router
operation. It does not qualify larger reverse populations, OOM, musl allocator
behavior, multi-PTR ordering or later changes after `0eaaef8`. The separate
ordinary-five-case equality remains valid for its own forward-only inputs;
it never implied that the new reverse index was free.
