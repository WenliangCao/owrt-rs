# Configured CNAME comparison screen

Independent baseline B `9b91a192` plus approved stale compatibility fix
`b1136023`. Product change `16dec683`, branch `perf/dnsmasq-cname-20261015`.
This branch does not contain insertion or cursor changes.

The rejected cursor2 fixed-build timing exposed a preexisting configured-name
cost. Fixed-build PMU showed virtually unchanged instructions, but 8.6% more
cycles; sampled `local::wire_name` share moved 34.47% to 41.44%. When a
configured CNAME matches, the query-local hint branch is bypassed entirely.
The 400-alias fixture performs 819 allocations per request, mostly converting
every alias into an immediately discarded canonical wire key during two
linear scans. This makes the path sensitive to generated code layout.

The independent alias change compares each configured dotted alias directly
with the already-canonical key. Scan/first-match order and chain traversal
remain unchanged. It retains the old root representation, case folding,
binary byte handling, 63-byte labels, 255-byte wire limit, and invalid-name
empty-key equivalence for callers constructing malformed DnsConfig directly.
No index, persistent storage or new allocation is introduced. The regression
test compares 267 valid/invalid/binary names and their key cross-product with
the original allocating operation. Independent static review found no blocker;
376 native macOS DNS tests pass (five existing fixture tests ignored).

`cname1-screen.json` records all ten allocation scenes and three-pass configured
PMU data. Configured-answer allocations drop 819 to 18 per operation; requested
bytes drop 19436.6 to 1013.6, and instructions decrease about 54%. Other scenes
retain their allocation counts. These are counters, not qualified timing.
The exact shared fixture is `hotpath_probe_v2.rs`; raw evidence stays private.

Cursor3 is only the original cursor2 plus this independent alias comparison
(`32ef5964` in the cursor branch), with the same approved compatibility fix.
Its configured instruction count is also about 2.288 billion per 10,000
operations. It may reenter only if fresh plain timing versus **alias alone**
passes; unrelated alias savings cannot conceal the earlier cursor regression.
The combined source passes 380 macOS DNS tests. Full frozen candidate gates
are mandatory for any chosen combination. No router access.

## Quiet native screen complete

Reservation `alias-cursor3-20261015` completed all 90 windows with three
variants, five alternating rounds and all six scenes. Alias alone improves
configured-CNAME CPU 50.86% (W 1.07%, all five pairs); its other five scenes
remain within variation. The **incremental cursor comparison against alias
alone** improves hit 12.84% (W 1.04%), miss 21.40% (W 0.80%), and dynamic CNAME
6.49% (W 0.84%), each in all five pairs. Configured CNAME is 1.14% faster
(W 1.07%, five pairs); RRset and hosts remain within variation. The original
cursor2 rejection remains recorded and is not retroactively waived: only this
different combination passed the fresh screen.

Retain the alias comparison and query-local cursor together for full gates.
`cname1-cursor3-timing.json` records both independent effects, the combined
comparison, every raw window and artifact identity. No runs were replaced.
This remains native micro evidence; final source-combination controls, exact
SDK size/memory, full correctness, Oracle workloads and device gates remain
outstanding.
