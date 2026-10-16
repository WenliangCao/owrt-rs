# Keep a positive address beside its cache expiry

Independent6ab child1df135dc stores valid positive A/AAAA bytes in a private
EntryDetails enum beside expiry. Other records keep both independent CNAME
target and negative authority fields. The original immutable Arc<Record> stays
available for generic lookup, logging, transfer and external readers. There is
no new index, heap object, unsafe code or invalidation protocol.

Details and Record are built together at the only Entry construction point.
Cache exposes only shared Entry references, and its mutations never alter
Record. External cloned Entry records cannot mutate the cache's retained Arc.
Fresh eligibility uses the same family/length/negative invariant, ID generation,
owner/revision, expiry and stale predicates. Malformed and other record kinds
retain the general path. Independent5ec04eed found no semantic blocker.

Mac727library tests/8ignored and musl all-target checks pass. New48type/negative/
length cases check original bytes, snapshots, rejected/accepted authority setters
and child clear; the prior40cc double-metadata snapshot test is reused exactly.
Original tests remain. Linux/SDK qualification is still pending.

The byte-identical c43 snapshot-count probe ran its original16count controls.
All8pairs have every output field equal except side. Entry and Option<Entry>
remain72B; pure compile-time Linux-target size probes independently return72B
for both. At capacity1000, constructor99alloc/93248B and20snapshot332800B are
unchanged. With800records plus20content detaches,80alloc/92732requested bytes,
91072live bytes and423955peak extra bytes are identical. All drops return to
the original baseline. This is requested allocation accounting, not SDK RSS,
PSS, allocator fragmentation or runtime performance.

Local final code shows the fresh eligibility path reading Entry's inline tag
and expiry without the old Record payload, and the writer reading inline bytes.
The compiler now outlines eligibility into384B; this extra call/layout change
must be measured too. Shared local entry3804→3584B, address writer1092→1148B,
invalid232→240B, get160B unchanged; whole local ELF grows976B. These are static
observations only, including adverse growth. The original resource budgets and
correctness gates still apply before any selection; current6ab/803 artifacts
are untouched.

[All original counts, checks, target layout and codegen identities](inline-address-details-local.json).
