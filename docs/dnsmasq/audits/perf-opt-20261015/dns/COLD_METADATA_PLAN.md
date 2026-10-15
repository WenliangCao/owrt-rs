# Keep ordinary cache entries compact

Independent F child `40cc86fe` moves optional CNAME-target and negative-SOA-owner
metadata from every Entry into one optional shared allocation. Ordinary address
records retain the same record pointer, expiry and flags without carrying those
unused values inline. No cache index, slot numbering, record encoding, LRU or
expiry policy changes. The intent is to reduce content-block memory touched by
ordinary hits; this is a hypothesis until the pinned artifacts are measured.

Both optional fields remain independent. They are not a union: the existing
setters permit an unusual negative CNAME to hold both values, and the new test
preserves that public contract. Content-block COW still happens first; a metadata
setter then detaches the shared metadata only when needed. TCP snapshots may
share immutable metadata, but changes in one view must not alter another.

This introduces an allocation when CNAME/negative metadata is first populated
and an additional pointer on those paths. It may trade address working-set size
for extra insertion work and CNAME latency. Quantify both sides, including
snapshot content-block detachment, before selecting it. Do not infer A53 cache
misses, IPC or CPU savings from a type-size reduction alone.

The product diff passed714 local library tests with8 ignored and Linux-musl
all-target checking. Its subsequently added target/authority snapshot regression
also passes. Local allocator/type-size checks are being run separately and are
excluded from timing. Exact-source Linux related gates and the unchanged SDK
build remain prerequisites for daemon screening; full44 is still pending.

[The frozen native plan](cold-metadata-native-plan.json) independently compares
the prototype to F using the same15 scenes, fixed operation counts,3 grouped
PMU pairs and5 plain CPU pairs:240 windows. The existing runner's measurement
loops are unchanged; only its final count assertion now derives from the fixed
plan dimensions. Keep all CNAME, RRset, host, synthetic and miss controls, all
failed attempts and original W/direction rules. No data from other prototypes
is pooled. A32-window exact-SDK low200/s/high-unpaced owner screen follows;
low-load precision and high-load variable-N limitations remain unchanged.

Do not modify the active fresh-address screen or combine the product changes.
This plan has not started any Oracle workload. An eventual candidate must still
pass complete frozen-C correctness and full independent physical qualification
against E; local mechanism evidence alone cannot promote it.
