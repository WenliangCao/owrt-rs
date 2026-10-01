# Frozen reverse typed-transfer primitive gate

This separate Stage 4 fixture extends the existing 307-observation transfer
contract without changing its driver, corpus or comparator. Freeze the tool
and matrix before execution. Exact matching-source C runs first: 21 cases,
three native and three SDK-musl processes each, 126 processes total. These
are source primitives, not executions of the stock-image dnsmasq ELF.

The driver includes unchanged `cache.c`, forks a real child, lets
`cache_end_insert` send through a real pipe, and invokes unchanged
`cache_recv_insert` in the parent. Child and parent commands share initial
state but have separate intervening mutations. The fixture uses positive
forward/reverse IPv4/IPv6 records only; no synthetic negative-reverse record.
`H` calls the real local DHCP cache publication function, but this is a cache
primitive local-ownership fixture, not a reachable DHCP daemon lifecycle proof.

The 20 deterministic cases cover IPv4/IPv6 address replacement, same target at
different addresses, preservation of same-name forward records, parent local
reverse coexistence and local forward/configured-CNAME collisions, shared
capacity and reverse-victim RRset removal, successful empty transaction cleanup,
uncommitted/failed child suppression, parent abort after a complete imported
prefix, absolute expiry before/at/past the deadline, finite/forever stale, and
absence of a second min/max TTL clamp. Count real parent insertion and eviction
operations; never import child counters. All rows and complete lookup/LRU orders
must match across all six C processes before deterministic qualification.

One separately identified multiple-PTR case observes three target names for
one address. Before any address lookup, child and parent dynamic LRU order
must expose the two reversal steps: child insertion-order LRU, then opposite
parent LRU after export/import. Address lookup follows C's salted hash-bucket
traversal and can change returned order and LRU. Capture the exact order from
every process, including hash bucket diagnostics on stderr. Do not sort records,
compare sets, discard divergent runs or fold this row into deterministic passes.
Later Rust comparison reports each retained exact trace separately and keeps
unmatched order as an explicit boundary.

C sends the original PTR target name, absolute deadline, reverse/family flags
and 4/16 address bytes in the union. The parent passes those flags directly to
`really_insert`; it must not apply forward local-name conflict rules to reverse
records. Parent reverse insertion preserves local hosts/DHCP/config records,
removes committed dynamic entries with the same family/address, scans mortal
entries globally for expiry, and uses the common slots and LRU. Pending records
are invisible to replacement, allowing several PTR targets to commit together.
Failure and expiry behavior reuse the separately qualified transfer boundaries;
past-deadline float-to-unsigned conversion is a compiler/runtime observation,
not a claim about the stock image's existing ELF.

Reuse only hash-verified source, headers, compiler and non-cache objects from
the original 307 C baseline. Link new native/SDK oracle artifacts and record
all identities and loader resolution. Each run uses a fresh ignored directory
inside the Linux isolation wrapper. Raw commands, addresses, packets, logs,
ELFs and failures remain private. Missing observations and changed rows must
be detected by the comparator calibration. No router or performance timing.

A later Rust probe must execute actual capture/import APIs from a frozen
candidate source. It may supply the parent's current local-record view but
must not repair importer decisions or sort outputs. Keep representation costs,
OOM, partial pipe EOF, private TCP transport/snapshot adoption and actual-image
service behavior outside this primitive gate.
