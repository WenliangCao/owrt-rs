# Reverse ordering across child/parent transfer

The retained transfer evidence exposes two separate questions: the allowed
variation between C processes, and the candidate's dependence on physical slot
assignment. This is a source review of existing evidence, not a new gate or a
change to the original comparator. Its complete comparison still exits 1.

`cache.c:295` hashes the case-insensitive target name using bytes from the
`typestr` pointer array. This makes bucket assignment process-layout dependent.
`cache_find_by_addr` (`cache.c:1261`) visits buckets in increasing order and
promotes each matching dynamic record to the LRU head. Returned dynamic
records therefore follow the reverse of that traversal. Neither slot number
nor insertion order alone describes this operation.

`cache_hash` (`cache.c:312`) inserts different reverse names at the bucket head,
while keeping identical-name entries together in insertion order. Child
`cache_end_insert` sends its pending chain, and parent `cache_recv_insert`
builds another pending chain before committing it. Their pre-lookup LRUs show
the two existing reversal steps. Address lookup then rebuilds the head prefix
from the target-name buckets.

The old six C invocations all placed the three targets in **distinct buckets**.
That fact is present in their saved stderr, not inferred from Rust behavior.
The table identifies targets by their input positions, avoiding publication of
the raw fixture. Each three-invocation group has one exact stdout trace;
native bucket numbers themselves vary between invocations.

| Existing artifact | Child address lookup | Parent address lookup |
| --- | --- | --- |
| Native C, three invocations | 2, 1, 3 | 2, 1, 3 |
| SDK-musl C, three invocations | 1, 2, 3 | 1, 2, 3 |
| Private `54346fd` | 1, 2, 3 | 3, 2, 1 |

The candidate scans slot indices in `lookup_reverse`; export/import assigns
different slots, so it cannot reproduce either complete retained C trace.
This explains the four native and two SDK differences already reported in
[the transfer result](REVERSE_TRANSFER_AFTER_RESULT.md). The records, absolute
deadlines, counters and the pre-lookup double reversal otherwise match there.

It would be incorrect to generalize the table into “all child and parent
reverse answers must have identical order.” Distinct names which collide in
one C bucket can change relative order when the parent commits the reversed
chain. Identical names have their own preserved-group insertion rule. A future
order qualification must distinguish those cases and their pressure/LRU effects.
It must also preserve the local-record prefix ahead of dynamic reverse entries.

No slot-based permutation is accepted here merely because a different C
process could conceivably produce it. Conversely, copying the C pointer-byte
hash or fixing one observed permutation is not an established requirement.
Before changing representation, freeze an explicit model of permitted order
variation and test its state effects against independent C observations. Keep
the old exact traces, mismatch counts and comparator result unchanged.

Evidence was read directly from the existing hash-verified archive:
`private/dnsmasq-rewrite/reverse-transfer-gate-20261001/private/evidence/c-before-evidence.tar.gz`,
SHA-256 `c799b6ddbbbc5582c6da244d1e029e28ca7499b57f8a0b371ed7cb73c7a463a2`.
The six raw stdout hashes are already indexed by
`REVERSE_TRANSFER_C_BASELINE.json`; the Rust after differences are indexed by
`REVERSE_TRANSFER_AFTER_RESULT.json`. No process was rerun, result sorted,
candidate edited, performance measured or physical router accessed.
