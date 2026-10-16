# One fewer cache-content indirection, with a wider snapshot root

IndependentG child2b4f8b16 replaces `Arc<ContentBlock { Box<[Option<Entry>]> }>`
with `Arc<[Option<Entry>]>`. Slot/Record layout, IDs, LRU, name indices and
mutation order remain unchanged. Slice length keeps the last block's actual
capacity, with no fixed64-entry padding. No unsafe code or new index is added.

Mac722tests/8ignored and musl all-target checks pass. The additional test covers
0/1/63/64/65/1000capacities, shared snapshot visibility, child clear isolation
and unique-block backing retention. The pre-existing private snapshot-count
probe is reused byte-for-byte;16fixed allocation-only controls all have zero
errors and return to their original live-byte baseline. No timing is collected.

At capacity1000, empty constructor allocations fall99→83 and requested/live
bytes93248→93120: one fewer allocation per16content blocks, but only128B fewer
requested live bytes. Twenty snapshots instead request332800→335360B (+2560B)
because their root handles widen8→16B. With800records and one content detach
per snapshot, lookup allocations fall80→60, but peak extra requested bytes
rise423955→426195 (+2240B). Both favorable and adverse changes are retained;
this is not an RSS or memory-saving claim.

Local final-codegen reproduces theG control. get/is_valid/invalid and selected
caller sizes are unchanged; accesses use the root's slice metadata directly
instead of loading the wrapper's separate Box storage. No instruction/cycle
benefit follows merely from removing a dependent address.

Existing full-gate diagnostics name/size ContentBlock and instrument its
constructor/root pointers. Their real layout/root adapters must be updated
accurately in a separate minimal step if this direction merits qualification.
They have not been changed, and this source is not full-gate ready. The current
6ab/opt2 screening queue remains separate.
[Full count controls, local commands and code identities](content-slice-local.json);
[qualification coupling review](../loop/CACHE_CONTENT_SLICE_REVIEW.md).
