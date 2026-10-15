# Remaining name-index cost: read-only review

The exact C and D SDK artifacts both retain a scalar FNV loop. C's
`names_for` occupies `0xe12a4..0xe1420`; D's identical-shaped range starts
at `0xe12b8`. Each byte executes load-with-pointer-increment, decrement,
XOR, multiply and branch. The loop is not automatically unrolled.

However, **the function's sample share is not the FNV loop's share**:

| Fresh candidate C workload | Entire `names_for` samples | FNV loop | Initial-root/hash-call range | HashMap probe range |
| --- | ---: | ---: | ---: | ---: |
| UDP hit | 1,975 | 18 | 294 | 1,616 |
| UDP mixed | 2,007 | 174 | 745 | 1,013 |
| UDP miss | 1,409 | 204 | 911 | 200 |
| TCP miss | 146 | 16 | 62 | 58 |

Ranges exclude other prologue/epilogue instructions. FNV loop samples are
0.170% of all UDP-hit samples, while the whole function is 18.636%. These are
existing sparse self-instruction samples, not exact CPU percentages; source
and emitted instructions provide the independent mechanism check below.

The frozen hot wire name is 16 bytes. Its FNV loop therefore executes 80
instructions per initial lookup, with 16 dependent multiplications. An ideal
four-byte unroll can remove at most 24 decrement/branch instructions before
grouping and remainder overhead; it cannot parallelize the hash recurrence.
It also adds a tail path/code footprint. This concrete control-work budget,
corroborated by the segmented samples, is too small to justify a full native
screen or product change at present. No claim is made that the exact cycle
saving can be calculated from instruction count alone.

`Name` is an immutable `Vec<u8>` wrapper. Root/dotted constructors and the
compressed-name decoder create it; no mutable wire accessor exists. Thus a
cached canonical shard could be kept coherent, but no existing digest is
available to reuse. A stored field would expand its payload/layout, affect
every containing record/question/clone, and require preserving existing
semantic equality and hashing rather than hashing the new metadata. It would
also impose hash work on non-cache parser consumers. That is disproportionate
to the available control-work saving and is not selected.

The decoder walks label boundaries and bulk-copies chunks; it does not already
run a reusable per-byte canonical hash. Fusing FNV there adds byte work and
needs either persistent state or new question/caller plumbing. Fusing it with
`canonical_wire` helps only callers already allocating that canonical copy.
The ordinary lowercase hit path borrows its original bytes and makes no such
copy. Either approach still needs the independent randomized HashMap hash.
Neither is selected for the current hit path.

The actual HashMap path already loads and compares eight control bytes with
AArch64 NEON, extracts matching high-seven-bit tags, checks candidate key
length and calls `memcmp` on the bytes. Its table entries have a 32-byte stride.
Repeated groups use the library's triangular eight-byte probe steps. Of the
1,616 UDP-hit probe samples, 1,151 land at the first `cmeq` and 183 at the key
length comparison; **zero land in the repeat-group range**. Mixed also has
zero, miss one and TCP miss three. Sampling does not prove all lookups finish
in one group, but it does not support attributing the hot function to long
probe chains or byte-by-byte key comparison.

Recomputing the unchanged FNV on all 800 frozen hot names uses all 64 shards,
with 4–22 names per shard. Library insertion-only growth would give four
8-bucket, forty-four 16-bucket and sixteen 32-bucket maps (1,248 buckets total).
This is an explicit capacity inference, not a runtime bucket dump; randomized
placement and actual probe lengths are not inferred from it.

No low-complexity HashMap change is selected on this evidence. Reserving more
buckets changes memory/first-insert failure costs; shrink/rehash adds allocation
and COW boundaries; replacing the group implementation or hasher changes the
library/compiler or security contract; compact custom roots would introduce a
new representation. None is justified by a few sampled instructions. If later
device evidence warrants revisiting this path, the narrow next control is
actual groups/key comparisons under the existing frozen workload, with unchanged
RandomState and capacity—not an unmeasured layout replacement.

`name-shard-readonly-review.json` records exact ELF/map/disassembly/source hashes
and address-segment counts. No product code, hash algorithm, shard count,
dependency, compiler setting or D gate was changed. D proceeds to its own
device comparison; this local rejection is not a claim that all project-wide
optimization directions are exhausted.
