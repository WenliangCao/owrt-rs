# Cold cache metadata: independent local size and allocation review

Reviewed F `3a3d8e3e` against the independent prototype
`40cc86fef86553f12834af36e0e2ccc23aa913ef`. No product source was changed.
The source review found no lifetime or field-coexistence blocker. The actual
Apple AArch64 types shrink as intended, with a measured extra allocation when
an entry first acquires metadata. This is allocation/layout evidence only;
no timing, Oracle, exact SDK ELF or router work was performed.

## Actual sizes and cold-field costs

The probes link the real release library; these are not mirrored struct
definitions. Rust 1.98.1, opt3, fat LTO, one codegen unit and panic-abort match
the existing local controls.

| Type / operation | F | Cold metadata |
| --- | ---: | ---: |
| `Entry` bytes | 72 | 32 |
| `Option<Entry>` bytes | 72 | 32 |
| `[Option<Entry>; 64]` bytes | 4,608 | 2,048 |
| First dynamic CNAME target: allocation calls / requested bytes | 0 / 0 | 1 / 64 |
| First negative authority: allocation calls / requested bytes | 0 / 0 | 1 / 64 |
| Add authority as the second field on a unique entry | 0 / 0 | 0 / 0 |
| Shared-snapshot target update, with authority already present | 3 / 4,650 | 4 / 2,154 |
| Subsequent unique authority update | 0 / 0 | 0 / 0 |

Setter input names and existing records are prepared before those setter
measurements. The shared-update fixture has a 64-slot block and an alias
containing both fields. F copies 4,608 bytes of entries, the 32-byte outer Arc
allocation and a 10-byte authority name. The prototype copies 2,048 bytes,
the same outer allocation/name, and a new 64-byte metadata Arc. It therefore
adds one allocation while requesting 2,496 fewer bytes. The subsequent
authority replacement releases the old 10-byte name on both sides.

The changed requested-storage terms are `-40 × capacity + 64 × M`, where M
is the number of entries actually carrying metadata, not the number of all
negative records. Common names, records, indices and allocator residency are
outside that expression. Ordinary positive entries have M=0. With all slots
occupied by metadata-bearing entries, these terms instead increase by 24
bytes per slot; the crossover is M/capacity=62.5%. This is not an RSS formula.

## Source and Arc lifetime review

All three setters obtain a mutable entry through `entry_mut`, which first
applies `Arc::make_mut` to the containing content block. Only then does
`metadata_mut` apply `Arc::make_mut` to the entry's metadata. A shared content
block therefore clones its entries and retains their metadata Arcs before
the selected entry's metadata detaches. A plain cache snapshot shares the
whole block and does not allocate one metadata Arc per entry.

The target and authority remain independent fields; either setter preserves
the other field. The supplied regression test deliberately exercises both
fields on the same negative CNAME, independent child changes and child validity
after dropping the parent. An independent reviewer confirmed the setter order,
capture/import access and `outdated_cname` access retain the existing contract.

Dynamic targets copy `EntryId`; local targets clone their existing
`Arc<LocalTarget>`. Metadata contains no Arc back to a cache entry, so this
change introduces no reference-count cycle. Authority `Name` still owns its
bytes. A metadata COW clone can copy those bytes even when the setter then
replaces the authority. Conversely, detaching a block for an unrelated entry
now only shares untouched metadata Arcs, avoiding F's authority-name clones
for those untouched entries. Ordinary `metadata=None` entries do not acquire
a metadata allocation. Deletion/clear and the final snapshot release drop
their Arcs through the existing ownership boundaries.

## Existing hot15 and snapshot allocation controls

The existing host-miss local runner was reused with only the candidate source
and label changed. All 15 scenes ran for 8,000 operations on each side: 30
valid rows, equal checksums and zero final live-byte delta. Fourteen scene
pairs have identical allocation/reallocation/requested-byte counters,
including the three CNAME scenes. Their measured loops do not include the
fixture's initial metadata publication. Host-localise retains the existing
process-dependent allocation variation: reallocations 18,470/17,570 and
requested bytes 8,103,680/7,370,880. No causal saving is assigned to that row.

The existing snapshot probe was adapted privately to link the actual crate.
All CPU/Instant reads were disabled, and inert timing fields are omitted from
the derived receipt. Its ordinary live lookup does not detach entry content:
it changes the snapshot's private LRU. A separately labelled control invokes
the existing negative-authority setter on a positive entry after lookup. This
setter rejects the record only after `entry_mut`, so it exercises the actual
content-block detach boundary without adding metadata or changing record data.
This is a detach mechanism control, not an ordinary-hit performance claim.

| Capacity / filled | Population live requested bytes, F → prototype | Extra live bytes after 20 forced detaches, F → prototype |
| --- | ---: | ---: |
| 64 / 60 | 25,358 → 22,798 | 92,800 → 41,600 |
| 1,000 / 1,000 | 302,220 → 262,220 | 91,072 → 40,832 |

The 64-slot case saves 51,200 requested/live bytes across 20 detaches. The
1,000-slot fixture touches nineteen full 64-slot blocks and one 40-slot tail,
saving 50,240 bytes. Allocation-call counts are unchanged in these ordinary
entry controls. Snapshot-clone allocations and live-lookup allocations are
identical on both sides. All eight valid snapshot runs complete 20 hits with
zero errors, balanced final snapshot live bytes and balanced population drop.

One earlier fixture failure is retained: capacity=64, filled=64 generates seven
long names, while F's existing limit is floor(capacity/10)=6. F failed during
population before any snapshot. The valid second input set uses 64/60 and
1,000/1,000, without changing the template or replacing the failure log. The
64/60 case still has a full 64-slot content array.

There were 51 local commands: 50 successful and the retained invalid-fixture
failure. All 324 source-file hashes were checked against the two named Git
inputs after execution. Raw probes, logs and the failed attempt remain in
private `perf-opt-20261015/cold-metadata-local`.
[The complete derived receipt](cold-metadata-local-review.json) includes source,
tool/probe/artifact identities, all commands and all valid allocation rows.
No performance promotion follows from this review.
