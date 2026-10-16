# Cache content Arc slice: source scope review

The proposed `Vec<Arc<[Option<Entry>]>>` representation has no identified
product-semantic blocker. Review source is `6ab0f064b69087add3be1cb2bf5604fbaf42dffa`;
its `cache.rs` Git blob `f0be14a923ab184bf2f0e2af0e6bf5ef02bc2409` is identical
to the locally inspected a15 source. This is read-only review: no patch,
compilation, allocation measurement, qualification-tool edit or remote action.

`ContentBlock` contains only `Box<[Option<Entry>]>` and derives Clone.
`Cache::snapshot` clones the vector of Arc roots; `entry` reads a slot, and
`entry_mut` performs COW on its block. With a direct Arc slice, snapshot still
shares roots and `Arc::make_mut` clones the same initialized elements when
shared. `Entry::clone` continues sharing immutable Record and local-target
Arcs while copying its own expiry/target/authority/flags exactly as before.
No Entry/Slot/Record, LRU, name index or transfer interface needs to change.

Keep the existing per-block `Arc::make_mut` then element-by-element clear
order. Replacing shared blocks with new empty arrays would skip the existing
COW/drop boundary. Keep the lower-bound reset, name revision, slot generation
and name-root clearing unchanged. `NameLookup` binds the Cache owner address,
name-root vector address and revision, not the content wrapper address.

Construction must retain actual lengths: capacity150 has64/64/22 entries,
capacity1 has one, and capacity0 has no content roots. `get` already checks
the slot/generation before indexing. Existing snapshot tests retain content
root `Arc::ptr_eq`, Record sharing and private clear semantics with a slice;
there is no production or ordinary test Weak observer for content roots.
The retained-view tests cover negative authority, reverse/lease invalidation,
rotation and import. Existing zero/small/150/4096 clear tests do not strongly
exercise a populated final partial block: a useful targeted check is mutating
the last slot across a64/65 or150 boundary while the parent snapshot retains
the old entry, followed by clear. This review adds or runs no test.

Pinned Rust1.98.1's local `alloc/src/sync.rs:2515` supports slice `make_mut`;
shared roots clone elements and unique roots mutate in place. The existing
Weak dissociation behavior remains, though no content Weak is present.
`Arc::from(Vec)` allocates the Arc slice and moves the items before releasing
the temporary Vec (`sync.rs:4036`): one fewer persistent allocation does not
mean one constructor allocation. On the supported64-bit layout, a slice Arc
is a fat handle, so each snapshot content-root vector needs an additional
word per block compared with the old thin Arc. Constructor/COW requested
bytes, root-vector growth and emitted loads need actual local measurement;
no CPU or overall memory improvement is claimed from fewer indirections.

Qualification tooling is representation-coupled and must not be silently
bypassed if this ever advances beyond a local prototype:

| Tool | Required later consideration |
| --- | --- |
| `m6b_tcp_a_layout.py` | `SIZES` names the removed wrapper; root-vector bytes currently multiply both content and name roots by one thin Arc size. Content/name handle widths must be accounted separately. |
| `m6b_resource_roots.rs` | Layout print and controls use ContentBlock/`.entries`; direct fat-pointer-to-usize casts must extract the data address. Root identity still refers to one real nonempty allocation. |
| `m6b_resource_companion.py` | Constructor and two content-detach text anchors bind the old spelling and must still observe each real creation/detach. |
| Root mutable helper | `m6b_root_mut<T: Clone>` is Sized and cannot take a slice. The std implementation's `CloneToUninit` bound is unstable to name externally; use an explicit safe slice helper if adaptation is eventually authorized. |
| `m6b_tcp_a_guards.py` / `m6b_tcp_internal.py` | Negative mutation and layout receipt fields name the wrapper. Adapt actual representation fields without weakening the mutation, ownership, business or resource assertions. |

The existing reverse-order sidecar instead uses `entry`/slot APIs and has no
identified wrapper coupling. Root's decision is to leave all full-gate tools
unchanged now, first measure an independent product prototype's actual
constructor/COW/codegen cost, and retire it if unsupported. Only a justified
later qualification would receive a separately reviewed minimal tool adapter;
never fabricate a former ContentBlock size or change the frozen C oracle.
