# Singleton lookup: one borrowed slice, unchanged ownership boundary

Prototype `8ed0cfdf` is based solely on measured singleton `b1180f72`. It changes
the first `CacheContext::answer_records_filtered` lookup into an explicit
`ids_owner` plus one `&[EntryId]` view, and changes the original final
`drop(ids)` to `drop(ids_owner)` at the same location. No other lookup, product
prototype, compiler flag or original singleton result changes.

There is a concrete local code-generation mechanism: pinned Rust 1.98.1 with
fat LTO had not removed all repeated owner decoding. The optimized Apple
AArch64 IR contained nine distinct loads of this lookup owner's tag/capacity
word; the slice form has three. Those remaining loads select the initial
slice and implement the shared early-return cleanup and explicit normal
cleanup. These are static load sites, not nine/three loads per query.

The same function's emitted assembly instruction lines fall from 3,118 to
3,021. Its local frame grows from 880 to 896 bytes (96-byte save area plus
784/800 bytes). Both observations are retained: the source simplification is
not proof of faster execution, lower dynamic instructions or lower total
stack use. This is Mac code generation, not the exact SDK ELF. It does not
establish that the previous miss/synth/lease/RRset native regressions are fixed.

## Lifetime review

An independent source review found no remaining lifetime blocker. The owner
continues to hold `Many(Vec<EntryId>)`; the slice never escapes and `EntryId`
contains copied, generation-checked values. Cache mutations do not invalidate
that Vec. `direct_negative`, `direct_cname` and `direct_nodata` store copied
IDs, and the separate CNAME terminal owners are unchanged.

PTR reverse/synth, empty/filtered answers, RD-off, direct negative answers,
typed CNAME and CNAME-terminal returns all retain scope cleanup. Writer and
append errors through `?`, explicit `Err` and `Full` returns also drop the
owner at the original return boundary. The main positive loop still releases
the owner before the `written` completion and final filtered-name lookup.
Dropping only the slice at this point would have extended the Vec lifetime;
the prototype explicitly drops the owner instead.

## Local checks

- Release library and both existing allocation probes compile with unchanged
  opt3/fat-LTO/codegen1/panic-abort settings. A separate untracked probe emits
  optimized IR/assembly for the code-generation comparison.
- The existing `cargo test --lib cache` filter passes 127 tests, with three
  ignored and zero failed; no new implementation-mirroring tests were added.
- Fifteen whole-answer scenes and five admission scenes run on both sides at
  8,000 operations: 40 controls, equal output checksums and zero final live
  bytes throughout. Nineteen scene pairs have identical allocation counters.
- Host-localise retains equal allocation counts but differing reallocations
  (18,500/17,600) and requested bytes (8,094,080/7,594,240). This fixture already
  has process-dependent bucket/rotation variability. The difference is
  retained without a causal savings claim or selective rerun.

All 49 local build/test/probe commands exited successfully. Source hashes bind
the base Git blob and prototype commit. Raw logs, probes, full LLVM IR and
assembly remain under private `perf-opt-20261015/singleton-slice-local`.
[The derived receipt](singleton-slice-local-result.json) records every command,
all allocation controls, output/artifact hashes and the static code evidence.

No Oracle/router access, remote build or timing was performed. The prototype
remains unselected until an independent fixed timing screen and any required
correctness/SDK/device gates justify further use.
