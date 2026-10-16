# Keep possible lease-expiry traversal outside the common frame

Independent6ab child84912e54 moves the original empty/expiry-bound guard to
its only caller, immediately after CLASS_IN, and makes the unchanged traversal
non-inlined. It adds no new predicate, clock, expiry index or state. CNAME/PTR
order, sticky removal, COW and subsequent cache hint construction remain the
same. Source-only independent review0a202a2b confirms exact reversal to6ab.

Mac725library tests/8ignored and musl all-target checks pass. Local final
AArch64 code reduces the shared local entry3804→3096B and its frame400→368B.
The newly separate expiry traversal is1440B with a144B frame; cached ownership
and answer_local_or_cached code sizes stay528/4060B. Whole local ELF decreases
328B. These are code-generation observations, not runtime performance.

The helper is not marked cold: an early conservative expiry bound may keep
this path eligible after a prior record expired. Such generations now pay an
extra function call/frame; any future screen must retain all lease/CNAME/PTR
controls. The current6ab source/artifact, original qualification tools and C
expectations are unchanged. SDK and Linux/runtime qualification are pending.

[Source, commands and complete private codegen receipt](lease-expiry-frame-local.json).
