# Iterate one lease-ID slice without an outer iterator

Source210801cf is an independent child of6ab. LeaseNames::lookup keeps the same
API, case conversion, empty-table guard, ID order, active flags and original
live/expiry predicate. It now selects the matching ID slice (or an empty slice)
before returning its iterator. It no longer returns an outer Option iterator
and flatten adapter for a single list. No new presence API or duplicated lookup
predicate is added; the separate530 boolean prototype is not included.

Mac726library tests/8ignored and musl all-target checking pass. The new test
compares full ordered entry identities against the former adapter in576cases:
four stale policies, empty/parent/expired-child views, six names including
mixed case/non-terminal/absent, and eight clocks including rollback and extremes.
It also checks repeated exhaustion. Existing tests retain publication, alias,
reverse, local ownership and accepted-view behavior. Linux runtime is pending.

The local final AArch64 control reproduces6ab ELF77096845. The ownership guard
still makes two calls, but its iterator advancement changes from816B of
FlattenCompat code to240B of direct slice find_map code. This is a static code
mechanism, not a measured576B executed saving. lookup itself grows692→712B;
LeaseNames::name_exists grows760→916B while its frame shrinks192→160B. The
ownership guard and shared local entry sizes remain528/3804B. Whole local ELF
falls5022240→5021352B (−888B); all adverse individual changes remain recorded.

These local rust-lld/bundled-musl files are not canonical SDK artifacts. There
is no timing, allocation-count, IPC or physical improvement claim. Independent
review and existing screening follow current frozen6ab work; nothing is added
to its running artifact, and no qualification tool or C expectation is changed.

[Exact source, check logs and generated-code receipt](lease-lookup-slice-local.json).
