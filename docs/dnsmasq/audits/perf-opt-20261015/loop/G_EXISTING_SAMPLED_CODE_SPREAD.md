# Existing G sampled-code spread

Read-only regrouping of the original independently reviewed UDP cycle sample
uses the same exact G SDK ELF, process map and raw samples. All5497 original
samples and every attributed emitted-range count reproduce;5213 samples
are user PCs in G's ELF,284 remain outside this regrouping. No C sample was
locally available for the same calculation, and none was downloaded.

The ELF sample has1416 distinct PCs across531 distinct64-byte address bins
and63 distinct4096-byte bins. The busiest324/386/479 of the64-byte bins account
for90%/95%/99% of its sampled period. These are address bins, not measured
cache lines, fills, misses or a simultaneous working set. Unsampled intervening
instructions and temporal reuse are unknown. Neither the whole2.1MB ELF nor
this sampling establishes an A53 instruction-cache capacity bottleneck.

The original poll_inner range has111/5497 samples (2.019%); consume_releases
has36 (0.655%). This gives the new117 layout prototype a concrete but limited
Oracle target. Reducing its empty-path local frame from1520 to224 does not
explain the whole physical C/G gap or imply a runtime saving. The prototype
is a6ab child, not the sampled185 source. The physical G stage diagnostic
and actual product timing remain the deciding evidence.

The original raw/ELF hashes, count checks, denominator and limitations are
retained in [the derived receipt](g-existing-sampled-code-spread.json). No
benchmark, observer, comparator, source or remote state changed.
