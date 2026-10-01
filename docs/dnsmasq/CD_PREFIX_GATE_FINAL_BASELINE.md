# Final ordinary CD prefix fixture boundary

The final fixture passed **10 cases / 134 observations** on both native and
strictly verified image C before the final Rust comparisons. Native/image
observations match. All CD replacement, CNAME-pointer visibility, direct-owner
miss, empty-CD-reply cleanup, pressure eviction and recovery cases from the
[original baseline](CD_PREFIX_GATE_BASELINE.md) remain intact.

Two unrelated recovery operations were removed: the no-CD controls already
have a committed replacement, so they now finish by verifying that replacement
instead of replacing the owner a second time through another new alias. The
no-CD controls finish with address suffix 21; the CD cases still recover and
finish with suffix 44. The reduced total is 134 rather than 136.

This change responds to a retained **C calibration failure**, not a Rust
failure or a relaxed expected value. The first image after-run on the original
fixture (`cd-prefix-image-after-01`) matched 123 observations in nine cases, but
its no-CD AAAA control forwarded the final old-alias lookup after the extra
second replacement. C failed calibration before Rust ran that case. The earlier
native after-run matched all 136. All raw results remain preserved.

The source supports a hash-collision explanation: `cache_scan_free`
(`cache.c:560-600`) clears the old target's UID before continuing its bucket
scan, where a later alias can be discarded as outdated; `really_insert` restores
the target UID only after that scan. `cache_hash` places the replacement at the
front of its bucket. The hash mixer at `cache.c:295-310` reads bytes of `typestr`,
which contains relocated pointers. Thus process layout can affect which names
collide. This is a source-supported inference: the failed process's bucket
layout was not captured. The gate does not claim to resolve or emulate that
separate collision-sensitive behavior.

The final fixture omits that unnecessary second replacement only in the
ordinary no-CD controls. It does not accept an unexpected hit/miss, erase a
counter difference, choose names after observing a result, or retry until a
run passes. It was first frozen against both C binaries with no Rust execution.
The tool also now reports `matched: null` when observation stages differ;
subtracting one stage-list error from the observation count was misleading.
Earlier raw `matched` fields in such cases must not be interpreted as actual
per-observation parity counts; their case mismatch counts remain valid.

Final tool SHA-256:
`7179d7661adfe9c55dc4de8b5b09d4f131ede673a7b7468857bb8243c9ca9bb9`.
Raw final baselines are
`private/tcp-writeback-gates/cd-prefix-c-final-baseline-01` and
`private/tcp-writeback-gates/cd-prefix-image-final-baseline-01`.
The companion JSON records identities, counts, raw hashes and cross-reference
comparison. No product code or C timeout was changed by this gate work.
