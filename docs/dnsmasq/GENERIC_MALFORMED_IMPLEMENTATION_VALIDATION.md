# Ordered generic extraction errors reach the client

Product `ac8a3b6` fixes the 14 reply differences established by the independent
[malformed generic baseline](GENERIC_MALFORMED_BEFORE_RESULT.md). Generic
embedded-name decoding errors now leave the ordered extractor through a
`Result`, after any completed cache prefix. The common UDP reply stage clears
response records, preserves OPT, sets SERVFAIL and adds EDE_OTHER. Recipients
still restore their own question/ID and apply their UDP limit; they do not
repeat the normal policy pass on this completed error reply.

No packet-wide prevalidation, cache rollback or synthetic counter correction
was added. Capacity/commit failure remains distinct from a malformed packet.
Disabled generic types and opaque unknown RDATA keep their previous behavior.
The existing address/bogus path and this new error path share the same
record-removal helper, including preservation of the last OPT.

Independent review identified one necessary distinction before final
qualification: `canonical_rdata` can also return `RecordTooLong` when name
decompression exceeds the cache representation's u16 limit. That is not the
C malformed-name return path. `ac8a3b6` therefore preserves the previous
cache-abort/forward behavior for that limit. Very large RDATA and C's wrapping
representation remain unqualified; this change does not imitate that wrap.

| Final-source check | Result |
| --- | --- |
| Frozen malformed generic service gate | Native C35/35; actual image C35/35 |
| Single altered-reply negative control | 34 matches / one detected difference, exit1 |
| Original normal cache-rr gate | Native22/22 configuration +78/78 paired observations |
| Existing ordered policy service | 42 cases /210 client replies, zero differences |
| Existing bogus/CD cache service | Native256/256, zero differences |
| Isolated library / main tests | 389 /7 passed; 16 ignored |
| Native/musl all-target Clippy and formatting | Pass, warnings denied |

The malformed gate separately checks 196 auxiliary conditions per side and
retains the previous 14 failures. The normal gate's reverse nine remain C-only.
These counts are not pooled into a full-service equivalence claim. The earlier
image readiness timeout belongs to the `4bf072d` normal gate and remains open.
The final source has no failing daemon gate in the checks listed above.

An initial local development check failed when the caller edit preceded the
return-signature edit; the error was fixed before source `0fae34f` was frozen.
That intermediate build passed its checks but received no service qualification
before the separate representation-limit correction. Its artifacts and the
development note remain private; only the final `ac8a3b6` ELF is attributed to
the table above.

Final native ELF SHA-256:
`3d8462fac7a81707e3b24f84b1a25fc8b6903d808b66b14cc4f3ede9e230b692`.
The [JSON](GENERIC_MALFORMED_IMPLEMENTATION_VALIDATION.json) pins the source,
ELF, root regression logs/results and archive. Raw evidence is under ignored
`private/dnsmasq-rewrite/generic-malformed-fix-20261001/`; independent gate
artifacts are identified in [its after report](GENERIC_MALFORMED_AFTER_RESULT.md).
All listener experiments use the isolated build host. There is no new SDK
artifact, performance measurement or router acceptance.
