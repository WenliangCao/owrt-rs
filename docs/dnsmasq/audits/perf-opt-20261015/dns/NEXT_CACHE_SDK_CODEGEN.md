# Exact SDK code generation before the next measurements

All three independent sources now pass their related Linux gates (934,934,935)
and the unchanged SDK build, with2,136,859-byte ELFs inside the original budget.
These are unqualified exploratory artifacts. No full44 or performance result
is inferred. Source, ELF, build-receipt, same-link map, mapped byte ranges and
actual instruction bytes are bound in [the disassembly receipt](next-cache-sdk-codegen.json).
The sectionless static PIE files were decoded through executable PT_LOAD ranges.

| Exact SDK variant | Shared local/cache caller code / frame | General cache answer code / frame | Selected fresh writer code / frame |
| --- | ---: | ---: | ---: |
| F | 3540 / 592 B | 13524 / 2256 B | in general |
| Original fresh-address | 4528 / 720 B | 13524 / 2256 B | in caller |
| Writer refinement | 3980 / 608 B | 13524 / 2256 B | 1004 / 288 B |
| Cold metadata | 3536 / 592 B | 13484 / 2256 B | in general |
| Hosts miss index | 3540 / 592 B | 13524 / 2256 B | in general |

Refinement removes112B of the parent's shared caller reservation, but remains
16B above F. Its selected-hit two-frame subtotal608+288=896B exceeds the parent's
720B by176B. The helper adds a call; this is not a tail-call or zero-cost claim.
Mac had predicted a64B caller reduction and144B hit-chain increase, showing why
the exact SDK must be inspected separately. The general fallback remains the
same size/frame. Local-answer body/frame is14032/848B on F and both fresh paths,
14184/848B on cold metadata, and13900/832B on the hosts-miss prototype.

These are static entry reservations and emitted code extents, not measured
stack traffic, cache misses, complete hot working sets or causal CPU shares.
The cold-metadata32B Entry mechanism and extra64B metadata allocation were
measured in the separate local count controls; exact device and runtime costs
remain for the fixed screens. Do not combine independent variants or add their
point estimates. Preserve the parent's eight native regressions and below-gate
A53 result while evaluating whether the refinement actually improves them.
