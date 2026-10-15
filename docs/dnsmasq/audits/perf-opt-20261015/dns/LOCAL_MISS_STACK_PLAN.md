# Bounded storage for the conservative local-address miss check

Independent refinement `c44cd116` is based on `1676fbb6`, not on the older
whole-local-engine dotted-name experiment. Its only mechanism change is to use
the existing253-byte bounded converter inside the non-inline `unclaimed_address`
helper. The owned general local answer and lease-expiry functions remain intact.
This targets the measured extra temporary allocation on host, host-localise,
lease-address and dynamic CNAME fallback paths without placing a new stack
buffer in their original general engine frame.

The conversion helper and its exhaustive binary-label/maximum-name regression
come from retained `c627927d`. Returning None for a literal dot within a label,
ASCII lowercasing, root and maximum-length boundaries remain the same as the
owned converter. Scratch is borrowed only for read-only lookups and never
escapes. This adds a fixed stack reservation to the small helper, including
calls that ultimately reject the shortcut; it is not a zero-cost claim.

Mac717 library tests with8 ignored and musl all-target checking pass, including
the original600 local-answer comparisons, sticky lease expiry and malformed
Additional controls. Independent source review and hot15 count controls are
being completed. Exact Linux gates and an unchanged SDK build remain pending.

[The fixed screen](local-miss-stack-native-plan.json) compares this refinement
independently to F with the original15 scenes/240 windows. It preserves fixed
operations,3 grouped user-PMU pairs,5 plain pairs, checksums and W/direction
rules. It does not replace or pool the parent's unstarted plan or its allocation
observations. Reuse the existing runner; no new instrumentation or test framework
is introduced. Start only after current reservations and this source's gates/
build finish. Any retained variant can continue through the original low/high
SDK owner screen and independent A53 check; complete candidate qualification
still requires the frozen full gates and a discernible physical E comparison.
