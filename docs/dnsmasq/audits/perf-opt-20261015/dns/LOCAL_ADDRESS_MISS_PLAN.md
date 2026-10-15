# Bypass local reply machinery only after proving an address miss

Independent F child `9617d93e` puts a conservative read-only check before the
normal local-answer call. Only a well-formed ordinary IN A/AAAA question can
qualify. Any configured CNAME, raw record of that type, interface declaration
or published interface, synthetic domain, local-only/literal-address rule,
hosts owner/nonterminal, live lease or expired matching lease/nonterminal sends
the question back to the original engine. A bulk hosts generation also always
uses the original engine because its retained lease nodes can rotate even
without a host answer.

If no local answer or lookup side effect is possible, the caller returns None
after the original read-only cache CNAME/name inspection, retaining its hint.
It avoids local pseudoheader sizing and the general local reply function's
frame/work. Cache answering still runs normally, including cached CNAME
priority and EDNS handling. No local-ownership memo, index or invalidation
protocol is added. The check rereads current state for every query.

The check uses the existing dotted-name conversion and indexes. It does not
eliminate that allocation. Rejected cases may perform additional checks and,
if they reach the name stage, an additional temporary allocation. This is a
material tradeoff to screen; local-positive and lease paths must remain in the
results. A read-only check alone is not a claim of free or faster fallback.

The new test compares600 combinations against the original LocalAnswerer
(10 configurations,5 names,2 address types,2 transports,3 clock inputs), then
checks actual lease expiry followed by clock rollback in one generation and
the retained-bulk fallback. Mac library715/8 and musl all-target checking pass.
An independent semantic review and existing hot15 allocation controls follow.
Frozen-C and related Linux runtime gates have not yet qualified this source.

[The fixed plan](local-address-miss-native-plan.json) uses the existing240-window
15-scene F comparison with unchanged operation counts,3 user PMU pairs and5
plain CPU pairs. It preserves all fallback controls, output checksums, identity
checks, W/direction rules and failures. No prior variant's samples are pooled.
Exact Linux related gates and the original SDK recipe precede screening.
Current Oracle work must finish first. A supported variant can then use the
original32-window low/high SDK owner screen and independent A53 comparison;
native gains alone do not qualify or select a combined next candidate.
