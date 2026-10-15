# Fresh single-address cache answer prototype

Independent F child `2a9d53b0` keeps the ordinary single fresh A/AAAA answer
out of the general cache reply state machine. The existing inspected name
hint must identify exactly one live, nonnegative record of the requested
address family and valid data length. Name address, cache owner/root identity,
revision and entry generation checks remain mandatory. Every rejection is
read-only; the original lookup still owns expiry, CNAME, negative, mixed and
multi-record behavior. Success performs the original single-slot LRU promotion
without allocating a Vec of IDs. The original writer, TTL calculation, logging,
truncation and surrounding EDNS processing remain in use.

The original answer function body is moved intact behind a non-inline general
fallback. This is a narrow performance experiment, not a behavior repair or
permission to bypass local ownership. It is independent of the name-buffer,
dotted-name, singleton and event-loop prototypes. The A53 stage experiment
motivates addressing the answer call, but its coarse intervention differences
are not exact or additive costs and do not predict this prototype's saving.

Local library tests pass 716 with 8 ignored; Linux-musl all-target checking
passes. The new reply test compares 576 A/AAAA, TTL, flags, DNSSEC, filtering,
buffer-limit and logging combinations to the unchanged general implementation.
A second test checks successful promotion and read-only rejected hints,
including expiry followed by the original removal and multi-record fallback.
Two initial test failures remain in private logs: QueryEvent lacks PartialEq
(comparison now uses its existing Debug representation), and separate cache
insert transactions replaced the first A record (the multi-record fixture now
inserts both records in one transaction). Neither required a product change.
Exact-source Linux gates and the unchanged SDK build are required before the
daemon screen. Full frozen-C correctness is still pending.

## Fixed native screening

[The fixed plan](fresh-address-native-plan.json) reuses the existing
`run_layout_native_screen.py` unchanged: 15 scenes, three grouped user PMU pairs
at 200,000 operations and five plain CPU pairs at 2,000,000 operations, except
raw-address/configured-CNAME at 200,000. Compare fresh-address and the separately
prepared singleton-slice `8ed0cfdf` independently against F, in 480 windows.
The latter explicitly tests whether reducing repeated owner dispatch improves
the earlier singleton's four adverse scenes; no prior result is pooled or
discarded. Source and probe identities, checksum rules, CPU placement and
W/direction comparison are unchanged. No native result qualifies the device.

Run only after Linux gates and SDK construction finish, with the Oracle workload
reservation. Retain a failed attempt and stop rather than selectively replacing
windows. The unchanged exact-SDK owner screen then compares fresh-address and F
alone: 3 PMU pairs plus 5 plain pairs at each of low 200/s and high unpaced load,
32 windows. Preserve low-load tick precision and W/direction rules. Variable-N
high load remains a pipeline diagnostic, not an isolated-server capacity or
fixed-N acceptance result. No fresh strace matrix is needed for this change.

Only supported immutable changes may enter a subsequent combined candidate;
that candidate still needs full correctness, complete timing and an independent
E comparison on A53. Product sources already being measured will not change.

## Allocation mechanism checked locally

[Thirty Mac count-only controls](fresh-address-local-allocation.json) completed
with equal output checksums and zero live-byte deltas in all 15 scene pairs.
Ordinary hit, upper-case hit, hit with leases and typed-config hit each remove
one 64-byte allocation. Ordinary fixture hits change from 4 allocations/245
requested bytes to 3/181. These fixture names differ from the physical 270-byte
whole-E-owner count, and the scopes must not be pooled. Other allocation counts
stay equal. Host-localise requested-byte/reallocation variation remains visible;
that fixture's bucket/rotation depends on process addresses and no causal
improvement is claimed for it. All 34 commands and their logs were rechecked;
162 input files on each side matched the source commits after the run.

The unchanged SDK builder completed source `2a9d53b0`: ELF
`b52432a274ab9dda36d60e568e4b618e755d34e69ffce72bc5343df485fcce7f`,
2,136,859 bytes, receipt
`1463c8849b8aecf273f058cea827815753923bcc3844c4ec467776ccaac0c660`.
This is a built unqualified prototype, with no CPU result yet.
