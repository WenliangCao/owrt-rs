# Frozen C hit-path attribution

The frozen hit workload does **not** create A and AAAA entries for each hot
name. `m6a_loadgen.c::choose_dns` selects the type from `index % 10`, and the
name from the same `sequence % 800` index. Its 800 owners are 560 A-only and
240 AAAA-only names. The upstream returns one requested-type answer RR.
Existing profile records from the exact candidate C independently confirm all 4,000
measured queries follow this mapping, with zero dual-type owners; all 40
sampled replies contain one answer RR.

A local diagnostic on frozen source `f7f7a2ed` confirms the actual extraction
and lookup path. One thousand generated prewarm replies pass through the real
`CacheContext::insert_reply_with_policy`, leaving 800 singleton name indices
and no multi-record indices. Four thousand ordinary cached answers then make:

| Counter | Count |
| --- | ---: |
| `names_for` / `inspect_name` | 4,000 each |
| Singleton hints / reused singleton hints | 4,000 each |
| Multi-record selections / lookup fallbacks | 0 |
| Question, owner/root or revision rejection | 0 |

Every answer contains one RR. Independent source review also confirms that
the production UDP owner passes the same question borrow and cache through
inspection and lookup; the plain workload does not mutate the name index
between them. The hint is active. It removes the second name-index search;
the initial search is still required.

The fresh SDK profile's 18.64% self-instruction samples in `names_for` are
therefore compatible with successful reuse. That percentage is not an exact
CPU share or evidence of fallback. The same UDP-hit profile has 6,042 kernel
samples out of 10,598 total. The earlier native microbenchmark covers the
local/cache API without socket/owner/kernel work and uses 23-byte wire names,
whereas this workload uses 16-byte wire names. Different scopes, names and
SDK/libc code generation mean its percentage gain cannot be transferred to
device CPU or RTT. These are attribution limits, not a substituted performance
acceptance result; the complete device series remains authoritative.

No concrete behavior defect was found. Fresh candidate C profiles still
attribute 11.09% of UDP-miss and 18.12% of TCP-miss instruction samples to
`insert_at_counted`, so the preserved expiry-pressure experiment remains a
concrete next direction. It stays paused until C's device comparison finishes.

`c-hint-attribution.json` records identities and counters. The small
`c-hint-attribution.patch` reproduces test-only instrumentation in an ignored
copy of frozen C. It is not a product patch or a benchmark framework. Raw
source copies/build logs remain private. No Oracle workloads, bulk transfers,
router access or changes to timed C occurred during this investigation.
