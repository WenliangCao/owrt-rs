# Ordered cache insertion effects — 2026-10-01

Exact dnsmasq 2.93 `extract_addresses` starts a cache transaction and inserts
while traversing the Answer section. `really_insert` removes existing records
and may evict live records immediately. A later malformed RR or rebind rejection
skips commit; those earlier removals and eviction counters are not rolled back.
The former Rust whole-section validation and clean-reply admission lost them.

`CacheContext` now traverses and inserts in that order, restarts at each CNAME,
and leaves aborted entries pending until the next insertion starts. Zero TTL
and failed insertion still stop cache mutation at the primitive boundary.
Bogus-wildcard matching retains its separate transaction: the first matching
RR's owner and TTL create an NXDOMAIN entry, even with `no-negcache`.
Static/dynamic doctor execution and its pre-cache metrics remain before this
stage. Client reply filtering still runs independently for each recipient.

The expanded gate also found an A followed by a CNAME for the same owner in one
reply. Both are inserted by C, but its answer path follows the first CNAME
before selecting a terminal address. Rust now preserves that selection.

Evidence is private at
`private/dnsmasq-rewrite/cache-policy-20261001/oracle/` and on the build host at
`/home/ubuntu/dns-cache-policy-20261001/private/`. No physical device was used.

| Gate | Result |
| --- | --- |
| Frozen original policy baseline, `baseline-04` | 21 cases / 249 operations; 74 differences |
| Initial ordered-insertion candidate, `candidate-01` | Same 249 operations; zero differences |
| Expanded policy, `expanded-02` | 29 cases / 471 operations; two mixed A/CNAME replay differences |
| Expanded policy after replay fix, `expanded-03` | 471 operations; zero differences |
| Deliberate live-freed counter mutation, `negative-01` | 470 matches / one difference; exit 1 |
| Original malformed replacement, `replacement-01` | Seven operations / zero differences; old cache hits become misses |
| Clipped later sections, `clipped-final-01` | 96 operations / zero differences |
| Empty-OPT cache lookup, `edns-final-01` | 155 operations / zero differences |
| Cache replies and actual counters, `cache-answer-metrics-final-01` | 764 operations / 382 counter snapshots / zero differences |
| Cache primitive counters, `metrics-01` | 215 observations / zero differences |
| Actual clipped-section daemon replay, `clipped-service-02` | IPv4/IPv6, 32 cases / 64 replies, zero differences |
| Actual pending-reply cache effects, `policy-service-01` | IPv4/IPv6, 42 cases / 210 replies, zero differences |
| Host DNS library | 204 passed / four ignored |

The 29-case gate includes unrelated owners/types, RRsets, CNAME pressure and
cycles, invalid CNAME targets, zero TTL, rebind order/domain exception, bogus
owner/negative-cache behavior, static doctor order, A/AAAA lookups and recovery
after aborted transactions. Hard C anchors require prefix deletion, survival
of unrelated names, live eviction without insertion, separate bogus insertion
and subsequent recovery. Comparator calibration rejects a changed counter and
missing observation. Exact source-object digests and generated C/Rust binaries
are recorded with each gate; raw packets/configuration stay private.

Preserved unsuccessful setup rounds: `baseline-01` used sudo's unavailable
Rust compiler; `baseline-03` exposed missing imports in the inherited draft
probe. The corrected baseline is `baseline-04`. `expanded-01` intentionally
failed its recovery assertion because its recovery address was itself rewritten
by that case's doctor into private space; the corrected corpus uses an unaffected
address and retains the failed trace. These rounds are not passes.
The first actual-service invocation used a nonexistent C binary path and never
started a daemon; `clipped-service-02` uses the verified exact native ELF
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
Its Rust ELF is
`2c21bba92f8cd3903c0411af0aff52c610c059fd37cdd9ba108e6cb13fcda616`.

`cache_policy_service_diff.py` exercises the complete UDP chain without
artificially injecting cache entries: it holds a cold query's upstream reply,
warms that owner through an independent CNAME query, verifies a preexisting
cache hit, then releases the held reply. Later A/AAAA replies and actual
upstream sends expose the deletion, retention, rebind and bogus-cache effects.
The 21 scenarios run with both IPv4 and IPv6; all five replies in each case
remain in one observed clock second so TTL fields are compared exactly.
The actual-service negative control deliberately adds one upstream-send
observation and requires one failing case.

This closes the measured prefix-side-effect boundary. It does not establish
all cache behavior, TCP publication, DNSSEC metadata, arbitrary cached RR types,
full service equivalence, or performance acceptance. The later ordinary
empty-OPT cold-insertion fix and separate service gate are recorded in
[the EDNS cache phase](DNS_CACHE_EDNS_PHASE.md#cold-empty-opt-insertion--2026-10-01-continuation).
