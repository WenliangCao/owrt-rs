# NXDOMAIN/SOA pressure and the corrected ordinary-miss lookup gap

The independent supported NXDOMAIN/SOA pressure gate confirms the DO fix also
preserves LRU effects for NXDOMAIN and cached generic SOA records. It exposes
one existing non-DO gap: a plain A/AAAA miss against a same-name cached SOA
skipped C's final generic-record lookup in Rust, changing the next eviction.
The product at `5c15e16` corrects that miss path and passes the complete frozen
gate against native C and the actual image; before/failure stages remain below.

This is a separate 120-observation gate from the earlier
[direct/CNAME 120](DO_LOOKUP_PRESSURE_RESULT.md). Their counts must not be
interchanged. Its [plan](DO_SOA_PRESSURE_PLAN.md) freezes 54 NX observations
and 66 SOA observations across 12 profiles, with all C schedules calibrated
before Rust runs. The default two-send SERVFAIL retry and all 30 UBus metrics
are retained.

| Run | C calibration | Rust result | Fixture failures |
| --- | --- | --- | --- |
| `soa-native-baseline-02` | 120/120 | C only | 0 |
| `soa-image-baseline-01` | 120/120 | C only | 0 |
| `soa-native-before-01`, old `ddac95d` | 120/120 | 108 match, 12 differ | 0 |
| `soa-image-before-01`, old `ddac95d` | 120/120 | 108 match, 12 differ | 0 |
| `soa-native-after-01`, DO fix `aeba67e` | 120/120 | 116 match, 4 differ | 0 |
| `soa-image-after-01`, DO fix `aeba67e` | 120/120 | 116 match, 4 differ | 0 |

The old implementation differs on two victim/owner probes per A/AAAA profile
for NX DO, SOA DO and SOA plain touch. The DO fix removes the eight DO
comparison differences. The remaining four rows are the two probes in each
plain SOA profile; the identical four rows also differed before the DO fix.
Thus they are not a regression introduced by `aeba67e`.

In the SOA schedule, a negative child answer populates one SOA and one typed
negative marker. A QTYPE=ANY child query promotes only the negative address
entry and forwards, leaving SOA oldest. After filling the cache, C's plain
A/AAAA miss on the SOA owner still visits `F_RR|F_NXDOMAIN` at
`rfc1035.c:2283`, promotes the SOA and forwards. The next newcomer evicts the
child negative. Rust's `answer_records` sees no initial CNAME/address/NXDOMAIN
IDs and returns before generic lookup, so it evicts the SOA instead.

The gate compares the resulting DNS response content, SOA authority presence,
upstream order and intermediate counters, not just final totals. All profiles
still perform the same number of insertions and one live eviction. Missing
rows are rejected and an altered cache-hit observation produces exactly one
self-comparison difference. A standalone injected paired negative awaits a
fully corrected replay; no all-pass NX/SOA result is claimed yet.

## Preserved prerequisite attempts

The separate [NX/TXT gate](DO_CROSS_TYPE_PRESSURE_PLAN.md) calibrated 108/108
observations against both C variants (`cross-native-baseline-01` and
`cross-image-baseline-01`). Its `cross-native-before-01` attempt failed Rust
startup in every profile because `cache-rr=TXT` is explicitly unsupported;
zero rows were compared. This is a configuration boundary, not LRU evidence.
The complete tool and failed startup logs remain. TXT storage and lookup
semantics are not claimed as implemented.

The initial SOA attempt (`soa-native-baseline-01`) calibrated 94 rows but
rejected both untouched SOA profiles. Its source-derived initial assumption
mistook insertion order for LRU order: C's `cache_end_insert` traverses the
reverse pending chain and links each record at the head, leaving SOA newer
than the negative child. The untouched control consequently evicted child,
just like the touch profiles, and did not distinguish lookup effects. No Rust
ran. The documented pre-Rust correction adds the QTYPE=ANY child promotion;
both C variants then fully calibrate the discriminating schedule. No measured
Rust mismatch was used to choose an expected result.

## Scope and identities

SOA insertion uses the already-supported negative response path, without
`cache-rr`. The result does not qualify arbitrary generic RR insertion,
multiple generic types/order, hash-bucket purge, stale answers, or every
no-answer branch. In particular, RD-disabled queries with existing address
IDs and other early-return paths are outside these schedules.

The unchanged SOA gate source SHA-256 is
`cd0e07de387f983f8f8d0bf1d73a9440b7ee105369d5a095838bf1ac7465335d`.
Old Rust ELF SHA-256 is
`334819a9cbb1096c71066d27af8b6dc0eefb453e117ff2a4d0b25d0edee2b65d`;
DO-fixed Rust ELF is
`d2643e676b226ab3527d2ba8a76ae887d2e56743eab5df7a9b78f70f6fef203d`.
The native C and verified image identities are the same as the direct/CNAME
report, and each run retains the full identity including loader/libraries.

Artifacts and a file-hash manifest are under
`private/dnsmasq-rewrite/do-lookup-pressure-20261001/private/`, with the build
host copy at `/home/ubuntu/dns-do-pressure-20261001/work01/private/`.
All service experiments used `run_isolated.sh`; no physical router was
accessed. This report contains no product change. The ordinary miss correction
and its frozen replay remain outstanding.

## Final corrected product replay

The root-owned product fix `5c15e16da102a209c1040ba5a5d44d8abb1ca58d`
adds the final generic/NXDOMAIN lookup before returning an A/AAAA/CNAME initial
cache miss. It does not emit an unrelated generic record. Generic qtypes
already visit that group and do not perform a second lookup/rotation.
Independent source review found this narrow boundary consistent with the
matching C sequence; the unqualified early-return branches listed above remain
outside this change.

The unchanged NX/SOA tool gives:

| Run | Result |
| --- | --- |
| `soa-native-final-5c15e16` | 120/120 paired observations, zero differences/failures |
| `soa-image-final-5c15e16` | 120/120 paired observations, zero differences/failures |
| `soa-native-final-negative-5c15e16` | Exactly one deliberately altered cache-hit observation differs; exit 1, zero fixture failures |

The same ELF also passes the separate unchanged direct/CNAME pressure gate
against both C variants, with its own exactly-one-mismatch negative. Each gate
still has 120 observations; these are two distinct workloads. Direct comparison
of the saved native/image C-only baselines yields 120/120 identical decoded
observations per gate without any new daemon run.

Executed Rust ELF SHA-256:
`87f68b790d6a19f1cf25bdfcc33093f603016b3df8d1f8df5b959c74f6990b90`.
Source archive SHA-256:
`c68add496d9acb2067b066a0abb3a23eee288b0611744ec05b4162737cb66e2a`.
Build directory: `/home/ubuntu/dns-do-lookup-fix-20261001/5c15e16-01/`.
The ELF and every final trace are also retained in the local private evidence
directory and file-hash manifest. Both measured lookup/eviction gaps are now
closed; this does not change the TXT unsupported boundary or claim complete
cache equivalence.
