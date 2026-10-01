# DO lookup pressure: confirmed service difference

The exact no-DNSSEC C daemon promotes cached A/AAAA and CNAME records before
refusing to answer a DO query from those records. The original Rust early DO
return skipped that lookup. Under bounded cache pressure, Rust evicts a different
owner and consequently makes different upstream requests. Both native C and
the actual OpenWrt image reproduce the difference. The corrected product at
`5c15e16` passes this complete frozen gate against both C variants; the earlier
failing evidence and correction stages are retained below.

## Frozen evidence

The [plan](DO_LOOKUP_PRESSURE_PLAN.md) was committed before execution. Its
12 profiles cross A/AAAA, direct/CNAME and untouched/plain/DO controls, with
capacities 3/4. The DO query receives SERVFAIL so its upstream reply cannot
replace or repopulate the touched cache entry. C's default single-server
SERVFAIL retry is retained exactly; each forwarded failure has two sends.

| Run | C calibration | Paired comparison | Fixture failures |
| --- | --- | --- | --- |
| `native-baseline-02` | 120/120 | C only | 0 |
| `image-baseline-01` | 120/120 | C only | 0 |
| `native-before-01` | 120/120 | 112 match, 8 differ | 0 |
| `image-before-01` | 120/120 | 112 match, 8 differ | 0 |

Each C schedule completes and passes source-derived cache-hit, insertion,
eviction and upstream-send checks before any Rust process starts. The
comparator rejects a missing row and detects exactly one deliberately altered
cache-hit observation in its self-calibration. The standalone `--inject-error`
paired negative control awaits a corrected Rust replay; it is not yet claimed.

All eight differences are confined to the four DO profiles. After the DO touch
and insertion of one newcomer, C's B probe misses and its owner probe hits;
Rust's B probe hits and its owner probe misses. Plain touch and untouched
controls match. This changes packet content, ordering of upstream sends and
intermediate UBus counters. Each profile still performs one live eviction and
the same number of insertions, so terminal aggregate counts alone would miss
this behavior. No measured difference is normalized away.

The CNAME schedule first promotes the terminal target, leaving the owner alias
oldest. A DO touch promotes only the alias: C stops at its failed DNSSEC
eligibility condition before chasing the target. A plain touch follows the
chain. Both preserve the target in this particular pressure schedule.

## Exact source boundary

`rfc1035.c::answer_request` invokes `cache_find_by_name` for CNAME/NXDOMAIN at
line 1754 before the DO condition at line 1786; the A/AAAA invocation at line
2079 precedes the condition at line 2101. `cache_not_validated` (line 1687)
requires enabled DNSSEC validation, which this image does not supply.
`cache.c::cache_find_by_name` (line 1174) promotes matching records, rotates
RRsets and purges invalid entries in the visited hash bucket. Rust
`CacheContext::answer_udp` rejects a nonzero OPT TTL before `answer_records`,
so the DO bit bypasses that mutable lookup.

This gate establishes pressure/victim effects for these empty-OPT IN A/AAAA
requests only. It does not establish equivalence for hash-bucket-wide expiry
purge, multi-address round-robin ordering, stale flags, negative-marker/type
ordering, other qtypes or unsupported EDNS metadata. It does not qualify TCP
snapshot representation or production/resource behavior.

## Identity and retained artifacts

- C native ELF:
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Actual image ELF:
  `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
  Its runner, musl loader and four libraries pass `verify_reference` on every
  image run; native UBus client dependencies remain separately identified.
- Executed Rust source: `ddac95da230239f10e318ca8a52e16621653e605`.
  This is also the unchanged product implementation at report base `8c900f0`.
- Rust ELF:
  `334819a9cbb1096c71066d27af8b6dc0eefb453e117ff2a4d0b25d0edee2b65d`.
- Gate source SHA-256:
  `3d2fd04aca8c52147ac40dc6903720d7cad01ea1523abb622ccb85e3ac34753d`.

Private artifacts are in
`private/dnsmasq-rewrite/do-lookup-pressure-20261001/private/`, with raw packets,
all 30 metrics per operation, generated configurations, binaries, traces and
an `evidence-sha256.json` manifest. The build-host copy is
`/home/ubuntu/dns-do-pressure-20261001/work01/private/`.

The initial `native-baseline-01` failed every profile at the fixture's
single-send assertion on its first SERVFAIL; no Rust ran. Completed rows and
logs are retained, but that premature assertion prevented appending the failed
operation's packets. The corrected gate appends packets before validation.
A subsequent binary transfer initially failed because the output directory
was root-owned; its local setup note is retained and no Rust process ran in
that attempt. Neither attempt is counted as acceptance.

Every network experiment used the isolated build-host network/mount/PID
namespace wrapper. No physical router was accessed. The gate and report make
no product implementation change; a corrected replay remains outstanding.

## Corrected product replay

The root-owned product fix at `aeba67e930e48386ad971d93fd96342cef7ec874`
preserves the C lookup sequence for empty-OPT IN A/AAAA DO queries:
CNAME/NXDOMAIN first, then the requested address kind, then generic/NXDOMAIN
when the first result is not a CNAME. A dynamic CNAME stops lookup before
following its target. The query still forwards. Existing non-DO answer
construction is unchanged.

The same frozen 120-observation tool replays successfully against the fresh
`aeba67e` ELF:

| Run | Result |
| --- | --- |
| `native-after-01` | 120/120 paired observations, zero differences/failures |
| `image-after-01` | 120/120 paired observations, zero differences/failures |
| `native-negative-01` | Exactly one deliberately altered cache-hit observation differs; exit 1, zero fixture failures |

Executed Rust ELF SHA-256:
`d2643e676b226ab3527d2ba8a76ae887d2e56743eab5df7a9b78f70f6fef203d`.
Source archive SHA-256:
`7217dc5345a1bc8ba5f33a3c3625477fd5a00a748a711b05b42dadc6d08bb9e0`.
Build directory:
`/home/ubuntu/dns-do-lookup-fix-20261001/aeba67e-01/`.

The independent source review found the implemented lookup order consistent
with the matching C branches. Its generic/NXDOMAIN third stage is source
supported but was not exercised by these 120 schedules; a separately frozen
cross-type/SOA unit owns that additional evidence. All original before runs
and the initial fixture failure remain. This closes the measured direct and
CNAME DO eviction gap, with all earlier scope exclusions still in force.

## Regression after the separate ordinary-miss correction

The subsequent product source `5c15e16da102a209c1040ba5a5d44d8abb1ca58d`
corrects a separately measured non-DO generic-lookup miss boundary described
in [the NX/SOA report](DO_SOA_PRESSURE_RESULT.md). This original direct/CNAME
120-observation fixture remains unchanged and was replayed on that final ELF:

- `native-final-5c15e16`: 120/120 paired observations; zero differences/failures.
- `image-final-5c15e16`: 120/120 paired observations; zero differences/failures.
- `native-final-negative-5c15e16`: exactly one altered cache-hit observation
  differs; exit 1, zero fixture failures.

Final Rust ELF SHA-256 is
`87f68b790d6a19f1cf25bdfcc33093f603016b3df8d1f8df5b959c74f6990b90`.
The final source archive, build directory and same-ELF NX/SOA evidence are
recorded in the linked report. Earlier `aeba67e` results are retained under
their original identity, not relabeled as final-source runs.
