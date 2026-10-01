# DO lookup pressure: confirmed service difference

The exact no-DNSSEC C daemon promotes cached A/AAAA and CNAME records before
refusing to answer a DO query from those records. Current Rust's early DO
return skips that lookup. Under bounded cache pressure, Rust evicts a different
owner and consequently makes different upstream requests. Both native C and
the actual OpenWrt image reproduce the difference.

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
