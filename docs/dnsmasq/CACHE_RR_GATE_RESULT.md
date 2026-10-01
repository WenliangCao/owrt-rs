# cache-rr and generic forward-cache baseline

The independently frozen [gate](CACHE_RR_GATE_PLAN.md) fully calibrates against
native C and the actual image: 22 configuration cases and 87 packet
observations each. Of those packets, 78 belong to the forward-generic paired
scope; nine reverse-PTR observations are deliberately C-only. The old product
at `5c15e16` lacks `cache-rr` startup support and default generic insertion.
No corrected product replay is claimed in this baseline.

| Run | Configuration | Service scope | Failures / differences |
| --- | --- | --- | --- |
| `native-baseline-01` | C 22/22 | C 87/87, including reverse 9 | 0 |
| `image-baseline-01` | C 22/22 | C 87/87, including reverse 9 | 0 |
| `native-before-01` | 16/22 acceptance differences | 18 compared, 12 differ; reverse 9 C-only | 17 Rust profile startup failures |
| `image-before-01` | 16/22 acceptance differences | 18 compared, 12 differ; reverse 9 C-only | 17 Rust profile startup failures |

The 16 configuration differences are C-accepted `cache-rr` arguments rejected
by the old Rust implementation. All six invalid arguments are rejected by
both. The 17 service failures are the explicit unsupported-option startup
boundary, with complete logs retained; those profiles contribute no paired
rows. Among the six profiles which can start, unenabled positive TXT and
unknown RR types match all six observations. Default SRV, non-address PTR,
SRV NODATA with SOA and unenabled TXT NXDOMAIN each differ in all three rows,
including the seed's insertion metrics and subsequent cache/forward behavior.
These are service comparison differences, not fixture calibration failures.

## Measured C interfaces

The C parser accepts lowercase names, decimal types, comma/repeated options,
duplicates, empty fields and zero values. Defined numeric 65552 narrows to 16
and enables TXT storage; zero list entries never match (`util.c:124`). `ANY`
enables the queried type, while positive QTYPE=ANY and QTYPE=CNAME schedules
still produce no insertions. Invalid labels/sign/hex/decimal syntax fail.
Values beyond signed-int range remain outside this bounded parser gate.

Positive forward storage is demonstrated for small/large TXT, opaque unknown
records (including pointer-looking bytes), explicit MX/SOA, default SRV and
non-address PTR. The named-RDATA decoder follows the exact C `rrfilter_desc`
layout, so semantic comparison permits different valid compression while
keeping unknown bytes opaque. Three TXT records preserve observable
round-robin order. CNAME-to-TXT links, SOA-backed generic negative entries and
name-wide NXDOMAIN are included.

The three capacity-3 replacement profiles distinguish normal commit, request
CD and raw upstream CD. The two CD variants still remove the old target during
ordered extraction while suppressing final alias/target commit. Sentinel state,
request-CD restoration and intermediate metrics are retained. They do not use
DO, arbitrary EDNS options or a differently qualified envelope to force misses.
Forwarded failure probes retain the exact two-send SERVFAIL retry.

The reverse-PTR C-only profiles confirm IPv4 and IPv6 address-indexed records
and reverse-owner CNAME-to-generic-PTR behavior. They remain excluded from Rust
paired totals. A Generic(12) map is not treated as an equivalent reverse cache.
The known SRV negative/no-SOA C undefined-read evidence remains linked through
`DNS_CACHE_REPLY_PHASE.md`; this gate uses valid SOAs for generic negatives and
does not fabricate a passing case for that defect.

## Identities and preservation

- Gate SHA-256:
  `172561b2bea3e0b85a9bf05bbf1c663feaade545944887dd56c6706df295d90d`.
- Old Rust source: `5c15e16da102a209c1040ba5a5d44d8abb1ca58d`.
- Old Rust ELF:
  `87f68b790d6a19f1cf25bdfcc33093f603016b3df8d1f8df5b959c74f6990b90`.
- Native C ELF:
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Actual image ELF:
  `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
  Every image run verifies its runner, matching musl loader and dependencies.

All baseline attempts passed C calibration without a fixture revision. Every
C schedule finishes before any Rust schedule in its run. The comparator
rejects a missing row and detects exactly one changed observation during
self-calibration. A standalone paired negative awaits a fully passing Rust
ELF. Comparing the saved native/image C baselines also yields 87/87 identical
decoded observations; that check performs no new daemon experiment.

Raw configurations, stdout/stderr, packets, counters, identities and their
SHA-256 manifest are in
`private/dnsmasq-rewrite/cache-rr-gate-20261001/private/`, mirrored from
`/home/ubuntu/dns-cache-rr-20261001/work01/private/`. All executions use the
isolated build-host wrapper. No router or performance experiment was involved.
Reverse cache integration, malformed generic data, DNSSEC/EDNS expansion,
integer overflow and complete RRtype configuration coverage remain open.
