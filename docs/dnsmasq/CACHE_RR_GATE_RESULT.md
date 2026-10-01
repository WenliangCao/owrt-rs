# cache-rr and generic forward-cache result

The independently frozen [gate](CACHE_RR_GATE_PLAN.md) fully calibrates against
native C and the actual image: 22 configuration cases and 87 packet
observations each. Of those packets, 78 belong to the forward-generic paired
scope; nine reverse-PTR observations are deliberately C-only. The old product
at `5c15e16` lacks `cache-rr` startup support and default generic insertion.
The corrected source `4bf072d` passes the original 22 configuration cases and
78 forward observations against native C and actual-image C. One earlier image
run retains a separate Rust startup-readiness failure, described below.

| Run | Configuration | Service scope | Failures / differences |
| --- | --- | --- | --- |
| `native-baseline-01` | C 22/22 | C 87/87, including reverse 9 | 0 |
| `image-baseline-01` | C 22/22 | C 87/87, including reverse 9 | 0 |
| `native-before-01` | 16/22 acceptance differences | 18 compared, 12 differ; reverse 9 C-only | 17 Rust profile startup failures |
| `image-before-01` | 16/22 acceptance differences | 18 compared, 12 differ; reverse 9 C-only | 17 Rust profile startup failures |
| `native-after-01` | 22/22 match | 78/78 paired; reverse 9 C-only | 0 |
| `image-after-01` | 22/22 match | 75/75 paired; reverse 9 C-only | 1 Rust readiness timeout; no rows for that profile |
| `image-after-02` | 22/22 match | 78/78 paired; reverse 9 C-only | 0 |
| `native-negative-01` | 22/22 match | 78 compared; reverse 9 C-only | exactly 1 deliberately injected difference |
| `native-malformed-regression-01` (`ac8a3b6`) | 22/22 match | 78/78 paired; reverse 9 C-only | 0 |

The 16 configuration differences are C-accepted `cache-rr` arguments rejected
by the old Rust implementation. All six invalid arguments are rejected by
both. The 17 service failures are the explicit unsupported-option startup
boundary, with complete logs retained; those profiles contribute no paired
rows. Among the six profiles which can start, unenabled positive TXT and
unknown RR types match all six observations. Default SRV, non-address PTR,
SRV NODATA with SOA and unenabled TXT NXDOMAIN each differ in all three rows,
including the seed's insertion metrics and subsequent cache/forward behavior.
These are service comparison differences, not fixture calibration failures.

The image attempt retains a `disabled-mx` startup failure: its UBus lookup
succeeded, but the single initial `ready.test` packet received no answer within
two seconds. Its trace has no scheduled rows or wires, and daemon logs are
empty. Rust registers UBus before binding DNS sockets (`main.rs`), which gives
a source-supported startup-race hypothesis; the saved evidence does not prove
that cause. This failed attempt is not a 78-row pass and is never discarded.
The same frozen tool and ELF then pass the complete gate in a fresh output
directory, run sequentially after this owner's other active service gates had
finished. This successful repeat does not establish startup reliability.

The subsequent malformed-reply propagation source `ac8a3b6` passes a fresh
normal native-C replay: 22 configuration cases and 78 paired forward rows,
with zero differences or fixture failures. Its ELF is
`3d8462fac7a81707e3b24f84b1a25fc8b6903d808b66b14cc4f3ede9e230b692`.
The fixture is unchanged. Image, negative-control and QTYPE-zero results above
and in the linked anchor remain attributed to `4bf072d`; they were not rerun
on `ac8a3b6`. This bounded regression does not enlarge reverse coverage.

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
- Corrected Rust source: `4bf072d`; ELF:
  `8406757bb3c597bdce1673ec7036a6d1d69728fe17b0d5a55d8b506b21192070`.
- Corrected source archive SHA-256:
  `1765e80ca5f3e6bc6da038e6665db087dbe0d8a6c82c69360f366bee44780eca`.
- Native C ELF:
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Actual image ELF:
  `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
  Every image run verifies its runner, matching musl loader and dependencies.

All baseline attempts passed C calibration without a fixture revision. Every
C schedule finishes before any Rust schedule in its run. The comparator
rejects a missing row and detects exactly one changed observation during
self-calibration. The standalone native paired negative uses the corrected
frozen ELF and returns exit 1 with exactly the deliberately changed first
cache-hit field; all other 77 observations and all configuration outcomes
match. Comparing the saved native/image C baselines also yields 87/87 identical
decoded observations; that check performs no new daemon experiment.

Raw configurations, stdout/stderr, packets, counters, identities and their
SHA-256 manifest are in
`private/dnsmasq-rewrite/cache-rr-gate-20261001/private/`, mirrored from
`/home/ubuntu/dns-cache-rr-20261001/work01/private/`. All executions use the
isolated build-host wrapper. No router or performance experiment was involved.
Reverse cache integration, malformed generic data, DNSSEC/EDNS expansion,
integer overflow and complete RRtype configuration coverage remain open.
The separate [QTYPE-zero anchor](CACHE_RR_ZERO_RESULT.md) qualifies zero and
empty list-entry behavior without changing this gate's 78-row denominator.
