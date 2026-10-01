# Ordinary EDNS cache replies

Ordinary empty OPT queries can now consume dynamic cache entries populated by
plain DNS queries. Previously every OPT query bypassed this cache path, causing
extra upstream requests and differences in reconstructed sections and AA.
The wrapper uses the existing cached record builder with the client UDP limit,
then applies the same OPT rule as local `receive_query` answers. Empty OPT needs
15 bytes of available configured space even though its wire length is 11;
stale EDE 3 is appended directly and needs 17 bytes. These separate limits and
integer clock behavior are taken from exact C, not inferred from Rust output.

The wrapper accepts one unsigned, empty OPT whose TTL-shaped metadata field is
zero and whose query has no AD request. DO/AD and other EDNS cache metadata
remain on the existing upstream path. This change does not establish full
DNSSEC, EDNS-option or TCP cache equivalence.

Two additional insertion defects surfaced during the gate and were fixed:

- Non-QUERY upstream packets no longer enter the ordinary answer cache. C
  exits `process_reply` before extraction for these opcodes.
- Overlong A/AAAA RDATA contributes its first complete 4/16 address bytes to
  the cache, matching C's bounded address extraction. The old exact-length
  filter could incorrectly produce a negative cache entry. Reads do not cross
  a short record's declared RDATA boundary.

## Frozen-time evidence

`tools/dnsmasq/cache_edns_diff.py` links the exact C objects and invokes
`extract_addresses`, `answer_request` and `add_pseudoheader` in source order.
The Rust probe calls the production cache insertion and lookup methods. Both
sides use capacity 100, the same TTLs, 60-second stale retention, 30-second
no-SOA negative fallback, disabled round robin, query bytes and configured UDP
sizes. Clocks are explicit and equal: TTLs, stale flags, misses, errors and
OPT/EDE contents compare exactly. DNS compression encoding may differ, while
record order remains significant. No socket or benchmark is involved.

The final corpus has **155 steps / 143 queries**, including A, AAAA, safe
overlong address records, a long CNAME chain, negative entries, fresh/stale/
expired entries, client sizes below/at/above 512, configured limits and the
15/17-byte addition boundaries. C produces **68 stale observations and 7
misses**. Both counts are checked before any equivalence result is accepted.

Evidence remains under ignored
`private/dnsmasq-rewrite/dns-alias-config-20261001/`:

| Evidence | Result |
|---|---|
| `source02/private/cache-edns-c-baseline-01/` | Initial 93-step C baseline, 85 queries, 40 stale observations, 5 misses. The AAAA fixture unintentionally used 17-byte RDATA; retained rather than discarded. |
| `source03/private/cache-edns-diff-01/` | Probe build failure: private configuration field used in a struct initializer. No differential cases executed. |
| `source03/private/cache-edns-diff-02/` | 64/93 matches; all 29 failures exposed the overlong AAAA insertion defect. |
| `source03/private/cache-edns-c-baseline-02/` | Expanded 155-step C baseline adds normal 16-byte AAAA and overlong A while retaining the original 17-byte case. |
| `source04/private/cache-edns-diff-03/` | **155/155 matches**, zero failures. |
| `source04/private/cache-edns-calibration-01/` | Deliberately changed decoded RCODE: **154 matches / 1 failure**, exit 1. Original raw output retained. |
| `source04/private/lib-isolated-regression-04.log` | Linux isolated library regression: **361 passed / 0 failed / 15 ignored**. |

`service-source-04.tar.gz` and its per-file identity manifest retain the exact
source used by the final frozen-time probe. Related real-service evidence is
in [the alias phase](DNS_ALIAS_SERVICE_PHASE.md): 97 observations, matching
upstream counts, cache reuse and coalesced replies. The source04 native release
build also passes with Rust 1.98.1; its ELF SHA-256 is
`7ee4d53bf4bc6f43ac10a07fd3df2a74a0ab034f72d0c057ec63a12dc4493f64`.
`source04/private/build-04.log` retains an initial output-directory permission
failure after the root-owned isolated test; `build-04b.log` records the passing
build in a separate private target directory. No permission or source semantics
were changed to obtain the build. The ELF and compiler identity stay private.
There is no performance gain, target-package or physical-router acceptance
claim in this phase.

## Cold empty-OPT insertion — 2026-10-01 continuation

The earlier work established lookup of cache entries warmed by plain queries.
The UDP completion path still excluded every query carrying OPT from insertion.
The actual cold-query gate now removes that exclusion for ordinary empty OPT.
Cache eligibility is computed from the first retained query when its upstream
reply completes and stored separately on `UncheckedReply`. It never changes
`Flags`, the forwarding-table key, packet bytes, duplicate matching or retry
state. C's `FREC_NO_CACHE` remains a different contract: exact `forward.c`
uses it for source-bound EDNS configuration and includes it in the duplicate
lookup mask. Option-bearing, versioned, signed and DO/AD/CD cache metadata remain
outside this measured ordinary subset.

Evidence is under
`private/dnsmasq-rewrite/cache-policy-20261001/oracle/` (same names below the
build host's `/home/ubuntu/dns-cache-policy-20261001/private/`):

| Gate | Result |
| --- | --- |
| `empty-opt-before-01` | 32 IPv4/IPv6 cases, 64 replies; 26 differing cases. Per family C sent 19 upstream queries, Rust 32. |
| `empty-opt-final-01` | Same 32 cases, 64 replies; zero differences, 19 upstream queries per family on both sides. |
| `empty-opt-final-negative-01` | Extra upstream observation detected: 31 cases match, one differs; exit 1. |
| `plain-final-01` | Plain-query regression: 32 cases / 64 replies, zero differences. |
| `edns-coalescing-01` | Four OPT-order profiles × IPv4/IPv6: eight cases, 16 client replies and 16 upstream sends all match. |
| `edns-coalescing-negative-01` | Missing recipient mutation detected: seven cases match, one differs; exit 1. |
| `edns-probe-api-final-01` | 155 frozen-time EDNS/cache observations match. |
| `clipped-probe-api-final-01` | 96 frozen-time clipped-section observations match. |
| `policy-probe-api-final-01` | 471 ordered policy/cache/counter observations match. |

`dns_edns_coalescing_diff.py` holds the first reply while another client sends
the same question with different empty/padding/opaque option content. That
request must coalesce; retrying that same client must resend the first query's
identical wire bytes and socket. Both original recipients then receive exactly
one reply. This directly guards against accidentally treating Rust's limited
cache metadata support as C's `FREC_NO_CACHE`.

The final native release ELF is
`53d86cc9e122fc404a9312fe5986a63a764c41a8969a1ffce410ac59607a12f1`.
Both release build and all-targets Clippy pass with warnings denied. The pure
cache test wrapper is now `cfg(test)`; standalone generated probes inject their
own caller of the real policy-aware API, rather than leaving unused production
methods. The host library passed 370 tests with seven ignored; the frozen Linux
snapshot passed 374 tests with 15 ignored in an isolated namespace after its
test binary was built with warnings denied. `warning-gates/source-sha256.json`
records that source snapshot. The unchanged
forward-state/counter gate passed all 1,285 operations with its existing state,
counter-mutation and missing-observation calibrations; evidence is the sibling
`forward-final-02/` directory. Its first invocation had a wrong compiler path
and executed no Rust comparisons; that failed directory remains preserved.

These results cover ordinary empty-OPT cold insertion and its forwarding
boundary. They do not establish EDNS-option cache equivalence, DNSSEC, TCP
cache publication, full service equivalence or performance improvement.
