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
