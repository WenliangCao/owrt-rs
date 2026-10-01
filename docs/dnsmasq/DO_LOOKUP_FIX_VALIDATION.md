# DO lookup side effects: implementation and regressions

Product `aeba67e` fixes the independently observed DO pressure difference.
Empty-OPT IN A/AAAA requests with DO still forward, while their cache lookups
now happen in C order: CNAME/NXDOMAIN, requested address family, then generic
RR/NXDOMAIN if no answer was possible. A dynamic CNAME stops the lookup before
its target. The first CNAME/NXDOMAIN retains its observed stale flag.

This follows `rfc1035.c::answer_request` at 1754/1786, 2079/2101 and 2283/2295;
the mutable lookup precedes each DNSSEC eligibility check. Other query types,
option payloads and unsupported OPT metadata retain their existing boundary.
The non-DO answer builder and cache representation are unchanged. An independent
source review confirmed the grouping, early stop, non-IN and RD=0 behavior;
source review alone is not additional executed coverage.

The independent [pressure gate](DO_LOOKUP_PRESSURE_RESULT.md) improves from
112 matches / eight differences to **120/120 against native C and 120/120
against actual image C**. Its altered-hit negative control detects exactly one
difference. The original failures remain archived.

The same fixed native Rust ELF also passes:

| Check | Result |
| --- | --- |
| Existing DO/AD/CD service matrix, native C | 750/750, zero differences |
| Same service matrix, actual image C | 750/750, zero differences |
| Ordinary CD extraction/commit, native C | 134/134, zero differences |
| Isolated full library / main tests | 389 / 7 passed; 16 ignored |
| Native and aarch64-musl all-target Clippy | Pass with warnings denied |
| Crate formatting and diff whitespace | Pass |

Tests were compiled outside sudo, then the two named library/main harnesses
ran through `run_isolated.sh` with one test thread. Every service run used the
same isolation wrapper. Ignored tests and extra probe harnesses are not counted
as passes. These checks had no failed attempts.

Native Rust ELF SHA-256:
`d2643e676b226ab3527d2ba8a76ae887d2e56743eab5df7a9b78f70f6fef203d`.
The [JSON](DO_LOOKUP_FIX_VALIDATION.json) pins the source archive, ELF, command
logs, result files and evidence archive. Raw source, executable, packets,
configurations and logs remain in ignored
`private/dnsmasq-rewrite/do-lookup-fix-20261001/`; the build-host freeze is
`/home/ubuntu/dns-do-lookup-fix-20261001/aeba67e-01/`.

The product still has no adopted TCP snapshot/writeback implementation. This
unit does not qualify hash-bucket expiry effects, multi-record rotation,
negative/generic lookup pressure, all EDNS metadata, a new SDK Rust package,
performance or router behavior. Those remain separate gates.

## Subsequent ordinary-miss correction

`5c15e16` additionally preserves C's final generic lookup after an ordinary
A/AAAA/CNAME miss. An unrelated generic record is promoted without becoming
an answer. Queries that already looked up the generic group do not rotate it
again. This 12-line change follows the independently frozen
[NX/SOA pressure gate](DO_SOA_PRESSURE_RESULT.md): the original implementation
had 12 differences, the DO repair left four existing non-DO differences, and
the final source has none.

The final ELF passes **120/120 NX/SOA observations against each of native and
image C**, and independently preserves **120/120 direct/CNAME observations
against each reference**. Each gate has its own 120-row denominator and
one-difference negative control. Full isolated library389/main7 tests pass,
with 16 ignored; native/musl all-target Clippy and formatting pass. No failing
build or unit attempt occurred. The earlier 750/134 regressions above belong
to `aeba67e`, not a relabelled run of this later source.

Final ELF SHA-256:
`87f68b790d6a19f1cf25bdfcc33093f603016b3df8d1f8df5b959c74f6990b90`.
The [final validation JSON](GENERIC_LOOKUP_FIX_VALIDATION.json) pins command,
source and archive identities. Raw build/test evidence is under the earlier
private root's `5c15e16/` directory, with build-host freeze
`/home/ubuntu/dns-do-lookup-fix-20261001/5c15e16-01/`.

The NX/TXT prerequisite uncovered unsupported `cache-rr` configuration and
remains a retained startup failure, not an LRU pass. Generic insertion,
existing-address/RD-disabled no-answer paths, rotation, bucket-wide expiry,
stale combinations and resource costs remain separate qualification work.
