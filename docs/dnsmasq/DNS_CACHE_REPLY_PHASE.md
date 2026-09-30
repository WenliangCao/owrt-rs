# DNS cache reply synthesis phase

This phase adds one bounded wire-writing primitive after the dynamic cache
primitives. It is still caller-owned: the daemon must select the RRset and
decide cacheability, CNAME/negative/SOA handling, RCODE, DNSSEC/EDNS flags and
whether a stale result may be served.

| C source | Behaviour / invariant | Rust boundary | Evidence |
|---|---|---|---|
| `rfc1035.c:1649-1690,2100-2170,2283-2347` | A caller-selected positive RR uses the remaining TTL and its canonical owner/RDATA; output remains bounded and section placement is caller-owned | `cache_reply::append_positive_record` | positive A/AAAA/generic TTL and section tests |
| `rfc1035.c:1738-1810,2283-2350` | CNAME traversal, qtype filtering and name-wide NXDOMAIN precedence are part of `answer_request`, not a single-record writer | `append_cname_record` returns the linked target; daemon owns the bounded chain walk | daemon loopback CNAME→terminal A cache-hit regression |
| `rfc1035.c:1170-1209,2384-2410` | Negative insertion uses SOA TTL/MINIMUM and answer replay emits the retained SOA in authority; no-SOA `--neg-ttl` has no authority | `Cache::insert_negative` + `append_negative_authority`; daemon owns extraction and RCODE | SOA/NODATA and CNAME→NXDOMAIN loopback regressions; negative TTL tests |
| `rfc1035.c:2050-2140` | The packet writer is bounded; a record that cannot fit sets TC without writing a partial RR | `PacketWriter` plus `WireError::Full` | bounded writer regression test |

The module does not perform cache lookup, build a complete response, parse
upstream packets or insert records. It does not add EDNS OPT, stale marker,
DNSSEC AD bit, RCODE, cache flags or client-specific policy. `DnsDaemon` now
has a deliberately narrower caller path around these primitives: direct
A/AAAA RRsets, complete CNAME→terminal RRsets, CNAME→negative chains and
SOA-backed or no-SOA NODATA/NXDOMAIN fallback, and CNAME-type queries over
already cached aliases or name-wide NXDOMAIN. EDNS and full cacheability
remain incomplete.

The focused `cache_reply` suite has six tests and runs in the normal crate
test gate. It is evidence for wire synthesis only, not full cache or daemon
equivalence.

## CNAME caller and negative-chain increment, 2026-09-30

The exact OpenWrt-patched C object build now drives a socket-free oracle that
feeds upstream packets through `extract_addresses` and client queries through
`answer_request` at identical, explicit timestamps. No Rust output supplies
expected packets. Both sides have capacity 150, `neg-ttl=30`, default TTL
limits, no hosts/resolver input and disabled stale caching.

| Exact C contract | Rust change | Evidence |
|---|---|---|
| `rfc1035.c:1738–1810`: QTYPE=CNAME emits only the first cached alias; it does not follow a target negative and this branch retains AA | `DnsDaemon::cached_answer_at` supports CNAME, preserving flags and remaining TTL | Positive/NODATA/NXDOMAIN chains of lengths 1, 2, 5; CNAME answer flags are `0x8580` for RD |
| `rfc1035.c:879–885,946–956,1146–1209`: positive CNAME queries do not populate the cache; an unanswered NXDOMAIN can populate name-wide negative state | `cache_reply_at` accepts direct CNAME NXDOMAIN but does not insert positive CNAME/NODATA or a CNAME answer inside an NXDOMAIN envelope | Repeated CNAME/A/AAAA queries; direct SOA and no-SOA NXDOMAIN; expiration |
| `rfc1035.c:2100–2170,2283–2347`: terminal negative selection is qtype-specific unless NXDOMAIN, and normal lookup expires it | CNAME-terminal negative lookup uses requested kind plus NXDOMAIN before authority replay | Initial run-02 exposed three false AAAA NODATA hits from A NODATA chains; retained regression also checks a 30-second negative cannot inherit a 60-second CNAME lifetime |
| `rfc1035.c:1796–1801,2147–2167`: cache answers reuse question/preceding CNAME-target name offsets | Cache writer accepts caller-owned owner offsets; daemon retains each target offset, with no compression dictionary | Initial run-04 exposed two incorrect TC replies for long names. Exact C and Rust now produce 406-byte CNAME and 422-byte CNAME+A answers within the same 512-byte limit |

The last change avoids recopying each owner name and reduces bytes appended;
its primary purpose is the observable truncation contract. It introduces no
new allocation, unsafe code or lookup structure. CPU/throughput improvement
has not been measured and is not claimed.

`tools/dnsmasq/cache_answer_diff.py` builds with
`--build-reference <exact Linux C build> --output <private build directory>`;
the resulting oracle/config/identity can then be supplied with
`--oracle-command '<oracle> -C <cache.conf>' --oracle-identity <identity.json>`.
An SSH command to the isolated build host is supported. Run output must be
below ignored `private/`. The ordinary daemon test suite contains six new
fixed-contract tests; its separate ignored oracle-driver test is run explicitly
by the differential tool and is not silently counted as passing.

Final evidence: `private/dnsmasq-rewrite/cache-answer-20260930/run-06/summary.json`:
**158 commands, 122 client queries, 0 semantic mismatches**. Calibration checks
reset, miss, insertion, exact NXDOMAIN flags, expiry and a deliberately changed
RCODE. Output row counts must match the input count. DNS compression encoding
and ASCII name case are normalized; IDs, flags, TTL, RDATA, record/section and
event order, cache hit/miss remain exact. The exact full C build is not an
ASan/UBSan build; no sanitizer claim is made for this run. Initial failures and
all later output remain preserved, including run-02 and run-04.

Relevant source gate: `cargo test --lib dns::` **122 passed, 2 ignored**
(the external C configuration check and this explicitly exercised oracle
driver); `cargo clippy --lib -- -D warnings` passed. This does not cover
EDNS/DNSSEC cache metadata, generic/ANY cache policy, TCP forwarding, cache
pressure/service integration, full daemon equivalence or performance acceptance.
