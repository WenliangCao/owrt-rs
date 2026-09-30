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
SOA-backed or no-SOA NODATA/NXDOMAIN fallback. CNAME-type queries, EDNS and
full cacheability stay outside this module.

The focused `cache_reply` suite has six tests and runs in the normal crate
test gate. It is evidence for wire synthesis only, not full cache or daemon
equivalence.
