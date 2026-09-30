# DNS cache reply synthesis phase

This phase adds the wire boundary after the dynamic cache primitives. It is
still caller-owned: the daemon must decide cacheability, SOA metadata,
DNSSEC/EDNS flags and whether a stale result may be served.

| C source | Behaviour / invariant | Rust boundary | Evidence |
|---|---|---|---|
| `rfc1035.c:2283-2350` | A cache hit keeps the client ID/question, projects remaining TTL and emits only the requested RR type; a name-wide NXDOMAIN marker answers any qtype | `cache_reply::answer_from_cache` with `CacheQuery` | positive TTL and NXDOMAIN tests |
| `rfc1035.c:1738-1775,2283-2347` | CNAME answers include the alias and follow at most ten targets; loops or missing targets do not escape the bound | `append_entry` with `EntryId` visited set and depth bound | alias plus terminal A test |
| `rfc1035.c:1170-1190,2283-2347` | Negative/NODATA cache entries are answerable without manufacturing an answer RR; SOA authority construction remains a separate caller step | negative hit returns an empty-answer response; NXDOMAIN sets RCODE 3 | NODATA and NXDOMAIN tests |
| `rfc1035.c:2050-2140` | The packet writer is bounded; a cache hit that cannot fit is truncated through the existing writer boundary, while a miss remains distinguishable | `PacketWriter` plus `AppendOutcome::Full` | bounded writer regression coverage in wire/cache phases |

The module does not parse upstream packets or insert records. It does not add
an SOA authority section, EDNS OPT, stale marker, DNSSEC AD bit, cache flags or
client-specific policy. Those remain explicit integration gates before this
boundary can be used by `DnsDaemon`.

The focused `cache_reply` suite has four tests and runs in the normal crate
test gate. It is evidence for wire synthesis only, not full cache or daemon
equivalence.
