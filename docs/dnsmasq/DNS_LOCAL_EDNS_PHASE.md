# Local DNS UDP sizing and EDNS boundary

`LocalDnsService` previously passed its receive-buffer size directly to the
answer writer, omitted OPT from local replies, and retained a fitting RR
prefix after truncation. The pinned C contract separates these operations:

| C source | Implemented boundary |
| --- | --- |
| `forward.c:1879-1901,1952-1956` | No OPT means a 512-byte answer-body limit; OPT uses the client's size with the exact configured-max/512 condition order |
| `rfc1035.c:1514-1643,2446-2463` | Owner compression affects fit; a failed RR append sets TC and removes every answer/authority/additional RR |
| `forward.c:1975-1990` | Hosts/configured-record replies append OPT using the configured output envelope and preserve client DO |
| `forward.c:589-602` | Address/local-rule replies append OPT using the client envelope and clear DO on UDP |
| `forward.c:2733-2755` | TCP local replies retain their full frame envelope and preserve DO |
| `edns0.c:103-234` | Empty OPT requires room for its 11 bytes plus four reserved bytes; otherwise the transmitted length and arcount remain unchanged |

`new_with_limits` separates receive capacity from advertised EDNS size.
`DnsDaemon` supplies both explicitly; the old constructor remains available.
The answer engine reports whether it used a forwarding rule, allowing the
service to preserve the different C OPT policies. Question owners and CNAME
target owners use existing offsets. A truncated RRset becomes a question-only
TC response before OPT is appended. Invalid/truncated additional sections
are treated as absent OPT when the question can still be answered locally,
matching C's `find_pseudoheader` failure behavior.

`tools/dnsmasq/dns_local_udp_diff.py` drives both actual daemons in isolated
IPv4/IPv6 loopback networks. Its fixed corpus includes TXT bodies near 512
and 1232, larger TCP answers, 30/31-record address sets, CNAME chains, local
rules, DO on/off, client size 0/512/1232/4096, and truncated OPT records.
It compares complete wire bytes, packet lengths, flags, counts, TTLs and RR
order; it does not sort records or normalize away truncation differences.
The comparator calibrates equality plus changed length, bytes and TC flags.

Evidence is in `private/dnsmasq-rewrite/dns-local-edns-20261001/`:

* `c-baseline-01/` establishes 488 exact-C observations.
* `before-fix-01/` retains 446 mismatches against the prior Rust executable.
* `paired-01/` reduces those to 28 address-order mismatches, described below.
* `paired-03/` compares 528 cases after adding malformed-OPT coverage and
  separating the sizing fixtures' addresses: zero wire differences.

The C append envelope has an observable edge: with configured maximum 1232
and client OPT size 512, a complete 512-byte TXT answer body receives an
11-byte OPT, producing 523 bytes. With configured maximum 512, answer bodies
498 through 512 receive no OPT because of the four-byte reservation. The
implementation preserves these caller boundaries. This is evidence of C
compatibility, not proof of a strict client-advertised datagram-size bound.

The discovered address-selection defect was kept explicit: a `host-record`
whose address already has PTR ownership is placed after reverse-owned peers
by C's `cache_hash`, while the current config-record path emits declaration
order. The initial fixture exposed this by sharing addresses across names.
The `--shared-addresses` option retains that counterexample. The subsequent
generation unit closes the reverse-owner/duplicate/rotation bypass and this
fixture now passes 528 exact-byte cases for its observed seed; the stricter
cross-listener state gate is documented in `DNS_HOSTS_GENERATION_PHASE.md`.
Default sizing fixtures use disjoint addresses to test framing independently.
This phase does not declare all local DNS behavior equivalent.

Related DNS tests pass 137 with two existing oracle-dependent tests ignored;
musl library clippy passes. The separately identified upstream empty-OPT
11-to-14-byte space bug in `forward_service::prepare_query` is subsequently
closed by the 1,217-case gate recorded in `DNS_FORWARD_SERVICE_PHASE.md`.

A later review found a regression in this absent-OPT fallback: after a complete
first OPT, a truncated subsequent additional RR incorrectly left that OPT
selected. C returns NULL for the entire scan. `find_pseudoheader` now clears
the selected OPT on that failure while retaining already discovered TKEY state.
The retained `private/dnsmasq-rewrite/partial-opt-review-20261001/before-suite/`
has 90 mismatches in 13,213 cases. `after-suite/` passes all 76,213 exact-C
primitive cases with ASan/UBSan and 10,000 fixed-seed mutations; the 20 wire
unit tests also pass, including every truncation of a later OPT. This primitive
gate does not establish complete daemon handling of malformed replies.
