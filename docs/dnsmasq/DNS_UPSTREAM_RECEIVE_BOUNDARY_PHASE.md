# Upstream UDP receive-size and clipped-record boundary

The initial actual-daemon comparison found **32 differences in 68 cases**.
C delivered all 68 responses; the frozen Rust delivered 60. After the repair,
the **68 size cases and 64 policy cases have zero differences and zero
infrastructure failures**. This phase does not
claim DNS equivalence, target performance or production acceptance.

## Source contract and repair

The pinned image-matching C source is the authority. `dnsmasq.c` allocates
`edns_pktsz + MAXDNAME + RRFIXEDSZ`; `forward.c::reply_query` supplies that size
to `recvfrom`. Rust previously received into 65,535 bytes. The dispatcher now
supplies the configured maximum plus 265 bytes, so UDP clipping occurs at the
same receive boundary. The received packet is not artificially shortened
after a larger receive.

`forward.c::process_reply` does not require every RR to be complete before
processing the reply. The new UDP envelope preserves the received bytes until
policy has run. Address policy walks Answer records in source order:

- A clipped Answer ordinarily becomes question-only SERVFAIL. TC bypasses
  extraction and can preserve a structurally incomplete received answer.
- A clipped Authority or Additional does not by itself invalidate an earlier
  complete Answer. A clipped later Additional also makes an earlier OPT absent
  to `find_pseudoheader`.
- `check_bad_address` reads a bounded A/AAAA address before checking its
  declared RR end. An early ignore/bogus match can therefore win before later
  malformed data. Ordinary `extract_addresses` checks the declared end first;
  an early complete rebind match still wins over a later clipped Answer.
- The common doctor/alias stage runs before bogus/rebind processing. Recipient
  copies do not rerun ignore-address on an alias destination.
- `resize_packet` trims successfully walked sections but preserves the received
  length if a section is incomplete. UDP client-size limiting then clears
  sections and sets TC using only bounded header/question/OPT information.

The existing strict TCP envelope API remains unchanged in this unit. No new
unsafe code or dependency is needed. At an EDNS maximum of 1,232, requested
receive-buffer storage falls from 65,535 to 1,497 bytes per resolver, a reduction
of 64,038 bytes. This is an allocation-size calculation, not measured RSS,
allocator consumption or a throughput claim.

## Frozen actual-service workload

`tools/dnsmasq/dns_upstream_size_diff.py` runs only in the private loopback
network namespace established by `run_isolated.sh`. C and Rust use the same
configurations, upstream replies, cache capacity zero and client requests.
EDNS maxima 512 and 1,232 are each tested over IPv4 and IPv6.

The original size corpus has 17 cases per round: opaque and TXT records near
the advertised and actual receive limits, ordinary/oversized TC, clipped last
OPT, an earlier OPT before a clipped Additional, trailing padding and short
A data with/without TC. An independent 16-case policy corpus covers early
bogus/rebind/ignore decisions, declared-end order, CNAME and alias prefixes,
clipped Authority/Additional, NXDOMAIN/TC and packet-bound trailing-byte reads.

Client bytes, TTLs, flags, section counts, RCODE and upstream event order are
compared exactly. Only random upstream IDs are normalized. The harness first
calibrates equal observations, changed RCODE rejection and missing-observation
rejection. Raw traces, configs, source archives and ELFs stay private.

## Evidence and current scope

Evidence root: `private/dnsmasq-rewrite/upstream-boundary-20261001/`.

| Evidence | Result | Scope |
| --- | --- | --- |
| `before-01` | 32/68 differences, no infrastructure failures | Frozen Rust `2502ad8`; four size rounds |
| `policy-before-01` | Four Rust startup failures retained | C completed its four rounds; old Rust did not support the later address-prefix configuration; not a passing comparison |
| `upstream-sizes-02` | 68 comparisons, zero differences/failures | Both daemons returned all 17 replies in each round |
| `upstream-policy-02` | 64 comparisons, zero differences/failures | Both daemons returned 14 replies and ignored the same two replies per round |
| `reply-regression-01` | 19,981 successful commands, zero differences | 1,537 accepted packets; 890 excluded packets retained; ASan/UBSan C envelope/OPT/limiter oracle, not clipped-packet coverage |
| `address-regression-01` | 220 addresses, zero differences | Exact C `private_net`/`private_net6` oracle |

The before ELF SHA256 is
`2f06da580806cc4fec4c042d80ff298459cccdaf4fe1c4deb30d175a6ef63a5b`;
its retained source archive SHA256 is
`d8a8d8525872c6dfc0fec2351eaf4c8be3f63d5a5fb74ccf0718ddd5897cfd2d`.
The exact native C ELF SHA256 is
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
The repaired ELF is the shared `service-source-02` build, SHA256
`7819c7a13a1e85f1b5eb39f9d6613ed817de332f2b68463a5bb7e632347770f5`.
`source-02-identity.json` records the frozen source and per-file identities;
the matching archive and build log are retained with the shared alias-service
evidence. The later opcode cache-admission repair does not affect these
explicitly zero-cache workloads; it has its own alias/cache gate.

New unit regressions cover Answer-versus-Additional clipping, TC preservation,
early policy precedence, declared-end order and delayed trailing-byte trimming.
`dns-tests-02.log` retains one obsolete assertion that a clipped Answer should
be silently dropped. The exact C service gate establishes SERVFAIL instead.
The old failure-isolation fixture now corrupts the Question and a separate
regression checks SERVFAIL plus an unaffected sibling reply. Final
`dns-tests-03.log` has **194 passed, zero failed and four explicitly ignored**
DNS tests; the ignored tests are not counted as passed. `clippy-03.log` records
library clippy passing with warnings denied.

The strict TCP envelope still rejects incomplete RRs. The zero-cache packet
gate above does not cover cache side effects or receive errno handling. Those
two later units are separately documented: the
[clipped-section cache repair](DNS_CLIPPED_CACHE_PHASE.md) closes the complete
Answer/later-section gap, while exposing the distinct malformed-replacement
transaction gap; the [receive-error repair](DNS_UDP_RECEIVE_ERROR_PHASE.md)
has controlled I/O coverage and retains the real errno coverage limitation.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/dns_upstream_size_diff.py \
  --c "$EXACT_C_DAEMON" --rust "$RUST_DAEMON" \
  --corpus sizes --output private/upstream-sizes

sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/dns_upstream_size_diff.py \
  --c "$EXACT_C_DAEMON" --rust "$RUST_DAEMON" \
  --corpus policy --output private/upstream-policy
```
