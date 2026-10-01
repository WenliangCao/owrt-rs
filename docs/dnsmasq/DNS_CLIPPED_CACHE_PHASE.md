# Cache complete answers when later DNS sections are clipped

The original frozen-clock gate found **30 differences in 96 operations**.
Rust discarded cache insertion when Authority or Additional was incomplete,
even if all relevant Answer records were complete. The repaired gate has
**96/96 matching operations**, including insertion counters, CNAME chains,
negative SOA/fallback behavior, TTL aging and expiry. A separate malformed
replacement audit still has **two differences in seven operations**, described
below; this is not a global zero-defect or equivalence claim.

## Contract and implementation

Exact C `rfc1035.c::extract_addresses` walks the Answer section. A complete
positive RRset can commit without validating unrelated later sections.
`find_soa` examines Authority in order for negative caching; an earlier valid
matching SOA remains usable even when a later authority is clipped. If no SOA
can be obtained, the configured negative TTL can still supply a cache entry.

`cache_reply_at_with_local` now validates the header, question and complete
Answer section independently. `Records::parse_section` returns a borrowed,
cloneable iterator and its end offset, without copying or allocating a list of
RRs. Existing strict whole-message parsing remains strict. SOA selection walks
Authority records individually and stops at the first malformed record,
preserving an earlier selected SOA. A clipped Answer still cannot publish an
incomplete new RRset.

No cache capacity, TTL, safety check or resource limit is increased. This
removes a requirement to walk unrelated Additional records at this cache
entry, but there is no profile or performance gain claim for this change.

## Gates and evidence

The exact C oracle links the matching native reference object files and calls
`extract_addresses`/`answer_request`; Rust calls the production cache caller
methods at the same explicit times 100, 105 and 160. Both use capacity 100,
negative TTL 30 and disabled stale caching. Only complete-packet DNS compression
representation and the existing comparator's ASCII name case normalization
are allowed; TTL, flags, RCODE, RDATA, record order, counters and misses remain
observable. Calibration requires insertion/hit/expiry, rejection of incomplete
Answers, changed-counter detection and missing-observation rejection.

The actual-service gate runs 16 fixtures over each of IPv4 and IPv6 in private
loopback namespaces. Each fixture sends two queries with separate client IDs,
using unique owner/target names. Both requests must complete in one observed
wall-clock second; crossing the second fails the run instead of normalizing
away TTL. The C reference must forward twice for the three malformed-Answer
fixtures and only once for the 13 cached cases. Complete replies compare by
protocol semantics; structurally incomplete replies compare raw bytes.

| Gate | Result |
| --- | --- |
| Frozen cache baseline `before-02` | 30 differences / 96 operations |
| Frozen cache repair `cache-clipped-after-02` | 96 operations, zero differences |
| Actual `cache-clipped-service-01` | 32 cases / 64 client replies; each implementation forwards 19 queries per family; zero differences or infrastructure failures |
| Cache/counter regression `cache-regression-01` | 764 operations, zero differences; each implementation reports 95 hits, 69 misses, 188 insertion events and 30 resets |
| Empty-OPT/stale regression `edns-regression-01` | 155 operations, zero differences; 68 stale answers and seven misses |
| Local DNS tests `dns-tests-01.log` | 203 passed, zero failed, four explicitly ignored |
| Library clippy `clippy-01.log` | Passed with warnings denied |

All raw artifacts are under ignored
`private/dnsmasq-rewrite/cache-clipped-20261001/`. The successful source archive
is `source-after-02.tar`, SHA256
`b7515831d8838928e2dd0bcc9fbe903506e8775420927db47501744d07ed77d5`;
`source-after-02-identity.json` records every source file. The actual Rust ELF
SHA256 is `72ab8c78d4fc752f8be72698772a42d5eb2abe4d321d74091a7fe5e0101d5be3`.
The native C ELF remains
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.

`before-01` retains a Rust toolchain-selection failure (default 1.98.0 versus
required 1.98.1); `after-01` retains a failed partial source synchronization
that lacked the newer doctor dependency. Neither is counted as a successful
comparison. The successful round freezes the complete source tree. C and Rust
probe binaries, build logs, private packet corpus, outputs and failed runs are
retained; compiler incremental caches are not evidence artifacts.

## Open malformed-replacement side effect

After an existing healthy A cache entry, a reply containing one complete
replacement A followed by a clipped Answer removes the old entry in C's
insertion transaction before extraction returns error 2. The replacement is
not committed, and the earlier deletion is not rolled back. Rust's whole
Answer precheck currently retains the healthy old entry. The seven-operation
audit observes two differences: C misses while Rust still returns the old
entry at times 100 and 105; both miss after its original TTL expires.

This is an explicit cache transaction behavior gap, not a waived reference
memory-safety defect. `cache_clipped_diff.py --corpus replacement` retains it
as a nonzero regression. It needs a following source-order repair, including
interaction with earlier rebind/bogus/doctor decisions. Ordinary empty-OPT
cold-query cache insertion and the strict TCP envelope remain separate open
boundaries. Passing the later-section fixtures does not cover those paths.

```sh
RUSTUP_TOOLCHAIN=1.98.1 python3 tools/dnsmasq/cache_clipped_diff.py \
  --reference-build "$EXACT_C_OBJECT_BUILD" --out private/clipped-cache

sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/cache_clipped_service_diff.py \
  --c "$EXACT_C_DAEMON" --rust "$RUST_DAEMON" \
  --out private/clipped-cache-service
```
