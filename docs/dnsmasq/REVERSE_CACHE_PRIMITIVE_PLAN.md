# Frozen reverse-cache primitive C-first plan

This stage qualifies the exact native C source interface before any Rust
storage change. It is not a stock-image primitive pass or a daemon performance
test. Existing direct IPv4/IPv6/CNAME PTR service observations remain the nine
C-only rows in `CACHE_RR_GATE_RESULT.md`; do not rerun or recount them here.
No product source changes or router access are part of this stage.

The driver includes unchanged exact `cache.c` and links the matching verified
C objects, including unchanged `rfc1035.c`. It uses normal configuration parsing,
`extract_addresses`, `answer_request`, `cache_find_by_addr` and
`cache_find_non_terminal`. A read-only state command records the dynamic LRU in
order, entry direction/type, target name, address, expiry and actual hash bucket.
It does not select buckets, change the hash function or inject cache records.
Every stored entry comes through the real upstream packet extractor.

All clocks are explicit: ordinary seeds at 100, TTL 120; replacement at 101;
expiry seeds TTL 10, lookup/insertion at 110, backward-clock probes at 100.
No hosts or upstream sockets are involved. Default capacity is 8, negative TTL
120, no round robin. Pressure profiles use capacity 3. Packets are IN class,
RD requests, RA positive replies, no OPT, unless explicitly specified below.
All driver execution still uses `run_isolated.sh` on the isolated build host.
Freeze the tool and complete matrix before compiling or running the oracle.

## Main fixed corpus: 14 independent processes

Each listed profile has one process/configuration and starts with an empty
cache. Every packet result, existence result, state inspection and metrics
command is retained; the tool records the resulting command-row denominator.

1. `direction-v4`: seed PTR at partial `2.0.192.in-addr.arpa`; query the full
   address spelling and partial spelling; assert target forward nonexistence
   and target A miss; insert an A for that target; query A and PTR independently;
   inspect two entries and insertion/eviction counts.
2. `direction-v6`: seed partial `8.b.d.0.1.0.0.2.ip6.arpa`; query full ip6.arpa,
   full ip6.int and partial spelling; assert target forward nonexistence and
   target AAAA miss; insert target AAAA; query AAAA and PTR; inspect state/counts.
3. `replace-v4`: seed a full spelling to old target; extract a replacement using
   the partial equivalent; query both spellings and old-target A; inspect one
   reverse-only entry and two committed insertions with no pressure eviction.
4. `replace-v6`: the same address-wide replacement using partial/full IPv6.
5. `same-target-two-addresses`: seed two IPv4 addresses to the same target;
   query both; replace only the first address with a new target; probe both;
   inspect two live entries and three inserts.
6. `nodata-owner-scope`: extract full-owner PTR NODATA with a valid SOA; query
   full owner (negative hit) and partial equivalent (miss), test forward
   existence; then seed partial positive PTR and probe both spellings. Inspect
   separate forward negative/SOA and reverse-positive entries.
7. `nxdomain-owner-scope`: as above with SOA-free NXDOMAIN and neg-ttl=120;
   NXDOMAIN must not establish forward existence. The later reverse positive
   and old forward NXDOMAIN are separately visible in state.
8. `no-negcache`: extract the same valid-SOA NODATA with no-negcache; query both
   spellings and inspect zero inserted records/counters.
9. `pressure-forward-insert`: capacity 3; seed A, PTR address 1, PTR address 2;
   hit A; insert another forward A; probe all four owners. The reverse address-1
   victim disappears, address 2 and both forward entries remain, live_freed=1.
10. `pressure-reverse-insert`: capacity 3; seed A, PTR address 1, another A;
    hit PTR address 1; insert PTR address 2; probe all four. The first forward A
    disappears; the two reverse entries and second A remain, live_freed=1.
11. `reverse-lookup-expiry`: seed two expiring PTRs, one expiring A and one
    live PTR. Invoke the real address lookup for the live PTR at 110, inspect
    state, then probe expired PTRs and the A at 100. This isolates address
    lookup from unrelated preceding forward question-bucket expiry: both old
    reverse entries stay removed while the forward A can still answer.
12. `reverse-insert-expiry`: seed expiring PTR and A plus a live PTR; insert a
    different PTR at 110 with spare capacity; inspect state; probe the old PTR
    and A at 100. Both expired directions stay removed without live eviction.
13. `rd0-pressure`: capacity 3; seed PTR address 1, A, PTR address 2; send RD0
    PTR for address 1 (no answer but lookup promotion); insert another A and
    probe all four. The old A is the victim. Preserve output flags and counters.

14. `mixed-case-target`: seed an uppercase reverse owner with mixed-case PTR
    target; query lowercase full and uppercase partial equivalent owners; test
    both target case forms for forward nonexistence; inspect stored target
    spelling and original-case PTR RDATA separately from the existing semantic
    decoder. This addition was frozen before any oracle build or execution.

The executable matrix has **125 main command rows** and **44 cohort rows**.
These are source-derived calibration predicates, not Rust-produced expected
rows. Every complete actual C row is saved as the prospective paired contract.
If a predicate fails, preserve the entire process and continue independent
profiles to discover the full failure boundary; do not label partial
calibration a pass or replace C's output with the prediction.

## Separate multi-target cohort: exactly four processes

Run the identical configuration and schedule in four independent C processes,
regardless of whether their orders match. Capacity 3: insert a two-target PTR
RRset for one address; insert a forward sentinel; query the PTR RRset; query
the sentinel; capture ordered LRU/hash state; insert a new forward record;
inspect state and counters; probe the original PTR and both forward records.
The old reverse RRset should be removed as the selected tail victim's entire
address cohort, with one live_freed increment for two removed records.

Retain actual response target order, hash buckets, pre-pressure tail and
post-pressure state for each process. C calibration may verify that both
supplied targets occur exactly once, but must not sort stored response/state
rows, choose one order as canonical, rerun to obtain consensus, or feed an
uncontrolled cohort order to Rust as a deterministic expected sequence.
Record order or selected target-name variation separately from ordinary
source-contract checks; the shared address victim and metrics are still
measured. This is C-only evidence pending a representation decision.

## Identities, calibration and exclusions

Verify exact cache/rfc1035/header/config hashes and record linked-object,
compiler, driver and binary identities. Preserve configuration, command corpus,
stdout/stderr and decoded rows under a new ignored private directory. Reject
missing rows and calibrate the saved-row comparator with exactly one changed
TTL or existence observation. The main matrix is not expanded after results;
any correction or follow-on scope requires a new committed fixture revision
and leaves the original attempt intact.

This stage excludes malformed PTR, CD/RA0 extraction-only effects, DO/AD/ANY,
local/lease coexistence, synthetic negative reverse entries, stale policies,
int-overflow parsing, transfer, allocation failure and production resource
acceptance. They remain the later stages in `REVERSE_CACHE_SOURCE_AUDIT.md`.
