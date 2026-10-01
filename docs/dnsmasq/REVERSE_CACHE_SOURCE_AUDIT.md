# Reverse cache source audit and proposed qualification stages

This is a source audit, not an executed reverse-cache gate or an implementation
claim. The reference is the exact patched dnsmasq 2.93 tree already recorded by
this project. No new reverse experiment, router access or timing run was made.
The existing [cache-rr baseline](CACHE_RR_GATE_RESULT.md) supplies nine native
and image C-only observations: direct IPv4, direct IPv6 and reverse-owner
CNAME-to-generic-PTR. Keep those observations and their original denominators;
they are not nine new Rust passes.

## Existing C interface and callers

| Boundary | Exact source | Observable contract |
| --- | --- | --- |
| Decode reverse owner | `rfc1035.c:202`, `in_arpa_name_2_addr` | IPv4/IPv6 address plus family; multiple textual owners can map to one address |
| Extract direct positive PTR | `rfc1035.c:802` | `cache_insert(PTR target name, address, ..., F_REVERSE | family)`; no `F_FORWARD` or `F_RR` |
| Insert/remove | `cache.c:519,665,692` | Shared transaction, cache slots, TTL policy, long-name budget, failure state and LRU |
| Address lookup | `cache.c:1261`, `cache_find_by_addr` | Scan reverse hash prefixes, expire every reverse owner, promote all address matches, return local entries before dynamic matches |
| Answer PTR/ANY | `rfc1035.c:1874` | Interface record, explicit PTR, address cache, synthetic reverse, then bogus-private fallback |
| Publish DHCP | `lease.c:564`, `cache.c:1758` | Unhash prior DHCP generation, publish names in lease/FQDN order, retain existing positive reverse ownership |
| Reload/remove local sources | `cache.c:493,1548,1742` | UID removal, dynamic cache clear, hosts reload and DHCP unhash have distinct ownership boundaries |
| Child-to-parent transfer | `cache.c:844,954` | Send committed target name, absolute expiry, flags and address; parent calls `really_insert` with reverse flags |

The positive entry's name is the PTR *target*, not the reverse query owner.
Consequently a cached PTR does not establish that target's forward existence,
does not answer its A/AAAA question, and does not conflict with forward records
of that name. A forward `Generic(12)` keyed by the original QNAME cannot express
this contract.

`in_arpa_name_2_addr` accepts omitted low-order IPv4 octets and IPv6 nibbles,
case-insensitive suffixes, `ip6.int` and the retained textual IPv6 bitstring
form. Defined decimal IPv4 values narrow to bytes; extra prefixes shift through
the fixed address. Labels such as RFC 2317 `0/24` fail address decoding and use
the generic route. Rust's existing `local::arpa_address` already implements
these source rules and has local-answer unit coverage. Reuse it; do not add a
second strict standard-library reverse-name parser. Signed-int overflow in C
`atoi` remains outside a defined compatibility claim.

## Extraction, negatives and answer order

The direct PTR scan applies only to QTYPE PTR, IN class and non-NXDOMAIN.
It scans matching answer-owner PTRs and inserts each target/address pair in
answer order. Earlier pending records are invisible to subsequent replacement
scans, so multiple PTR targets in one response can commit together. A later
transaction for the same family/address removes the existing dynamic reverse
RRset. It does not remove local hosts/DHCP/configuration records.

If no direct PTR matched, extraction falls through to the ordinary CNAME/RR
path. This is intentional: C cannot express an extracted CNAME pointing to a
reverse-only terminal entry. A CNAME followed by PTR is stored as a forward
CNAME plus a forward generic PTR target, even when a question or terminal
spelling looks like a reverse address. A packet with a directly matching PTR
and other answers must be observed separately before claiming the comment
implies a blanket CNAME-first rule.

Ordinary upstream PTR NODATA therefore uses a forward negative Generic(12)
entry and SOA metadata. PTR NXDOMAIN bypasses direct reverse extraction and
uses a forward name-wide NXDOMAIN entry. These are keyed by the original
negative owner, so positive address-spelling aliases must not automatically
share negative results. The `cache_add_dhcp_entry` branch which can remove an
`F_NEG | F_REVERSE` entry exists, but this upstream extractor does not create
that combination. Treat a directly constructed negative-reverse primitive
fixture as synthetic unless a reachable caller is established.

The commit conditions remain the existing RA/raw-CD/no-cache conditions.
An extraction-only transaction can remove old reverse entries without
committing replacements. A malformed later PTR or a capacity/name-allocation
failure preserves earlier removals and pressure counters; unfinished pending
records are cleaned by the next `cache_start_insert`. Do not prevalidate the
whole response and erase these ordered effects.

C first follows forward CNAME/NXDOMAIN records, then applies local/explicit
PTR precedence, then performs `cache_find_by_addr`, and only uses the final
forward generic lookup if no answer was selected. Dynamic PTR requires RD and
an allowed DO policy, but address lookup and its expiry/LRU effects occur
*before* that rejection. A dynamic reverse record does not answer QTYPE ANY;
local hosts/DHCP reverse records can. The stale flag is visited before the
ANY exclusion. PTR DO/AD admission is currently outside Rust's measured
ordinary query envelope and must receive its own C gate before broadening it.

## Shared storage, expiry and local ownership

Reverse insertion globally scans mortal entries for expiry, even with spare
capacity (`cache_scan_free`'s reverse branch and `freed_all=F_REVERSE`). Forward
insertion normally scans its relevant bucket and only performs the global
expiry pass under pressure. Reverse lookup instead scans reverse entries only,
including unrelated addresses; it does not globally expire forward-only data.
These different scopes are observable after wall time moves backwards.

Dynamic reverse and forward entries use the same slots and LRU. A lookup moves
all matching dynamic reverse entries to the head. Evicting a reverse victim
removes its family/address RRset; evicting a forward victim applies its
forward name/type conflict set. `dns_cache_live_freed` counts the selected live
victim, not every member removed. `dns_cache_inserted` counts committed entries.
A second per-address cache with its own capacity would change both decisions.

TTL handling reuses the current common contracts: response `max-ttl`, insertion
min/max-cache-TTL, zero-TTL transaction failure when stale caching is disabled,
absolute expiry, strict stale test and TTL zero when serving stale data.
Finite stale cutoff and forever mode apply to reverse entries too. DHCP uses
its configured local/DHCP TTL capped by lease lifetime; immortal hosts carry
the configured TTL directly. Reload drops dynamic forward/reverse records and
resets insertion/eviction metrics while hosts and leases follow their existing
reload/publication lifecycle.

Hosts bulk load gives the first address owner the reverse flag and suppresses
later duplicate-address owners. `host-record` loads before hosts files. During
DHCP publication, an existing positive dynamic PTR can prevent the new lease
from acquiring reverse ownership even though its forward name is inserted.
C intentionally checks at time zero, not wall-clock publication time. A lease
which lost reverse ownership does not acquire it merely because the dynamic
PTR later expires; a later publication is a different event.

A local host/DHCP and dynamic reverse entry can coexist: reverse insertion
protects local records but does not reject the new dynamic entry. Address
lookup collects locals first and then dynamic matches, and `answer_request`
iterates the resulting chain. A local-first early return must not silently
hide a reachable late upstream response or its global expiry/LRU effects.
Reachability should use delayed response versus lease-publication ordering,
not assume that a synthetic cache mixture occurs in the daemon. Static-only
DHCP hostname fallback remains static-only; adding dynamic reverse caching
must not change `dhcp_reverse_name_diff.py`'s established contract.

One ordering boundary needs measurement before implementation policy:
`cache_hash` hashes the PTR target name, and `cache_find_by_addr` scans hash
buckets in ascending order then promotes matches. `typestr` supplies pointer
bytes to that hash. Multiple different PTR target names can therefore have
process/layout-dependent traversal and LRU order. The current source audit
has not executed that variation. Keep every observed order and pressure
victim; do not sort response records or silently accept a set comparison.
`no-round-robin` does not disable this reverse lookup promotion and does not
introduce the forward hash-chain rotation.

## Current Rust gaps and minimum implementation boundary

| Current component | Reusable mechanism | Missing reverse contract |
| --- | --- | --- |
| `dns/cache.rs::Record` | Owned name, kind, payload and negative flag | Explicit reverse direction/address; target name must not enter forward existence/conflict predicates |
| `Cache`, `Slot`, `EntryId` | Shared finite slots, intrusive LRU, generations, transactions, counters and expiry policy | Address lookup; direction-specific conflict/expiry/eviction; ordering measured against C |
| `CacheContext` | Existing ordered reply extraction, CNAME fallback, response/error plumbing | Direct PTR scan and address answer branch; current address-form early return skips both direct and fallback paths |
| `local.rs`, `hosts.rs`, `lease_names.rs` | Reverse-name decoder, first local owners, lease expiry and publication | Coordinated local/dynamic reverse traversal rather than returning one local row before cache lookup |
| `PublicationCache::reverse_owned` | Existing explicit callback at the right publication boundary | It currently always returns false; time-zero lookup must preserve positive ownership and its real side effects |
| `CacheTransaction` | Captured committed order, expiry, real parent insertions and counters | Reverse direction/address through typed export/import; parent reverse insertion must not use forward local-conflict rules |

Reuse the existing cache owner, slots, generations and transactions. Add small
explicit reverse insertion/lookup operations; do not introduce a separate
manager, cache capacity or snapshot framework. `EntryId` itself needs no new
identity scheme. CNAME fallback remains generic and must not create links to
reverse-only terminals. Choose the smallest explicit record encoding only
after the first primitive contract is frozen; measure layout/allocation impact
rather than hiding a cost on every ordinary record. An address index, if used,
may accelerate matching but cannot omit global reverse expiry, common LRU or
C's observed ordering.

## Proposed independent C-first qualification stages

These are proposed schedules, not measured expectations or a runnable frozen
gate. Freeze each executable matrix and comparator before its first run, finish
and calibrate C before Rust, preserve all failures, and keep primitive/native
source oracles distinct from actual-image service observations.

1. **Primitive direction and address effects.** Reuse the actual
   `extract_addresses`/`answer_request` entrypoints in `cache_answer_driver.c`
   for frozen clocks and packet inputs. Add a separate corpus for partial/full
   IPv4 and partial/full/`ip6.int` IPv6 spelling aliases; positive PTR must not
   create target A/AAAA or forward-existence state. Exercise same IP/different
   target names, multiple PTR answers, same target/different IP, forward/reverse
   coexistence, address-wide replacement and absence of forward CNAME target
   preservation on reverse replacement. Include expired unrelated reverse and
   forward records before a reverse lookup/insert, then move time backwards to
   reveal exactly which removals persisted. Use one shared capacity-3 pressure
   schedule with forward and reverse victims and exact insertion/live-free
   counters. Capture returned order; multi-name ordering remains an explicit
   boundary if actual C processes disagree.
2. **Ordinary service and failure boundary.** Extend the existing service
   fixture through a separate tool; do not change its original 78/9 matrix.
   Reuse the saved direct IPv4/IPv6/alias nine observations as prior anchors.
   New profiles probe different address spellings, mixed forward/PTR capacity,
   multiple PTR targets, explicit PTR precedence, RD0/ANY side-effect pressure,
   and CNAME-to-literal-reverse-target versus RFC2317/non-address generic PTR.
   Add PTR NODATA with valid SOA and NXDOMAIN, each followed by equivalent
   address-spelling probes, plus no-negcache. Cover request-CD, raw-reply-CD and
   RA0 replacements, and a valid PTR prefix before malformed target data.
   Preserve failure flags/EDE, all 30 UBus counters and upstream sequence.
   Calibrate native C and the verified stock-image runner before old/new Rust.
3. **Local publication and lifecycle.** Extend the real-caller approach of
   `lease_cache_reachability.py`/`lease_cache_driver.c`, not its synthetic local
   blocker injection, for cache-before-lease and delayed-response-after-lease.
   Probe both forward and PTR answers, lease release, republish after PTR expiry,
   first FQDN/short-name ownership and HUP. Reuse the established DHCP DNS
   publication/lifecycle observers and complete-handler barriers. Synthetic
   negative-reverse removal can be a separately labelled primitive case;
   ordinary negative PTR must retain its forward-keyed semantics. Static hosts
   precedence and DHCP fallback regressions remain their original gates.
4. **Typed transfer and resource qualification.** Extend
   `cache_transfer_driver.c`/`cache_transfer_diff.py` with reverse operations
   using unchanged C `cache_recv_insert`, and compare typed Rust import against
   current parent forward/reverse/local state. Cover several child PTR records
   for one address: reversed committed transfer order and parent pending-record
   invisibility must both survive. Include parent pressure, absolute expiry,
   interrupted commit and subsequent cleanup. This does not authorize merging
   the private TCP transport/snapshot implementation. Recheck ordinary cache
   allocation/layout guards and existing primitive regressions before product
   adoption; reverse implementation is not itself a performance acceptance.

Start with stage 1 and the minimal direct-UDP portion of stage 2; keep the
local-coexistence and transfer gates explicit before claiming full reverse
support. Existing C-only nine observations, forward cache-rr 78, ordinary CD,
DO lookup pressure and static DHCP reverse-name results stay separately
attributed. Do not call source predictions, synthetic states or unexecuted
stages passing behavior.
