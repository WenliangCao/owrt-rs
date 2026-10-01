# Frozen reverse-cache and lease service gate

Stage 3 uses complete native and actual-image C daemons, real UDP DNS and DHCP
DISCOVER/REQUEST/RELEASE, and real private lease files. It has **six profiles,
62 ordered observations**: 36 ordinary DNS exchanges, one held DNS request and
its later delivered reply, 21 DHCP observations (8 OFFER, 8 ACK, 5 RELEASE),
and three completed HUP observations. Thus there are 37 DNS replies, not 62
DNS packets. Two functional expiry waits are retained outside the observation
denominator; they are not performance windows.

The earlier 61-event plan was never executed. The final pre-execution tool
freeze adds one observation and moves active-lease HUP before release in the
explicit-PTR profile, qualifying ownership reselection after cache clear.

Freeze this plan and the executable matrix before C execution. Finish native
and verified image C calibration before running source `62894d6` as the Rust
before candidate. Do not modify that candidate based on source predictions.
All executions use run_isolated.sh, only loopback, private files and fresh
output directories. No physical router, deployment or performance experiment.

## Audited caller and query boundaries

`lease_cache_reachability.py` deliberately uses actual cache callers, but its
D operation calls `cache_add_dhcp_entry` directly. It does not run the complete
`lease4_allocate → lease_set_hwaddr/set_hostname/set_expires → lease_update_dns`
sequence. The existing `lease_cache_driver.c` H operation can construct synthetic
local blockers; neither D nor H is sufficient for this new service claim.

Real DHCP in `rfc2131.c` reaches lease.c allocation/name/expiry setters. ACK's
normal maintenance persists the private file and calls `lease_update_dns` before
reply transmission. `lease_update_dns` unhashes the prior DHCP generation and
publishes FQDN before short name. `cache_add_dhcp_entry` asks for an address
owner at **time zero**, so a still-indexed dynamic PTR can suppress lease PTR
even when already expired in wall time. Expiring/removing that dynamic record
does not assign a reverse flag to the existing lease publication. A subsequent
publication must choose ownership again.

Rust's corresponding path is `dhcp::persistence::update_dns → DnsPublisher`
implemented by main's LeasePublisher, then `DnsDaemon::publish_lease_names`
and LeaseNames::build. Main first calls `local.handle_udp`, then the forwarding/
cache entrypoint only if local answering missed. The new gate sends packets to
the real listeners and cannot bypass that order by invoking answer_records.

A query genuinely forwarded before a lease exists can finish after the lease
has been published. Reverse insertion protects local records but still adds
the dynamic entry. C cache_find_by_addr enumerates local entries first and then
dynamic matches, so the next PTR can contain both. This is a real reachable
coexistence schedule, not an injected blocker state.

Static reverse-host fallback is avoided in the static-priority profile by an
explicit authoritative dhcp-host name for the same client. This keeps the test
about reverse ownership rather than retesting client-name replacement. HUP
uses the actual cache/hosts reload and lease republishing handlers.

## Common configuration and observation rules

Use the existing loopback DHCP fixture: 127.0.0.10 through .20, /8 mask, 600s
leases, authoritative DHCP, no ping and a private persistent lease file.
Domain is leases.test; local TTL is 17, DHCP TTL 60, dynamic cache capacity 32.
No hosts/resolver system files, no 0x20 encoding or round robin. One private
addn-hosts file supplies a ready host and optional static reverse owner. One
empty private dhcp-hostsfile provides the established HUP read-close marker.
The explicit PTR and fqdn-only options appear only in their named profiles.

Reuse DHCP packet construction, response validation and file parsing from
`dhcp_lease_lifecycle.py`. OFFER/ACK replies retain fixed fields, options and
T1/T2; all requests are selecting requests, so no renewal timer fuzz is needed.
Lease expiry must lie within the actual matching ACK's 600-second interval;
comparison represents that validated relationship instead of equal wall-clock
timestamps. Preserve original packets and absolute lease-file rows privately.
A DHCP observation includes its immediate post-event durable lease rows. Do not
retry a DNS query after ACK to hide delayed publication.

Initial readiness uses observed UDP bindings, then one local ready request;
UBus registration alone is not readiness. Each observation includes actual UBus
metrics and ordered upstream packets. DNS uses plain IN requests without OPT;
unknown upstream probes receive deterministic SERVFAIL. The fqdn-only short
name is that process's first forwarded request and sends once; later failures
after a server has been selected retain the two-send retry. Valid PTR replies use a single original-case target. The held
request has its own client socket; do not synthesize its insertion through a
primitive call or conflate it with subsequent local probes.

RELEASE expects no DHCP reply. Wait for its real lease row to disappear, then
perform a synchronous UBus request before the next DNS probe. For HUP, install
an IN_CLOSE_NOWRITE watch on the same empty DHCP hosts file before SIGHUP; its
read-close plus a synchronous UBus request establishes handler completion. No
repeated DNS readiness probes are used as mutation-prone barriers.

## Fixed schedules

Every numbered event below contributes one observation. A DHCP OFFER or ACK is
one real exchange; RELEASE includes the no-reply and durable-removal check.

### dynamic-before-lease: 13 observations

1. DNS: seed PTR for client-1's address with dynamic TTL 4.
2. DHCP: client-1 OFFER.
3. DHCP: client-1 ACK.
4. DNS: client1 A is local.
5. DNS: client1.leases.test A is local.
6. DNS: PTR still returns only the dynamic target, within its TTL.

Wait until at least 5.1 seconds after the seed reply; preserve wait timestamps.

7. DNS: expired PTR misses; the lease has not acquired reverse ownership.
8. DHCP: client-2 OFFER.
9. DHCP: client-2 ACK, forcing a new publication of both leases.
10. DNS: client-1 PTR now returns client1.leases.test.
11. DHCP: client-1 RELEASE; only client-2 remains in the file.
12. DNS: released client1 A misses.
13. DNS: released client-1 PTR misses.

### expired-before-publication: 8 observations

1. DNS: seed client-1 PTR with TTL 1.

Wait at least 2.1 seconds after that reply without querying DNS again. The
expired reverse record has not been removed by an address lookup.

2. DHCP: client-1 OFFER.
3. DHCP: client-1 ACK; time-zero ownership still sees the indexed PTR.
4. DNS: client1 A is local.
5. DNS: first PTR after publication misses after pruning the expired owner.
6. DHCP: client-2 OFFER.
7. DHCP: client-2 ACK forces republishing.
8. DNS: client-1 PTR now returns its FQDN.

### late-reply-coexist: 11 observations

1. DNS hold: send a PTR query, capture its actual upstream request and withhold
   the reply; assert that no recipient answer has arrived.
2. DHCP: client-1 OFFER.
3. DHCP: client-1 ACK.
4. DNS: another client queries PTR and receives only the local FQDN.
5. DNS deliver: release the held upstream PTR (TTL 120); the original recipient
   receives that forwarded dynamic answer.
6. DNS: PTR contains local FQDN first, then the dynamic target, with their
   separate TTLs and C's resulting flags.
7. DNS: client1 A remains local.
8. DHCP: client-1 RELEASE; file is empty.
9. DNS: PTR retains only the dynamic target.
10. HUP: unchanged hosts sources, complete the real handler.
11. DNS: PTR misses after dynamic cache clear.

### static-host-priority: 10 observations

Initially the hosts file maps client-1's address to static.leases.test. A matching
dhcp-host config fixes that client's authoritative name to client1.

1. DNS: PTR returns static.leases.test.
2. DHCP: client-1 OFFER.
3. DHCP: client-1 ACK.
4. DNS: PTR still returns only the static owner.
5. DNS: client1 A is published.
6. DNS: client1.leases.test A is published.
7. DHCP: client-1 RELEASE.
8. DNS: static PTR remains.
9. HUP: change the hosts owner to changed.leases.test and complete the handler.
10. DNS: PTR returns the changed static owner.

### explicit-ptr-priority: 12 observations

Configure ptr-record at the ordinary full reverse owner. Seed dynamic cache
through the different decimal spelling 266.0.0.127.in-addr.arpa, whose defined
byte narrowing maps to the same 127.0.0.10 address. Do not inject a local record.

1. DNS: alternate spelling forwards and caches the dynamic PTR, TTL 120.
2. DNS: full owner returns only the configured explicit PTR.
3. DHCP: client-1 OFFER.
4. DHCP: client-1 ACK.
5. DNS: full owner still returns explicit PTR.
6. DNS: alternate owner still returns dynamic PTR.
7. DNS: client1.leases.test A is published.
8. HUP: while the lease is still active, clear dynamic cache and complete the
   handler, including forced lease republishing.
9. DNS: alternate spelling now returns the lease FQDN.
10. DHCP: client-1 RELEASE.
11. DNS: configured full-owner PTR remains.
12. DNS: alternate spelling misses; the explicit PTR is not an address mapping.

### fqdn-only: 8 observations

Use dhcp-fqdn with the common domain. The other profiles are default-mode
controls which publish both short and FQDN names and select FQDN for reverse.

1. DHCP: client-1 OFFER.
2. DHCP: client-1 ACK.
3. DNS: client1.leases.test A is local.
4. DNS: short client1 A misses.
5. DNS: PTR returns client1.leases.test.
6. DHCP: client-1 RELEASE.
7. DNS: FQDN A misses.
8. DNS: PTR misses.

## Calibration and exclusions

Calibrate full event count/order, C-predicted hits/targets/address selection,
local-first coexistence order, OFFER/ACK/RELEASE semantics, durable file state,
HUP completion and UBus/resource cleanup. Preserve native and actual-image C
outputs independently. Only after both complete, compare unchanged source
62894d6 and retain every before difference or execution failure. Expected
answers come from C, never from a Rust probe or a hand-created local state.

Reject missing events and detect one changed DNS answer or lease row using the
saved comparator. Keep all flags, record order, original-case targets, TTLs and
metrics; allow at most one second of dynamic cached-PTR TTL phase. Static and
DHCP TTLs remain exact. Functional wait timestamps and absolute lease expiry
are retained, with only the explicitly validated timing relationships compared.

This gate does not claim IPv6 DHCP (the target is nodhcpv6), arbitrary hostsdir
incremental updates, leasefile failure handling, scripts, TCP transfer/snapshots,
multi-target dynamic PTR order, stale serving, resource/performance acceptance
or full component/deployment completion.

## Source-backed observer correction after the first C runs

The initial native/image `lease-*-baseline-01` both execute all 62 observations
without a process or DHCP-check failure, but calibrate only 54: fqdn-only's
first short-name failure forwards once rather than the generic two-send
prediction. Both then forward the later released-name probes twice.
`forward.c:429` selects forwardall when last_server is -1; `forward.c:1255`
retries SERVFAIL only outside forwardall. The correction changes only this
explicit per-row send-count predicate to one. Every packet, configuration,
action order and 62-row denominator is unchanged. The first failed calibrations
and their original tool are retained; new output directories qualify the
corrected observer before any Rust run. This is not a Rust behavior change.
