# Frozen local/reverse precedence and metadata addon

This independent **three-profile, 28-observation** C-first addon follows the
completed 62-event Stage 3 and five-case configuration anchor. Their matrices,
results and source identities remain unchanged. Run complete native and
verified actual-image C calibration before comparing the separately frozen
`0eaaef8` daemon. No candidate source edit is part of this gate.

The 28 observations comprise 17 ordinary/stale DNS exchanges, two genuinely
held requests plus their two deliveries, six DHCP exchanges (3 OFFER/3 ACK),
and one background-refresh observation. Thus there are 19 recipient DNS
responses. One functional stale wait is outside the count; no performance
window or physical-router work is involved.

## Exact source boundaries

The independent source audit agrees on these `rfc1035.c` boundaries:

- 1753-1814: forward CNAME/NXDOMAIN lookup precedes local PTR selection. A
  dynamic CNAME rejected for RD0 or unsigned DO causes a cache miss; it must
  not fall back to a later local lease PTR for the original address.
- 1874-1940: interface/explicit PTR wins before address-cache lookup.
- 1940-1990: the first address entry controls RD/DO admission once. If it is
  local, the later dynamic entries are included for PTR without repeating the
  eligibility test. Each entry's stale state is visited before ANY omits
  non-hosts/non-DHCP entries. An omitted dynamic entry does not clear AA, but
  can still make the answer stale.
- `forward.c:1955-2027`: stale cached answers receive EDE3 when OPT is present,
  increment the stale-answer metric and trigger a refresh after serving the
  client. The refresh's reply is not sent to that client a second time.

## Shared real-service setup

Reuse the existing complete-daemon DHCP harness, namespace isolation, private
600s lease file, domain=leases.test, local TTL17, DHCP TTL60, capacity32 and
ready-host setup. No synthetic local cache records or low-level query bypass.
Actual OFFER/ACK publishes the lease before following DNS observations. Retain
all packet fields, record order, original-case targets, metrics and durable
lease rows under private output directories. Preserve validated ACK-relative
lease expiry; allow at most one second of ordinary cached dynamic TTL phase.
No arbitrary EDNS options, signatures, DNSSEC validation or proxy-dnssec.

Unknown forwarded probes receive deterministic SERVFAIL. Each such probe in
this addon follows an earlier successful upstream response and should retain
the existing two-send retry. C supplies all decoded expected rows; a failed
prediction stays visible rather than becoming a Rust expected value.

## cname-before-lease: eight observations

1. Send PTR for the client's address-form owner before any lease exists. The
   upstream returns CNAME from that owner to a non-address terminal name plus
   PTR at the terminal; neither answer is a direct PTR at the original owner.
   Both forward entries commit through the existing fallback path.
2. Real client-1 DHCP OFFER.
3. Real client-1 DHCP ACK.
4. Query client1 A to establish the local publication is visible.
5. Ordinary PTR for the original address owner returns the cached CNAME+PTR
   chain, not the local address PTR, with no upstream exchange.
6. RD0 PTR for the original owner forwards and receives SERVFAIL; the rejected
   dynamic CNAME must not fall back to the local lease answer.
7. PTR with one empty OPT/DO similarly forwards and receives SERVFAIL.
8. Ordinary PTR again returns the original cached CNAME+PTR chain.

The successful upstream seed makes the two failure probes' forwarding state
explicit. Preserve CNAME and terminal TTL, owner order, request identity and
upstream metadata. No CNAME pointer or local blocker is manually constructed.

## coexist-flags: fourteen observations

1. Send direct PTR while no lease exists, capture its real upstream query and
   hold the reply. The client must still have no answer.
2. Real client-1 DHCP OFFER.
3. Real client-1 DHCP ACK.
4. Deliver the held upstream PTR with one dynamic target and TTL120. The
   original recipient receives that forwarded response.
5-12. In fixed order, query PTR then ANY; within each qtype use RD1/DO0,
   RD1/DO1, RD0/DO0, RD0/DO1. DO0 uses a plain question and DO1 one empty OPT.
13. PTR with RD1/DO1/CD1.
14. ANY with RD1/DO1/CD1.

Every query is answered without upstream traffic. PTR includes the local FQDN
first and dynamic target second, clears AA and uses each record's own TTL,
even for RD0 or DO. ANY includes only the local PTR and retains AA. CD is
preserved and unsigned replies do not assert AD. Empty OPT/DO output remains
part of the C-derived packet comparison.

## stale-any-visit: six observations

Use a fresh process with use-stale-cache=60; the lease remains live throughout.

1. Hold a genuine direct-PTR upstream query before lease publication.
2. Real client-1 DHCP OFFER.
3. Real client-1 DHCP ACK.
4. Deliver the held PTR with dynamic TTL1.

Wait at least 2.1s after delivery, without another DNS query.

5. Send RD1 ANY with an empty OPT. Receive a response before supplying any
   refresh answer. It contains only the local PTR (AA retained), plus EDE3;
   the stale dynamic entry was visited even though ANY did not emit it.
6. Capture exactly one background ANY request and answer NOERROR with no
   answers (matching empty OPT). Wait through a synchronous metrics barrier,
   then assert no second recipient reply or extra upstream packet. This
   deterministic refresh response avoids introducing SERVFAIL retry behavior.

Observe dns_stale_answered+1 and one logical refresh. The response-before-
refresh-answer check establishes that the stale answer did not wait for the
upstream; it does not claim kernel arrival ordering between two queued sockets.
No stale lease or multi-target dynamic population is included.

## Procedure and limits

Freeze tool/matrix before execution, preserve every attempt and failure, and
finish C before Rust in each paired run. Verify binary/image identities. Reject
missing observations and detect one deliberately changed saved response. Keep
source `0eaaef8` distinct from the `a4a38bc` 62-event result. No new label may
turn the uncertain multi-target cohort into paired acceptance. Further alias,
interface, stale/error, transfer and resource behavior remains separate work.
