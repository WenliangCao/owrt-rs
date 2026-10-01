# Frozen reverse-cache UDP C-first gate

This independent gate has **19 profiles and 124 UDP observations**. Freeze this
matrix and its tool before native C execution; complete native and verified
actual-image C calibration before any Rust comparison. It extends the prior
nine C-only direct IPv4/IPv6/CNAME service anchors without replaying their
three-step matrix. The four-process multi-target primitive cohort remains
C-only; no uncertain multi-target order enters this paired single-target scope.

All runs use the build-host isolated wrapper, fresh output directories and
loopback only. No router, timing or deployment work is included. Record exact
image/native identities, every packet, upstream sequence, all 30 UBus counters,
failures and complete schedules under ignored private directories.

## Source audit before fixture construction

- `rfc1035.c:802-860`: direct PTR matches the original question owner, decodes
  its target against the whole packet, inserts it, then checks declared endrr.
  It does not apply generic RDATA's target-within-RDLEN condition. If no direct
  PTR matches, it falls through to forward CNAME/Generic(12) extraction.
- `rfc1035.c:1939-1989`: address lookup precedes RD/DO rejection and ANY's
  dynamic-record exclusion. Thus each can promote reverse entries even when
  the answer must be forwarded. AD does not suppress ordinary unsigned cache
  consumption in this target no-DNSSEC build.
- `forward.c:1368,1433`: raw upstream CD or original request CD sets no-cache
  before restoring the recipient CD flag. Extraction still runs; only commit
  is suppressed. DO forces a new upstream response despite a warm PTR cache.
- `forward.c:767-775`: UDP process_reply unconditionally restores RA before
  extraction. A raw RA0 replacement is therefore a commit control here,
  unlike a direct extract_addresses call given RA0. Do not import the latter
  expectation into this UDP gate.
- `forward.c:756,824-844,879`: proxy-dnssec is off, so upstream AD is cleared;
  malformed extraction clears records and returns SERVFAIL/EDE_OTHER when a
  valid pseudoheader survived parsing. A declared endrr beyond the packet can
  make that pseudoheader unavailable; retain the resulting EDE/OPT boundary.
- `rrfilter.c:170`: no configured RR filter means its pass does not repair the
  deliberately cross-RDLEN PTR. Saved wire data and a tolerant decoder must
  distinguish this C behavior from a normal cached replay.

## Common fixture

Capacity is 8 except the specified capacity-3 profiles. No hosts/resolver files,
no 0x20 encoding, no round robin, neg-ttl=120. Positive records have TTL 120;
CNAME TTL is 90. The fixed ready host is local and outside dynamic capacity.
All packets use IN class. Requests use one empty version-zero OPT except the
explicit plain RD0/ANY pressure profiles, which omit OPT throughout. No
arbitrary EDNS options, signatures or extended RCODEs are admitted.

After UBus registration, inspect the isolated process UDP table until port
15353 is bound, then send one ready query and take initial counters. This new
fixture barrier is not a production startup fix; retain the earlier gate's
readiness failure and leave its frozen tool unchanged.

Cached probes use a deterministic upstream SERVFAIL fallback: if C misses, the
existing two-send retry and final response remain visible. Positive/new-answer
steps should forward once. Compare request identity, decoded section/record
order, flags, TTLs, malformed-RDATA markers, original-case PTR targets, raw
question bytes, upstream order/count and every counter. Permit only upstream
transaction-ID removal and at most one second of cached TTL phase. Never sort
answer rows or normalize away malformed bytes.

## Fixed profiles and row counts

| Group | Profiles | Rows each | Rows |
| --- | --- | --- | --- |
| Equivalent IPv4/IPv6 owners | 2 | 4 | 8 |
| Mixed forward/reverse capacity | 2 | 9 | 18 |
| Forward-keyed PTR NODATA/NXDOMAIN | 2 | 5 | 10 |
| Literal-address/RFC2317 CNAME fallback | 2 | 5 | 10 |
| Plain RD0/ANY lookup pressure | 2 | 9 | 18 |
| Malformed replacement prefix | 1 | 7 | 7 |
| Malformed prefix under pressure | 1 | 9 | 9 |
| PTR target crosses RDLEN | 1 | 3 | 3 |
| Valid PTR target, endrr beyond packet | 1 | 7 | 7 |
| Empty-OPT DO/AD admission/replay | 1 | 6 | 6 |
| DO-triggered normal/request-CD/raw-CD/RA0 replacement | 4 | 7 | 28 |
| **Total** | **19** | | **124** |

Equivalent-owner profiles seed a partial reverse name with a mixed-case target,
probe full and alternative spellings (uppercase partial IPv4; full ip6.int
IPv6), then query the target's A/AAAA with SERVFAIL fallback. Positive replay
shares the address entry; PTR insertion must not create a forward address.

The first capacity-3 profile seeds forward A, reverse address 1, reverse address
2; hits A, inserts forward B, then probes all four. Reverse address 1 is the
victim. The second seeds A, reverse address 1, B; hits reverse address 1,
inserts reverse address 2, then probes all four. A is the victim. Each has four
committed insertions and one live-victim increment.

Each negative profile seeds a full reverse-owner NODATA with a valid SOA or an
SOA-free NXDOMAIN, probes an equivalent partial spelling (miss), replays the
original negative (hit), inserts a positive PTR through the partial spelling,
then probes the full owner (positive address hit). Expected insert deltas are
2/0/0/1/0 for NODATA and 1/0/0/1/0 for NXDOMAIN. No negative target is treated
as an address-keyed reverse entry.

Each CNAME fallback profile has no PTR at the original query owner. Seed a
CNAME to either a literal reverse-address owner or an RFC2317 non-address
owner, plus PTR at that terminal; replay alias, probe terminal, probe an
otherwise equivalent address spelling without that forward key (miss), then
replay terminal. Alias plus Generic(12) terminal commit two entries.

The plain RD0/ANY profiles seed reverse address 1, forward A and reverse
address 2; touch address 1 with RD0 PTR or RD1 ANY, receiving the forwarded
SERVFAIL; insert B and probe all four. The lookup still promotes address 1,
so A is evicted. No OPT or metadata expansion is used for this group.

Malformed replacement seeds old PTR and an A sentinel, then uses DO to obtain
a response containing valid new PTR followed by a bad target label. The prefix
removes the old PTR but no new entry commits; the recipient sees SERVFAIL with
EDE0. Probe owner (miss) and sentinel (hit), recover the owner with a valid PTR
and replay it. Under pressure, seed three forward entries instead; the first
valid PTR prefix evicts the oldest with live_freed+1, then the bad target
aborts. Probe all three, recover the PTR and replay it.

The cross-RDLEN profile's first PTR has one-byte RDATA `c0`; the next RR's owner
begins with label length 12, completing a pointer to the question across the
RDATA boundary. Both outer frames are valid. C should commit the PTR whose
target is the query owner, forward the malformed-looking original response,
then emit valid cached PTRs for full and partial owner probes. Preserve the
first response's short RDATA and decoded malformed marker.

The endrr profile follows the replacement schedule but its one PTR contains a
valid complete target while declaring RDLEN beyond the entire packet. C inserts
the prefix before the final bounds failure, so old removal persists and no new
commit occurs. The recipient is SERVFAIL; the absent parseable pseudoheader is
expected to leave no EDE/OPT. This source-derived distinction is calibrated,
not inferred from the generic malformed gate or Rust.

The metadata profile seeds PTR with DO+AD and raw reply AD, then probes plain
and AD-only cache hits, DO-only and DO+AD misses using SERVFAIL upstream, then
plain cache hit. Only the seed inserts; none of these unsigned recipient
responses should assert AD. The two DO misses still exercise address lookup.

The four replacement profiles seed old PTR and a sentinel A, force a DO
replacement, probe owner and sentinel, recover/probe owner, then replay. Normal
and raw RA0 commit one replacement; request-CD and raw reply-CD remove the old
entry during extraction and suppress commit, so their owner probe misses and
the later recovery inserts. Recipient CD always matches the request. Raw RA0
is restored by UDP processing before commit. Each profile ends with an owner
hit and preserved sentinel; no capacity eviction is expected.

## Calibration and boundaries

Before Rust, verify every C schedule's hit/miss, inserted/live-freed deltas,
upstream count, RCODE, CD restoration, unsigned AD, malformed/error shape and
ready/cleanup checks. Complete the entire C side before the Rust side of any
paired invocation. Preserve partial results if a C prediction fails; a failed
calibration is not a Rust mismatch and cannot be silently replaced. Reject
missing rows and detect one deliberately modified result; a standalone paired
negative requires a fully passing frozen Rust ELF.

This gate does not qualify local/DHCP coexistence, transfer, stale refresh,
multiple PTR target order, arbitrary EDNS, DNSSEC validation, integer overflow,
resource/production acceptance or physical deployment. Those remain separate.
