# Frozen generic RDATA error and cache-prefix gate

This is a separate, bounded extension of the cache-rr contract. The existing
78-observation fixture remains unchanged. Exact patched C supplies all expected
packets and counters. Run complete native and image C calibrations before the
unchanged `4bf072d` Rust ELF, then qualify a separately identified correction.

Source contract: `rfc1035.c:974-1064` expands names only for enabled generic
storage (default SRV/non-address PTR, configured RR types, or cache-rr=ANY).
Missing names and a compressed name whose encoded bytes cross RDLEN return 2.
`forward.c:824-844` clears all response records, sets SERVFAIL, and attaches
EDE_OTHER when an OPT can be retained. Disabled generic extraction leaves the
RDATA opaque. Unknown enabled types also remain opaque under rrfilter_desc.
Cache insertion stays ordered: completed records may remove old entries or
evict live entries before a later invalid record prevents final commit.

## Frozen matrix: eight profiles, 35 packet observations

Six seed/two-replay profiles (18 observations):

1. Default SRV: six fixed RDATA bytes with no target name.
2. Enabled MX: two preference bytes with no exchange name.
3. Enabled SOA: first compressed name only, missing second name.
4. Enabled MX: one byte of a compression pointer lies inside RDLEN, its second
   byte is the length-12 initial label of the following structurally valid RR.
   The resulting pointer targets the valid question at offset 12. This tests
   RDLEN overrun without an out-of-packet access or undefined reference state.
5. Disabled MX control with the same missing exchange: forward unchanged on
   all three requests and insert nothing.
6. Enabled unknown type 65280 containing pointer-looking opaque bytes: commit
   once and serve both replays from cache.

The first four profiles expect SERVFAIL, zero answer/authority records, EDE 0,
one upstream exchange and no insertion on every request. Every request uses
an empty version-zero OPT without DO/AD/CD. The disabled control stays NOERROR
and preserves its malformed bytes; the unknown control preserves opaque bytes.

Two ordered-prefix profiles (17 observations), all with capacity three:

- Replacement (eight): seed owner SRV, seed sentinel SRV; query a new alias
  whose answer is CNAME-to-owner, valid replacement SRV, then malformed SRV.
  Probe owner, alias and sentinel with controlled upstream SERVFAIL fallback;
  recover owner with a valid answer; replay recovered owner. The failed
  transaction inserts zero, old owner disappears, alias stays invisible,
  sentinel remains cached, and live_freed stays zero.
- Pressure (nine): seed owner, sentinel, victim; send the same prefix through a
  new alias, then probe owner, sentinel and victim; recover/replay owner.
  Admission of two pending records evicts owner then sentinel, increasing
  live_freed by two despite zero inserted. Victim remains cached. Recovery
  starts a new transaction, frees the pending prefix and commits one record.

These real-daemon observations prove prefix removals, eviction counters,
invisibility of uncommitted entries and successful subsequent recovery.
There is no public pending-count API: pending membership is source-supported,
not reported as a directly measured daemon field. All 30 UBus counters and
upstream counts/order are compared. SERVFAIL fallback retains the established
two-send retry. DNS identities, flags, EDE, RR order, names, opaque RDATA and TTL
are retained; only upstream IDs and at most one second of cached TTL phase are
normalized. Missing rows must fail; one altered flag must be detected.

Freeze this plan and tooling before execution. Preserve each failure and
partial trace in a unique ignored private directory. All listener experiments
use run_isolated.sh on oracle and verified reference identities. This gate
does not qualify router behavior, performance, DNSSEC/EDNS expansion, reverse
PTR, allocation failure, arbitrary malformed packets or C undefined reads.
