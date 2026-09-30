# TCP forwarding caller policy

`TcpDnsService` wraps the per-connection `TcpUpstream` transport and shared
runtime routing table. The main listener attempts local answers first, then
uses `handle_with_local()` with that connection's `LocalDnsService` snapshot.
The narrower `handle()` entry point has no hosts/configuration snapshot for
local-name NXDOMAIN conversion; the daemon must use `handle_with_local()`.

The accepted configuration currently enables no client-dependent EDNS query
decoration. TCP therefore forwards the original query unchanged, including its
ID and OPT advertisement. It does not add UDP's empty OPT or inherit UDP's
`ignore-address` predicate. Cancellation/deadline errors remain session-close
signals; exhausting upstream I/O returns C's REFUSED error.

| Exact reference boundary | Implemented caller behavior |
| --- | --- |
| `tcp_request` / `make_local_answer` | No route: REFUSED; original OPT clients receive EDE 14. Exhausted I/O: REFUSED/EDE 23 |
| `setup_reply` | Preserve query ID/RD/CD/Z; clear AA/TC/AD and set QR/RA |
| TCP error EDE versus UDP | TCP restores query DO; shared refusal helper takes an explicit `copy_do` flag because UDP clears it |
| Opcode and `extract_request` rejection | Non-QUERY becomes NOTIMP; bad question count/nonstandard answer/authority counts become REFUSED; unskippable questions close |
| `process_reply` envelope | Restore CD, apply AD proxy policy, set RA, strip unsolicited OPT or advertise configured OPT size, retain TCP answer length |
| Extended RCODE | Capture before OPT stripping so extended errors do not accidentally enter NOERROR address policy |
| Address policy and `add_pseudoheader` | Rebind produces EDE 15; malformed address/CNAME/owner produces SERVFAIL/EDE 0 where C has a response OPT |
| `check_for_local_domain` + `lookup_domain(F_CONFIG)` | Known local name NXDOMAIN becomes NODATA with AA, using the per-connection hosts/config snapshot and exact address-rule classification |
| `tcp_talk` identity | Preserve the upstream reply ID; C does not validate or replace it on this TCP path |

The F_CONFIG lookup considers configured address/zero rules, skips upstream and
local-only tiers when searching shorter suffixes, and preserves the late dotless
override. It does not treat every server rule as a local name. Root-name ownership
also distinguishes explicit TXT/PTR/MX/SRV/NAPTR lists from hosts/CNAME-derived
non-terminals.

`tcp_caller_diff.py` links a thin driver and verbatim hash-pinned
`forward.c::process_reply` / `domain_no_rebind` bodies to audited reference
objects, including the full nodhcpv6 feature macro set. C generates every expected
reply. The Rust probe calls the actual caller helpers through a test-only wrapper
appended to an ignored source copy. Full bytes are compared, including IDs, flags,
TTL, order, OPT options, DO, EDE and trailing-byte removal. The scope intentionally
excludes cache insertion and logging/ubus side effects; the C harness disables
cache insertion with the explicit `no_cache` caller argument.

The corpus has 235 single-query cases: 143 NOERROR, 38 REFUSED, 20 SERVFAIL,
18 NXDOMAIN, 12 NOTIMP, two forwarding admissions and two close decisions. All
235 match. Cases include IN/CH classes, unknown types, signed replies, extended
RCODE, existing/malformed EDE options, non-final OPT relocation, malformed
compressed owners/CNAMEs, rebind exceptions, 4 KiB TCP answers, and 50 local-name
NXDOMAIN cases. The comparator/counter calibration deliberately checks one
success and two failures. Three local transport/caller regression tests pass.

There is a separate confirmed C session-state defect: after a no-route query
with OPT, the next ordinary query on the same connection receives a carried-over
OPT; a fresh ordinary connection receives none. `have_pseudoheader` survives the
C loop until an upstream success resets it. The Rust caller uses the current
query's OPT state. `tcp_caller_session_scope.py` reproduces and reports this
difference; it must not be included among equivalence passes. The broader task's
acceptance status must retain this discrepancy, alongside the transport's
separately documented C frame-length defect.

Raw C-only and differential attempts are retained under ignored
`private/dnsmasq-rewrite/tcp-caller-20260930/`. `diff-04/result.json` is the final
235-case comparison with calibrated counters and complete tool/source identities.
The `session-scope` and `session-c-tool` directories retain the independent and
repeatable-tool observations of the C carry-over packets.

This phase does not establish full TCP functional equivalence: dynamic-cache
snapshot/writeback, doctor/ubus, remaining record filtering, full local-answer
EDNS behavior and the session discrepancy still require their own evidence.
It makes no performance or production-acceptance claim.
