# Independent review of local/reverse answers and DHCP FQDN wiring

Reviewed private source `eeed470` (DHCP FQDN wiring) and `a4a38bc` (local plus
dynamic reverse answers), based on `ff3f184`'s publication ownership change.
This review reads the exact patched C source and candidate code. It changes no
candidate code and runs no experiment. It finds no additional required repair
within the direct local-plus-dynamic PTR and FQDN wiring scope; source-derived
expectations below are not test passes.

`rfc1035.c:1940-1990` admits the address chain using its first record. A local
first record permits later dynamic PTR entries even with RD clear or DO set.
Each entry is checked for stale state before ANY skips dynamic data. Returned
dynamic data clears AA; each record uses its own TTL. The candidate implements
these operations in the local reverse branch, before packet construction.
It preserves explicit PTR precedence and does not call dynamic reverse lookup
when that branch wins. Configured CNAME terminals share the same local context.

The new context reaches both the main UDP listener and `DnsDaemon::handle_udp`.
The external-local entrypoint explicitly requires an already admitted query.
Dynamic stale traversal is returned through the existing `QueryResult::Stale`
path, retaining send-before-refresh and metric handling. With OPT, the service
uses the existing EDE 3 builder and configured output limit. A skipped dynamic
ANY record can still make the local-only reply stale, while AA stays set.
The direct mixed response clears AA, including when packet construction later
truncates. CD remains request-derived and local/nonvalidated data does not
assert AD. Actual RD/DO/CD/ANY service combinations require their independent
C-first addon; the added Rust unit fixture is not that qualification.

The `dhcp-fqdn` flag is connected through option parsing, default-domain
validation in both syntax/run paths, lease-file restoration, configured/static
name updates, ACK/BOOTP hostname collision policy, and DNS publication after
persistence. Publication retains FQDN-first order and suppresses short names
only when configured. C `lease.c:148` restores names before domains are supplied;
FQDN-only collision checks therefore retain duplicate short names. Later
`lease_calc_fqdns` does not deduplicate them. The candidate's restore policy and
subsequent FQDN initialization preserve this source distinction; ordinary
short-name collision handling remains the default.

The review identified boundaries for separate evidence:

- Dynamic CNAME/NXDOMAIN lookup precedes local PTR in C (`rfc1035.c:1753-1814`).
  The local-first caller still checks only configured CNAMEs. A previously
  cached reverse-QNAME CNAME chain can therefore be hidden after DHCP publishes
  a local reverse owner. The proposed narrow gate seeds that chain, performs
  a real ACK, then compares ordinary/RD0/DO queries before any implementation
  change. DO/RD0 must not fall back locally after C rejects a cached CNAME.
- `cache_engine::append_local_terminal` still invokes the local engine without
  a cache context. Dynamic-CNAME terminal composition is not newly qualified
  by the configured-CNAME integration above.
- Stale state of the local DHCP entry itself remains an existing unqualified
  boundary. This change adds dynamic-tail traversal; it does not prove every
  local expiry/prune interaction.
- C interface reverse names precede explicit PTR and bypass address-cache
  lookup. `interface-name` is listed in the option catalog but has no runtime
  implementation in this candidate, so interface precedence is not qualified.
- Recovered duplicate names across address-dependent domains, recovered equal
  FQDNs, and live authoritative-name collisions deserve narrow C cases if the
  lifecycle fixture does not already cover them.

Multi-PTR ordering, private TCP adoption, shared-index resource cost and
production acceptance remain outside this review. No physical router was
accessed, and no timing or allocation result is inferred from source inspection.
