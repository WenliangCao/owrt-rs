# DNS runtime upstream routing phase

This phase adds the configuration-to-upstream-group boundary for the target
`dnsmasq 2.93-r1` `nodhcpv6` variant. It is a routing adapter, not a claim that
the daemon already owns the complete DNS event loop. The current binary still
uses the local-only runner; callers must pass ownership from hosts, cache and
CNAME lookup before calling `RoutingTable::select`.

| C source | Behaviour and invariant | Rust implementation | Evidence |
| --- | --- | --- | --- |
| `domain-match.c:106-237` | Search the complete name and progressively shorter right-hand suffixes. Matching is ASCII case-insensitive; exact rules outrank wildcard rules at the same suffix. | `RoutingTable::select`, `RuleBucket::matched_pattern`, `matches_domain` | `dns::routing::tests::nonwildcard_priority_and_character_wildcards`, `wildcard_dot_preserves_label_boundary` |
| `domain-match.c:284-377` | For one suffix, local IPv6, local IPv4, zero addresses and local-only rules precede resolver/upstream servers. If the requested local family is absent, continue at a shorter suffix. | `local_addresses` and the family-mismatch continuation in `select` | `local_family_priority_and_shorter_suffix_fallback`, `local_only_and_zero_tiers_precede_upstream` |
| `domain-match.c:539-590` | A dotless rule applies only to a name without a dot and is considered after the ordinary suffix path; DS/DNSKEY lookup disables the dotless path. | `DomainPattern::dotless`, `allow_dotless`, DS parent stripping | `dotless_overrides_default_but_not_specific_domain`, `ds_parent_and_dnskey_skip_dotless` |
| `domain-match.c:218-237`, `rfc1035.c:1302-1344` | DS lookup strips the first label before matching the parent domain. A/AAAA/ANY flags select local address families; other record types remain upstream queries. | `QueryFamily`, DS normalization in `select` | `ds_parent_and_dnskey_skip_dotless`, `upstream_transport_family_is_independent_and_order_is_preserved` |
| `option.c` server rule parsing and `domain-match.c:384-430` | Each literal upstream endpoint belongs to the matching suffix server group. `server=/.../#` expands the already-resolved default resolver list at that suffix; the resolver tier wins over ordinary upstreams at that suffix. | `from_config`, `validate_endpoint`, `ServerGroup` construction | `local_default_precedes_upstream_and_default_resolver_rule_uses_input` |
| `domain-match.c:284-377` | Exact and wildcard records with the same suffix are one C server tier, so a wrong-family local literal cannot be bypassed by a wildcard upstream. | Suffix-keyed `RuleBucket` with multiple `DomainPattern`s | `nonwildcard_priority_and_character_wildcards`, family fallback fixture |

`RouteSelection::LocalRecord` is returned immediately when the caller says a
hosts/cache/configured record or CNAME already owns the name. `LocalAddress`
retains selected literal addresses for the caller's answer path. `LocalOnly`
stops forwarding, and `Upstream` carries the selected `GroupId`, matched
pattern and query family. `into_groups()` returns stable-ID groups sorted by
ID for later hand-off to `ForwardDispatcher`.

The adapter rejects platform-dependent settings instead of silently dropping
them. A hostname endpoint returns `UnresolvedHostname`; an IPv6 scope returns
`UnresolvedScope`; any source address/interface binding returns
`UnresolvedSource`; and an empty resolver list for `server=/.../#` returns
`MissingDefaultResolvers`. The owning OpenWrt adapter must perform the C
AI_ADDRCONFIG/SOCK_DGRAM hostname lookup, scope/interface resolution and
source socket setup before constructing this table. Resolver-file loading and
`no-resolv` policy remain outside this module.

## Focused evidence

`dns::routing::tests` has ten isolated fixtures and passed 10/10 in the current
crate run. They cover local ownership, A/AAAA/ANY family priority, zero and
local-only precedence, family fallback, exact and both wildcard forms,
dotless rules, DS parent routing, mixed upstream transport families, resolver
expansion, group metadata and all four unresolved-platform errors. The tests
use only in-memory `DnsConfig` values and `Name`s; they do not bind sockets or
read the host resolver file.

The prior local C/Rust audit in
`docs/dnsmasq/DNS_ROUTING_CONTRACT.md` covers 72 local-routing semantic cases
with zero mismatch. That evidence validates the local answer boundary; the
ten runtime-adapter fixtures validate group construction and route metadata.
They are separate from the UDP transport evidence in
`docs/dnsmasq/DNS_UPSTREAM_PHASE.md`.

## Remaining integration boundary

`dns::daemon::DnsDaemon` now calls the route table for every unowned client
query and passes the selected group to `ForwardDispatcher`/`UpstreamResolver`.
It restores coalesced client IDs and applies the existing address-policy and
EDNS envelope before returning client responses. The containing listener still
owns UDP sockets and resolver-file loading; TCP upstream, cache/SOA insertion,
ubus metrics, source/interface-bound sockets and UCI reload lifecycle remain
outside this phase. No claim of production replacement, target-router
performance or full DNS equivalence is made until those boundaries are wired
and independently tested against the exact C implementation.
