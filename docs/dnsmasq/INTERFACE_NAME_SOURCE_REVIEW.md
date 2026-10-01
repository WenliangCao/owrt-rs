# Interface-derived DNS names: implementation boundary

`interface-name` is present in the target option catalog but has no runtime
implementation in current product `78f1e81`. The direct local/PTR work does not
qualify its higher-priority reverse answers. This review identifies the existing
C interface before choosing a representation or implementing the option.
No configuration or network experiment is performed here.

| Exact C location | Required behavior and caller boundary |
| --- | --- |
| `option.c:4906-4970` | Append directives in configuration order; canonicalize the name; accept an interface with optional `/4` or `/6`. The shared parser also handles `dynamic-host`, but rejects prototype addresses for `interface-name`. Preserve first-name PTR priority. |
| `network.c:358-464` | Populate a separate address list for each matching interface name, independent of the interfaces on which DNS listens. Match the interface label with the target's `IF_NAMESIZE` boundary. Deduplicate addresses within a directive and prepend accepted entries. |
| `network.c:395-454` | IPv6 temporary, tentative and deprecated addresses remain eligible for reverse lookup but are excluded from forward answers. An address-only IPv6 list cannot represent this distinction. |
| `rfc1035.c:1875-1941` | PTR/ANY first searches interface-derived addresses, before explicit `ptr-record` and hosts/DHCP/dynamic reverse cache. An interface match answers with its configured name and local TTL, bypassing the reverse cache. |
| `rfc1035.c:2016-2088` | A/AAAA/ANY looks up matching interface-name directives and refreshes interface enumeration. It combines their eligible addresses in stored order and supports IPv4 `localise-queries`. No-address cases bypass ordinary address-cache lookup; their final reply semantics still need C observations. |
| `rfc1035.c:1379-1420` | Interface names and their subdomains establish local-domain existence independently of whether the interface currently has an address. |
| `dnsmasq.c:372-380` | Startup enumeration precedes lease FQDN calculation, since address-derived domain configuration also depends on this snapshot. |
| `dnsmasq.c:1221-1238` | Each main poll cycle resets the enumeration guard before processing network-change events. The enumeration cache is an event-loop boundary, not an arbitrary time-based TTL. |
| `dnsmasq.c:2037-2048`; `network.c:736-751` | TCP acceptance refreshes before forking. Further enumeration calls in the child do nothing, preserving the inherited interface snapshot and avoiding competing reads of the parent's netlink socket. |

The parser's use of the same structure for `interface-name` and `dynamic-host`
does not permit silently implementing only the current deployment's names.
Prototype-address subnet composition belongs to the latter option and needs
its own evidence before being enabled. Wildcard/name matching, repeated names,
family suffixes and invalid input must follow this parser, not the separate
listener `interface=` matching rules.

The existing Rust `interfaces.rs` provides a small Linux 64-bit `getifaddrs`
wrapper for DHCP IPv4 context selection. It preserves IPv4 aliases, interface
index, netmask, broadcast and loopback state. It neither returns owned interface
labels nor supplies IPv6 per-address tentative/deprecated/temporary flags.
Extending its address enum alone would therefore not satisfy the DNS contract.
Keep its established DHCP behavior intact when adding a separately qualified
DNS snapshot. The source does not justify adding a new networking dependency.

The local answerer also needs a current interface snapshot, local-existence
participation, interface-before-explicit-PTR ordering, and the same snapshot
for configured CNAME terminals. A replacement which merely rewrites hosts
entries would lose no-address existence, IPv6 reverse-only states, directive
ordering and the TCP lifetime boundary.

The next qualification should first freeze a small configuration and actual
UDP/TCP service matrix inside isolated Linux namespaces. Cover family filters,
two names on one interface, one name on multiple directives, explicit PTR
collision, an absent interface, alias addition/removal, and an accepted TCP
connection across that change. Use exact native and image C before selecting
Rust expectations. A separate IPv6-state fixture must establish that the test
kernel actually supports the requested address flags; an unavailable setup is
not a product pass. Enumeration allocation/socket failures and localization
remain separate boundaries. This note does not freeze or run that future gate.
