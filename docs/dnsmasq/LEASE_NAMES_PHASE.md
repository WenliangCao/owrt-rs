# DHCP DNS publication checkpoint

The dedicated lease-name generation implements the publication boundary in
`lease.c:564-620`, `cache.c:1742-1911` and `rfc1035.c:1654-1679`. It retains all
publication inputs for hosts reload, including records suppressed by the
current static hosts generation. Publication order remains newest lease first,
FQDN before short name; fqdn-only filtering is performed by `update_dns`.

The exact native C baseline has 17 scenarios. The oracle calls the actual
`cache_add_dhcp_entry`, `cache_unhash_dhcp`, `answer_request`,
`check_for_local_domain` and upstream extraction implementation. It is linked
with the audited nodhcpv6 native objects, after checking the exact unmodified
feature header and source identities. Positive calibration observes a real
DHCP cache entry; negative calibration requires an invalid configuration to
exit unsuccessfully. No production listeners, router state or device leases
are used.

Raw configuration, commands, packets, stderr, executable and result are under
ignored `private/dnsmasq-rewrite/lease-names-20261001/baseline-01/`. Its oracle
SHA-256 is `dc511d22fc0c096784e12850dcb5a48a820f400ce5c56758e44956ece435f8d3`.
`tools/dnsmasq/lease_names_diff.py` recreates the C-only baseline with the exact
native reference build and patched source tree. This is host ABI evidence,
not target/router acceptance or performance evidence.

| Contract | Observed C behavior | Rust boundary |
| --- | --- | --- |
| TTL/expiry | Configured DHCP TTL, otherwise local TTL; limited by remaining lease; equality is expired with stale serving disabled | Snapshot policy and lookup |
| Infinite lease | Configured TTL without duration ceiling | Snapshot policy |
| FQDN/short | First published address owner retains PTR | Publication order |
| Same-family static address | Same address suppresses duplicate; different address rejects lease name | Hosts precedence and warning |
| Other-family static address | IPv4 lease coexists with IPv6 hosts data | Hosts precedence |
| Configured CNAME | Warning emitted but lease address still inserted; CNAME wins forward lookup, lease can own PTR | Snapshot warning; answer integration pending |
| Non-terminal parent | Prevents upstream NXDOMAIN; does not itself answer locally | `name_exists` separate from `lookup` |
| Existing forward NXDOMAIN | Remains cached after lease publication | Caller must not clear whole name/cache |
| Existing positive PTR | Retains ownership over lease publication | `PublicationCache::reverse_owned` |
| Replacement | Only DHCP entries/non-terminals are removed | Immutable generation replacement |

The first module checkpoint has four focused regressions, derived from these
C observations: expiry/parent presence and FQDN PTR, hosts suppression and
reload recovery, CNAME warning-with-insertion, and preexisting PTR ownership.
The immutable source compiles independently of the pending service integration.
Passing these tests does not establish complete DHCP-to-DNS equivalence.

Remaining checks include actual-answer differential comparison after UDP/TCP
integration, precise forwarded-cache deletion (including static early-stop
boundaries), configured stale-cache behavior, restored FQDN publication,
before-ACK visibility, reload lifecycle, and target build/regression gates.
