# DHCP DNS publication and local answers

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

The subsequent local-answer gate uses a new 25-scenario C baseline. Nineteen
scenarios compare the Rust publication source and the production local answer
engine: **1,100 command observations, 500 DNS replies, 38 DHCP inventories,
zero mismatches**. Six upstream-cache scenarios remain in the C baseline and
are explicitly deferred to the forwarded-cache publication gate; they are not
counted as Rust passes. The comparator checks IDs, flags, TTLs, RDATA and DNS
answer order, normalizing compression only. Cache inventory enumeration order
is sorted because enumeration order is not an observable query selection order.
An injected wrong DNS answer must produce exactly one comparator failure.

The expanded cases cover configured CNAMEs terminating at a DHCP name, mixed
static families, static duplicate/mismatching addresses, publication's hosts
round-robin side effect, FQDN PTR ownership, no promotion after the original PTR
owner expires, and extending a real parent's lease expiry when a later child
name expires later. Snapshot lookup does not synthesize NODATA for an absent
RR type. UDP/TCP service methods accept an explicit clock and the same immutable
lease generation; the ordinary methods use wall time.

The exact C `use-stale-cache` behavior is retained: its shared expiry predicate
also admits DHCP entries until the configured stale limit, and a lease one
second past expiry produces a wire TTL of `4294967295` via `crec_ttl` narrowing.
This surprising value was observed in actual C responses, is compared without
normalization, and has a regression. Lease pruning normally removes the entry
first. It is not replaced by a guessed zero-TTL rule.

Final evidence for this unit is in ignored
`private/dnsmasq-rewrite/lease-names-20261001/{baseline-03,diff-03}/`; previous
baselines/runs are retained. C oracle SHA-256:
`bfbf0a0a537bc895c5a72831f7aee3260088a3429c7830cdd0d5c42fbd97a2aa`.
The local library gate reported 303 passed / 5 explicitly ignored, and
`cargo clippy --all-targets -- -D warnings` passed. The ignored C-specific gates
were not counted as passes. No performance improvement is claimed.

Remaining checks include precise forwarded-cache deletion (including static
early-stop boundaries), restored FQDN publication, before-ACK visibility,
service reload lifecycle, and target build/regression gates. The caller must
replace the shared source before acknowledging DHCP and clone its `Arc` when
creating a TCP child snapshot. A module/local-answer pass does not establish
complete DHCP-to-DNS service equivalence.
