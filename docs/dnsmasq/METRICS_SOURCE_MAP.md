# Exact C metrics write sites and publication gate

This is source-contract metadata for the exact patched dnsmasq 2.93 reference,
not a claim that Rust's engines update these counters. The reference is the
nodhcpv6 variant identified in [OPENWRT_CONTRACT.md](OPENWRT_CONTRACT.md).
Line numbers below refer to its patched `src/` tree. A scan of every C
`metrics[...]` write and `clear_metrics` caller produced this table.

All 30 fields are u32 in `ubus.c:222-223`, in the order below. Ordinary counters
wrap modulo 2^32. The process initially zeroes daemon state. `clear_metrics`
(`metrics.c:56-74`) clears every metric and per-upstream statistics, but its only
C caller is the DBus method at `dbus.c:915`; DBus is not compiled in this image.
UBus has no reset method. SIGHUP/cache reload resets **only the first two**
(`cache.c:1566-1567`), so their windows differ from cumulative query/lease
counters after reload. Reconnecting ubus resets none of them.

`METRIC_` is omitted from enum names in this table. “Counter” means cumulative
until the relevant reset above; it does not mean one count per received packet
or one count per successful socket send.

| Public field | C enum | Actual write sites | Trigger / variant / window |
| --- | --- | --- | --- |
| `dns_cache_inserted` | `DNS_CACHE_INSERTED` | `cache.c:866`; reset `:1566` | One committed `new_chain` record in `cache_end_insert`, after rejecting outdated CNAME pointers. A multi-record response can add several; transaction failure adds none. TCP child inserts travel over its pipe and are committed/count again in the parent. Hosts/DHCP entries use other paths. Cache-reload window. |
| `dns_cache_live_freed` | `DNS_CACHE_LIVE_FREED` | `cache.c:774`; reset `:1567` | Capacity-pressure spill after an expiry scan, only when the chosen record's expiry is still in the future. Expired/stale victims do not count as live freed. Cache-reload window. |
| `dns_queries_forwarded` | `DNS_QUERIES_FORWARDED` | `forward.c:579` | Once per UDP `forward_query` action with at least one successful upstream send; the source condition also permits DNSSEC subqueries, unavailable here. A retry can increment; sending one action to several upstreams still increments once. The TCP request path has no corresponding write. Counter. |
| `dns_auth_answered` | `DNS_AUTH_ANSWERED` | chosen `forward.c:1936`, increment `:2002` | Auth answering branch requires `HAVE_AUTH`, excluded in this variant. Counter slot remains in wire output. |
| `dns_local_answered` | `DNS_LOCAL_ANSWERED` | `forward.c:621`; chosen `:1929,:1957`, increment `:2002` | UDP local/cache answer at `receive_query`, excluding stale answers; also locally generated fallback/refusal/error results at `forward_query`'s reply exit. Connmark-disallowed assignment `:1929` is not compiled here. Increment follows the send call, not proof that the client received it. TCP ordinary local answers do not increment it. Counter. |
| `dns_stale_answered` | `DNS_STALE_ANSWERED` | chosen `forward.c:1957`, increment `:2002` | UDP stale-cache answer. The same incoming query may then be forwarded to refresh the cache and increment forwarded too. Counter. |
| `dns_unanswered` | `DNS_UNANSWERED_QUERY` | `forward.c:3165,:3189` | `get_new_frec` reclaims an old outstanding record at `4*TIMEOUT`, or reuses the oldest at `TIMEOUT` when no free record exists. Counts forward records, not each merged client. It is not incremented automatically at every timeout tick or on every SERVFAIL. Counter. |
| `dnssec_max_crypto_use` | `CRYPTO_HWM` | max update `forward.c:1421-1422,:2692-2693`; child/parent max merge `cache.c:1053-1054` | DNSSEC validation work high-water mark, gated by `HAVE_DNSSEC`, unavailable here. Pipe write of the child's value `cache.c:927-928` is transport, not another increment. |
| `dnssec_max_sig_fail` | `SIG_FAIL_HWM` | max update `dnssec.c:702-703`; child/parent max merge `cache.c:1057-1058` | DNSSEC signature-failure high-water mark, unavailable here. Pipe write `cache.c:930-931` is not an increment. |
| `dnssec_max_work` | `WORK_HWM` | max update `forward.c:1424-1425,:2695-2696`; child/parent max merge `cache.c:1061-1062` | DNSSEC subquery-work high-water mark, unavailable here. Pipe write `cache.c:933-934` is not an increment. |
| `bootp` | `BOOTP` | `rfc2131.c:694` | BOOTP branch after selection/allocation handling, including an error message that then causes no reply. Earlier rejected/malformed packets never reaching this statement do not count. Counter. |
| `pxe` | `PXE` | `rfc2131.c:953,:1042` | PXE boot-item reply or proxy branch. The proxy branch increments even when it subsequently returns 0 because of ignore. Its DHCPACK-shaped wire reply does not traverse the ordinary `DHCPACK` counter increment. Counter. |
| `dhcp_ack` | `DHCPACK` | `rfc2131.c:1738,:1784` | Ordinary successful REQUEST/rapid-commit ACK after lease updates, or successful INFORM ACK. Counts constructing/logging ACK before network delivery, not each allocated lease. Counter. |
| `dhcp_decline` | `DHCPDECLINE` | `rfc2131.c:1248` | DECLINE after matching server-id and present requested-address validation, even if no matching lease is pruned. Counter. |
| `dhcp_discover` | `DHCPDISCOVER` | `rfc2131.c:1349` | DISCOVER after address selection/ignored-client handling, before a no-address/error return. Rapid commit includes DISCOVER but bypasses ordinary REQUEST and OFFER counters. Counter. |
| `dhcp_inform` | `DHCPINFORM` | `rfc2131.c:1757` | INFORM handling before ignore/zero-ciaddr return. A successfully answered INFORM also increments ACK. Counter. |
| `dhcp_nak` | `DHCPNAK` | conditional `rfc2131.c:1565` | Failed ordinary REQUEST processing that reaches NAK generation; rapid-commit failures select NOANSWER instead. Early ignored/rebinding-other-server returns do not count a NAK. Counter. |
| `dhcp_offer` | `DHCPOFFER` | `rfc2131.c:1377` | Accepted DISCOVER reaching offer construction, after possible rapid-commit diversion. No OFFER count for DISCOVER returning an allocation error or ignored result. Counter. |
| `dhcp_release` | `DHCPRELEASE` | `rfc2131.c:1282` | RELEASE after context and matching server-id validation, including an unknown-lease release. This counter is not identical to `leases_pruned_4`. Counter. |
| `dhcp_request` | `DHCPREQUEST` | `rfc2131.c:1490` | Ordinary REQUEST after request-mode validation; early returns for other servers/unicast-vs-rebinding policy do not count. Rapid commit jumps to the label after this statement. Counter. |
| `noanswer` | `NOANSWER` | conditional `rfc2131.c:1565` | A rapid-commit request reaches the error path after DISCOVER processing; no NAK is sent. Not a generic DHCP packet-drop/no-response counter. Counter. |
| `leases_allocated_4` | `LEASES_ALLOCATED_4` | `lease.c:874` | Every successful `lease4_allocate`, including startup lease-file restoration (`lease.c:100`) and BOOTP allocations. Renewing an existing lease does not allocate. Counter; never the current lease count. |
| `leases_pruned_4` | `LEASES_PRUNED_4` | conditional `lease.c:634` | `lease_prune` unlinks either an expired lease or its explicit target, when the stored IPv4 address is nonzero. RELEASE, DECLINE and replacement can all prune. Startup calls prune after reading restored leases (`lease.c:252`). Counter. |
| `leases_allocated_6` | `LEASES_ALLOCATED_6` | `lease.c:891` | Successful `lease6_allocate`, behind `HAVE_DHCP6`, excluded in this image. |
| `leases_pruned_6` | `LEASES_PRUNED_6` | conditional `lease.c:634` | Same prune statement selects this slot when `lease->addr.s_addr == 0`; that statement itself is not DHCPv6-gated. Ordinary IPv4 leases choose slot 4. A restored `0.0.0.0` IPv4 entry reaches the zero-address branch; the later [lease-counter phase](METRICS_LEASE_PHASE.md) verifies this against actual C. Do not hardcode slot 6 to zero solely from NO_DHCP6. |
| `tcp_connections` | `TCP_CONNECTIONS` | increments `dnsmasq.c:2158,:2283`; decrements `:1651,:1954` | **Active child-slot gauge**, not a cumulative connection counter. Ordinary TCP fork increments at `:2158`; DNSSEC asynchronous child fork at `:2283` is excluded here. A slot decrements only when both waitpid completion and pipe EOF have occurred, in either order. Debug/nonforked mode is different. `max_procs_used` is a separate high-water value and is not this wire field. |
| `dhcp_leasequery` | `DHCPLEASEQUERY` | `rfc2131.c:1093` | LEASEQUERY enabled, nonzero source, and source allowlist accepted. Rejected queries before this point do not count. Counter. |
| `dhcp_lease_unassigned` | `DHCPLEASEUNASSIGNED` | `rfc2131.c:1107` | Query names a nonzero address with no lease that is available in configured DHCP contexts. Counts response classification. |
| `dhcp_lease_actve` | `DHCPLEASEACTIVE` | `rfc2131.c:1168` | Query resolves to an eligible active lease. Original public misspelling is required. Counts response classification. |
| `dhcp_lease_unknown` | `DHCPLEASEUNKNOWN` | `rfc2131.c:1182` | Query retains unknown classification when constructing response, after other eligibility processing. Counts response classification. |

## Current Rust boundary

The later [cache-counter phase](METRICS_CACHE_PHASE.md) and
[lease-counter phase](METRICS_LEASE_PHASE.md) add real owner-held counter updates
and exact C snapshot tests. Product aggregation/publication is a separate gate;
the paragraph below records the earlier source-map snapshot before those hooks.

At this source-map snapshot, `metrics.rs` provides storage, wrapping additions,
two-field cache-reload reset, and wire serialization. A repository scan finds
its `Metric::...` calls only in that module's test, not production engine
increment sites. `UbusService::process_one` borrows the caller's metrics; the
standalone probe uses explicit synthetic values to verify serialization only.
Neither is permission to publish invented zero engine counters.

The publication gate is therefore still open: attach each counter to the
corresponding real DNS/DHCP/lease/TCP operation, then compare ordered live C/Rust
snapshots over matching inputs, reload windows, startup restoration, failures,
retries, multiple records, merged queries and TCP child/pipe lifecycle. Names,
u32 widths and serializer agreement alone do not close that gate.
