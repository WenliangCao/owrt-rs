# Initial hosts and restored-lease publication: independent Rust review

This read-only review concerns the preserved D failure
`hostsdir-dhcp-name-effects`, specifically `initial-helper:helper`. It does
not reinterpret that failure as an accepted HUP ordering difference. D remains
immutable and unqualified pending a separate fix and its gates.

The Rust call chain supports the early-publication diagnosis:

1. The main loop runs `step_dhcp_files` before `step_dns_files`.
2. A completed DHCP input bank enters `finish_file_update`, then first
   `initialize`, then `maintain(..., force_dns=true)`.
3. `LeasePublisher::replace` can publish restored names into `local.leases`
   before the DNS `initial_cache_reload` step.
4. That DNS step sets `hosts_initializing=true`, then `reload_hosts_data`
   unconditionally clones `local.leases` as retained leases for
   `configured_hosts_bulk`. They become nodes in the initial hosts chain.
5. Later `hosts_changed` calls `update_configured_names`, whose reverse lookup
   uses `provider_hosts().provider_reverse`. The latter intentionally refuses
   a static rename when a retained DHCP node comes first. This rule is needed
   for runtime HUP, but the artificially retained initial nodes can suppress
   the initial rename according to bucket order.

The matching C startup-order proof belongs to the independent correctness
review; no C behavior is inferred solely from this Rust chain. Existing
captured C/Rust helper outputs remain the behavioral evidence.

The smallest promising repair is to build the **initial** hosts generation
without these artificially early published lease nodes, while leaving genuine
runtime HUP retention intact. Deferring all of `DhcpProvider::initialize` is
broader and risks changing startup lease/prune clocks, persistence/alarm work
and the already frozen original helper event. The existing
`polling_resolver_keeps_initial_hostsdir_dhcp_and_helper_work_behind_publication`
test explicitly requires that first helper event to keep the restored name.

An initial-call-only boolean is insufficient by itself. A HUP may supersede an
unfinished first hosts FIFO scan; `hosts_full_reload` becomes true although
there has still been no completed initial publication. The existing
`hosts_initializing` latch deliberately survives that transition. Cold-start
exclusion must also apply to such HUP rescans until initial completion or the
existing explicit failure-completion boundary. It must not reintroduce the
early lease nodes simply because the second scan was requested by HUP.

Focused verification should retain the original failed service case and cover
both deterministic lease/static bucket orders. It should also cover initial
FIFO plus HUP, the no-hostsdir path, and the existing genuine runtime-HUP
retention test. Existing failure/queued-packet/helper admission tests remain
authoritative: keep old published views until complete publication, retain the
frozen first helper delivery, release pending hosts only through the real
provider publication, and keep later incremental recovery working.

These findings and the initial-HUP caveat were sent to the DHCP fix owner.
No product edits, remote reproductions, changed C expectations or test waivers
were made by this review. The actual repair still requires a separate diff
review; this document approves neither an unseen patch nor its qualification.
