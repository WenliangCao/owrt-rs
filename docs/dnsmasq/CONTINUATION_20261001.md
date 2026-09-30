# Continuation checkpoint — 2026-10-01

Task remains active. Full functionality, zero-known-defect delivery, paired
performance/resource improvement and production acceptance are **not complete**.
Do not stop at the successful staging build or claim language migration completes
optimization. User-owned `docs/prompts/` edits remain untouched.

## Stable checkpoint

Product freeze `574f5ed88d8d3c9453f0ac9c25a891933b5a128b` is archived in
`private/dnsmasq-rewrite/freeze-574f5ed/`. Build tooling fixes are separate.
`PACKAGE_574F5ED_RESULT.md` records the inert target package, exact target C and
image dependencies, the source/ELF/APK hashes, retained warnings, all intermediate
runs and target-artifact differential checks. ELF body **+720686 B / +267.6%**
is an open resource regression. No physical router was accessed.

Completed units since the linked prior process include exact C identity and
oracle macro corrections; local/CNAME/negative cache corrections; SIGHUP; TCP
transport/caller/refusal/frame ordering/cancellation and old-connection hosts
snapshots; DHCP destination/name authority/config/context/timers/ICMP/ARP;
TFTP TID/errors/resources/single-port/range; and protected SDK staging builds.
The master report links their individual, limited coverage. Counts must never
be added up as if they proved complete service equivalence.

Confirmed C reference defects are retained separately: SRV uninitialized read,
TFTP stale DATA/FD leak, TCP failed-retry prefix and cross-query OPT carry-over.
A compatibility clarification was asked asynchronously; no answer was received
at this checkpoint. Continue preserving correct Rust answers and cleanup while
listing the differences explicitly; do not mark full equivalence or silently
waive the delivery standard. C/C ASLR-dependent initial record order also needs
a validated state model, never a per-reply sort or Rust-generated answer oracle.

## In progress and ownership

- **Root / main integration:** `main.rs` now has explicit local receive/EDNS
  limits, configured-hosts generation, a shared `ParentDns` local cursor and
  reload generation, TCP per-connection snapshots, UDP `forward_udp` and
  `poll_with_local`, and DHCP idle tick/maintenance reporting. These latest
  changes need the corresponding ongoing library commits and fresh focused
  Linux integration gates before commit. `ParentDns` locks contain bounded
  local work and zero-wait upstream polling; socket waits/sends stay outside.
  Forward caches and upstream tables are still per UDP listener: shared cache
  budgets and cross-listener coalescing remain open, not fixed by sharing hosts.
- **tftp_integration:** local EDNS envelope committed `4d711eb`, OPT tight-boundary
  correction committed `6c74e1f`. Finishing configured-hosts prefix/duplicate/PTR
  ownership and cross-listener round-robin state model. API
  `local::configured_hosts(config, ttl)` must run before hosts-file ingestion;
  main already uses it. Preserve former shared-address failures; do not hide
  address order behind sorted comparisons.
- **dhcp_audit:** persistence core committed `aa9790d`; implementing configuration,
  validated option12/FQDN input and real leasefile/DORA/restart/expiry integration.
  Main is already wired to `tick`, `take_maintenance_report`, nonfatal file/DNS
  errors and ARP/probe warnings. All experiments must explicitly use a private
  lease path with the new runtime; do not restart old no-leasefile fixtures on
  new binaries (C CLI default is `/var/lib/misc/dnsmasq.leases`). DNS publication
  stays pending until the dedicated publisher is actually attached.
- **reference_gate:** dedicated DHCP DNS snapshot/source model and actual C
  cache/answer oracle; shared UDP known-local NXDOMAIN correction plus EDNS
  advertised-size/EDE policy. Coordinate with the hosts-generation owner before
  editing local/hosts/service. Main consumes `poll_with_local(Duration::ZERO,
  &parent.local)`; DHCP publisher must synchronously apply the snapshot before
  ACK and keep enough unfiltered lease records to rebuild after hosts reload.
  Never replace this with ordinary hosts rows or blanket cache clearing.
- **reference_gate resource subtask:** read-only cost analysis and frozen DYN1
  candidate in `SIZE_COST_574F5ED.md`. Diagnostic build is authorized after quiet
  profiling windows, with only dynamic-musl/PIE flags changed from product freeze;
  feature/security/capacity gates stay fixed. No default recipe adoption or speed
  claim is authorized by a mere smaller file. Existing LTO/strip are not new gains.
- **dns_cache:** C-only cost plan frozen in `C_COST_DIAGNOSTIC_V1.md`.
  Formal windows wait for successful tester/perf counter
  calibration and a coordinated quiet build-host interval. This is diagnostic
  C baseline work, not paired Rust performance acceptance or router performance.

## Next integration gates

1. Finish current library units, run their exact C oracles, and commit them.
2. Re-run only affected main tests: local UDP/record cursor state, TCP/reload,
   UDP reply policy, DHCP file/idle-expiry. Use ignored/private output directories;
   preserve every failed round. Then commit main changes and update ledger counts.
3. Attach synchronous DHCP DNS publisher and selective cache invalidation, then
   compare DORA/renew/rebind/release/expiry/restart + DNS/file effects with target C.
4. Continue full configuration/static/tag/FQDN, relay/PXE/leasequery/helper,
   OpenWrt UCI/procd/ujail/ubus/ACL/metrics/hotplug/odhcpd/rpcd/LuCI contracts.
5. Only after relevant correctness gates, run frozen paired optimization goals.
   Host artifacts do not establish physical-router performance or production
   acceptance. Deployment needs a separate explicit request and recovery gate.

Tools/build hosts are not blockers: exact native and target C references,
matching SDK and isolated Linux namespace access are available. Source and raw
artifact locations are in the private manifests; do not contact the router to
recover information already available offline.
