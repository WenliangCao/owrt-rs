# Synchronous DHCP/DNS publication and parent reload

This closes the tested lease-publication path; complete dnsmasq equivalence,
remaining cache/clock boundaries and resource/performance acceptance remain open.

`LeasePublisher` synchronously locks the single parent DNS state, applies the
source-derived selective forward-cache invalidation, builds the dedicated DHCP
name generation, and installs it before returning to the DHCP state/runtime.
The state layer can only send its ACK after publication returns. File failures
retain C's nonfatal behavior; they do not undo state or suppress DNS publication.
Ordinary hosts rows are not used as substitutes for leases: lease expiration,
TTL, parent names and PTR ownership remain separate. Existing TCP sessions retain
their own shared-then-copy-on-write DHCP snapshot, as C's child processes do.

SIGHUP uses a parent event gate with a fixed lock order: event, DHCP provider
when needed, parent DNS. UDP queries/polling, DHCP processing/maintenance and TCP
snapshot creation enter as concurrent readers. Reload enters exclusively,
rebuilds hosts and clears forwarded answers, reloads DHCP host-file rules,
updates the lease file and forces DNS publication before readers resume. No
client receive, client send or TCP upstream wait holds the event gate. The
existing ICMP probe is inside DHCP processing; other readers can still run.
The main configuration is not reparsed on HUP. Maintenance and host-file errors
are surfaced in the daemon log.

The event gate is a correctness boundary, not a claimed performance improvement.
Its cost and the remaining worker/poll/socket layout need representative paired
measurement; synchronous publication must not be weakened to improve speed.

`tools/dnsmasq/dhcp_dns_diff.py` uses identical private configuration, hosts and
lease paths, loopback upstream behavior and namespace isolation for C/Rust.
The C daemon supplies the DNS and upstream-event trace. After each DHCP ACK the
tester immediately queries DNS, without waiting for delayed publication. Lease
file expiration is checked against the corresponding address's DHCP transaction
wall-clock interval; every DNS TTL remains part of the exact comparison.

Evidence in `private/dnsmasq-rewrite/lease-dns-service-20261001/`:

- `lease-dns-01`: 30/30 matched events. Covers DORA, immediate A/FQDN/PTR/CNAME,
  TCP, known parent and unknown qtype NXDOMAIN conversion, preexisting A cache,
  hosts-file conflict/rebuild, renewal, restart, release, and a restored finite
  lease expiring without any new DHCP packet. Both lease-file and DNS removal
  are checked.
- `lease-dns-calibration-01`: mutating one decoded reply flag yields 29 matches,
  one mismatch and exit 1. Original packet bytes are retained.
- `lease-dns-02`: expanded fixed corpus 34/34 matches; additionally preloads an
  AAAA NXDOMAIN, publishes a DHCP A name, verifies that the old name-wide negative
  remains as C requires, then checks release. Fixed C anchors validate the
  OFFER/no-publication, ACK address/TTL, FQDN PTR and final empty lease file.

The native C ELF is pinned in each summary. These are build-host native socket
checks, not target-image dependency or router performance evidence. The related
ordinary host-file reload fixture separately passed 41 checks over 13 snapshots,
168 DNS replies and five DHCP exchanges; its negative controls and unsupported
selector boundary are recorded in `DHCP_HOST_FILES_PHASE.md`.

Known boundaries are explicit. Publication-time invalidation is not a substitute
for insertion-time local ownership checks: an upstream query pending before a
lease can return later, and the cache must reject conflicting data at insertion.
That race and CNAME targets pointing to local records are a separate active gate.
`LEASE_NAMES_PHASE.md` retains the same-bucket incidental expiration counterexample
under clock rollback; the passing monotonic/queried-name cases do not close it.
Upstream PTR caching, complete TCP cache inheritance/writeback, tags/inotify/helper,
UBus/doctor and production startup/privilege contracts are not established here.
