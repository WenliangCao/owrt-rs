# DNS-disabled listeners and startup ordering

`port=0` now skips DNS hosts/resolver ingestion, the DNS forward/cache object,
DNS entropy descriptor, and all DNS UDP/TCP listeners. It still permits the
implemented DHCP or TFTP service. DHCP retains its domain configuration and
persistent lease processing while `update_dns` keeps dirty state when DNS is
disabled; there is no pretend empty DNS publication. This does not enable other
DNS or interface directives whose runtime behavior remains unsupported.

All enabled engines prepare their resources before any listener worker starts.
The DHCP lease file is opened/restored and DHCP is bound before DNS sockets,
matching `dnsmasq.c:311–400`. DNS/TFTP preparation completes before the initial
lease-file/DNS maintenance, and that maintenance completes before workers can
answer the first query. Previously a DNS worker could answer while leases were
still being restored/published, or during a later engine's startup failure.
The initial DNS test no longer waits for publication to catch up after readiness.

Network socket setup failures carry `EC_BADNET=2`; DHCP's typed initialization
error carries file failures as 3, entropy failures as 5, and stored-lease capacity
exhaustion as 5. See `PORT_ZERO_DHCP_PHASE.md` for exact source and calibration.
The main error code boundary classifies origin, not errno. This closes those
specified errors, not every daemon logging/privilege/helper startup path.

`tools/dnsmasq/port_zero_tftp_diff.py` provides an independent actual-C/TFTP-only
namespace gate: private hosts and resolver FIFO paths have no writer. Both C
and Rust start, transfer a file, survive SIGHUP, transfer again, exit normally
and release the TFTP port; DNS TCP/UDP port 53 remains bindable throughout.
Opening either DNS input would block and fail the bounded transfer/exit checks.
The reference and Rust use identical arguments/configuration. The dedicated
transfer port is random; its source address and dedicated-port property are
checked, while data/block/opcode bytes remain exact.

Evidence in `private/dnsmasq-rewrite/port-zero-tftp-20261001/` retains the first
7/7 comparison and `port-zero-tftp-02` after startup preparation moved ahead of
workers, also **7/7**. A deliberate DATA mutation is rejected by calibration.
`private/dnsmasq-rewrite/lease-dns-service-20261001/lease-dns-startup-03` additionally
passes **34/34** DHCP/DNS events, now requiring the first restored-name query
to succeed without a polling allowance. Native build-host C is the reference;
these are not target-image dependency or physical-router gates.

The independent DHCP-only port-zero gate is **72/72**, with its 71/1 negative
control and original clock-boundary failure retained. Its socket snapshot is
C one UDP descriptor / Rust two because the existing interface-control socket
is retained. That is an explicit resource cost, not a performance saving or a
complete descriptor-peak measurement. No throughput/CPU improvement is claimed.
