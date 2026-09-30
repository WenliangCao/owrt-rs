# TFTP transfer port range phase

Source contracts are `option.c:3648-3661` for parsing and
`tftp.c:303-357` for allocation. `TftpListener::bind_with_port_range` consumes
the typed optional range. The existing `bind` constructor uses `None`.
The daemon caller must explicitly pass `TftpConfig::port_range`; readiness
now accepts the option instead of rejecting a parsed but unused value.

The listener normalizes reversed endpoints and tries the lowest port first.
Only `EADDRINUSE` advances to the next port. A zero start requests an ephemeral
port even with a nonzero end; single-port mode uses the server socket and
ignores the transfer range. Allocation/bind failure consumes that request
without opening its file, records a nonfatal transport error and retains the
other transfers. Successful, aborted, timed-out and request-error sockets
return their ports to the range.

The isolated exact-C/Rust `run-11-range/` in
`private/dnsmasq-rewrite/tftp-listener-tid-20260930/` passed 19 observations for
each of IPv4 and IPv6, 38 total with zero differences. Cases include an
externally occupied first port, exhaustion while another transfer remains
active, reuse after external release, completion and error, failure before
file-open when the range is full, zero start, and single-port operation while
both configured transfer ports are occupied. The first available port is
checked explicitly, rather than merely checking range membership. The
additional Linux test covers port 65535 exhaustion and release without
integer wrap, and the zero-start branch in both address families.

All 32 host TFTP tests and 34 Linux namespace TFTP tests pass. The complete
related service suite was rerun after the port-binding change: `run-12-final/`
has 192 observations, 12 explicit single-port reference-defect differences,
zero unexpected mismatches. Single-port C defects remain separately classified
in `TFTP_SINGLE_PORT_PHASE.md`, not turned into zero-difference equivalence.

Current range selection is linear in the number of occupied candidates, as
in C. Rust's standard socket constructor allocates a descriptor for each bind
attempt, whereas C retries bind using one descriptor. This is an unmeasured
syscall cost difference, not a claimed performance improvement; optimizing it
requires its own correctness and measurement gate. No production permissions,
physical-router performance, helper/PXE integration, arbitrary interface
changes or allocator-pressure acceptance follows from these host results.
