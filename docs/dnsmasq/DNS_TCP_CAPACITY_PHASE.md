# TCP connection capacity and queued admission

2026-10-01. Exact C normal foreground (`-k`) mode leaves excess TCP
connections queued while `max-tcp-connections` slots are occupied. Rust now
checks the shared slot count before accepting: the unchanged actual-service
gate passes **31/31**, and its injected negative fails exactly one row.
The frozen pre-fix Rust baseline remains **23/31 matched, eight differences,
exit 1** in the preserved evidence.

## Existing interface and failure boundary

`dnsmasq.c::set_dns_listeners` (lines 1900–1915 in the matching 2.93 source)
only polls the TCP listener if a slot has both `tcp_pids[i] == 0` and
`tcp_pipes[i] == -1`. `check_dns_listeners` rechecks those conditions before
`do_tcp_connection` (lines 1989–2003), because other work may consume the last
slot after poll. A slot is released after both child exit and cache-pipe EOF;
either event may occur first. This also controls the actual UBus
`tcp_connections` gauge. Debug mode (`-d`) does not establish this contract.

Rust commit `31d6056e1c1c2f1ff1be66dcbe8ca4ee42787b82` calls `accept()`
before checking `ParentEvents.tcp_active` against the configured limit.
Its `continue` then drops the accepted stream. Consequently a client whose
TCP handshake completed at capacity receives a close/reset and cannot recover
on the same connection when an active connection exits. Multiple Rust TCP
listeners share the same counter; any fix must reserve capacity and accept
consistently across them without holding shared service locks during waits.

## Frozen service evidence

`tools/dnsmasq/dns_tcp_capacity_diff.py` runs both full binaries with identical
configuration and packets, using an isolated loopback network/mount/PID
namespace and a private `/run` and ubusd. Both use `-k`; C additionally gets
explicit root user/group, private pid file and stderr logging. The same local
hosts record avoids involving the separately unfinished TCP cache-writeback
contract. No DHCP, router or production network is touched.

Two profiles use limits 1 and 2 and addresses `127.0.0.1` and `127.0.0.2`.
The second profile fills the two slots through different destination addresses.
Each profile confirms the following sequence:

- All admitted clients answer a local DNS query, and the gauge reaches the
  configured limit.
- An additional connected client submits its DNS frame. C leaves it pending
  during a 200 ms observation window; Rust closes it.
- The parent still answers UDP, and an admitted TCP client remains usable.
- Closing one admitted client lets C answer the queued frame and another
  query on that same connection. Rust has already lost the queued client.
- All connections close; the gauge reaches zero. A fresh TCP connection then
  answers successfully, closes, and the daemon shuts down with exit 0.

The 31 comparison rows include every decoded DNS field, 14 complete snapshots
of all 30 real UBus counters, admission outcomes and both shutdown statuses.
The same four rows fail in each profile: pending admission, response after
slot release, connection reuse, and the resulting connection gauge. Other
rows match. Initial and final gauge values, exact address/TTL/flags, the one
parent UDP local-answer increment, zero unrelated counters and all successful
C replies are independently calibrated. Three deliberate admission, gauge
and RCODE mutations plus a missing-row mutation are detected per profile.
Every helper lifecycle/UBus check passes for C and Rust. An additional pair
using the exact C executable on both sides passes 31/31; the command-line
negative control reports 30/31 and exits 1. Those runs independently exercise
the full comparison and negative-control paths before the fix.

Evidence is retained under
`private/dnsmasq-rewrite/tcp-capacity-20261001/`: `freeze-01/` records the
committed source archive and identities; `before-01-evidence.tar.gz` and its
extracted `private/before-01/` preserve configs, raw queries/replies, all UBus
calls, logs, fixture checks, source build output and the complete nonzero
comparison. The corresponding remote root is
`/home/ubuntu/dnsmasq-tcp-capacity-20261001`.

- Exact C ELF SHA-256:
  `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
- Rust baseline ELF SHA-256:
  `0793cefeba63ea13f3baad4e01b98c807acf03db73f1f98517f6a37bf546cc54`.
- Committed source archive SHA-256:
  `a1ce65c1040ec08eb6a1a4519d9375217cf1aea8895301ab5e1ed5cd6f67181d`.

Reproduce on the authorized oracle through `tools/dnsmasq/run_isolated.sh`
with `--reference-build <exact native C build> --rust <frozen Rust ELF>
--out <new private directory>`. `--inject-failure` changes one compared
admission observation and must keep the gate nonzero.

## Corrected shared admission

Isolated candidate commit `88c46f5990e268a0ad4c5e1d13b60bb752f6845b`
moves the existing parent-event lock and capacity check before the nonblocking
`accept()`. Keeping the lock through successful accept and snapshot creation
serializes all listener admissions. A full listener leaves its connection
queued; the lock is released before retry sleeps. The slot count increments
only after acceptance and snapshot creation. Existing connection-owned permits
release their slots on worker completion and setup/spawn failure.

`after-01` passes all 31 comparison rows, including both queued connections
answering after a slot release and continuing to answer on the same socket.
All 14 full metric snapshots agree with C, all fixture checks pass, both
daemons exit 0, and neither retains a child after the closing gauge reaches
zero. `after-negative-01` reports **30/31, exactly one injected admission
mismatch, exit 1**. The test tool is byte-identical to the before-fix tool:
`13293710fc4d30dd729a5f5a2e6e98bf6a743b8e199ea2549b1136ace9b2094d`.
Only the private evidence path changes in the generated configurations;
limits, hosts, addresses, requests and observation order are unchanged.

The tested candidate Rust ELF SHA-256 is
`4a8df539688df4562d4d326fa72b69dd72baed20baf4b67ffb018aa0578375c2`.
Its frozen source archive SHA-256 is
`9d335cdd2d4c68cd4e9e611677d0b3b64805ebcd88a813b0e48ac0fd6dcb308a`.
The same local evidence root retains `after-01-evidence.tar.gz`, extracted
`private/after-01/` and `private/after-negative-01/`, and
`freeze-01/candidate-identity.json`. Earlier C/C calibration runs remain in
`calibration-01-evidence.tar.gz`. These identities qualify the isolated
candidate; a later integration snapshot requires its own affected checks.

This establishes the native service admission boundary. It does not qualify
TCP backlog overflow, admission fairness, arbitrary packet fragmentation,
pipe-backpressure/reaping races, target-image execution or performance.
The closing descriptor counts (C 15, Rust 9) are retained as observations;
they are neither peak-resource measurements nor an improvement claim.
